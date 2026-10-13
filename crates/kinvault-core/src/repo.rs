use std::collections::{HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fastcdc::v2020::StreamCDC;

use crate::backend::Backend;
use crate::crypto::{Keys, MasterKey};
use crate::error::{Error, Result};
use crate::exclude::Excludes;
use crate::ids::{ChunkId, PackId, SnapshotId};
use crate::index::{CachedFile, Index};
use crate::pack::{self, BlobKind, PackBuilder};
use crate::snapshot::{self, Node, NodeKind, Snapshot, Tree};

mod maintenance;
pub use maintenance::{PruneStats, VerifyReport};

const CHUNK_MIN: u32 = 256 * 1024;
const CHUNK_AVG: u32 = 1024 * 1024;
const CHUNK_MAX: u32 = 4 * 1024 * 1024;
const DEFAULT_PACK_TARGET: usize = 32 * 1024 * 1024;
const PACK_CACHE_SLOTS: usize = 4;

/// Running totals reported while a backup is in progress.
#[derive(Debug, Default, Clone, Copy)]
pub struct BackupProgress {
    pub files: u64,
    pub total_bytes: u64,
    pub bytes_read: u64,
    pub bytes_uploaded: u64,
}

pub type ProgressFn = Arc<dyn Fn(&BackupProgress) + Send + Sync>;

/// How far a restore got, out of what it restores in total.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RestoreProgress {
    pub files: u64,
    pub bytes: u64,
    pub total_files: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Default, Clone)]
pub struct BackupStats {
    pub files: u64,
    /// Files whose content had to be read because they were new or changed.
    pub files_changed: u64,
    pub dirs: u64,
    pub total_bytes: u64,
    pub bytes_read: u64,
    pub new_chunks: u64,
    pub packs_uploaded: u64,
    pub bytes_uploaded: u64,
    /// Entries that couldn't be read and were skipped.
    pub warnings: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct RestoreStats {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub bytes: u64,
}

/// One backup set: an encrypted, deduplicated snapshot store on a [`Backend`].
pub struct Repository<B: Backend> {
    backend: B,
    keys: Keys,
    index: Index,
    pack_target: usize,
    excludes: Vec<PathBuf>,
    exclude_patterns: Excludes,
    progress: Option<ProgressFn>,
}

impl<B: Backend> Repository<B> {
    pub fn open(backend: B, master: &MasterKey, index: Index) -> Self {
        Self {
            backend,
            keys: master.derive_keys(),
            index,
            pack_target: DEFAULT_PACK_TARGET,
            excludes: Vec::new(),
            exclude_patterns: Excludes::default(),
            progress: None,
        }
    }

    pub fn set_pack_target(&mut self, bytes: usize) {
        self.pack_target = bytes;
    }

    /// Called after each file during backups; keep it cheap.
    pub fn set_progress(&mut self, progress: Option<ProgressFn>) {
        self.progress = progress;
    }

    /// Absolute paths (and everything below them) to leave out of backups.
    pub fn set_excludes(&mut self, excludes: Vec<PathBuf>) {
        self.excludes = excludes;
    }

    /// Patterns for files and folders to leave out of backups. Earlier
    /// snapshots keep what they hold until retention removes them.
    pub fn set_exclude_patterns(&mut self, patterns: Excludes) {
        self.exclude_patterns = patterns;
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Reconciles the local index with the packs the backend actually holds.
    /// Only headers of packs we don't know yet are downloaded.
    pub fn sync_index(&mut self) -> Result<()> {
        let remote: HashSet<PackId> = self.backend.list_packs()?.into_iter().collect();
        let local = self.index.known_packs()?;
        for gone in local.difference(&remote) {
            self.index.remove_pack(gone)?;
        }
        for new in remote.difference(&local) {
            let (len, mut tail) = self.backend.get_pack_tail(new, pack::HEADER_TAIL_GUESS)?;
            let needed = pack::header_tail_len(&tail)?;
            if needed > tail.len() as u64 {
                (_, tail) = self.backend.get_pack_tail(new, needed)?;
            }
            let entries = pack::read_header_tail(&self.keys, len, &tail)?;
            self.index.add_pack(new, &entries)?;
        }
        Ok(())
    }

    fn fetch_pack(&self, id: &PackId) -> Result<Vec<u8>> {
        let data = self.backend.get_pack(id)?;
        if blake3::hash(&data).as_bytes() != &id.0 {
            return Err(Error::Corrupt(format!("pack {id} does not match its id")));
        }
        Ok(data)
    }

    pub fn backup(
        &mut self,
        sources: &[PathBuf],
        hostname: &str,
    ) -> Result<(SnapshotId, BackupStats)> {
        self.backup_if_changed(sources, hostname, None)
    }

    /// Like [`Self::backup`], but if the result would be identical to the
    /// `previous` snapshot (same sources, same contents), no new snapshot is
    /// stored and `previous` is returned. Saves traffic and keeps retention's
    /// "latest N" for real changes.
    pub fn backup_if_changed(
        &mut self,
        sources: &[PathBuf],
        hostname: &str,
        previous: Option<&SnapshotId>,
    ) -> Result<(SnapshotId, BackupStats)> {
        self.sync_index()?;
        let mut run = BackupRun {
            repo: self,
            writer: PackWriter::default(),
            stats: BackupStats::default(),
        };

        let mut nodes: Vec<Node> = Vec::new();
        let mut paths = Vec::new();
        for src in sources {
            let abs = fs::canonicalize(src)
                .map_err(|e| Error::NotFound(format!("backup source {}: {e}", src.display())))?;
            let name = snapshot_root_name(&abs);
            if nodes.iter().any(|n| n.name == name) {
                continue;
            }
            paths.push(abs.to_string_lossy().into_owned());
            if let Some(node) = run.store_path(&abs, name)? {
                nodes.push(node);
            }
        }
        nodes.sort_by(|a, b| a.name.cmp(&b.name));
        let root = run.store_tree(Tree { nodes })?;
        run.flush()?;
        let stats = run.stats;

        if let Some(prev) = previous
            // Gone (e.g. pruned) or unreadable: just store a new one.
            && let Ok(old) = self.load_snapshot(prev)
            && old.root == root
            && old.paths == paths
            && old.hostname == hostname
        {
            return Ok((*prev, stats));
        }

        let snapshot = Snapshot {
            time_ns: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as i64,
            hostname: hostname.to_string(),
            paths,
            root,
            file_count: stats.files,
            total_bytes: stats.total_bytes,
        };
        // Written last: a snapshot only becomes visible once all its data is stored.
        let (id, data) = snapshot::encode_snapshot(&self.keys, &snapshot)?;
        self.backend.put_snapshot(&id, &data)?;
        Ok((id, stats))
    }

    pub fn load_snapshot(&self, id: &SnapshotId) -> Result<Snapshot> {
        snapshot::decode_snapshot(&self.keys, id, &self.backend.get_snapshot(id)?)
    }

    /// All snapshots, oldest first.
    pub fn list_snapshots(&self) -> Result<Vec<(SnapshotId, Snapshot)>> {
        let mut out = Vec::new();
        for id in self.backend.list_snapshots()? {
            out.push((id, self.load_snapshot(&id)?));
        }
        out.sort_by_key(|(_, s)| s.time_ns);
        Ok(out)
    }

    /// Resolves a unique hex prefix (or "latest") to a snapshot id.
    pub fn find_snapshot(&self, prefix: &str) -> Result<SnapshotId> {
        if prefix == "latest" {
            return self
                .list_snapshots()?
                .pop()
                .map(|(id, _)| id)
                .ok_or_else(|| Error::NotFound("no snapshots".into()));
        }
        let prefix = prefix.to_ascii_lowercase();
        let matches: Vec<SnapshotId> = self
            .backend
            .list_snapshots()?
            .into_iter()
            .filter(|id| id.to_hex().starts_with(&prefix))
            .collect();
        match matches.as_slice() {
            [id] => Ok(*id),
            [] => Err(Error::NotFound(format!("snapshot {prefix}"))),
            _ => Err(Error::Invalid(format!(
                "snapshot prefix {prefix} is ambiguous"
            ))),
        }
    }

    /// Restores a snapshot under `target`. Sources are recreated by their
    /// original absolute path relative to `target`. `include` restricts the
    /// restore to one path (in snapshot terms, e.g. `home/me/Documents/a.txt`).
    pub fn restore(
        &mut self,
        id: &SnapshotId,
        target: &Path,
        include: Option<&str>,
    ) -> Result<RestoreStats> {
        self.restore_with_progress(id, target, include, &mut |_| true)
    }

    /// Like [`Self::restore`], reporting progress as data is written.
    /// `progress` returning false cancels the restore with [`Error::Cancelled`]
    /// (files restored so far are left in place).
    pub fn restore_with_progress(
        &mut self,
        id: &SnapshotId,
        target: &Path,
        include: Option<&str>,
        progress: &mut dyn FnMut(&RestoreProgress) -> bool,
    ) -> Result<RestoreStats> {
        let snapshot = self.load_snapshot(id)?;
        if !self.index.has_chunk(&snapshot.root)? {
            self.sync_index()?;
        }
        let include = include
            .map(|s| s.trim_matches('/').to_string())
            .filter(|s| !s.is_empty());
        let mut ctx = RestoreCtx {
            cache: VecDeque::new(),
            stats: RestoreStats::default(),
            progress: RestoreProgress {
                total_files: snapshot.file_count,
                total_bytes: snapshot.total_bytes,
                ..Default::default()
            },
            report: progress,
        };
        if let Some(inc) = include.as_deref() {
            // Only part of the snapshot: count what that part holds.
            let (files, bytes) = self.count_tree(&snapshot.root, "", Some(inc), &mut ctx.cache)?;
            ctx.progress.total_files = files;
            ctx.progress.total_bytes = bytes;
        }
        if !(ctx.report)(&ctx.progress) {
            return Err(Error::Cancelled);
        }
        fs::create_dir_all(target)?;
        self.restore_tree(&snapshot.root, target, "", include.as_deref(), &mut ctx)?;
        Ok(ctx.stats)
    }

    /// Files and bytes under `rel` that `include` selects.
    fn count_tree(
        &self,
        tree_id: &ChunkId,
        rel: &str,
        include: Option<&str>,
        cache: &mut VecDeque<(PackId, Vec<u8>)>,
    ) -> Result<(u64, u64)> {
        let tree: Tree = postcard::from_bytes(&self.read_blob(tree_id, cache)?)?;
        let (mut files, mut bytes) = (0, 0);
        for node in &tree.nodes {
            let node_rel = if rel.is_empty() {
                node.name.clone()
            } else {
                format!("{rel}/{}", node.name)
            };
            let Some(child_include) = included(include, &node_rel) else {
                continue;
            };
            match &node.kind {
                NodeKind::Dir { tree } => {
                    let (f, b) = self.count_tree(tree, &node_rel, child_include, cache)?;
                    files += f;
                    bytes += b;
                }
                _ if child_include.is_some() => {}
                NodeKind::File { size, .. } => {
                    files += 1;
                    bytes += size;
                }
                NodeKind::Symlink { .. } => {}
            }
        }
        Ok((files, bytes))
    }

    fn read_blob(&self, id: &ChunkId, cache: &mut VecDeque<(PackId, Vec<u8>)>) -> Result<Vec<u8>> {
        let loc = self
            .index
            .locate(id)?
            .ok_or_else(|| Error::NotFound(format!("chunk {id} is not in any known pack")))?;
        if !cache.iter().any(|(p, _)| *p == loc.pack) {
            let data = self.fetch_pack(&loc.pack)?;
            if cache.len() >= PACK_CACHE_SLOTS {
                cache.pop_front();
            }
            cache.push_back((loc.pack, data));
        }
        let (_, data) = cache.iter().find(|(p, _)| *p == loc.pack).unwrap();
        pack::decode_blob(&self.keys, id, pack::blob_bytes(data, &loc.entry)?)
    }

    fn restore_tree(
        &self,
        tree_id: &ChunkId,
        dir: &Path,
        rel: &str,
        include: Option<&str>,
        ctx: &mut RestoreCtx,
    ) -> Result<()> {
        let tree: Tree = postcard::from_bytes(&self.read_blob(tree_id, &mut ctx.cache)?)?;
        for node in &tree.nodes {
            validate_name(&node.name)?;
            let node_rel = if rel.is_empty() {
                node.name.clone()
            } else {
                format!("{rel}/{}", node.name)
            };
            let Some(child_include) = included(include, &node_rel) else {
                continue;
            };
            let path = dir.join(&node.name);
            match &node.kind {
                NodeKind::Dir { tree } => {
                    fs::create_dir_all(&path)?;
                    self.restore_tree(tree, &path, &node_rel, child_include, ctx)?;
                    ctx.stats.dirs += 1;
                    set_mode(&path, node.mode)?;
                }
                // The include path points inside a file; nothing to restore here.
                _ if child_include.is_some() => continue,
                NodeKind::File { chunks, .. } => {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let mut file = fs::File::create(&path)?;
                    for chunk in chunks {
                        let data = self.read_blob(chunk, &mut ctx.cache)?;
                        std::io::Write::write_all(&mut file, &data)?;
                        ctx.stats.bytes += data.len() as u64;
                        ctx.progress.bytes += data.len() as u64;
                        if !(ctx.report)(&ctx.progress) {
                            return Err(Error::Cancelled);
                        }
                    }
                    file.set_modified(from_mtime_ns(node.mtime_ns))?;
                    drop(file);
                    set_mode(&path, node.mode)?;
                    ctx.stats.files += 1;
                    ctx.progress.files += 1;
                    if !(ctx.report)(&ctx.progress) {
                        return Err(Error::Cancelled);
                    }
                }
                NodeKind::Symlink { target } => {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    if path.symlink_metadata().is_ok() {
                        fs::remove_file(&path)?;
                    }
                    make_symlink(target, &path)?;
                    ctx.stats.symlinks += 1;
                }
            }
        }
        Ok(())
    }
}

struct RestoreCtx<'a> {
    cache: VecDeque<(PackId, Vec<u8>)>,
    stats: RestoreStats,
    progress: RestoreProgress,
    report: &'a mut dyn FnMut(&RestoreProgress) -> bool,
}

/// Whether a node at `node_rel` is restored when only `include` (a path in
/// the snapshot) is wanted: `None` to skip it, otherwise the include to apply
/// to its children (`Some(None)`: everything below it).
fn included<'a>(include: Option<&'a str>, node_rel: &str) -> Option<Option<&'a str>> {
    match include {
        None => Some(None),
        Some(inc) if inc == node_rel => Some(None),
        Some(inc) if inc.starts_with(&format!("{node_rel}/")) => Some(Some(inc)),
        Some(inc) if node_rel.starts_with(&format!("{inc}/")) => Some(None),
        Some(_) => None,
    }
}

/// Buffers new blobs into packs and uploads them when full. Data and trees
/// go into separate packs so that walking snapshots (prune, verify) only
/// needs the small tree packs.
#[derive(Default)]
struct PackWriter {
    data: PackBuilder,
    tree: PackBuilder,
    packs: u64,
    bytes: u64,
}

impl PackWriter {
    fn contains(&self, id: &ChunkId) -> bool {
        self.data.contains(id) || self.tree.contains(id)
    }

    fn builder(&mut self, kind: BlobKind) -> &mut PackBuilder {
        match kind {
            BlobKind::Data => &mut self.data,
            BlobKind::Tree => &mut self.tree,
        }
    }

    fn add<B: Backend>(
        &mut self,
        repo: &mut Repository<B>,
        id: ChunkId,
        kind: BlobKind,
        plaintext: &[u8],
    ) -> Result<()> {
        let builder = self.builder(kind);
        builder.add(&repo.keys, id, kind, plaintext)?;
        if builder.len() >= repo.pack_target {
            self.flush_kind(repo, kind)?;
        }
        Ok(())
    }

    fn flush_kind<B: Backend>(&mut self, repo: &mut Repository<B>, kind: BlobKind) -> Result<()> {
        let builder = std::mem::take(self.builder(kind));
        if builder.is_empty() {
            return Ok(());
        }
        let finished = builder.finish(&repo.keys)?;
        repo.backend.put_pack(&finished.id, &finished.data)?;
        repo.index.add_pack(&finished.id, &finished.entries)?;
        self.packs += 1;
        self.bytes += finished.data.len() as u64;
        Ok(())
    }

    fn flush<B: Backend>(&mut self, repo: &mut Repository<B>) -> Result<()> {
        self.flush_kind(repo, BlobKind::Data)?;
        self.flush_kind(repo, BlobKind::Tree)
    }
}

struct BackupRun<'a, B: Backend> {
    repo: &'a mut Repository<B>,
    writer: PackWriter,
    stats: BackupStats,
}

impl<B: Backend> BackupRun<'_, B> {
    fn warn(&mut self, path: &Path, err: impl std::fmt::Display) {
        self.stats
            .warnings
            .push(format!("{}: {err}", path.display()));
    }

    fn store_blob(&mut self, kind: BlobKind, data: &[u8]) -> Result<ChunkId> {
        let id = self.repo.keys.chunk_id(data);
        if self.is_stored(&id)? {
            return Ok(id);
        }
        self.writer.add(self.repo, id, kind, data)?;
        self.stats.new_chunks += 1;
        Ok(id)
    }

    fn store_tree(&mut self, tree: Tree) -> Result<ChunkId> {
        self.store_blob(BlobKind::Tree, &postcard::to_allocvec(&tree)?)
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush(self.repo)?;
        self.stats.packs_uploaded = self.writer.packs;
        self.stats.bytes_uploaded = self.writer.bytes;
        Ok(())
    }

    fn report_progress(&self) {
        if let Some(progress) = &self.repo.progress {
            progress(&BackupProgress {
                files: self.stats.files,
                total_bytes: self.stats.total_bytes,
                bytes_read: self.stats.bytes_read,
                bytes_uploaded: self.writer.bytes,
            });
        }
    }

    fn is_stored(&self, id: &ChunkId) -> Result<bool> {
        Ok(self.writer.contains(id) || self.repo.index.has_chunk(id)?)
    }

    /// Returns `None` for entries that are skipped (unreadable or special files).
    /// Errors are only returned for failures that should abort the backup.
    fn store_path(&mut self, path: &Path, name: String) -> Result<Option<Node>> {
        if self.repo.excludes.iter().any(|e| path.starts_with(e)) {
            return Ok(None);
        }
        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                self.warn(path, e);
                return Ok(None);
            }
        };
        let ft = meta.file_type();
        let left_out = if ft.is_dir() {
            self.repo.exclude_patterns.excludes_dir(path)
        } else {
            self.repo.exclude_patterns.excludes_file(path)
        };
        if left_out {
            return Ok(None);
        }
        let kind = if ft.is_symlink() {
            match fs::read_link(path) {
                Ok(t) => NodeKind::Symlink {
                    target: t.to_string_lossy().into_owned(),
                },
                Err(e) => {
                    self.warn(path, e);
                    return Ok(None);
                }
            }
        } else if ft.is_dir() {
            NodeKind::Dir {
                tree: self.store_dir(path)?,
            }
        } else if ft.is_file() {
            match self.store_file(path, &meta)? {
                Some(kind) => kind,
                None => return Ok(None),
            }
        } else {
            return Ok(None);
        };
        Ok(Some(Node {
            name,
            kind,
            mode: mode(&meta),
            mtime_ns: mtime_ns(&meta),
        }))
    }

    fn store_dir(&mut self, path: &Path) -> Result<ChunkId> {
        self.stats.dirs += 1;
        let mut entries: Vec<fs::DirEntry> = match fs::read_dir(path) {
            Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
            Err(e) => {
                self.warn(path, e);
                Vec::new()
            }
        };
        entries.sort_by_key(|e| e.file_name());
        let mut nodes = Vec::with_capacity(entries.len());
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(node) = self.store_path(&entry.path(), name)? {
                nodes.push(node);
            }
        }
        self.store_tree(Tree { nodes })
    }

    fn store_file(&mut self, path: &Path, meta: &fs::Metadata) -> Result<Option<NodeKind>> {
        let key = path.to_string_lossy();
        let (size, mtime, inode) = (meta.len(), mtime_ns(meta), inode(meta));

        if let Some(cached) = self.repo.index.cached_file(&key)?
            && cached.size == size
            && cached.mtime_ns == mtime
            && cached.inode == inode
            && cached
                .chunks
                .iter()
                .try_fold(true, |ok, c| Ok::<_, Error>(ok && self.is_stored(c)?))?
        {
            self.stats.files += 1;
            self.stats.total_bytes += size;
            return Ok(Some(NodeKind::File {
                size,
                chunks: cached.chunks,
            }));
        }

        let file = match fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                self.warn(path, e);
                return Ok(None);
            }
        };
        let mut chunks = Vec::new();
        let mut read = 0u64;
        for chunk in StreamCDC::new(file, CHUNK_MIN, CHUNK_AVG, CHUNK_MAX) {
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => {
                    self.warn(path, format!("{e:?}"));
                    return Ok(None);
                }
            };
            read += chunk.length as u64;
            chunks.push(self.store_blob(BlobKind::Data, &chunk.data)?);
        }
        self.stats.files += 1;
        self.stats.files_changed += 1;
        self.stats.bytes_read += read;
        self.report_progress();
        self.stats.total_bytes += read;
        // Cache keyed on the metadata seen *before* reading, so a file modified
        // mid-read gets a new mtime and is re-read next time.
        self.repo.index.put_cached_file(
            &key,
            &CachedFile {
                size,
                mtime_ns: mtime,
                inode,
                chunks: chunks.clone(),
            },
        )?;
        Ok(Some(NodeKind::File { size: read, chunks }))
    }
}

/// Name of a source in the snapshot root: its absolute path without the
/// leading separator, with Windows prefixes/drive colons flattened. Restores
/// recreate each source under this relative path.
pub fn snapshot_root_name(abs: &Path) -> String {
    let s = abs.to_string_lossy().replace('\\', "/");
    let s = s.strip_prefix("//?/").unwrap_or(&s).replace(':', "");
    let s = s.trim_matches('/');
    if s.is_empty() {
        "root".to_string()
    } else {
        s.to_string()
    }
}

/// Rejects names that could escape the restore target.
fn validate_name(name: &str) -> Result<()> {
    let bad = name.is_empty()
        || name.starts_with('/')
        || name.contains('\\')
        || name
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..");
    if bad {
        return Err(Error::Corrupt(format!("unsafe path in snapshot: {name:?}")));
    }
    Ok(())
}

fn mtime_ns(meta: &fs::Metadata) -> i64 {
    match meta.modified() {
        Ok(t) => match t.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_nanos() as i64,
            Err(e) => -(e.duration().as_nanos() as i64),
        },
        Err(_) => 0,
    }
}

fn from_mtime_ns(ns: i64) -> SystemTime {
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(ns.unsigned_abs())
    }
}

#[cfg(unix)]
fn mode(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode(_meta: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn inode(meta: &fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::ino(meta)
}

#[cfg(not(unix))]
fn inode(_meta: &fs::Metadata) -> u64 {
    0
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if mode != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn make_symlink(target: &str, link: &Path) -> Result<()> {
    Ok(std::os::unix::fs::symlink(target, link)?)
}

#[cfg(windows)]
fn make_symlink(target: &str, link: &Path) -> Result<()> {
    Ok(std::os::windows::fs::symlink_file(target, link)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_names() {
        assert_eq!(
            snapshot_root_name(Path::new("/home/me/Docs")),
            "home/me/Docs"
        );
        assert_eq!(snapshot_root_name(Path::new("/")), "root");
        assert_eq!(
            snapshot_root_name(Path::new(r"\\?\C:\Users\me")),
            "C/Users/me"
        );
    }

    #[test]
    fn unsafe_names_rejected() {
        for bad in ["", "..", "a/../b", "/etc", "a//b", r"a\b", "./a"] {
            assert!(validate_name(bad).is_err(), "{bad:?} should be rejected");
        }
        validate_name("home/me/file.txt").unwrap();
    }
}
