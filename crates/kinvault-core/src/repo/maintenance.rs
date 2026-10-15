//! Pruning old snapshots and verifying that stored data is intact.

use std::collections::{HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{PackWriter, Repository};
use crate::backend::Backend;
use crate::error::{Error, Result};
use crate::ids::{ChunkId, PackId};
use crate::pack;
use crate::retention::RetentionPolicy;
use crate::snapshot::{NodeKind, Tree};

/// Packs with less than this fraction of live data are rewritten by prune.
/// Lower means less traffic (repacking downloads the pack) but more wasted space.
const REPACK_BELOW_LIVE: f64 = 0.3;

#[derive(Debug, Default, Clone)]
pub struct PruneStats {
    pub snapshots_kept: u64,
    pub snapshots_removed: u64,
    pub packs_deleted: u64,
    pub packs_repacked: u64,
    /// Approximate size of the packs deleted (including repacked ones).
    pub bytes_deleted: u64,
    pub bytes_downloaded: u64,
    pub bytes_uploaded: u64,
}

#[derive(Debug, Default, Clone)]
pub struct VerifyReport {
    pub snapshots: u64,
    pub trees: u64,
    pub chunks_referenced: u64,
    /// Data chunks referenced by a snapshot but not stored anywhere.
    pub missing_chunks: u64,
    pub packs_checked: u64,
    pub bytes_checked: u64,
    /// Packs found corrupted; they were removed so the next backup re-uploads
    /// whatever still exists locally.
    pub damaged_packs: Vec<PackId>,
    pub errors: Vec<String>,
}

impl VerifyReport {
    pub fn is_ok(&self) -> bool {
        self.missing_chunks == 0 && self.damaged_packs.is_empty() && self.errors.is_empty()
    }
}

type PackCache = VecDeque<(PackId, Vec<u8>)>;

impl<B: Backend> Repository<B> {
    fn read_tree(&self, id: &ChunkId, cache: &mut PackCache) -> Result<Tree> {
        Ok(postcard::from_bytes(&self.read_blob(id, cache)?)?)
    }

    /// Every tree and data chunk reachable from `roots`. Fails if any tree
    /// can't be read, so callers never act on an incomplete picture.
    fn reachable(&self, roots: &[ChunkId], cache: &mut PackCache) -> Result<HashSet<ChunkId>> {
        let mut seen = HashSet::new();
        let mut stack = roots.to_vec();
        while let Some(tree_id) = stack.pop() {
            if !seen.insert(tree_id) {
                continue;
            }
            for node in self.read_tree(&tree_id, cache)?.nodes {
                match node.kind {
                    NodeKind::Dir { tree } => stack.push(tree),
                    NodeKind::File { chunks, .. } => seen.extend(chunks),
                    NodeKind::Symlink { .. } => {}
                }
            }
        }
        Ok(seen)
    }

    /// Removes snapshots the policy doesn't keep, then frees the space only
    /// they used: unused packs are deleted, mostly-unused packs are rewritten.
    pub fn prune(&mut self, policy: &RetentionPolicy) -> Result<PruneStats> {
        self.sync_index()?;
        let mut stats = PruneStats::default();
        let snapshots = self.list_snapshots()?;
        let times: Vec<_> = snapshots.iter().map(|(id, s)| (*id, s.time_ns)).collect();
        let keep = policy.select(&times);

        // Work out what is still needed before deleting anything.
        let roots: Vec<ChunkId> = snapshots
            .iter()
            .filter(|(id, _)| keep.contains(id))
            .map(|(_, s)| s.root)
            .collect();
        let mut cache = PackCache::new();
        let live = self.reachable(&roots, &mut cache)?;
        drop(cache);

        for (id, _) in &snapshots {
            if keep.contains(id) {
                stats.snapshots_kept += 1;
            } else {
                self.backend.delete_snapshot(id)?;
                stats.snapshots_removed += 1;
            }
        }

        let contents = self.index.pack_contents()?;
        let mut to_delete = Vec::new();
        let mut to_repack = Vec::new();
        for (pack, entries) in &contents {
            let total: u64 = entries.iter().map(|e| e.len as u64).sum();
            let used: u64 = entries
                .iter()
                .filter(|e| live.contains(&e.id))
                .map(|e| e.len as u64)
                .sum();
            if used == 0 {
                to_delete.push((*pack, total));
            } else if (used as f64) < REPACK_BELOW_LIVE * total as f64 {
                to_repack.push((*pack, total));
            }
        }

        // Copy the live blobs of mostly-dead packs into new packs first, so
        // nothing that is still needed is ever missing.
        let mut writer = PackWriter::default();
        for (pack, _) in &to_repack {
            let data = self.fetch_pack(pack)?;
            stats.bytes_downloaded += data.len() as u64;
            // Each chunk is listed under one pack only, so none is copied twice.
            for entry in contents[pack].iter().filter(|e| live.contains(&e.id)) {
                let plaintext =
                    pack::decode_blob(&self.keys, &entry.id, pack::blob_bytes(&data, entry)?)?;
                writer.add(self, entry.id, entry.kind, &plaintext)?;
            }
        }
        writer.flush(self)?;
        stats.bytes_uploaded = writer.bytes;
        stats.packs_repacked = to_repack.len() as u64;

        for (pack, size) in to_delete.iter().chain(&to_repack) {
            self.backend.delete_pack(pack)?;
            self.index.remove_pack(pack)?;
            stats.bytes_deleted += size;
        }
        stats.packs_deleted = to_delete.len() as u64;
        Ok(stats)
    }

    /// Checks that every snapshot's structure is complete, then downloads and
    /// fully decrypts up to `max_bytes` of packs, least recently checked
    /// first, so repeated runs eventually cover everything.
    pub fn verify(&mut self, max_bytes: u64) -> Result<VerifyReport> {
        self.sync_index()?;
        let mut report = VerifyReport::default();
        let mut cache = PackCache::new();
        let mut trees = HashSet::new();
        let mut chunks = HashSet::new();

        for id in self.backend.list_snapshots()? {
            let snapshot = match self.load_snapshot(&id) {
                Ok(s) => s,
                Err(e) => {
                    report.errors.push(format!("snapshot {id}: {e}"));
                    continue;
                }
            };
            report.snapshots += 1;
            let mut stack = vec![snapshot.root];
            while let Some(tree_id) = stack.pop() {
                if !trees.insert(tree_id) {
                    continue;
                }
                match self.read_tree(&tree_id, &mut cache) {
                    Ok(tree) => {
                        for node in tree.nodes {
                            match node.kind {
                                NodeKind::Dir { tree } => stack.push(tree),
                                NodeKind::File { chunks: c, .. } => chunks.extend(c),
                                NodeKind::Symlink { .. } => {}
                            }
                        }
                    }
                    Err(e) => report
                        .errors
                        .push(format!("directory listing {tree_id} (snapshot {id}): {e}")),
                }
            }
        }
        drop(cache);
        report.trees = trees.len() as u64;
        report.chunks_referenced = chunks.len() as u64;
        for chunk in &chunks {
            if !self.index.has_chunk(chunk)? {
                report.missing_chunks += 1;
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        for pack in self.index.packs_by_verify_age()? {
            if report.bytes_checked >= max_bytes {
                break;
            }
            match self.check_pack(&pack) {
                Ok(len) => {
                    report.packs_checked += 1;
                    report.bytes_checked += len;
                    self.index.mark_verified(&pack, now)?;
                }
                Err(
                    e @ (Error::Corrupt(_)
                    | Error::Decrypt
                    | Error::Encoding(_)
                    | Error::NotFound(_)),
                ) => {
                    report.errors.push(format!("pack {pack}: {e}"));
                    report.damaged_packs.push(pack);
                    // Forget it so the next backup re-uploads what still exists locally.
                    let _ = self.backend.delete_pack(&pack);
                    self.index.remove_pack(&pack)?;
                }
                // Network or local I/O problems say nothing about the data; stop here.
                Err(e) => return Err(e),
            }
        }
        Ok(report)
    }

    fn check_pack(&self, id: &PackId) -> Result<u64> {
        let data = self.fetch_pack(id)?;
        for entry in pack::read_header(&self.keys, &data)? {
            pack::decode_blob(&self.keys, &entry.id, pack::blob_bytes(&data, &entry)?)?;
        }
        Ok(data.len() as u64)
    }
}
