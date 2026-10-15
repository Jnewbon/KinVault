use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::ids::{PackId, SnapshotId};

/// Storage for one backup set's opaque objects. Implementations never see
/// plaintext; everything passed in is already encrypted.
pub trait Backend: Send + Sync {
    fn put_pack(&self, id: &PackId, data: &[u8]) -> Result<()>;
    fn get_pack(&self, id: &PackId) -> Result<Vec<u8>>;
    /// Returns the pack's total length and up to `max_len` bytes from its end,
    /// so the header can be read without downloading the whole pack.
    fn get_pack_tail(&self, id: &PackId, max_len: u64) -> Result<(u64, Vec<u8>)> {
        let mut data = self.get_pack(id)?;
        let total = data.len() as u64;
        let start = data.len().saturating_sub(max_len as usize);
        Ok((total, data.split_off(start)))
    }
    fn list_packs(&self) -> Result<Vec<PackId>>;
    fn delete_pack(&self, id: &PackId) -> Result<()>;
    fn put_snapshot(&self, id: &SnapshotId, data: &[u8]) -> Result<()>;
    fn get_snapshot(&self, id: &SnapshotId) -> Result<Vec<u8>>;
    fn list_snapshots(&self) -> Result<Vec<SnapshotId>>;
    fn delete_snapshot(&self, id: &SnapshotId) -> Result<()>;
}

impl<B: Backend + ?Sized> Backend for Box<B> {
    fn put_pack(&self, id: &PackId, data: &[u8]) -> Result<()> {
        (**self).put_pack(id, data)
    }
    fn get_pack(&self, id: &PackId) -> Result<Vec<u8>> {
        (**self).get_pack(id)
    }
    fn get_pack_tail(&self, id: &PackId, max_len: u64) -> Result<(u64, Vec<u8>)> {
        (**self).get_pack_tail(id, max_len)
    }
    fn list_packs(&self) -> Result<Vec<PackId>> {
        (**self).list_packs()
    }
    fn delete_pack(&self, id: &PackId) -> Result<()> {
        (**self).delete_pack(id)
    }
    fn put_snapshot(&self, id: &SnapshotId, data: &[u8]) -> Result<()> {
        (**self).put_snapshot(id, data)
    }
    fn get_snapshot(&self, id: &SnapshotId) -> Result<Vec<u8>> {
        (**self).get_snapshot(id)
    }
    fn list_snapshots(&self) -> Result<Vec<SnapshotId>> {
        (**self).list_snapshots()
    }
    fn delete_snapshot(&self, id: &SnapshotId) -> Result<()> {
        (**self).delete_snapshot(id)
    }
}

/// A repository in a plain directory (external disk, NAS mount, tests).
/// Layout: `packs/<2 hex>/<hex>` and `snapshots/<hex>`.
pub struct LocalDirBackend {
    root: PathBuf,
}

impl LocalDirBackend {
    pub fn create(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("packs"))?;
        fs::create_dir_all(root.join("snapshots"))?;
        Ok(Self { root })
    }

    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        if !root.join("packs").is_dir() || !root.join("snapshots").is_dir() {
            return Err(Error::NotFound(format!(
                "no repository at {}",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn pack_path(&self, id: &PackId) -> PathBuf {
        let hex = id.to_hex();
        self.root.join("packs").join(&hex[..2]).join(hex)
    }

    fn snapshot_path(&self, id: &SnapshotId) -> PathBuf {
        self.root.join("snapshots").join(id.to_hex())
    }

    /// Moves a pack to `trash/` instead of deleting it; see [`Self::purge_trash`].
    pub fn trash_pack(&self, id: &PackId) -> Result<()> {
        self.move_to_trash(&self.pack_path(id), "packs")
    }

    pub fn trash_snapshot(&self, id: &SnapshotId) -> Result<()> {
        self.move_to_trash(&self.snapshot_path(id), "snapshots")
    }

    fn move_to_trash(&self, path: &Path, kind: &str) -> Result<()> {
        let name = path.file_name().expect("object paths end in their id");
        let dest_dir = self.root.join("trash").join(kind);
        fs::create_dir_all(&dest_dir)?;
        let dest = dest_dir.join(name);
        match fs::rename(path, &dest) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            other => other?,
        }
        // The modification time records when it was deleted.
        fs::File::options()
            .write(true)
            .open(&dest)?
            .set_modified(std::time::SystemTime::now())?;
        Ok(())
    }

    /// Permanently removes trashed objects deleted more than `grace` ago.
    /// Returns the number of bytes freed.
    pub fn purge_trash(&self, grace: std::time::Duration) -> Result<u64> {
        let mut freed = 0;
        for kind in ["packs", "snapshots"] {
            let dir = self.root.join("trash").join(kind);
            let entries = match fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            for entry in entries {
                let entry = entry?;
                let meta = entry.metadata()?;
                let age = meta.modified()?.elapsed().unwrap_or_default();
                if age >= grace {
                    fs::remove_file(entry.path())?;
                    freed += meta.len();
                }
            }
        }
        Ok(freed)
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    fs::create_dir_all(
        path.parent()
            .expect("object paths are inside the repository"),
    )?;
    let tmp = path.with_extension("tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn read_object(path: &Path, what: &str) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Error::NotFound(what.to_string()),
        _ => e.into(),
    })
}

fn remove_object(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

fn hex_names(dir: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit()) {
            out.push(name);
        }
    }
    Ok(out)
}

impl Backend for LocalDirBackend {
    fn put_pack(&self, id: &PackId, data: &[u8]) -> Result<()> {
        write_atomic(&self.pack_path(id), data)
    }

    fn get_pack(&self, id: &PackId) -> Result<Vec<u8>> {
        read_object(&self.pack_path(id), &format!("pack {id}"))
    }

    fn get_pack_tail(&self, id: &PackId, max_len: u64) -> Result<(u64, Vec<u8>)> {
        let mut f = fs::File::open(self.pack_path(id)).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => Error::NotFound(format!("pack {id}")),
            _ => e.into(),
        })?;
        let total = f.metadata()?.len();
        let start = total.saturating_sub(max_len);
        f.seek(SeekFrom::Start(start))?;
        let mut buf = Vec::with_capacity((total - start) as usize);
        f.read_to_end(&mut buf)?;
        Ok((total, buf))
    }

    fn list_packs(&self) -> Result<Vec<PackId>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.root.join("packs"))? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                for name in hex_names(&entry.path())? {
                    out.push(PackId::from_hex(&name)?);
                }
            }
        }
        Ok(out)
    }

    fn delete_pack(&self, id: &PackId) -> Result<()> {
        remove_object(&self.pack_path(id))
    }

    fn put_snapshot(&self, id: &SnapshotId, data: &[u8]) -> Result<()> {
        write_atomic(&self.snapshot_path(id), data)
    }

    fn get_snapshot(&self, id: &SnapshotId) -> Result<Vec<u8>> {
        read_object(&self.snapshot_path(id), &format!("snapshot {id}"))
    }

    fn list_snapshots(&self) -> Result<Vec<SnapshotId>> {
        hex_names(&self.root.join("snapshots"))?
            .iter()
            .map(|n| SnapshotId::from_hex(n))
            .collect()
    }

    fn delete_snapshot(&self, id: &SnapshotId) -> Result<()> {
        remove_object(&self.snapshot_path(id))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn trash_hides_then_purges() {
        let tmp = tempfile::tempdir().unwrap();
        let b = LocalDirBackend::create(tmp.path()).unwrap();
        let id = PackId([1; 32]);
        b.put_pack(&id, b"data").unwrap();
        b.trash_pack(&id).unwrap();
        assert!(b.list_packs().unwrap().is_empty());
        assert!(matches!(b.get_pack(&id), Err(Error::NotFound(_))));
        // Trashing something already gone is fine.
        b.trash_pack(&id).unwrap();
        assert_eq!(b.purge_trash(Duration::from_secs(3600)).unwrap(), 0);
        assert!(tmp.path().join("trash/packs").join(id.to_hex()).exists());
        assert_eq!(b.purge_trash(Duration::ZERO).unwrap(), 4);
        assert!(!tmp.path().join("trash/packs").join(id.to_hex()).exists());

        let snap = SnapshotId([2; 32]);
        b.put_snapshot(&snap, b"snapshot").unwrap();
        b.trash_snapshot(&snap).unwrap();
        assert!(b.list_snapshots().unwrap().is_empty());
        assert_eq!(b.purge_trash(Duration::ZERO).unwrap(), 8);
    }

    #[test]
    fn open_needs_an_existing_repository() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            LocalDirBackend::open(tmp.path()),
            Err(Error::NotFound(_))
        ));
        LocalDirBackend::create(tmp.path()).unwrap();
        let b = LocalDirBackend::open(tmp.path()).unwrap();
        assert_eq!(b.root(), tmp.path());
    }

    /// Uses the trait's own `get_pack_tail`, which downloads the whole pack.
    struct WholePacks(LocalDirBackend);

    impl Backend for WholePacks {
        fn put_pack(&self, id: &PackId, data: &[u8]) -> Result<()> {
            self.0.put_pack(id, data)
        }
        fn get_pack(&self, id: &PackId) -> Result<Vec<u8>> {
            self.0.get_pack(id)
        }
        fn list_packs(&self) -> Result<Vec<PackId>> {
            self.0.list_packs()
        }
        fn delete_pack(&self, id: &PackId) -> Result<()> {
            self.0.delete_pack(id)
        }
        fn put_snapshot(&self, id: &SnapshotId, data: &[u8]) -> Result<()> {
            self.0.put_snapshot(id, data)
        }
        fn get_snapshot(&self, id: &SnapshotId) -> Result<Vec<u8>> {
            self.0.get_snapshot(id)
        }
        fn list_snapshots(&self) -> Result<Vec<SnapshotId>> {
            self.0.list_snapshots()
        }
        fn delete_snapshot(&self, id: &SnapshotId) -> Result<()> {
            self.0.delete_snapshot(id)
        }
    }

    /// Runs every operation of the trait against an empty backend.
    fn exercise(b: &dyn Backend) {
        let pack = PackId([3; 32]);
        b.put_pack(&pack, b"0123456789").unwrap();
        assert_eq!(b.get_pack(&pack).unwrap(), b"0123456789");
        assert_eq!(b.get_pack_tail(&pack, 4).unwrap(), (10, b"6789".to_vec()));
        assert_eq!(
            b.get_pack_tail(&pack, 100).unwrap(),
            (10, b"0123456789".to_vec())
        );
        assert_eq!(b.list_packs().unwrap(), vec![pack]);
        b.delete_pack(&pack).unwrap();
        b.delete_pack(&pack).unwrap();
        assert!(matches!(b.get_pack(&pack), Err(Error::NotFound(_))));
        assert!(matches!(b.get_pack_tail(&pack, 4), Err(Error::NotFound(_))));

        let snap = SnapshotId([4; 32]);
        b.put_snapshot(&snap, b"s").unwrap();
        assert_eq!(b.get_snapshot(&snap).unwrap(), b"s");
        assert_eq!(b.list_snapshots().unwrap(), vec![snap]);
        b.delete_snapshot(&snap).unwrap();
        assert!(matches!(b.get_snapshot(&snap), Err(Error::NotFound(_))));
        assert!(b.list_snapshots().unwrap().is_empty());
    }

    #[test]
    fn every_backend_shape_behaves_the_same() {
        let tmp = tempfile::tempdir().unwrap();
        exercise(&LocalDirBackend::create(tmp.path().join("plain")).unwrap());
        let boxed: Box<dyn Backend> =
            Box::new(LocalDirBackend::create(tmp.path().join("boxed")).unwrap());
        exercise(&boxed);
        exercise(&WholePacks(
            LocalDirBackend::create(tmp.path().join("whole")).unwrap(),
        ));
    }

    #[test]
    fn stray_files_are_ignored_when_listing() {
        let tmp = tempfile::tempdir().unwrap();
        let b = LocalDirBackend::create(tmp.path()).unwrap();
        b.put_pack(&PackId([5; 32]), b"p").unwrap();
        fs::write(tmp.path().join("packs/README"), b"").unwrap();
        fs::write(tmp.path().join("packs/05/notes.txt"), b"").unwrap();
        fs::write(tmp.path().join("snapshots/notes.txt"), b"").unwrap();
        assert_eq!(b.list_packs().unwrap(), vec![PackId([5; 32])]);
        assert!(b.list_snapshots().unwrap().is_empty());
    }

    #[test]
    fn storage_errors_are_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let b = LocalDirBackend::create(tmp.path()).unwrap();
        // A folder where an object should be can't be read or removed.
        let pack = PackId([6; 32]);
        fs::create_dir_all(b.pack_path(&pack)).unwrap();
        assert!(matches!(b.get_pack(&pack), Err(Error::Io(_))));
        assert!(matches!(b.delete_pack(&pack), Err(Error::Io(_))));
        // A file where a trash folder should be can't be listed. (One level
        // down: on Windows a path below a file is just "not found".)
        fs::create_dir_all(tmp.path().join("trash")).unwrap();
        fs::write(tmp.path().join("trash/packs"), b"").unwrap();
        assert!(matches!(b.purge_trash(Duration::ZERO), Err(Error::Io(_))));
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_pack_is_an_error_not_missing() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let b = LocalDirBackend::create(tmp.path()).unwrap();
        let pack = PackId([7; 32]);
        b.put_pack(&pack, b"p").unwrap();
        let path = b.pack_path(&pack);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        // Root can read anything, so there's nothing to check then.
        let root = fs::read(&path).is_ok();
        assert!(root || matches!(b.get_pack_tail(&pack, 1), Err(Error::Io(_))));
    }
}
