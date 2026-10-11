use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::ids::{PackId, SnapshotId};

/// Storage for one backup set's opaque objects. Implementations never see
/// plaintext; everything passed in is already encrypted.
pub trait Backend: Send + Sync {
    fn put_pack(&self, id: &PackId, data: &[u8]) -> Result<()>;
    fn get_pack(&self, id: &PackId) -> Result<Vec<u8>>;
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
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
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
