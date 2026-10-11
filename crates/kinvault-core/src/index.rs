//! Local SQLite cache that makes incremental backups cheap: which chunks the
//! remote already has (and where), and which files are unchanged since last run.
//! It is a pure cache — it can always be rebuilt from the remote's pack headers.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::Result;
use crate::ids::{ChunkId, PackId};
use crate::pack::{BlobEntry, BlobKind};

const SCHEMA: &str = "
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA busy_timeout = 30000;
    CREATE TABLE IF NOT EXISTS packs (id BLOB PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS chunks (
        id BLOB PRIMARY KEY,
        pack BLOB NOT NULL,
        kind INTEGER NOT NULL,
        offset INTEGER NOT NULL,
        len INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS chunks_by_pack ON chunks(pack);
    CREATE TABLE IF NOT EXISTS verified (pack BLOB PRIMARY KEY, at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS files (
        path TEXT PRIMARY KEY,
        size INTEGER NOT NULL,
        mtime_ns INTEGER NOT NULL,
        inode INTEGER NOT NULL,
        chunks BLOB NOT NULL
    );
";

#[derive(Clone, Copy, Debug)]
pub struct ChunkLocation {
    pub pack: PackId,
    pub entry: BlobEntry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedFile {
    pub size: u64,
    pub mtime_ns: i64,
    pub inode: u64,
    pub chunks: Vec<ChunkId>,
}

pub struct Index {
    conn: Connection,
}

impl Index {
    pub fn open(path: &Path) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn known_packs(&self) -> Result<HashSet<PackId>> {
        let mut stmt = self.conn.prepare("SELECT id FROM packs")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = HashSet::new();
        for row in rows {
            out.insert(PackId::from_slice(&row?)?);
        }
        Ok(out)
    }

    pub fn add_pack(&mut self, pack: &PackId, entries: &[BlobEntry]) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO packs (id) VALUES (?1)",
            [&pack.0[..]],
        )?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO chunks (id, pack, kind, offset, len) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for e in entries {
                let kind = match e.kind {
                    BlobKind::Data => 0,
                    BlobKind::Tree => 1,
                };
                stmt.execute(params![
                    &e.id.0[..],
                    &pack.0[..],
                    kind,
                    e.offset as i64,
                    e.len
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn remove_pack(&mut self, pack: &PackId) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM chunks WHERE pack = ?1", [&pack.0[..]])?;
        tx.execute("DELETE FROM packs WHERE id = ?1", [&pack.0[..]])?;
        tx.execute("DELETE FROM verified WHERE pack = ?1", [&pack.0[..]])?;
        tx.commit()?;
        Ok(())
    }

    pub fn has_chunk(&self, id: &ChunkId) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT 1 FROM chunks WHERE id = ?1")?;
        Ok(stmt.exists([&id.0[..]])?)
    }

    pub fn locate(&self, id: &ChunkId) -> Result<Option<ChunkLocation>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT pack, kind, offset, len FROM chunks WHERE id = ?1")?;
        let row = stmt
            .query_row([&id.0[..]], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, u32>(3)?,
                ))
            })
            .optional()?;
        let Some((pack, kind, offset, len)) = row else {
            return Ok(None);
        };
        let kind = if kind == 1 {
            BlobKind::Tree
        } else {
            BlobKind::Data
        };
        Ok(Some(ChunkLocation {
            pack: PackId::from_slice(&pack)?,
            entry: BlobEntry {
                id: *id,
                kind,
                offset: offset as u64,
                len,
            },
        }))
    }

    /// Every known pack with the blobs the index attributes to it. Packs whose
    /// blobs all live elsewhere appear with an empty list.
    pub fn pack_contents(&self) -> Result<HashMap<PackId, Vec<BlobEntry>>> {
        let mut out: HashMap<PackId, Vec<BlobEntry>> = self
            .known_packs()?
            .into_iter()
            .map(|p| (p, Vec::new()))
            .collect();
        let mut stmt = self
            .conn
            .prepare("SELECT id, pack, kind, offset, len FROM chunks")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, u32>(4)?,
            ))
        })?;
        for row in rows {
            let (id, pack, kind, offset, len) = row?;
            let kind = if kind == 1 {
                BlobKind::Tree
            } else {
                BlobKind::Data
            };
            let entry = BlobEntry {
                id: ChunkId::from_slice(&id)?,
                kind,
                offset: offset as u64,
                len,
            };
            out.entry(PackId::from_slice(&pack)?)
                .or_default()
                .push(entry);
        }
        Ok(out)
    }

    pub fn mark_verified(&self, pack: &PackId, at_unix: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO verified (pack, at) VALUES (?1, ?2)",
            params![&pack.0[..], at_unix],
        )?;
        Ok(())
    }

    /// Known packs, never-verified first, then least recently verified.
    pub fn packs_by_verify_age(&self) -> Result<Vec<PackId>> {
        let mut stmt = self.conn.prepare(
            "SELECT packs.id FROM packs LEFT JOIN verified ON verified.pack = packs.id
             ORDER BY verified.at IS NOT NULL, verified.at",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        rows.map(|r| PackId::from_slice(&r?)).collect()
    }

    pub fn cached_file(&self, path: &str) -> Result<Option<CachedFile>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT size, mtime_ns, inode, chunks FROM files WHERE path = ?1")?;
        let row = stmt
            .query_row([path], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            })
            .optional()?;
        let Some((size, mtime_ns, inode, chunks)) = row else {
            return Ok(None);
        };
        Ok(Some(CachedFile {
            size: size as u64,
            mtime_ns,
            inode: inode as u64,
            chunks: postcard::from_bytes(&chunks)?,
        }))
    }

    pub fn put_cached_file(&self, path: &str, file: &CachedFile) -> Result<()> {
        let mut stmt = self.conn.prepare_cached(
            "INSERT OR REPLACE INTO files (path, size, mtime_ns, inode, chunks) VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        stmt.execute(params![
            path,
            file.size as i64,
            file.mtime_ns,
            file.inode as i64,
            postcard::to_allocvec(&file.chunks)?
        ])?;
        Ok(())
    }
}
