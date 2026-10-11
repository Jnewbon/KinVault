use serde::{Deserialize, Serialize};

use crate::crypto::Keys;
use crate::error::{Error, Result};
use crate::ids::{ChunkId, SnapshotId};

const SNAPSHOT_AAD: &[u8] = b"kinvault snapshot v1";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum NodeKind {
    File { size: u64, chunks: Vec<ChunkId> },
    Dir { tree: ChunkId },
    Symlink { target: String },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// Entry name. In the snapshot's root tree this is the source's absolute
    /// path without its leading separator (e.g. `home/me/Documents`).
    pub name: String,
    pub kind: NodeKind,
    /// Unix permission bits; 0 when unknown.
    pub mode: u32,
    pub mtime_ns: i64,
}

/// One directory listing, stored as a deduplicated `Tree` blob.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Tree {
    pub nodes: Vec<Node>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Snapshot {
    /// Creation time, nanoseconds since the Unix epoch.
    pub time_ns: i64,
    pub hostname: String,
    pub paths: Vec<String>,
    pub root: ChunkId,
    pub file_count: u64,
    pub total_bytes: u64,
}

pub fn encode_snapshot(keys: &Keys, snapshot: &Snapshot) -> Result<(SnapshotId, Vec<u8>)> {
    let sealed = keys.seal_meta(SNAPSHOT_AAD, &postcard::to_allocvec(snapshot)?)?;
    Ok((SnapshotId(*blake3::hash(&sealed).as_bytes()), sealed))
}

pub fn decode_snapshot(keys: &Keys, id: &SnapshotId, data: &[u8]) -> Result<Snapshot> {
    if blake3::hash(data).as_bytes() != &id.0 {
        return Err(Error::Corrupt(format!(
            "snapshot {id:?} does not match its id"
        )));
    }
    Ok(postcard::from_bytes(&keys.open_meta(SNAPSHOT_AAD, data)?)?)
}
