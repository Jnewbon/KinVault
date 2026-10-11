//! Wire protocol (ALPN `kinvault/1`). Each request uses its own QUIC
//! bi-directional stream: the client sends a length-prefixed postcard
//! [`Request`], followed by the raw object for uploads, then finishes its
//! side. The host answers with a [`Response`], followed by raw object bytes
//! for `Data`/`Tail` responses.

use iroh::endpoint::{RecvStream, SendStream};
use kinvault_core::{PackId, SnapshotId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::{NetError, transport};

pub const ALPN: &[u8] = b"kinvault/1";
/// Largest pack or snapshot either side will accept.
pub const MAX_OBJECT_LEN: u64 = 512 * 1024 * 1024;
const MAX_MESSAGE_LEN: usize = 32 * 1024 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Request {
    /// Which of the sender's repositories on this host the request is for.
    pub repo: String,
    pub op: Op,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Op {
    Status,
    ListPacks,
    PutPack { id: PackId, len: u64 },
    GetPack { id: PackId },
    GetPackTail { id: PackId, max_len: u64 },
    DeletePack { id: PackId },
    ListSnapshots,
    PutSnapshot { id: SnapshotId, len: u64 },
    GetSnapshot { id: SnapshotId },
    DeleteSnapshot { id: SnapshotId },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Response {
    Ok,
    Status {
        used_bytes: u64,
        quota_bytes: Option<u64>,
    },
    PackIds(Vec<PackId>),
    SnapshotIds(Vec<SnapshotId>),
    /// `len` raw bytes follow.
    Data {
        len: u64,
    },
    /// `len` raw bytes (the end of a `total_len` byte pack) follow.
    Tail {
        total_len: u64,
        len: u64,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Denied,
    NotFound,
    QuotaExceeded,
    BadRequest,
    Internal,
}

/// Repository names become directory names on the host.
pub fn valid_repo_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub(crate) async fn write_msg<T: Serialize>(
    send: &mut SendStream,
    msg: &T,
) -> Result<(), NetError> {
    let bytes = postcard::to_allocvec(msg)?;
    send.write_all(&(bytes.len() as u32).to_le_bytes())
        .await
        .map_err(transport)?;
    send.write_all(&bytes).await.map_err(transport)?;
    Ok(())
}

pub(crate) async fn read_msg<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T, NetError> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.map_err(transport)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_MESSAGE_LEN {
        return Err(NetError::Protocol(format!(
            "message of {len} bytes is too large"
        )));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.map_err(transport)?;
    Ok(postcard::from_bytes(&buf)?)
}

pub(crate) async fn read_payload(recv: &mut RecvStream, len: u64) -> Result<Vec<u8>, NetError> {
    if len > MAX_OBJECT_LEN {
        return Err(NetError::Protocol(format!(
            "object of {len} bytes is too large"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    recv.read_exact(&mut buf).await.map_err(transport)?;
    Ok(buf)
}
