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
use crate::limits::{PACE_CHUNK, RateLimiter};

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
    PutPack {
        id: PackId,
        len: u64,
    },
    GetPack {
        id: PackId,
    },
    GetPackTail {
        id: PackId,
        max_len: u64,
    },
    DeletePack {
        id: PackId,
    },
    ListSnapshots,
    PutSnapshot {
        id: SnapshotId,
        len: u64,
    },
    GetSnapshot {
        id: SnapshotId,
    },
    DeleteSnapshot {
        id: SnapshotId,
    },
    /// Claims an invite. Allowed from peers the host doesn't know yet;
    /// `repo` is ignored.
    RedeemInvite {
        token: [u8; 16],
        /// What the host should call the redeeming peer.
        name: Option<String>,
        /// Storage the redeeming peer offers the host in return.
        offer: Option<Offer>,
        /// Addresses the redeeming peer's owner configured, so the host can
        /// reach it for reciprocal backups.
        hosts: Vec<String>,
    },
    /// Asks to be paired as one of the host owner's own devices, after both
    /// owners confirmed it while finding nearby devices. Allowed from peers
    /// the host doesn't know yet; `repo` is ignored.
    Pair {
        /// The requesting instance's name.
        name: String,
        /// Addresses the requesting peer's owner configured.
        hosts: Vec<String>,
    },
    /// Erases the whole repository. The host hides it at once and deletes
    /// it after [`REPO_DELETE_DELAY`](crate::REPO_DELETE_DELAY), so a
    /// compromised sender can't destroy backups instantly.
    DeleteRepo,
}

/// Storage one peer offers another.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offer {
    pub quota_bytes: Option<u64>,
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
    Redeemed {
        host_name: String,
        quota_bytes: Option<u64>,
    },
    Paired {
        host_name: String,
    },
    DeleteScheduled {
        /// When the host erases the repository (Unix seconds).
        erase_after_unix: i64,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Denied,
    NotFound,
    QuotaExceeded,
    BadRequest,
    Internal,
    /// Uploads are only accepted during the host's time window.
    OutsideWindow,
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

pub(crate) async fn read_payload(
    recv: &mut RecvStream,
    len: u64,
    limiter: Option<&RateLimiter>,
) -> Result<Vec<u8>, NetError> {
    if len > MAX_OBJECT_LEN {
        return Err(NetError::Protocol(format!(
            "object of {len} bytes is too large"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    let Some(limiter) = limiter else {
        recv.read_exact(&mut buf).await.map_err(transport)?;
        return Ok(buf);
    };
    // Reading slowly makes QUIC flow control slow the sender down.
    let mut filled = 0;
    while filled < buf.len() {
        let end = (filled + PACE_CHUNK).min(buf.len());
        match recv.read(&mut buf[filled..end]).await.map_err(transport)? {
            Some(n) => {
                limiter.consume(n).await;
                filled += n;
            }
            None => {
                return Err(NetError::Protocol(
                    "stream ended before the object was complete".into(),
                ));
            }
        }
    }
    Ok(buf)
}

pub(crate) async fn write_payload(
    send: &mut SendStream,
    data: &[u8],
    limiter: Option<&RateLimiter>,
) -> Result<(), NetError> {
    let Some(limiter) = limiter else {
        return send.write_all(data).await.map_err(transport);
    };
    for piece in data.chunks(PACE_CHUNK) {
        limiter.consume(piece.len()).await;
        send.write_all(piece).await.map_err(transport)?;
    }
    Ok(())
}
