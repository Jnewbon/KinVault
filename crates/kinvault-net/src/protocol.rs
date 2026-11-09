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
/// Largest request a host reads. Requests are read before the host checks
/// who is asking, so this stays small; the biggest (an invite or pairing
/// request listing a few addresses) needs far less.
pub(crate) const MAX_REQUEST_LEN: usize = 64 * 1024;
/// Largest response a client reads (a long list of pack ids).
pub(crate) const MAX_RESPONSE_LEN: usize = 32 * 1024 * 1024;
/// Most packs one `Delivery::Have` asks about, so the request stays small.
pub(crate) const MAX_HAVE: usize = 1000;
/// Largest forwarding order a host accepts (about 400,000 packs).
pub(crate) const MAX_ORDER_LEN: u64 = 16 * 1024 * 1024;

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
    // New variants go last: postcard numbers them by position.
    /// Asks this host to forward objects of the sender's repository to
    /// another host: `len` bytes of a postcard [`ForwardOrder`] follow.
    Forward {
        len: u64,
    },
    /// How the sender's forwarding orders for one of its places are going.
    ForwardStatus {
        place: String,
    },
    /// Drops the sender's unfinished forwarding orders for a place.
    ForwardCancel {
        place: String,
    },
    /// Delivers to `delegation.owner`'s repository here (`repo`), on the
    /// owner's behalf. Allowed from a relay this host doesn't know, as long
    /// as the owner signed `delegation` for it.
    Deliver {
        delegation: Delegation,
        item: Delivery,
    },
}

/// What a relay delivers, or asks about, for an owner.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Delivery {
    /// Which of these packs the owner's repository holds already.
    Have { packs: Vec<PackId> },
    /// A pack of `len` bytes follows.
    Pack { id: PackId, len: u64 },
    /// A snapshot of `len` bytes follows.
    Snapshot { id: SnapshotId, len: u64 },
    /// Moves objects the owner listed to the trash. The owner signs the
    /// list itself, so a relay can only pass on deletions it was given.
    Delete(Box<Deletion>),
}

/// Objects an owner wants deleted from one of its repositories on one
/// host, signed by the owner. They go to the trash for the host's grace
/// period, as when the owner deletes them itself.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Deletion {
    pub owner: iroh::EndpointId,
    pub host: iroh::EndpointId,
    pub repo: String,
    pub snapshots: Vec<SnapshotId>,
    pub packs: Vec<PackId>,
    pub expires_unix: i64,
    pub signature: Vec<u8>,
}

impl Deletion {
    /// Most objects one deletion may list, so it fits in a request.
    pub const MAX_OBJECTS: usize = 1000;

    pub fn sign(
        owner: &iroh::SecretKey,
        host: iroh::EndpointId,
        repo: &str,
        snapshots: Vec<SnapshotId>,
        packs: Vec<PackId>,
        expires_unix: i64,
    ) -> Self {
        let mut d = Self {
            owner: owner.public(),
            host,
            repo: repo.to_string(),
            snapshots,
            packs,
            expires_unix,
            signature: Vec::new(),
        };
        d.signature = owner.sign(&d.signed_bytes()).to_bytes().to_vec();
        d
    }

    fn signed_bytes(&self) -> Vec<u8> {
        let fields = (
            "kinvault deletion v1",
            &self.owner,
            &self.host,
            &self.repo,
            &self.snapshots,
            &self.packs,
            self.expires_unix,
        );
        postcard::to_allocvec(&fields).expect("serialising plain fields")
    }

    /// Checks the owner signed it for `host`'s `repo`, and it's still valid.
    pub fn check(&self, host: &iroh::EndpointId, repo: &str, now: i64) -> Result<(), String> {
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "malformed signature".to_string())?;
        self.owner
            .verify(
                &self.signed_bytes(),
                &iroh::Signature::from_bytes(&signature),
            )
            .map_err(|_| "the owner didn't sign this deletion".to_string())?;
        if self.host != *host || self.repo != repo {
            return Err("this deletion is for another repository".into());
        }
        if self.expires_unix < now {
            return Err("this deletion has expired".into());
        }
        if self.snapshots.len() + self.packs.len() > Self::MAX_OBJECTS {
            return Err("this deletion lists too many objects".into());
        }
        Ok(())
    }
}

/// An owner's permission for one relay to deliver new objects into one of
/// its repositories on one host, until `expires_unix`. Nothing else: the
/// relay can't list, read or delete anything there.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub owner: iroh::EndpointId,
    pub relay: iroh::EndpointId,
    pub host: iroh::EndpointId,
    pub repo: String,
    pub expires_unix: i64,
    /// The owner's Ed25519 signature over the fields above.
    pub signature: Vec<u8>,
}

impl Delegation {
    pub fn sign(
        owner: &iroh::SecretKey,
        relay: iroh::EndpointId,
        host: iroh::EndpointId,
        repo: &str,
        expires_unix: i64,
    ) -> Self {
        let mut d = Self {
            owner: owner.public(),
            relay,
            host,
            repo: repo.to_string(),
            expires_unix,
            signature: Vec::new(),
        };
        d.signature = owner.sign(&d.signed_bytes()).to_bytes().to_vec();
        d
    }

    fn signed_bytes(&self) -> Vec<u8> {
        let fields = (
            "kinvault delegation v1",
            &self.owner,
            &self.relay,
            &self.host,
            &self.repo,
            self.expires_unix,
        );
        postcard::to_allocvec(&fields).expect("serialising plain fields")
    }

    /// Checks the signature and that it lets `relay` deliver to `host`'s
    /// `repo` at `now`. Says why not otherwise.
    pub fn check(
        &self,
        relay: &iroh::EndpointId,
        host: &iroh::EndpointId,
        repo: &str,
        now: i64,
    ) -> Result<(), String> {
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "malformed signature".to_string())?;
        self.owner
            .verify(
                &self.signed_bytes(),
                &iroh::Signature::from_bytes(&signature),
            )
            .map_err(|_| "the owner didn't sign this permission".to_string())?;
        if self.relay != *relay {
            return Err("this permission is for another relay".into());
        }
        if self.host != *host {
            return Err("this permission is for another host".into());
        }
        if self.repo != repo {
            return Err("this permission is for another repository".into());
        }
        if self.expires_unix < now {
            return Err("this permission has expired".into());
        }
        Ok(())
    }
}

/// Objects of the sender's repository on this host for it to copy to
/// another host, as `delegation` allows. Packs go first, then snapshots in
/// order, so the other host never lists a snapshot it can't restore.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ForwardOrder {
    /// Chosen by the sender, unique among its orders.
    pub id: String,
    /// The sender's name for the destination, for status and cancelling.
    pub place: String,
    pub delegation: Delegation,
    /// How to reach `delegation.host`: known addresses and configured
    /// host names (see [`crate::HostAddr`]).
    pub addrs: Vec<std::net::SocketAddr>,
    pub hosts: Vec<String>,
    pub packs: Vec<PackId>,
    pub snapshots: Vec<SnapshotId>,
    /// Pace and hours for sending.
    pub upload_limit: Option<u64>,
    pub window: Option<crate::TimeWindow>,
    /// Deletions the owner signed, passed on once everything is delivered.
    pub deletions: Vec<Deletion>,
}

/// How a forwarding order is going.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForwardInfo {
    pub id: String,
    pub state: ForwardState,
    pub packs_sent: u64,
    pub packs_total: u64,
    pub bytes_sent: u64,
    /// The last problem, if any (it's retried while `Pending`).
    pub error: Option<String>,
    /// When it last changed (Unix seconds).
    pub updated_unix: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardState {
    /// Waiting, or under way; retried until it's done or fails for good.
    Pending,
    Done,
    /// Can't be done (e.g. the other host refused); not retried.
    Failed,
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
    // New variants go last: postcard numbers them by position.
    /// For each pack asked about, whether it's stored.
    Present(Vec<bool>),
    Forwarding(Vec<ForwardInfo>),
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

/// Longest name a peer may give itself (as for nearby beacons).
pub const MAX_PEER_NAME_LEN: usize = 256;
/// Most host addresses a peer may give, and the longest each may be.
pub const MAX_PEER_HOSTS: usize = 32;
pub const MAX_HOST_LEN: usize = 300;

/// Whether a name and host list a peer sent about itself are small enough
/// to store in the config. Says why not otherwise.
pub fn check_peer_info(name: Option<&str>, hosts: &[String]) -> Result<(), String> {
    if name.is_some_and(|n| n.len() > MAX_PEER_NAME_LEN || n.chars().any(char::is_control)) {
        return Err("the name is too long or has control characters".into());
    }
    if hosts.len() > MAX_PEER_HOSTS || hosts.iter().any(|h| h.len() > MAX_HOST_LEN) {
        return Err("too many or too long host addresses".into());
    }
    Ok(())
}

/// Makes a name fit [`check_peer_info`]: drops control characters and cuts
/// it to [`MAX_PEER_NAME_LEN`] bytes. Used on names this instance sends, so
/// a long configured name doesn't make peers reject every request.
pub fn clamp_peer_name(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_PEER_NAME_LEN {
            break;
        }
        out.push(c);
    }
    out
}

/// Makes a host list fit [`check_peer_info`]: drops overlong entries and
/// keeps the first [`MAX_PEER_HOSTS`].
pub fn clamp_peer_hosts(hosts: Vec<String>) -> Vec<String> {
    hosts
        .into_iter()
        .filter(|h| h.len() <= MAX_HOST_LEN)
        .take(MAX_PEER_HOSTS)
        .collect()
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

/// Reads one length-prefixed message of at most `max_len` bytes.
pub(crate) async fn read_msg<T: DeserializeOwned>(
    recv: &mut RecvStream,
    max_len: usize,
) -> Result<T, NetError> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.map_err(transport)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > max_len {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_info_limits() {
        let hosts = vec!["nas.example.org:4433".to_string()];
        assert!(check_peer_info(Some("Laptop"), &hosts).is_ok());
        assert!(check_peer_info(None, &[]).is_ok());
        assert!(check_peer_info(Some(&"x".repeat(MAX_PEER_NAME_LEN + 1)), &[]).is_err());
        assert!(check_peer_info(Some("bad\nname"), &[]).is_err());
        assert!(check_peer_info(None, &vec!["h".to_string(); MAX_PEER_HOSTS + 1]).is_err());
        assert!(check_peer_info(None, &["h".repeat(MAX_HOST_LEN + 1)]).is_err());
    }

    #[test]
    fn clamped_peer_info_passes_the_check() {
        // Multi-byte characters straddling the limit must not be split.
        let long = format!("a\n{}", "é".repeat(200));
        let name = clamp_peer_name(&long);
        assert!(name.len() <= MAX_PEER_NAME_LEN && !name.contains('\n'));
        assert!(name.starts_with("aé"));
        let mut hosts = vec!["h".repeat(MAX_HOST_LEN + 1)];
        hosts.extend((0..40).map(|i| format!("host{i}.example:1")));
        let hosts = clamp_peer_hosts(hosts);
        assert_eq!(hosts.len(), MAX_PEER_HOSTS);
        assert_eq!(hosts[0], "host0.example:1");
        assert!(check_peer_info(Some(&name), &hosts).is_ok());
    }
}
