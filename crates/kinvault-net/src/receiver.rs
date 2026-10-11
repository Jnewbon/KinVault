use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use kinvault_core::{Backend, LocalDirBackend};

use crate::error::NetError;
use crate::limits::{RateLimiter, TimeWindow};
use crate::protocol::{
    ErrorCode, MAX_OBJECT_LEN, Offer, Op, Request, Response, read_msg, read_payload,
    valid_repo_name, write_msg,
};

/// What an authorised peer may do on this host.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Grant {
    /// Maximum bytes the peer may store across all its repositories,
    /// including recently deleted data still in the grace period.
    pub quota_bytes: Option<u64>,
    /// Maximum upload rate in bytes per second.
    pub upload_limit: Option<u64>,
    /// Uploads are only accepted inside this daily window (host's local time).
    pub window: Option<TimeWindow>,
}

/// A peer claiming an invite.
#[derive(Clone, Debug)]
pub struct InviteRedemption {
    pub peer: EndpointId,
    pub token: [u8; 16],
    pub name: Option<String>,
    pub offer: Option<Offer>,
    pub hosts: Vec<String>,
}

/// What the host tells a peer whose invite was accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteAccepted {
    pub host_name: String,
    pub quota_bytes: Option<u64>,
}

/// Decides whether an invite is valid; on success it is expected to have
/// granted the peer access (via [`Receiver::allow`]) and consumed the invite.
pub type InviteHandler = Arc<
    dyn Fn(InviteRedemption) -> Pin<Box<dyn Future<Output = Result<InviteAccepted, String>> + Send>>
        + Send
        + Sync,
>;

/// Host side of the protocol. Stores each peer's objects under
/// `<root>/<peer id>/<repo>/`; it can verify object hashes but never decrypt them.
#[derive(Clone)]
pub struct Receiver {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiver")
            .field("root", &self.inner.root)
            .finish_non_exhaustive()
    }
}

struct PeerAccess {
    grant: Grant,
    limiter: Option<Arc<RateLimiter>>,
}

struct Inner {
    root: PathBuf,
    peers: RwLock<HashMap<EndpointId, PeerAccess>>,
    /// Cached bytes stored per peer; dropped after writes and recomputed lazily.
    usage: Mutex<HashMap<EndpointId, u64>>,
    invites: RwLock<Option<InviteHandler>>,
}

type Reply = (Response, Option<Vec<u8>>);
type Failure = (ErrorCode, String);

impl Receiver {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            inner: Arc::new(Inner {
                root: root.into(),
                peers: RwLock::default(),
                usage: Mutex::default(),
                invites: RwLock::default(),
            }),
        }
    }

    /// Grants (or updates) a peer's access.
    pub fn allow(&self, peer: EndpointId, grant: Grant) {
        let mut peers = self.inner.peers.write().unwrap();
        // Keep the existing limiter if the rate is unchanged, so updates don't reset pacing.
        let limiter = match (
            peers.get(&peer).and_then(|p| p.limiter.clone()),
            grant.upload_limit,
        ) {
            (Some(l), Some(rate)) if l.bytes_per_sec() == rate => Some(l),
            (_, Some(rate)) => Some(Arc::new(RateLimiter::new(rate))),
            (_, None) => None,
        };
        peers.insert(peer, PeerAccess { grant, limiter });
    }

    pub fn revoke(&self, peer: &EndpointId) {
        self.inner.peers.write().unwrap().remove(peer);
    }

    pub fn set_invite_handler(&self, handler: InviteHandler) {
        *self.inner.invites.write().unwrap() = Some(handler);
    }

    fn access(&self, peer: &EndpointId) -> Option<(Grant, Option<Arc<RateLimiter>>)> {
        self.inner
            .peers
            .read()
            .unwrap()
            .get(peer)
            .map(|p| (p.grant, p.limiter.clone()))
    }

    fn peer_dir(&self, peer: &EndpointId) -> PathBuf {
        self.inner.root.join(peer.to_string())
    }

    /// Bytes the peer currently stores on this host (including its trash).
    pub async fn usage(&self, peer: &EndpointId) -> io::Result<u64> {
        if let Some(used) = self.inner.usage.lock().unwrap().get(peer) {
            return Ok(*used);
        }
        let dir = self.peer_dir(peer);
        let used = tokio::task::spawn_blocking(move || dir_size(&dir))
            .await
            .map_err(io::Error::other)??;
        self.inner.usage.lock().unwrap().insert(*peer, used);
        Ok(used)
    }

    fn invalidate_usage(&self, peer: &EndpointId) {
        self.inner.usage.lock().unwrap().remove(peer);
    }

    /// Permanently deletes data peers deleted more than `grace` ago.
    /// Returns the number of bytes freed.
    pub async fn purge_trash(&self, grace: Duration) -> io::Result<u64> {
        let root = self.inner.root.clone();
        let freed = tokio::task::spawn_blocking(move || -> io::Result<u64> {
            let mut freed = 0;
            for peer in read_dirs(&root)? {
                for repo in read_dirs(&peer)? {
                    match LocalDirBackend::open(&repo) {
                        Ok(b) => freed += b.purge_trash(grace).map_err(io::Error::other)?,
                        Err(_) => continue,
                    }
                }
            }
            Ok(freed)
        })
        .await
        .map_err(io::Error::other)??;
        if freed > 0 {
            self.inner.usage.lock().unwrap().clear();
        }
        Ok(freed)
    }

    async fn handle_stream(
        &self,
        peer: EndpointId,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<(), NetError> {
        let req: Request = read_msg(&mut recv).await?;
        let (resp, payload) = match self.dispatch(peer, req, &mut recv).await {
            Ok(reply) => reply,
            Err((code, message)) => {
                // Don't make the client upload a payload we're going to discard.
                let _ = recv.stop(0u32.into());
                (Response::Error { code, message }, None)
            }
        };
        write_msg(&mut send, &resp).await?;
        if let Some(data) = payload {
            send.write_all(&data)
                .await
                .map_err(crate::error::transport)?;
        }
        send.finish().map_err(crate::error::transport)?;
        Ok(())
    }

    async fn redeem(&self, redemption: InviteRedemption) -> Result<Reply, Failure> {
        let handler = self.inner.invites.read().unwrap().clone();
        let Some(handler) = handler else {
            return Err((
                ErrorCode::Denied,
                "this host does not accept invites".into(),
            ));
        };
        let accepted = handler(redemption)
            .await
            .map_err(|e| (ErrorCode::Denied, e))?;
        Ok((
            Response::Redeemed {
                host_name: accepted.host_name,
                quota_bytes: accepted.quota_bytes,
            },
            None,
        ))
    }

    async fn dispatch(
        &self,
        peer: EndpointId,
        req: Request,
        recv: &mut RecvStream,
    ) -> Result<Reply, Failure> {
        if let Op::RedeemInvite {
            token,
            name,
            offer,
            hosts,
        } = req.op
        {
            return self
                .redeem(InviteRedemption {
                    peer,
                    token,
                    name,
                    offer,
                    hosts,
                })
                .await;
        }
        let Some((grant, limiter)) = self.access(&peer) else {
            return Err((
                ErrorCode::Denied,
                format!("{peer} is not allowed to store data here"),
            ));
        };
        if !valid_repo_name(&req.repo) {
            return Err((
                ErrorCode::BadRequest,
                format!("invalid repository name {:?}", req.repo),
            ));
        }
        let repo_dir = self.peer_dir(&peer).join(&req.repo);
        let backend = Arc::new(blocking(move || LocalDirBackend::create(repo_dir)).await?);

        match req.op {
            Op::Status => {
                let used = self.usage(&peer).await.map_err(internal)?;
                Ok((
                    Response::Status {
                        used_bytes: used,
                        quota_bytes: grant.quota_bytes,
                    },
                    None,
                ))
            }
            Op::ListPacks => {
                let b = backend.clone();
                Ok((
                    Response::PackIds(blocking(move || b.list_packs()).await?),
                    None,
                ))
            }
            Op::ListSnapshots => {
                let b = backend.clone();
                Ok((
                    Response::SnapshotIds(blocking(move || b.list_snapshots()).await?),
                    None,
                ))
            }
            Op::PutPack { id, len } => {
                let data = self
                    .receive_object(&peer, &grant, limiter.as_deref(), len, recv)
                    .await?;
                if blake3::hash(&data).as_bytes() != &id.0 {
                    return Err((
                        ErrorCode::BadRequest,
                        format!("pack {id} content does not match its id"),
                    ));
                }
                let b = backend.clone();
                blocking(move || b.put_pack(&id, &data)).await?;
                self.invalidate_usage(&peer);
                Ok((Response::Ok, None))
            }
            Op::PutSnapshot { id, len } => {
                let data = self
                    .receive_object(&peer, &grant, limiter.as_deref(), len, recv)
                    .await?;
                if blake3::hash(&data).as_bytes() != &id.0 {
                    return Err((
                        ErrorCode::BadRequest,
                        format!("snapshot {id} content does not match its id"),
                    ));
                }
                let b = backend.clone();
                blocking(move || b.put_snapshot(&id, &data)).await?;
                self.invalidate_usage(&peer);
                Ok((Response::Ok, None))
            }
            Op::GetPack { id } => {
                let b = backend.clone();
                let data = blocking(move || b.get_pack(&id)).await?;
                Ok((
                    Response::Data {
                        len: data.len() as u64,
                    },
                    Some(data),
                ))
            }
            Op::GetPackTail { id, max_len } => {
                let b = backend.clone();
                let (total_len, tail) = blocking(move || b.get_pack_tail(&id, max_len)).await?;
                Ok((
                    Response::Tail {
                        total_len,
                        len: tail.len() as u64,
                    },
                    Some(tail),
                ))
            }
            Op::GetSnapshot { id } => {
                let b = backend.clone();
                let data = blocking(move || b.get_snapshot(&id)).await?;
                Ok((
                    Response::Data {
                        len: data.len() as u64,
                    },
                    Some(data),
                ))
            }
            // Deletions go to the trash for a grace period, so a compromised
            // sender can't immediately destroy its own history.
            Op::DeletePack { id } => {
                let b = backend.clone();
                blocking(move || b.trash_pack(&id)).await?;
                Ok((Response::Ok, None))
            }
            Op::DeleteSnapshot { id } => {
                let b = backend.clone();
                blocking(move || b.trash_snapshot(&id)).await?;
                Ok((Response::Ok, None))
            }
            Op::RedeemInvite { .. } => unreachable!("handled above"),
        }
    }

    /// Checks window, size limits and quota, then reads an uploaded object.
    async fn receive_object(
        &self,
        peer: &EndpointId,
        grant: &Grant,
        limiter: Option<&RateLimiter>,
        len: u64,
        recv: &mut RecvStream,
    ) -> Result<Vec<u8>, Failure> {
        if let Some(window) = grant.window
            && !window.is_open_now()
        {
            return Err((
                ErrorCode::OutsideWindow,
                format!("this host only accepts uploads between {window} (its local time)"),
            ));
        }
        if len > MAX_OBJECT_LEN {
            return Err((
                ErrorCode::BadRequest,
                format!("object of {len} bytes exceeds the size limit"),
            ));
        }
        if let Some(quota) = grant.quota_bytes {
            let used = self.usage(peer).await.map_err(internal)?;
            if used.saturating_add(len) > quota {
                return Err((
                    ErrorCode::QuotaExceeded,
                    format!("{used} of {quota} bytes used; upload needs {len} more"),
                ));
            }
        }
        read_payload(recv, len, limiter)
            .await
            .map_err(|e| (ErrorCode::BadRequest, e.to_string()))
    }
}

impl ProtocolHandler for Receiver {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let peer = connection.remote_id();
        tracing::debug!(%peer, "accepted connection");
        // Serve streams until the peer closes the connection.
        while let Ok((send, recv)) = connection.accept_bi().await {
            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.handle_stream(peer, send, recv).await {
                    tracing::debug!(%peer, "request failed: {e}");
                }
            });
        }
        Ok(())
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> kinvault_core::Result<T> + Send + 'static,
) -> Result<T, Failure> {
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(kinvault_core::Error::NotFound(m))) => Err((ErrorCode::NotFound, m)),
        Ok(Err(e)) => Err(internal(e)),
        Err(e) => Err(internal(e)),
    }
}

fn internal(e: impl std::fmt::Display) -> Failure {
    tracing::warn!("internal error serving request: {e}");
    (ErrorCode::Internal, "internal storage error".to_string())
}

fn read_dirs(dir: &Path) -> io::Result<Vec<PathBuf>> {
    match fs::read_dir(dir) {
        Ok(entries) => Ok(entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

fn dir_size(dir: &Path) -> io::Result<u64> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut total = 0;
    for entry in entries {
        let entry = entry?;
        let meta = entry.metadata()?;
        total += if meta.is_dir() {
            dir_size(&entry.path())?
        } else {
            meta.len()
        };
    }
    Ok(total)
}
