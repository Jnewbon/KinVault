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
use kinvault_core::{Backend, LocalDirBackend, PackId, SnapshotId};

use crate::error::NetError;
use crate::limits::{RateLimiter, TimeWindow};
use crate::protocol::{
    Delegation, Delivery, ErrorCode, ForwardOrder, MAX_HAVE, MAX_OBJECT_LEN, MAX_ORDER_LEN,
    MAX_REQUEST_LEN, Offer, Op, PeerName, Request, Response, read_msg, read_payload,
    valid_repo_name, write_msg,
};

mod forward;
pub use forward::ForwardQueue;

/// How long a repository its owner deleted is kept before it is erased.
pub const REPO_DELETE_DELAY: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Per-peer directory of deleted repositories, named `<erase unix>-<repo>`.
/// Repository names can't start with a dot, so it never clashes with one.
const DELETED_DIR: &str = ".deleted";
/// Uploads one peer may have in progress; more wait their turn. Each is
/// held in memory until stored, so this bounds what a peer can make the
/// host buffer (at most this many times [`MAX_OBJECT_LEN`]).
const UPLOADS_PER_PEER: usize = 4;

/// Storage a peer uses on this host.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerUsage {
    /// Everything it stores, including what is waiting to be erased.
    pub used_bytes: u64,
    /// Data it deleted that is erased once its grace period is over.
    pub deleting_bytes: u64,
}

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

/// A nearby peer asking to be paired as one of the owner's devices.
#[derive(Clone, Debug)]
pub struct PairRequest {
    pub peer: EndpointId,
    pub name: String,
    pub hosts: Vec<String>,
}

/// Decides whether to pair with a peer; on success it is expected to have
/// granted the peer access and returns this host's name.
pub type PairHandler = Arc<
    dyn Fn(PairRequest) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>>
        + Send
        + Sync,
>;

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
    usage: Mutex<HashMap<EndpointId, CachedUsage>>,
    uploads: Mutex<HashMap<EndpointId, Arc<PeerUploads>>>,
    invites: RwLock<Option<InviteHandler>>,
    pairing: RwLock<Option<PairHandler>>,
    /// This host's own id, which deliveries must be addressed to.
    identity: RwLock<Option<EndpointId>>,
    forwarding: RwLock<Option<Arc<ForwardQueue>>>,
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
                uploads: Mutex::default(),
                invites: RwLock::default(),
                pairing: RwLock::default(),
                identity: RwLock::default(),
                forwarding: RwLock::default(),
            }),
        }
    }

    /// Sets this host's id. Relays can only deliver for an owner once it's set.
    pub fn set_identity(&self, id: EndpointId) {
        *self.inner.identity.write().unwrap() = Some(id);
    }

    /// Lets peers have this host forward their objects to other hosts,
    /// queueing orders in `queue`; see [`Self::run_forwarding`].
    pub fn enable_forwarding(&self, queue: Arc<ForwardQueue>) {
        *self.inner.forwarding.write().unwrap() = Some(queue);
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

    pub fn set_pair_handler(&self, handler: PairHandler) {
        *self.inner.pairing.write().unwrap() = Some(handler);
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
        Ok(self.usage_detail(peer).await?.used_bytes)
    }

    /// What the peer stores here, and how much of it is waiting to be erased.
    pub async fn usage_detail(&self, peer: &EndpointId) -> io::Result<PeerUsage> {
        let version = match self.cached_usage(peer) {
            Ok(usage) => return Ok(usage),
            Err(version) => version,
        };
        let dir = self.peer_dir(peer);
        let usage = tokio::task::spawn_blocking(move || -> io::Result<PeerUsage> {
            // Deleted repositories, plus objects in each repository's trash.
            let mut deleting = dir_size(&dir.join(DELETED_DIR))?;
            for repo in read_dirs(&dir)? {
                if repo.file_name() != Some(DELETED_DIR.as_ref()) {
                    deleting += dir_size(&repo.join("trash"))?;
                }
            }
            Ok(PeerUsage {
                used_bytes: dir_size(&dir)?,
                deleting_bytes: deleting,
            })
        })
        .await
        .map_err(io::Error::other)??;
        self.store_usage(peer, version, usage);
        Ok(usage)
    }

    /// The cached usage, or the cache version to count it against.
    fn cached_usage(&self, peer: &EndpointId) -> Result<PeerUsage, u64> {
        let cache = self.inner.usage.lock().unwrap();
        let cached = cache.get(peer);
        cached
            .and_then(|c| c.usage)
            .ok_or(cached.map_or(0, |c| c.version))
    }

    /// Caches a count started at cache `version`, unless what the peer
    /// stores changed since: the count may have missed that change.
    fn store_usage(&self, peer: &EndpointId, version: u64, usage: PeerUsage) {
        let mut cache = self.inner.usage.lock().unwrap();
        let cached = cache.entry(*peer).or_default();
        if cached.version == version {
            cached.usage = Some(usage);
        }
    }

    fn invalidate_usage(&self, peer: &EndpointId) {
        let mut cache = self.inner.usage.lock().unwrap();
        let cached = cache.entry(*peer).or_default();
        cached.usage = None;
        cached.version += 1;
    }

    fn invalidate_all_usage(&self) {
        for cached in self.inner.usage.lock().unwrap().values_mut() {
            cached.usage = None;
            cached.version += 1;
        }
    }

    /// Permanently deletes data peers deleted more than `grace` ago.
    /// Returns the number of bytes freed.
    pub async fn purge_trash(&self, grace: Duration) -> io::Result<u64> {
        let root = self.inner.root.clone();
        let freed = tokio::task::spawn_blocking(move || -> io::Result<u64> {
            let mut freed = 0;
            let now = unix_now();
            for peer in read_dirs(&root)? {
                for deleted in read_dirs(&peer.join(DELETED_DIR))? {
                    let due = deleted
                        .file_name()
                        .and_then(|n| n.to_str())
                        .and_then(|n| n.split_once('-'))
                        .and_then(|(t, _)| t.parse::<i64>().ok())
                        .is_some_and(|t| t <= now);
                    if due {
                        freed += dir_size(&deleted)?;
                        fs::remove_dir_all(&deleted)?;
                    }
                }
                for repo in read_dirs(&peer)? {
                    if repo.file_name() == Some(DELETED_DIR.as_ref()) {
                        continue;
                    }
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
            self.invalidate_all_usage();
        }
        Ok(freed)
    }

    async fn handle_stream(
        &self,
        peer: EndpointId,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<(), NetError> {
        let req: Request = read_msg(&mut recv, MAX_REQUEST_LEN).await?;
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
                // Peers check the name, so send it trimmed to what they accept.
                host_name: PeerName::lossy(&accepted.host_name),
                quota_bytes: accepted.quota_bytes,
            },
            None,
        ))
    }

    async fn pair(&self, request: PairRequest) -> Result<Reply, Failure> {
        let handler = self.inner.pairing.read().unwrap().clone();
        let Some(handler) = handler else {
            return Err((ErrorCode::Denied, "this host does not pair".into()));
        };
        let host_name = handler(request).await.map_err(|e| (ErrorCode::Denied, e))?;
        Ok((
            Response::Paired {
                host_name: PeerName::lossy(&host_name),
            },
            None,
        ))
    }

    /// Hides a peer's repository; [`Self::purge_trash`] erases it later.
    async fn delete_repo(&self, peer: &EndpointId, repo: &str) -> Result<Reply, Failure> {
        let erase_after_unix = unix_now() + REPO_DELETE_DELAY.as_secs() as i64;
        let peer_dir = self.peer_dir(peer);
        let repo_name = repo.to_string();
        tokio::task::spawn_blocking(move || {
            schedule_erase(&peer_dir, &repo_name, erase_after_unix)
        })
        .await
        .map_err(internal)?
        .map_err(internal)?;
        self.invalidate_usage(peer);
        tracing::info!(%peer, repo, "peer deleted a repository; erasing it in a week");
        Ok((Response::DeleteScheduled { erase_after_unix }, None))
    }

    /// Stops accepting a peer's backups and erases everything it stored
    /// here after [`REPO_DELETE_DELAY`]. Returns when (Unix seconds).
    pub async fn remove_peer(&self, peer: &EndpointId) -> io::Result<i64> {
        self.revoke(peer);
        let erase_after_unix = unix_now() + REPO_DELETE_DELAY.as_secs() as i64;
        let peer_dir = self.peer_dir(peer);
        tokio::task::spawn_blocking(move || -> io::Result<()> {
            for repo in read_dirs(&peer_dir)? {
                let Some(name) = repo.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if name != DELETED_DIR {
                    schedule_erase(&peer_dir, name, erase_after_unix)?;
                }
            }
            Ok(())
        })
        .await
        .map_err(io::Error::other)??;
        self.invalidate_usage(peer);
        Ok(erase_after_unix)
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
                // `name` and `hosts` were checked while decoding.
                .redeem(InviteRedemption {
                    peer,
                    token,
                    name: name.map(PeerName::into_string),
                    offer,
                    hosts: hosts.into_vec(),
                })
                .await;
        }
        if let Op::Pair { name, hosts } = req.op {
            return self
                .pair(PairRequest {
                    peer,
                    name: name.into_string(),
                    hosts: hosts.into_vec(),
                })
                .await;
        }
        // From a relay, which may not be a peer itself: allowed if the owner
        // it delivers for signed a permission for it.
        if let Op::Deliver { delegation, item } = req.op {
            return self.deliver(peer, &req.repo, delegation, item, recv).await;
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
        if let Op::DeleteRepo = req.op {
            return self.delete_repo(&peer, &req.repo).await;
        }
        match req.op {
            Op::Forward { len } => return self.take_order(peer, req.repo, len, recv).await,
            Op::ForwardStatus { place } => {
                let queue = self.forward_queue()?;
                let info = queue.status(&peer, &place).await.map_err(internal)?;
                return Ok((Response::Forwarding(info), None));
            }
            Op::ForwardCancel { place } => {
                let queue = self.forward_queue()?;
                queue.cancel(&peer, &place).await.map_err(internal)?;
                return Ok((Response::Ok, None));
            }
            _ => {}
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
                self.put_object(
                    &peer,
                    &grant,
                    limiter.as_deref(),
                    &backend,
                    Object::Pack(id),
                    len,
                    recv,
                )
                .await
            }
            Op::PutSnapshot { id, len } => {
                self.put_object(
                    &peer,
                    &grant,
                    limiter.as_deref(),
                    &backend,
                    Object::Snapshot(id),
                    len,
                    recv,
                )
                .await
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
                // Same total, but more of it is now waiting to be erased.
                self.invalidate_usage(&peer);
                Ok((Response::Ok, None))
            }
            Op::DeleteSnapshot { id } => {
                let b = backend.clone();
                blocking(move || b.trash_snapshot(&id)).await?;
                // Same total, but more of it is now waiting to be erased.
                self.invalidate_usage(&peer);
                Ok((Response::Ok, None))
            }
            Op::RedeemInvite { .. }
            | Op::Pair { .. }
            | Op::DeleteRepo
            | Op::Deliver { .. }
            | Op::Forward { .. }
            | Op::ForwardStatus { .. }
            | Op::ForwardCancel { .. } => {
                unreachable!("handled above")
            }
        }
    }

    /// Reads an uploaded object, checks it matches its id, and stores it in
    /// `owner`'s repository, counted against `owner`'s quota.
    #[allow(clippy::too_many_arguments)]
    async fn put_object(
        &self,
        owner: &EndpointId,
        grant: &Grant,
        limiter: Option<&RateLimiter>,
        backend: &Arc<LocalDirBackend>,
        object: Object,
        len: u64,
        recv: &mut RecvStream,
    ) -> Result<Reply, Failure> {
        let (data, reservation) = self
            .receive_object(owner, grant, limiter, len, recv)
            .await?;
        let (what, id) = match object {
            Object::Pack(id) => ("pack", id.0),
            Object::Snapshot(id) => ("snapshot", id.0),
        };
        if blake3::hash(&data).as_bytes() != &id {
            return Err((
                ErrorCode::BadRequest,
                format!("{what} {} content does not match its id", hex::encode(id)),
            ));
        }
        let b = backend.clone();
        match object {
            Object::Pack(id) => blocking(move || b.put_pack(&id, &data)).await?,
            Object::Snapshot(id) => blocking(move || b.put_snapshot(&id, &data)).await?,
        }
        reservation.release().await;
        Ok((Response::Ok, None))
    }

    fn forward_queue(&self) -> Result<Arc<ForwardQueue>, Failure> {
        self.inner
            .forwarding
            .read()
            .unwrap()
            .clone()
            .ok_or_else(|| (ErrorCode::Denied, "this host doesn't forward".to_string()))
    }

    /// Queues an order from `peer` to forward objects of its `repo` here.
    async fn take_order(
        &self,
        peer: EndpointId,
        repo: String,
        len: u64,
        recv: &mut RecvStream,
    ) -> Result<Reply, Failure> {
        let queue = self.forward_queue()?;
        let me = self.identity()?;
        if len > MAX_ORDER_LEN {
            return Err((
                ErrorCode::BadRequest,
                format!("order of {len} bytes is too large"),
            ));
        }
        let data = read_payload(recv, len, None)
            .await
            .map_err(|e| (ErrorCode::BadRequest, e.to_string()))?;
        let order: ForwardOrder = postcard::from_bytes(&data)
            .map_err(|e| (ErrorCode::BadRequest, format!("malformed order: {e}")))?;
        let d = &order.delegation;
        if d.owner != peer {
            return Err((
                ErrorCode::Denied,
                "the permission isn't the sender's".into(),
            ));
        }
        if d.host == me {
            return Err((
                ErrorCode::BadRequest,
                "can't forward to this same host".into(),
            ));
        }
        d.check(&me, &d.host, &d.repo, unix_now())
            .map_err(|e| (ErrorCode::Denied, e))?;
        if !valid_repo_name(&d.repo) {
            return Err((ErrorCode::BadRequest, "invalid repository name".into()));
        }
        queue
            .add(peer, repo, order)
            .await
            .map_err(|e| (ErrorCode::BadRequest, e))?;
        Ok((Response::Ok, None))
    }

    fn identity(&self) -> Result<EndpointId, Failure> {
        self.inner.identity.read().unwrap().ok_or_else(|| {
            (
                ErrorCode::Internal,
                "this host doesn't know its own id".into(),
            )
        })
    }

    /// Handles a delivery from relay `peer` into the owner's `repo` here.
    async fn deliver(
        &self,
        peer: EndpointId,
        repo: &str,
        delegation: Delegation,
        item: Delivery,
        recv: &mut RecvStream,
    ) -> Result<Reply, Failure> {
        let me = self.identity()?;
        delegation
            .check(&peer, &me, repo, unix_now())
            .map_err(|e| (ErrorCode::Denied, e))?;
        let owner = delegation.owner;
        let Some((grant, limiter)) = self.access(&owner) else {
            return Err((
                ErrorCode::Denied,
                format!("{owner} is not allowed to store data here"),
            ));
        };
        if !valid_repo_name(repo) {
            return Err((
                ErrorCode::BadRequest,
                format!("invalid repository name {repo:?}"),
            ));
        }
        let repo_dir = self.peer_dir(&owner).join(repo);
        let backend = Arc::new(blocking(move || LocalDirBackend::create(repo_dir)).await?);
        match item {
            Delivery::Have { packs } => {
                if packs.len() > MAX_HAVE {
                    return Err((ErrorCode::BadRequest, "asked about too many packs".into()));
                }
                let b = backend.clone();
                let found =
                    blocking(move || Ok(packs.iter().map(|p| b.has_pack(p)).collect())).await?;
                Ok((Response::Present(found), None))
            }
            Delivery::Pack { id, len } => {
                self.put_object(
                    &owner,
                    &grant,
                    limiter.as_deref(),
                    &backend,
                    Object::Pack(id),
                    len,
                    recv,
                )
                .await
            }
            Delivery::Delete(d) => {
                if d.owner != owner {
                    return Err((ErrorCode::Denied, "the deletion isn't the owner's".into()));
                }
                d.check(&me, repo, unix_now())
                    .map_err(|e| (ErrorCode::Denied, e))?;
                let b = backend.clone();
                blocking(move || {
                    // Already gone is fine: the deletion may be passed on twice.
                    let gone = |r: kinvault_core::Result<()>| match r {
                        Err(kinvault_core::Error::NotFound(_)) => Ok(()),
                        other => other,
                    };
                    for id in &d.snapshots {
                        gone(b.trash_snapshot(id))?;
                    }
                    for id in &d.packs {
                        gone(b.trash_pack(id))?;
                    }
                    Ok(())
                })
                .await?;
                self.invalidate_usage(&owner);
                Ok((Response::Ok, None))
            }
            Delivery::Snapshot { id, len } => {
                self.put_object(
                    &owner,
                    &grant,
                    limiter.as_deref(),
                    &backend,
                    Object::Snapshot(id),
                    len,
                    recv,
                )
                .await
            }
        }
    }

    fn peer_uploads(&self, peer: &EndpointId) -> Arc<PeerUploads> {
        self.inner
            .uploads
            .lock()
            .unwrap()
            .entry(*peer)
            .or_insert_with(|| {
                Arc::new(PeerUploads {
                    slots: Arc::new(tokio::sync::Semaphore::new(UPLOADS_PER_PEER)),
                    reserved: tokio::sync::Mutex::new(0),
                })
            })
            .clone()
    }

    /// Checks window, size limits and quota, then reads an uploaded object.
    /// The returned reservation counts the object against the quota until it
    /// is stored and released.
    async fn receive_object(
        &self,
        peer: &EndpointId,
        grant: &Grant,
        limiter: Option<&RateLimiter>,
        len: u64,
        recv: &mut RecvStream,
    ) -> Result<(Vec<u8>, Reservation), Failure> {
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
        let uploads = self.peer_uploads(peer);
        let slot = uploads
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(internal)?;
        {
            // Checking and reserving under one lock means uploads running
            // at the same time can't all pass against the same usage.
            let mut reserved = uploads.reserved.lock().await;
            if let Some(quota) = grant.quota_bytes {
                let used = self
                    .usage(peer)
                    .await
                    .map_err(internal)?
                    .saturating_add(*reserved);
                if used.saturating_add(len) > quota {
                    return Err((
                        ErrorCode::QuotaExceeded,
                        format!("{used} of {quota} bytes used; upload needs {len} more"),
                    ));
                }
            }
            *reserved += len;
        }
        let reservation = Reservation {
            receiver: self.clone(),
            peer: *peer,
            uploads,
            len,
            released: false,
            _slot: slot,
        };
        let data = read_payload(recv, len, limiter)
            .await
            .map_err(|e| (ErrorCode::BadRequest, e.to_string()))?;
        Ok((data, reservation))
    }
}

/// A peer's usage as last counted. `version` goes up whenever what the peer
/// stores changes, so a count taken across a change is never kept.
#[derive(Default)]
struct CachedUsage {
    usage: Option<PeerUsage>,
    version: u64,
}

/// A peer's uploads in progress.
struct PeerUploads {
    slots: Arc<tokio::sync::Semaphore>,
    /// Bytes of uploads in progress, not yet in the usage figure.
    reserved: tokio::sync::Mutex<u64>,
}

/// An upload in progress: holds one of the peer's upload slots and counts
/// its bytes against the quota until released.
struct Reservation {
    receiver: Receiver,
    peer: EndpointId,
    uploads: Arc<PeerUploads>,
    len: u64,
    released: bool,
    _slot: tokio::sync::OwnedSemaphorePermit,
}

impl Reservation {
    /// The object is stored: usage now includes it, so stop reserving it.
    /// Both happen under the reservation lock, so a quota check never sees
    /// the stale usage without the reservation.
    async fn release(mut self) {
        let mut reserved = self.uploads.reserved.lock().await;
        self.receiver.invalidate_usage(&self.peer);
        *reserved -= self.len;
        self.released = true;
    }
}

impl Drop for Reservation {
    /// The upload failed or was abandoned before being stored.
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let (receiver, peer, uploads, len) = (
            self.receiver.clone(),
            self.peer,
            self.uploads.clone(),
            self.len,
        );
        // A failed write may still have left something on disk.
        let unreserve = async move {
            let mut reserved = uploads.reserved.lock().await;
            receiver.invalidate_usage(&peer);
            *reserved -= len;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(unreserve);
            }
            Err(_) => tracing::warn!(%peer, "upload reservation leaked"),
        }
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
    match tokio::task::spawn_blocking(f).await.map_err(internal)? {
        Ok(v) => Ok(v),
        Err(kinvault_core::Error::NotFound(m)) => Err((ErrorCode::NotFound, m)),
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

async fn blocking_io<T: Send + 'static>(
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(io::Error::other)?
}

#[derive(Clone, Copy)]
enum Object {
    Pack(PackId),
    Snapshot(SnapshotId),
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Hides a repository in the peer's deleted directory until `erase_after_unix`.
fn schedule_erase(peer_dir: &Path, repo: &str, erase_after_unix: i64) -> io::Result<()> {
    let from = peer_dir.join(repo);
    if !from.is_dir() {
        return Ok(()); // never stored anything, or already deleted
    }
    let deleted = peer_dir.join(DELETED_DIR);
    fs::create_dir_all(&deleted)?;
    // Deleted before (and used again since): keep both until due.
    let name = format!("{erase_after_unix}-{repo}");
    let mut to = deleted.join(&name);
    for n in 1.. {
        if !to.exists() {
            break;
        }
        to = deleted.join(format!("{name}-{n}"));
    }
    fs::rename(&from, &to)
}

#[cfg(test)]
mod tests {
    use iroh::protocol::Router;
    use iroh::{Endpoint, EndpointAddr};
    use kinvault_core::{PackId, SnapshotId};
    use tokio::runtime::Handle;

    use super::*;
    use crate::client::{RemoteBackend, pair, redeem_invite};
    use crate::protocol::{ALPN, MAX_REQUEST_LEN, MAX_RESPONSE_LEN};
    use crate::testutil::{addr_of, encode, local_endpoint, raw_call};
    use crate::ticket::InviteTicket;

    struct Setup {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        receiver: Receiver,
        host: Router,
        ep: Endpoint,
    }

    /// A host, and a client endpoint it accepts with `grant`.
    async fn setup(grant: Grant) -> Setup {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("host");
        let receiver = Receiver::new(&root);
        let host = crate::serve(local_endpoint().await, receiver.clone());
        let ep = local_endpoint().await;
        receiver.allow(ep.id(), grant);
        Setup {
            _tmp: tmp,
            root,
            receiver,
            host,
            ep,
        }
    }

    impl Setup {
        fn addr(&self) -> EndpointAddr {
            addr_of(&self.host)
        }

        fn remote(&self, repo: &str) -> Arc<RemoteBackend> {
            let r = RemoteBackend::new(self.ep.clone(), self.addr(), repo, Handle::current());
            Arc::new(r.unwrap())
        }

        fn peer_dir(&self) -> PathBuf {
            self.root.join(self.ep.id().to_string())
        }

        async fn raw(&self, repo: &str, op: Op, payload: &[u8]) -> Response {
            let mut bytes = encode(&Request {
                repo: repo.into(),
                op,
            });
            bytes.extend_from_slice(payload);
            raw_call(&self.ep, self.addr(), &bytes).await.unwrap()
        }
    }

    async fn blocking_call<T: Send + 'static>(
        remote: &Arc<RemoteBackend>,
        f: impl FnOnce(&RemoteBackend) -> T + Send + 'static,
    ) -> T {
        let remote = remote.clone();
        tokio::task::spawn_blocking(move || f(&remote))
            .await
            .unwrap()
    }

    fn is_error(resp: &Response, want: ErrorCode) -> bool {
        matches!(resp, Response::Error { code, .. } if *code == want)
    }

    #[tokio::test]
    async fn relays_deliver_only_with_the_owners_permission() {
        use crate::protocol::Delegation;

        let s = setup(Grant::default()).await;
        let host_id = s.host.endpoint().id();
        s.receiver.set_identity(host_id);
        let owner = s.ep.secret_key().clone();
        // The relay isn't a peer of this host.
        let relay = local_endpoint().await;
        let later = unix_now() + 3600;
        let deliver = |d: &Delegation, repo: &str, item: Delivery, payload: &[u8]| {
            let mut bytes = encode(&Request {
                repo: repo.into(),
                op: Op::Deliver {
                    delegation: d.clone(),
                    item,
                },
            });
            bytes.extend_from_slice(payload);
            bytes
        };
        let data = b"an encrypted pack".to_vec();
        let id = PackId(*blake3::hash(&data).as_bytes());
        let put = Delivery::Pack {
            id,
            len: data.len() as u64,
        };
        let have = Delivery::Have { packs: vec![id] };

        let ok = Delegation::sign(&owner, relay.id(), host_id, "photos", later);
        let resp = raw_call(&relay, s.addr(), &deliver(&ok, "photos", have.clone(), &[]))
            .await
            .unwrap();
        assert!(
            matches!(&resp, Response::Present(p) if p == &[false]),
            "{resp:?}"
        );
        let resp = raw_call(
            &relay,
            s.addr(),
            &deliver(&ok, "photos", put.clone(), &data),
        )
        .await
        .unwrap();
        assert!(matches!(resp, Response::Ok), "{resp:?}");
        // Stored as the owner's, where the owner's own requests see it.
        assert!(s.peer_dir().join("photos/packs").exists());
        let listed = blocking_call(&s.remote("photos"), |r| r.list_packs())
            .await
            .unwrap();
        assert_eq!(listed, vec![id]);
        let resp = raw_call(&relay, s.addr(), &deliver(&ok, "photos", have, &[]))
            .await
            .unwrap();
        assert!(
            matches!(&resp, Response::Present(p) if p == &[true]),
            "{resp:?}"
        );

        // It can't do anything else there.
        let resp = raw_call(
            &relay,
            s.addr(),
            &encode(&Request {
                repo: "photos".into(),
                op: Op::ListPacks,
            }),
        )
        .await
        .unwrap();
        assert!(is_error(&resp, ErrorCode::Denied), "{resp:?}");

        // Nor deliver with a permission for someone or something else.
        let other = local_endpoint().await.id();
        let mut tampered = ok.clone();
        tampered.repo = "other".into();
        let refused = [
            (
                Delegation::sign(&owner, other, host_id, "photos", later),
                "photos",
            ),
            (
                Delegation::sign(&owner, relay.id(), other, "photos", later),
                "photos",
            ),
            (
                Delegation::sign(&owner, relay.id(), host_id, "photos", unix_now() - 1),
                "photos",
            ),
            (ok.clone(), "other"),
            (tampered, "other"),
            // Signed by someone who isn't the owner it names.
            (
                Delegation {
                    signature: Delegation::sign(
                        relay.secret_key(),
                        relay.id(),
                        host_id,
                        "photos",
                        later,
                    )
                    .signature,
                    ..ok.clone()
                },
                "photos",
            ),
        ];
        for (d, repo) in refused {
            let resp = raw_call(&relay, s.addr(), &deliver(&d, repo, put.clone(), &data))
                .await
                .unwrap();
            assert!(is_error(&resp, ErrorCode::Denied), "{d:?} {repo}: {resp:?}");
        }
        // Deletions pass through only as the owner signed them.
        use crate::protocol::Deletion;
        let delete = |d: Deletion| deliver(&ok, "photos", Delivery::Delete(Box::new(d)), &[]);
        let by_relay = Deletion::sign(
            relay.secret_key(),
            host_id,
            "photos",
            vec![],
            vec![id],
            later,
        );
        let elsewhere = Deletion::sign(&owner, host_id, "other", vec![], vec![id], later);
        for d in [by_relay, elsewhere] {
            let resp = raw_call(&relay, s.addr(), &delete(d)).await.unwrap();
            assert!(is_error(&resp, ErrorCode::Denied), "{resp:?}");
        }
        assert!(
            s.peer_dir()
                .join("photos")
                .join(format!("packs/{}", &id.to_hex()[..2]))
                .join(id.to_hex())
                .exists()
        );
        let signed = Deletion::sign(&owner, host_id, "photos", vec![], vec![id], later);
        for _ in 0..2 {
            // Twice is fine: it may be passed on again.
            let resp = raw_call(&relay, s.addr(), &delete(signed.clone()))
                .await
                .unwrap();
            assert!(matches!(resp, Response::Ok), "{resp:?}");
        }
        let listed = blocking_call(&s.remote("photos"), |r| r.list_packs())
            .await
            .unwrap();
        assert!(listed.is_empty(), "{listed:?}");

        // And not once the owner may no longer store data here.
        s.receiver.revoke(&s.ep.id());
        let resp = raw_call(&relay, s.addr(), &deliver(&ok, "photos", put, &data))
            .await
            .unwrap();
        assert!(is_error(&resp, ErrorCode::Denied), "{resp:?}");
    }

    #[tokio::test]
    async fn grants_keep_their_pacing_when_the_rate_is_unchanged() {
        let receiver = Receiver::new("/nowhere");
        assert!(format!("{receiver:?}").contains("/nowhere"));
        let peer = iroh::SecretKey::generate().public();
        let grant = Grant {
            upload_limit: Some(1000),
            ..Default::default()
        };
        receiver.allow(peer, grant);
        let first = receiver.access(&peer).unwrap().1.unwrap();
        receiver.allow(peer, grant);
        assert!(Arc::ptr_eq(
            &first,
            &receiver.access(&peer).unwrap().1.unwrap()
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pairing_and_invites_need_a_handler() {
        let s = setup(Grant::default()).await;
        let ticket = InviteTicket {
            host: s.addr(),
            hosts: Default::default(),
            host_name: crate::protocol::PeerName::lossy("host"),
            token: [0; 16],
            quota_bytes: None,
            ask_reciprocal: false,
            expires_unix: i64::MAX,
        };
        let err = redeem_invite(&s.ep, &ticket, None, None, Vec::new()).await;
        assert!(matches!(err, Err(NetError::Denied(_))));
        let err = pair(&s.ep, s.addr(), "phone".into(), Vec::new()).await;
        assert!(matches!(err, Err(NetError::Denied(_))));

        let handler: PairHandler = Arc::new(|r: PairRequest| {
            Box::pin(async move {
                match r.name.as_str() {
                    "phone" => Ok("laptop".to_string()),
                    _ => Err("not confirmed".to_string()),
                }
            })
        });
        s.receiver.set_pair_handler(handler);
        let name = pair(&s.ep, s.addr(), "phone".into(), Vec::new()).await;
        assert_eq!(name.unwrap(), "laptop");
        let err = pair(&s.ep, s.addr(), "stranger".into(), Vec::new()).await;
        assert!(matches!(err, Err(NetError::Denied(m)) if m == "not confirmed"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshots_are_stored_listed_and_trashed() {
        let s = setup(Grant::default()).await;
        let r = s.remote("repo");
        let data = b"snapshot".to_vec();
        let id = SnapshotId(*blake3::hash(&data).as_bytes());
        let put = data.clone();
        blocking_call(&r, move |r| r.put_snapshot(&id, &put))
            .await
            .unwrap();
        assert_eq!(
            blocking_call(&r, |r| r.list_snapshots()).await.unwrap(),
            [id]
        );
        assert_eq!(
            blocking_call(&r, move |r| r.get_snapshot(&id))
                .await
                .unwrap(),
            data
        );
        blocking_call(&r, move |r| r.delete_snapshot(&id))
            .await
            .unwrap();
        assert!(
            blocking_call(&r, |r| r.list_snapshots())
                .await
                .unwrap()
                .is_empty()
        );

        // The content must match the id.
        let wrong = SnapshotId([0; 32]);
        let err = blocking_call(&r, move |r| r.put_snapshot(&wrong, b"other")).await;
        assert!(err.unwrap_err().to_string().contains("does not match"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_requests_are_rejected() {
        let s = setup(Grant::default()).await;
        let resp = s.raw("../escape", Op::ListPacks, b"").await;
        assert!(is_error(&resp, ErrorCode::BadRequest), "{resp:?}");

        let id = PackId([1; 32]);
        let too_big = Op::PutPack {
            id,
            len: MAX_OBJECT_LEN + 1,
        };
        let resp = s.raw("repo", too_big, b"").await;
        assert!(is_error(&resp, ErrorCode::BadRequest), "{resp:?}");
        // Promises more than it sends.
        let short = Op::PutPack { id, len: 100 };
        let resp = s.raw("repo", short, b"only ten..").await;
        assert!(is_error(&resp, ErrorCode::BadRequest), "{resp:?}");

        // Not a request at all: the host gives up on the stream.
        let garbage = [3, 0, 0, 0, 0xff, 0xff, 0xff];
        assert!(raw_call(&s.ep, s.addr(), &garbage).await.is_err());
    }

    #[test]
    fn counts_taken_across_a_change_are_not_cached() {
        let receiver = Receiver::new("/nowhere");
        let peer = iroh::SecretKey::generate().public();
        let stale = PeerUsage {
            used_bytes: 1,
            deleting_bytes: 0,
        };
        // A count starts, an upload is stored, then the count finishes:
        // it may have missed the upload, so it isn't kept.
        let version = receiver.cached_usage(&peer).unwrap_err();
        receiver.invalidate_usage(&peer);
        receiver.store_usage(&peer, version, stale);
        assert!(receiver.cached_usage(&peer).is_err());

        // An undisturbed count is kept...
        let version = receiver.cached_usage(&peer).unwrap_err();
        receiver.store_usage(&peer, version, stale);
        assert_eq!(receiver.cached_usage(&peer), Ok(stale));

        // ...until trash is purged, which changes every peer's usage, also
        // for counts already under way.
        receiver.invalidate_usage(&peer);
        let version = receiver.cached_usage(&peer).unwrap_err();
        receiver.invalidate_all_usage();
        receiver.store_usage(&peer, version, stale);
        assert!(receiver.cached_usage(&peer).is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn large_requests_are_refused_before_anything_else() {
        let s = setup(Grant::default()).await;
        // A whole request over the limit, from a peer the host doesn't
        // know: the host gives up on the stream instead of reading it.
        let stranger = local_endpoint().await;
        let huge = encode(&Request {
            repo: "x".repeat(MAX_REQUEST_LEN),
            op: Op::ListPacks,
        });
        assert!(raw_call(&stranger, s.addr(), &huge).await.is_err());
        // A normal-sized request from it is answered (and denied).
        let list = encode(&Request {
            repo: "repo".into(),
            op: Op::ListPacks,
        });
        let resp = raw_call(&stranger, s.addr(), &list).await.unwrap();
        assert!(is_error(&resp, ErrorCode::Denied), "{resp:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn parallel_uploads_share_the_quota() {
        let s = setup(Grant {
            quota_bytes: Some(1000),
            ..Default::default()
        })
        .await;
        // Four 400-byte uploads, all announced before any sends its data,
        // so all are checked against the same usage: only two fit.
        let conn = s.ep.connect(s.addr(), ALPN).await.unwrap();
        let mut streams = Vec::new();
        for i in 0..UPLOADS_PER_PEER as u8 {
            let data = vec![i; 400];
            let (mut send, recv) = conn.open_bi().await.unwrap();
            let header = encode(&Request {
                repo: "repo".into(),
                op: Op::PutPack {
                    id: PackId(*blake3::hash(&data).as_bytes()),
                    len: data.len() as u64,
                },
            });
            send.write_all(&header).await.unwrap();
            streams.push((send, recv, data));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut stored = 0;
        for (mut send, mut recv, data) in streams {
            // Refused uploads are stopped by the host, so these may fail.
            let _ = send.write_all(&data).await;
            let _ = send.finish();
            match read_msg::<Response>(&mut recv, MAX_RESPONSE_LEN)
                .await
                .unwrap()
            {
                Response::Ok => stored += 1,
                resp => assert!(is_error(&resp, ErrorCode::QuotaExceeded), "{resp:?}"),
            }
        }
        assert_eq!(stored, 2);
        assert!(s.receiver.usage(&s.ep.id()).await.unwrap() <= 1000);
        // Refused uploads gave back what they reserved.
        let uploads = s.receiver.peer_uploads(&s.ep.id());
        tokio::time::timeout(Duration::from_secs(5), async {
            while *uploads.reserved.lock().await != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn short_uploads_are_rejected_when_paced_too() {
        let s = setup(Grant {
            upload_limit: Some(1_000_000),
            ..Default::default()
        })
        .await;
        let short = Op::PutPack {
            id: PackId([1; 32]),
            len: 100,
        };
        let resp = s.raw("repo", short, b"only ten..").await;
        assert!(is_error(&resp, ErrorCode::BadRequest), "{resp:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn removing_a_peer_hides_its_repositories() {
        let s = setup(Grant::default()).await;
        let data = b"pack".to_vec();
        let id = PackId(*blake3::hash(&data).as_bytes());
        let r = s.remote("repo");
        let put = data.clone();
        blocking_call(&r, move |r| r.put_pack(&id, &put))
            .await
            .unwrap();
        // One deleted before the peer is removed stays as it is.
        let old = s.remote("old");
        blocking_call(&old, move |r| r.put_pack(&id, &data))
            .await
            .unwrap();
        old.delete_repo().await.unwrap();
        // Deleting a repository that was never used is fine.
        s.remote("unused").delete_repo().await.unwrap();
        // Folders that can't be repositories are left alone. (macOS refuses
        // names that aren't UTF-8.)
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStrExt;
            let odd = std::ffi::OsStr::from_bytes(b"\xff");
            fs::create_dir_all(s.peer_dir().join(odd)).unwrap();
        }
        fs::create_dir_all(s.peer_dir().join("not-a-repo")).unwrap();

        let erase_after = s.receiver.remove_peer(&s.ep.id()).await.unwrap();
        assert!(erase_after > unix_now());
        assert!(!s.peer_dir().join("repo").exists());
        let deleted: Vec<_> = read_dirs(&s.peer_dir().join(DELETED_DIR)).unwrap();
        // "old", then "repo" and "not-a-repo".
        assert_eq!(deleted.len(), 3);
        assert!(matches!(r.status().await, Err(NetError::Denied(_))));
        // Nothing is due yet; stray folders are skipped.
        assert_eq!(s.receiver.purge_trash(Duration::ZERO).await.unwrap(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn storage_failures_are_internal_errors() {
        let s = setup(Grant::default()).await;
        // A file where the peer's folder should be.
        fs::create_dir_all(&s.root).unwrap();
        fs::write(s.peer_dir(), b"").unwrap();
        let r = s.remote("repo");
        assert!(matches!(r.status().await, Err(NetError::Remote(_))));
        assert!(s.receiver.usage(&s.ep.id()).await.is_err());
        let err = blocking_call(&r, |r| r.list_packs()).await.unwrap_err();
        assert!(err.to_string().contains("internal storage error"));

        // A file where the host's storage should be.
        let broken = Receiver::new(s.peer_dir());
        assert!(broken.purge_trash(Duration::ZERO).await.is_err());
    }
}
