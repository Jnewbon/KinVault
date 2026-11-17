//! Forwarding: this host copies objects of a peer's repository to another
//! host on the peer's behalf (see [`ForwardOrder`]). Orders wait in a queue
//! directory and are worked through in the background, so they go out even
//! while the peer is switched off. The data is copied as it is, still
//! encrypted; this host can't read it.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr, EndpointId};
use kinvault_core::{Backend, LocalDirBackend};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use super::{Receiver, blocking_io, unix_now};
use crate::client::{Deliverer, connect};
use crate::error::NetError;
use crate::hosts::{dialable, with_hosts_where};
use crate::limits::RateLimiter;
use crate::protocol::{ForwardInfo, ForwardOrder, ForwardState, valid_repo_name};

/// Unfinished orders one peer may have waiting.
const MAX_PENDING_PER_PEER: usize = 64;
/// Finished orders kept per peer and place, for their status.
const KEEP_FINISHED: usize = 10;
/// Finished orders kept per peer across all its places.
const MAX_FINISHED_PER_PEER: usize = 64;
/// Places one peer may have orders for. Places are named by the peer, so
/// without a limit it could keep any number of finished orders here.
const MAX_PLACES_PER_PEER: usize = 16;
/// Bytes of unfinished orders one peer may have queued. Orders sit in the
/// state directory, outside the storage the peer is allowed, so this is
/// kept well below what a backup's own data would need.
pub(crate) const MAX_QUEUE_BYTES_PER_PEER: u64 = 64 * 1024 * 1024;
/// How long to wait for the other host to answer.
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
/// Waits between attempts when the other host can't be reached.
const FIRST_RETRY: Duration = Duration::from_secs(5 * 60);
const MAX_RETRY: Duration = Duration::from_secs(60 * 60);
/// Looks at the queue at least this often, e.g. for windows that opened.
const IDLE_CHECK: Duration = Duration::from_secs(5 * 60);
/// When to try again after an order's outcome couldn't be saved.
const SAVE_RETRY: Duration = Duration::from_secs(5);

/// Forwarding orders waiting or done. Each has a small status file
/// (`<owner>-<id>.json`), read for status and to find work, and while it's
/// unfinished an order file (`<owner>-<id>.order`) that never changes.
#[derive(Debug)]
pub struct ForwardQueue {
    dir: PathBuf,
    wake: Notify,
    /// Serialises changes, so two requests can't race on one file.
    lock: tokio::sync::Mutex<()>,
    /// Set once files written by older versions have been converted.
    migrated: tokio::sync::OnceCell<()>,
}

/// How an order is going: everything about it but the order itself.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Status {
    owner: EndpointId,
    /// The owner's repository here that the objects come from.
    repo: String,
    #[serde(default)]
    place: String,
    info: ForwardInfo,
    #[serde(default)]
    attempts: u32,
    /// Don't try again before this (Unix seconds).
    #[serde(default)]
    next_try_unix: i64,
    /// Size of the order file, counted against the owner's queue budget.
    #[serde(default)]
    order_bytes: u64,
    /// Only in files written by older versions, which kept the whole order
    /// in the status file.
    #[serde(default, skip_serializing)]
    order: Option<ForwardOrder>,
}

/// An order being worked on.
#[derive(Debug, Clone)]
struct Job {
    status: Status,
    order: ForwardOrder,
}

impl ForwardQueue {
    pub fn new(dir: impl Into<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            dir: dir.into(),
            wake: Notify::new(),
            lock: tokio::sync::Mutex::new(()),
            migrated: tokio::sync::OnceCell::new(),
        })
    }

    fn status_path(&self, owner: &EndpointId, id: &str) -> PathBuf {
        self.dir.join(format!("{owner}-{id}.json"))
    }

    fn order_path(&self, owner: &EndpointId, id: &str) -> PathBuf {
        self.dir.join(format!("{owner}-{id}.order"))
    }

    /// Every order's status, oldest change first.
    async fn statuses(&self) -> io::Result<Vec<Status>> {
        self.migrated.get_or_try_init(|| self.migrate()).await?;
        let dir = self.dir.clone();
        blocking_io(move || {
            let mut all = read_statuses(&dir)?;
            all.retain(|s| s.order.is_none());
            all.sort_by_key(|s| s.info.updated_unix);
            Ok(all)
        })
        .await
    }

    /// Moves orders out of status files written by older versions.
    async fn migrate(&self) -> io::Result<()> {
        let dir = self.dir.clone();
        let old: Vec<Status> = blocking_io(move || read_statuses(&dir))
            .await?
            .into_iter()
            .filter(|s| s.order.is_some())
            .collect();
        for mut status in old {
            let order = status.order.take().expect("filtered");
            status.place = order.place.clone();
            if status.info.state == ForwardState::Pending {
                status.order_bytes = self.save_order(&status, &order).await?;
            }
            self.save(&status).await?;
        }
        Ok(())
    }

    async fn save(&self, status: &Status) -> io::Result<()> {
        let path = self.status_path(&status.owner, &status.info.id);
        let data = serde_json::to_vec(status).map_err(io::Error::other)?;
        write_replacing(self.dir.clone(), path, data).await
    }

    /// Writes the order file; returns its size.
    async fn save_order(&self, status: &Status, order: &ForwardOrder) -> io::Result<u64> {
        let path = self.order_path(&status.owner, &order.id);
        let data = postcard::to_allocvec(&(&status.repo, order)).map_err(io::Error::other)?;
        let len = data.len() as u64;
        write_replacing(self.dir.clone(), path, data).await?;
        Ok(len)
    }

    async fn load(&self, status: Status) -> io::Result<Job> {
        let path = self.order_path(&status.owner, &status.info.id);
        let data = blocking_io(move || std::fs::read(path)).await?;
        let (_repo, order): (String, ForwardOrder) =
            postcard::from_bytes(&data).map_err(io::Error::other)?;
        Ok(Job { status, order })
    }

    async fn remove(&self, owner: &EndpointId, id: &str) -> io::Result<()> {
        let paths = [self.order_path(owner, id), self.status_path(owner, id)];
        blocking_io(move || {
            for path in paths {
                match std::fs::remove_file(&path) {
                    Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                    _ => {}
                }
            }
            Ok(())
        })
        .await
    }

    /// Queues an order from `owner` for objects of its repository `repo`.
    pub(super) async fn add(
        &self,
        owner: EndpointId,
        repo: String,
        order: ForwardOrder,
    ) -> Result<(), String> {
        if !valid_repo_name(&order.id) || !valid_repo_name(&order.place) {
            return Err("invalid order or place name".into());
        }
        let order_bytes = postcard::experimental::serialized_size(&(&repo, &order))
            .map_err(|e| e.to_string())? as u64;
        let _guard = self.lock.lock().await;
        let all = self.statuses().await.map_err(|e| e.to_string())?;
        let mine: Vec<&Status> = all.iter().filter(|s| s.owner == owner).collect();
        if mine.iter().any(|s| s.info.id == order.id) {
            return Err(format!("there's already an order {:?}", order.id));
        }
        let pending: Vec<&&Status> = mine
            .iter()
            .filter(|s| s.info.state == ForwardState::Pending)
            .collect();
        if pending.len() >= MAX_PENDING_PER_PEER {
            return Err(format!(
                "{} orders are still waiting; try again once some are done",
                pending.len()
            ));
        }
        let queued: u64 = pending.iter().map(|s| s.order_bytes).sum();
        if queued + order_bytes > MAX_QUEUE_BYTES_PER_PEER {
            return Err(format!(
                "{queued} bytes of orders are still waiting; try again once some are done"
            ));
        }
        let mut places: Vec<&str> = mine.iter().map(|s| s.place.as_str()).collect();
        places.sort_unstable();
        places.dedup();
        if !places.contains(&order.place.as_str()) && places.len() >= MAX_PLACES_PER_PEER {
            // Make way by forgetting the place used least recently, if all
            // its orders are finished.
            let idle = places
                .iter()
                .filter(|p| !pending.iter().any(|s| s.place == **p))
                .min_by_key(|p| {
                    mine.iter()
                        .filter(|s| s.place == **p)
                        .map(|s| s.info.updated_unix)
                        .max()
                });
            let Some(idle) = idle else {
                return Err(format!(
                    "orders for {MAX_PLACES_PER_PEER} places are still waiting"
                ));
            };
            for s in mine.iter().filter(|s| s.place == *idle) {
                self.remove(&owner, &s.info.id)
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }
        let mut status = Status {
            owner,
            repo,
            place: order.place.clone(),
            info: ForwardInfo {
                id: order.id.clone(),
                state: ForwardState::Pending,
                packs_sent: 0,
                packs_total: order.packs.len() as u64,
                bytes_sent: 0,
                error: None,
                updated_unix: unix_now(),
            },
            attempts: 0,
            next_try_unix: 0,
            order_bytes: 0,
            order: None,
        };
        // The order first: a status file without one is never worked on.
        status.order_bytes = self
            .save_order(&status, &order)
            .await
            .map_err(|e| e.to_string())?;
        self.save(&status).await.map_err(|e| e.to_string())?;
        self.wake.notify_one();
        Ok(())
    }

    /// The owner's orders for a place, oldest first.
    pub(super) async fn status(
        &self,
        owner: &EndpointId,
        place: &str,
    ) -> io::Result<Vec<ForwardInfo>> {
        // Not while a file is being replaced, which Windows refuses while
        // the file is open.
        let _guard = self.lock.lock().await;
        Ok(self
            .statuses()
            .await?
            .into_iter()
            .filter(|s| s.owner == *owner && s.place == place)
            .map(|s| s.info)
            .collect())
    }

    /// Drops the owner's unfinished orders for a place.
    pub(super) async fn cancel(&self, owner: &EndpointId, place: &str) -> io::Result<()> {
        let _guard = self.lock.lock().await;
        for s in self.statuses().await? {
            if s.owner == *owner && s.place == place && s.info.state == ForwardState::Pending {
                self.remove(owner, &s.info.id).await?;
            }
        }
        Ok(())
    }

    /// Updates an order's status unless it was cancelled meanwhile. Once
    /// it's finished, its order file goes.
    async fn update(&self, status: &mut Status) -> io::Result<()> {
        let _guard = self.lock.lock().await;
        if !self.status_path(&status.owner, &status.info.id).exists() {
            return Ok(());
        }
        if status.info.state != ForwardState::Pending {
            status.order_bytes = 0;
        }
        self.save(status).await?;
        if status.info.state != ForwardState::Pending {
            let path = self.order_path(&status.owner, &status.info.id);
            blocking_io(move || match std::fs::remove_file(path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            })
            .await?;
        }
        Ok(())
    }

    /// Forgets all but the newest finished orders of each owner and place,
    /// and of each owner overall.
    async fn trim(&self) -> io::Result<()> {
        let _guard = self.lock.lock().await;
        let mut finished: Vec<Status> = self
            .statuses()
            .await?
            .into_iter()
            .filter(|s| s.info.state != ForwardState::Pending)
            .collect();
        finished.sort_by_key(|s| std::cmp::Reverse(s.info.updated_unix));
        let mut per_place: HashMap<(EndpointId, String), usize> = HashMap::new();
        let mut per_owner: HashMap<EndpointId, usize> = HashMap::new();
        for s in finished {
            let in_place = per_place.entry((s.owner, s.place.clone())).or_default();
            let in_owner = per_owner.entry(s.owner).or_default();
            *in_place += 1;
            *in_owner += 1;
            if *in_place > KEEP_FINISHED || *in_owner > MAX_FINISHED_PER_PEER {
                self.remove(&s.owner, &s.info.id).await?;
            }
        }
        Ok(())
    }
}

/// Reads every status file in `dir`, skipping unreadable ones.
fn read_statuses(dir: &Path) -> io::Result<Vec<Status>> {
    let mut all = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(all),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        match std::fs::read(&path).map(|b| serde_json::from_slice::<Status>(&b)) {
            Ok(Ok(status)) => all.push(status),
            _ => tracing::warn!("ignoring unreadable forwarding order {}", path.display()),
        }
    }
    Ok(all)
}

/// Writes `data` to `path` in `dir` through a temporary file.
async fn write_replacing(dir: PathBuf, path: PathBuf, data: Vec<u8>) -> io::Result<()> {
    let mut tmp = path.clone().into_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    blocking_io(move || {
        std::fs::create_dir_all(&dir)?;
        std::fs::write(&tmp, data)?;
        replace(&tmp, &path)
    })
    .await
}

impl Receiver {
    /// Works through forwarding orders until the task is dropped.
    pub async fn run_forwarding(&self, endpoint: Endpoint) {
        let Some(queue) = self.inner.forwarding.read().unwrap().clone() else {
            return;
        };
        loop {
            let mut next = IDLE_CHECK;
            match queue.statuses().await {
                Ok(all) => {
                    for status in all {
                        if status.info.state != ForwardState::Pending {
                            continue;
                        }
                        let wait = status.next_try_unix - unix_now();
                        if wait > 0 {
                            next = next.min(Duration::from_secs(wait as u64));
                            continue;
                        }
                        let job = match queue.load(status.clone()).await {
                            Ok(job) => job,
                            Err(e) => {
                                // Cancelled meanwhile, or written half-way.
                                tracing::debug!("skipping a forwarding order: {e}");
                                continue;
                            }
                        };
                        if let Some(wait) = self.forward(&queue, &endpoint, job).await {
                            next = next.min(wait);
                        }
                    }
                }
                Err(e) => tracing::warn!("couldn't read the forwarding queue: {e}"),
            }
            if let Err(e) = queue.trim().await {
                tracing::warn!("couldn't tidy the forwarding queue: {e}");
            }
            tokio::select! {
                _ = queue.wake.notified() => {}
                _ = tokio::time::sleep(next) => {}
            }
        }
    }

    /// Works on one order. Returns when to look at it again, if it's still
    /// pending.
    async fn forward(
        &self,
        queue: &ForwardQueue,
        endpoint: &Endpoint,
        mut job: Job,
    ) -> Option<Duration> {
        let owner = job.status.owner;
        let place = job.order.place.clone();
        // The limits the owner set for this place, and those this host set
        // for the owner, both apply.
        let Some((grant, _)) = self.access(&owner) else {
            return finish(
                queue,
                &mut job,
                ForwardState::Failed,
                Some("its owner may no longer store data here".into()),
            )
            .await;
        };
        if !grant.forwarding {
            return finish(
                queue,
                &mut job,
                ForwardState::Failed,
                Some("this host no longer forwards backups for its owner".into()),
            )
            .await;
        }
        for window in [job.order.window, grant.window].into_iter().flatten() {
            let wait = window.until_open();
            if !wait.is_zero() {
                job.status.next_try_unix = unix_now() + wait.as_secs() as i64;
                let _ = queue.update(&mut job.status).await;
                return Some(wait);
            }
        }
        let rate = match (job.order.upload_limit, grant.upload_limit) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        tracing::info!(%owner, place, packs = job.order.packs.len(), "forwarding");
        let result = self.deliver_order(queue, endpoint, &mut job, rate).await;
        match result {
            Ok(()) => {
                tracing::info!(%owner, place, bytes = job.status.info.bytes_sent, "forwarded");
                finish(queue, &mut job, ForwardState::Done, None).await
            }
            // Gone or offline: try again later, waiting longer each time.
            Err(NetError::Transport(e)) => {
                tracing::debug!(%owner, place, "couldn't forward yet: {e}");
                let status = &mut job.status;
                let wait = FIRST_RETRY
                    .saturating_mul(1 << status.attempts.min(4))
                    .min(MAX_RETRY);
                status.attempts += 1;
                status.next_try_unix = unix_now() + wait.as_secs() as i64;
                status.info.error = Some(format!("the other host can't be reached: {e}"));
                status.info.updated_unix = unix_now();
                let _ = queue.update(status).await;
                Some(wait)
            }
            Err(NetError::OutsideWindow(e)) => {
                job.status.next_try_unix = unix_now() + FIRST_RETRY.as_secs() as i64;
                job.status.info.error = Some(e);
                let _ = queue.update(&mut job.status).await;
                Some(FIRST_RETRY)
            }
            Err(e) => {
                tracing::warn!(%owner, place, "forwarding failed: {e}");
                finish(queue, &mut job, ForwardState::Failed, Some(e.to_string())).await
            }
        }
    }

    async fn deliver_order(
        &self,
        queue: &ForwardQueue,
        endpoint: &Endpoint,
        job: &mut Job,
        rate: Option<u64>,
    ) -> Result<(), NetError> {
        let source_dir = self.peer_dir(&job.status.owner).join(&job.status.repo);
        let source = Arc::new(
            blocking_io(move || LocalDirBackend::open(source_dir).map_err(io::Error::other))
                .await
                .map_err(|e| NetError::Protocol(format!("its source repository is gone: {e}")))?,
        );
        // The addresses and names come from the peer: dial only ones a
        // host could have. Loopback only when this host itself listens only
        // there (instances on one machine, as in tests).
        let loopback = endpoint
            .bound_sockets()
            .iter()
            .all(|s| s.ip().is_loopback());
        let keep = |ip| dialable(ip, loopback);
        let host = job.order.delegation.host;
        let addr = job
            .order
            .addrs
            .iter()
            .filter(|s| keep(s.ip()))
            .fold(EndpointAddr::new(host), |a, s| a.with_ip_addr(*s));
        let addr = with_hosts_where(addr, &job.order.hosts, keep).await;
        let conn = connect(endpoint, addr, &[], DIAL_TIMEOUT).await?;
        let to = Deliverer {
            conn: conn.clone(),
            delegation: job.order.delegation.clone(),
            limiter: rate.map(RateLimiter::new),
        };
        let present = to.have(&job.order.packs).await?;
        job.status.info.packs_sent = present.iter().filter(|&&p| p).count() as u64;
        for (id, here) in job.order.packs.clone().iter().zip(present) {
            if here {
                continue;
            }
            let (s, id) = (source.clone(), *id);
            let data = blocking_io(move || s.get_pack(&id).map_err(io::Error::other))
                .await
                .map_err(|e| NetError::Protocol(format!("pack {id} isn't here: {e}")))?;
            to.put_pack(&id, &data).await?;
            let status = &mut job.status;
            status.info.packs_sent += 1;
            status.info.bytes_sent += data.len() as u64;
            status.info.updated_unix = unix_now();
            status.info.error = None;
            let _ = queue.update(status).await;
        }
        for id in job.order.snapshots.clone() {
            let s = source.clone();
            let data = blocking_io(move || s.get_snapshot(&id).map_err(io::Error::other))
                .await
                .map_err(|e| NetError::Protocol(format!("snapshot {id} isn't here: {e}")))?;
            to.put_snapshot(&id, &data).await?;
            job.status.info.bytes_sent += data.len() as u64;
        }
        for deletion in job.order.deletions.clone() {
            to.delete(deletion).await?;
        }
        conn.close(0u32.into(), b"done");
        Ok(())
    }
}

async fn finish(
    queue: &ForwardQueue,
    job: &mut Job,
    state: ForwardState,
    error: Option<String>,
) -> Option<Duration> {
    job.status.info.state = state;
    job.status.info.error = error;
    job.status.info.updated_unix = unix_now();
    match queue.update(&mut job.status).await {
        Ok(()) => None,
        // It's still pending on disk; look again soon rather than at the
        // next idle check. Delivering it again is harmless.
        Err(e) => {
            tracing::warn!("couldn't save a forwarding order: {e}");
            Some(SAVE_RETRY)
        }
    }
}

/// Moves `from` over `to`. Windows refuses while another handle has `to`
/// open (a status read, or a virus scanner), so it tries a few times.
fn replace(from: &Path, to: &Path) -> io::Result<()> {
    const TRIES: u32 = 20;
    for _ in 1..TRIES {
        match std::fs::rename(from, to) {
            Err(e) if in_use(&e) => std::thread::sleep(Duration::from_millis(25)),
            done => return done,
        }
    }
    std::fs::rename(from, to)
}

/// ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION on Windows.
fn in_use(e: &io::Error) -> bool {
    cfg!(windows) && matches!(e.raw_os_error(), Some(5 | 32))
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;
    use kinvault_core::PackId;

    use super::*;
    use crate::protocol::Delegation;

    /// An order from `owner` for `place`, listing `packs` packs.
    fn order(owner: &SecretKey, id: &str, place: &str, packs: usize) -> ForwardOrder {
        let other = SecretKey::generate().public();
        ForwardOrder {
            id: id.into(),
            place: place.into(),
            delegation: Delegation::sign(owner, other, other, "repo", i64::MAX),
            addrs: Vec::new(),
            hosts: Vec::new(),
            packs: (0..packs)
                .map(|i| PackId(*blake3::hash(&i.to_le_bytes()).as_bytes()))
                .collect(),
            snapshots: Vec::new(),
            upload_limit: None,
            window: None,
            deletions: Vec::new(),
        }
    }

    fn dir_bytes(dir: &Path) -> u64 {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum()
    }

    async fn finish_all(queue: &ForwardQueue) {
        for mut s in queue.statuses().await.unwrap() {
            s.info.state = ForwardState::Failed;
            queue.update(&mut s).await.unwrap();
        }
    }

    /// The finding's scenario: a peer (with however small a quota) sends
    /// many large orders for made-up places. The queue stays bounded.
    #[tokio::test]
    async fn one_peer_cant_fill_the_queue() {
        let tmp = tempfile::tempdir().unwrap();
        let queue = ForwardQueue::new(tmp.path());
        let owner = SecretKey::generate();
        // About 6.4 MB each; ten fit in the budget, the eleventh doesn't.
        let big = 200_000;
        let mut refused = None;
        for i in 0..20 {
            let o = order(&owner, &format!("o{i}"), &format!("p{i}"), big);
            if let Err(e) = queue.add(owner.public(), "repo".into(), o).await {
                refused = Some((i, e));
                break;
            }
        }
        let (i, e) = refused.expect("the budget runs out");
        assert_eq!(i, 10, "{e}");
        assert!(e.contains("still waiting"), "{e}");
        assert!(dir_bytes(tmp.path()) <= MAX_QUEUE_BYTES_PER_PEER + 64 * 1024);

        // Once they've failed, their orders are gone and only small status
        // files remain.
        finish_all(&queue).await;
        assert!(
            dir_bytes(tmp.path()) < 64 * 1024,
            "{}",
            dir_bytes(tmp.path())
        );

        // Another peer has its own budget.
        let other = SecretKey::generate();
        let o = order(&other, "o", "p", big);
        queue.add(other.public(), "repo".into(), o).await.unwrap();
    }

    #[tokio::test]
    async fn pending_orders_and_places_are_limited() {
        let tmp = tempfile::tempdir().unwrap();
        let queue = ForwardQueue::new(tmp.path());
        let owner = SecretKey::generate();
        let id = owner.public();
        for i in 0..MAX_PLACES_PER_PEER {
            let o = order(&owner, &format!("o{i}"), &format!("p{i}"), 1);
            queue.add(id, "repo".into(), o).await.unwrap();
        }
        // A new place while every place still has an order waiting.
        let o = order(&owner, "new", "new", 1);
        let e = queue.add(id, "repo".into(), o.clone()).await.unwrap_err();
        assert!(e.contains("places"), "{e}");
        // Once they're done, the least recently used place makes way.
        finish_all(&queue).await;
        queue.add(id, "repo".into(), o).await.unwrap();
        let places: std::collections::HashSet<_> = queue
            .statuses()
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.place)
            .collect();
        assert_eq!(places.len(), MAX_PLACES_PER_PEER);
        assert!(places.contains("new"));

        // Unfinished orders per peer, across places.
        for i in 0..MAX_PENDING_PER_PEER - 1 {
            let o = order(&owner, &format!("more{i}"), "new", 1);
            queue.add(id, "repo".into(), o).await.unwrap();
        }
        let o = order(&owner, "one-too-many", "new", 1);
        assert!(queue.add(id, "repo".into(), o).await.is_err());
    }

    #[tokio::test]
    async fn finished_orders_are_trimmed_per_peer() {
        let tmp = tempfile::tempdir().unwrap();
        let queue = ForwardQueue::new(tmp.path());
        let owner = SecretKey::generate();
        for round in 0..3 {
            for p in 0..MAX_PLACES_PER_PEER {
                for i in 0..10 {
                    let o = order(&owner, &format!("r{round}p{p}o{i}"), &format!("p{p}"), 1);
                    queue.add(owner.public(), "repo".into(), o).await.unwrap();
                }
                finish_all(&queue).await;
            }
        }
        queue.trim().await.unwrap();
        let left = queue.statuses().await.unwrap();
        assert_eq!(left.len(), MAX_FINISHED_PER_PEER);
    }

    #[tokio::test]
    async fn orders_from_older_versions_are_moved_out_of_status_files() {
        let tmp = tempfile::tempdir().unwrap();
        let owner = SecretKey::generate();
        let o = order(&owner, "old", "place", 3);
        // As older versions wrote it: the whole order in the JSON file.
        let old = serde_json::json!({
            "owner": owner.public(),
            "repo": "repo",
            "order": o,
            "info": {
                "id": "old", "state": "Pending", "packs_sent": 0, "packs_total": 3,
                "bytes_sent": 0, "error": null, "updated_unix": 1,
            },
            "attempts": 2,
            "next_try_unix": 5,
        });
        let status_path = tmp.path().join(format!("{}-old.json", owner.public()));
        std::fs::write(&status_path, serde_json::to_vec(&old).unwrap()).unwrap();

        let queue = ForwardQueue::new(tmp.path());
        let all = queue.statuses().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].place, "place");
        assert_eq!(all[0].attempts, 2);
        assert!(all[0].order_bytes > 0);
        let job = queue.load(all[0].clone()).await.unwrap();
        assert_eq!(job.order.packs, o.packs);
        // The status file no longer holds the order.
        let rewritten = std::fs::read_to_string(&status_path).unwrap();
        assert!(!rewritten.contains("delegation"), "{rewritten}");
    }

    #[test]
    fn order_lists_are_limited() {
        let owner = SecretKey::generate();
        let ok = order(&owner, "o", "p", 1);
        assert!(ok.check_limits().is_ok());
        let mut o = ok.clone();
        o.addrs = vec!["192.0.2.1:1".parse().unwrap(); crate::protocol::MAX_ORDER_ADDRS + 1];
        assert!(o.check_limits().is_err());
        let mut o = ok.clone();
        o.hosts = vec!["x".repeat(300)];
        assert!(o.check_limits().is_err());
        let mut o = ok;
        o.snapshots =
            vec![kinvault_core::SnapshotId([0; 32]); crate::protocol::MAX_ORDER_SNAPSHOTS + 1];
        assert!(o.check_limits().is_err());
    }
}
