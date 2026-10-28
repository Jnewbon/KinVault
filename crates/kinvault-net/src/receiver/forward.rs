//! Forwarding: this host copies objects of a peer's repository to another
//! host on the peer's behalf (see [`ForwardOrder`]). Orders wait in a queue
//! directory and are worked through in the background, so they go out even
//! while the peer is switched off. The data is copied as it is, still
//! encrypted; this host can't read it.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr, EndpointId};
use kinvault_core::{Backend, LocalDirBackend};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use super::{Receiver, blocking_io, unix_now};
use crate::client::{Deliverer, connect};
use crate::error::NetError;
use crate::limits::RateLimiter;
use crate::protocol::{ForwardInfo, ForwardOrder, ForwardState, valid_repo_name};

/// Unfinished orders one peer may have waiting.
const MAX_PENDING_PER_PEER: usize = 64;
/// Finished orders kept per peer and place, for their status.
const KEEP_FINISHED: usize = 10;
/// How long to wait for the other host to answer.
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
/// Waits between attempts when the other host can't be reached.
const FIRST_RETRY: Duration = Duration::from_secs(5 * 60);
const MAX_RETRY: Duration = Duration::from_secs(60 * 60);
/// Looks at the queue at least this often, e.g. for windows that opened.
const IDLE_CHECK: Duration = Duration::from_secs(5 * 60);

/// Forwarding orders waiting or done, one file each.
#[derive(Debug)]
pub struct ForwardQueue {
    dir: PathBuf,
    wake: Notify,
    /// Serialises changes, so two requests can't race on one file.
    lock: tokio::sync::Mutex<()>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Job {
    owner: EndpointId,
    /// The owner's repository here that the objects come from.
    repo: String,
    order: ForwardOrder,
    info: ForwardInfo,
    #[serde(default)]
    attempts: u32,
    /// Don't try again before this (Unix seconds).
    #[serde(default)]
    next_try_unix: i64,
}

impl ForwardQueue {
    pub fn new(dir: impl Into<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            dir: dir.into(),
            wake: Notify::new(),
            lock: tokio::sync::Mutex::new(()),
        })
    }

    fn path(&self, owner: &EndpointId, id: &str) -> PathBuf {
        self.dir.join(format!("{owner}-{id}.json"))
    }

    async fn jobs(&self) -> io::Result<Vec<Job>> {
        let dir = self.dir.clone();
        blocking_io(move || {
            let mut jobs = Vec::new();
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(jobs),
                Err(e) => return Err(e),
            };
            for entry in entries {
                let path = entry?.path();
                if path.extension().is_none_or(|e| e != "json") {
                    continue;
                }
                match std::fs::read(&path).map(|b| serde_json::from_slice::<Job>(&b)) {
                    Ok(Ok(job)) => jobs.push(job),
                    _ => tracing::warn!("ignoring unreadable forwarding order {}", path.display()),
                }
            }
            jobs.sort_by_key(|j| j.info.updated_unix);
            Ok(jobs)
        })
        .await
    }

    async fn save(&self, job: &Job) -> io::Result<()> {
        let path = self.path(&job.owner, &job.order.id);
        let tmp = path.with_extension("tmp");
        let data = serde_json::to_vec(job).map_err(io::Error::other)?;
        let dir = self.dir.clone();
        blocking_io(move || {
            std::fs::create_dir_all(&dir)?;
            std::fs::write(&tmp, data)?;
            std::fs::rename(&tmp, &path)
        })
        .await
    }

    async fn remove(&self, owner: &EndpointId, id: &str) -> io::Result<()> {
        let path = self.path(owner, id);
        blocking_io(move || match std::fs::remove_file(&path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
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
        let _guard = self.lock.lock().await;
        let jobs = self.jobs().await.map_err(|e| e.to_string())?;
        if jobs
            .iter()
            .any(|j| j.owner == owner && j.order.id == order.id)
        {
            return Err(format!("there's already an order {:?}", order.id));
        }
        let pending = jobs
            .iter()
            .filter(|j| j.owner == owner && j.info.state == ForwardState::Pending)
            .count();
        if pending >= MAX_PENDING_PER_PEER {
            return Err(format!(
                "{pending} orders are still waiting; try again once some are done"
            ));
        }
        let job = Job {
            owner,
            repo,
            info: ForwardInfo {
                id: order.id.clone(),
                state: ForwardState::Pending,
                packs_sent: 0,
                packs_total: order.packs.len() as u64,
                bytes_sent: 0,
                error: None,
                updated_unix: unix_now(),
            },
            order,
            attempts: 0,
            next_try_unix: 0,
        };
        self.save(&job).await.map_err(|e| e.to_string())?;
        self.wake.notify_one();
        Ok(())
    }

    /// The owner's orders for a place, oldest first.
    pub(super) async fn status(
        &self,
        owner: &EndpointId,
        place: &str,
    ) -> io::Result<Vec<ForwardInfo>> {
        Ok(self
            .jobs()
            .await?
            .into_iter()
            .filter(|j| j.owner == *owner && j.order.place == place)
            .map(|j| j.info)
            .collect())
    }

    /// Drops the owner's unfinished orders for a place.
    pub(super) async fn cancel(&self, owner: &EndpointId, place: &str) -> io::Result<()> {
        let _guard = self.lock.lock().await;
        for j in self.jobs().await? {
            if j.owner == *owner && j.order.place == place && j.info.state == ForwardState::Pending
            {
                self.remove(owner, &j.order.id).await?;
            }
        }
        Ok(())
    }

    /// Updates a job unless it was cancelled meanwhile.
    async fn update(&self, job: &Job) -> io::Result<()> {
        let _guard = self.lock.lock().await;
        if !self.path(&job.owner, &job.order.id).exists() {
            return Ok(());
        }
        self.save(job).await
    }

    /// Forgets all but the newest finished orders of each owner and place.
    async fn trim(&self) -> io::Result<()> {
        let _guard = self.lock.lock().await;
        let mut finished: Vec<Job> = self
            .jobs()
            .await?
            .into_iter()
            .filter(|j| j.info.state != ForwardState::Pending)
            .collect();
        finished.sort_by_key(|j| std::cmp::Reverse(j.info.updated_unix));
        let mut seen: Vec<(EndpointId, String, usize)> = Vec::new();
        for j in finished {
            let key = (j.owner, j.order.place.clone());
            let count = match seen.iter_mut().find(|(o, p, _)| (*o, p.clone()) == key) {
                Some((_, _, n)) => {
                    *n += 1;
                    *n
                }
                None => {
                    seen.push((key.0, key.1, 1));
                    1
                }
            };
            if count > KEEP_FINISHED {
                self.remove(&j.owner, &j.order.id).await?;
            }
        }
        Ok(())
    }
}

impl Receiver {
    /// Works through forwarding orders until the task is dropped.
    pub async fn run_forwarding(&self, endpoint: Endpoint) {
        let Some(queue) = self.inner.forwarding.read().unwrap().clone() else {
            return;
        };
        loop {
            let mut next = IDLE_CHECK;
            match queue.jobs().await {
                Ok(jobs) => {
                    for job in jobs {
                        if job.info.state != ForwardState::Pending {
                            continue;
                        }
                        let wait = job.next_try_unix - unix_now();
                        if wait > 0 {
                            next = next.min(Duration::from_secs(wait as u64));
                            continue;
                        }
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
        let owner = job.owner;
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
        for window in [job.order.window, grant.window].into_iter().flatten() {
            let wait = window.until_open();
            if !wait.is_zero() {
                job.next_try_unix = unix_now() + wait.as_secs() as i64;
                let _ = queue.update(&job).await;
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
                tracing::info!(%owner, place, bytes = job.info.bytes_sent, "forwarded");
                finish(queue, &mut job, ForwardState::Done, None).await
            }
            // Gone or offline: try again later, waiting longer each time.
            Err(NetError::Transport(e)) => {
                tracing::debug!(%owner, place, "couldn't forward yet: {e}");
                let wait = FIRST_RETRY
                    .saturating_mul(1 << job.attempts.min(4))
                    .min(MAX_RETRY);
                job.attempts += 1;
                job.next_try_unix = unix_now() + wait.as_secs() as i64;
                job.info.error = Some(format!("the other host can't be reached: {e}"));
                job.info.updated_unix = unix_now();
                let _ = queue.update(&job).await;
                Some(wait)
            }
            Err(NetError::OutsideWindow(e)) => {
                job.next_try_unix = unix_now() + FIRST_RETRY.as_secs() as i64;
                job.info.error = Some(e);
                let _ = queue.update(&job).await;
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
        let source_dir = self.peer_dir(&job.owner).join(&job.repo);
        let source = Arc::new(
            blocking_io(move || LocalDirBackend::open(source_dir).map_err(io::Error::other))
                .await
                .map_err(|e| NetError::Protocol(format!("its source repository is gone: {e}")))?,
        );
        let host = job.order.delegation.host;
        let addr = job
            .order
            .addrs
            .iter()
            .fold(EndpointAddr::new(host), |a, s| a.with_ip_addr(*s));
        let conn = connect(endpoint, addr, &job.order.hosts, DIAL_TIMEOUT).await?;
        let to = Deliverer {
            conn: conn.clone(),
            delegation: job.order.delegation.clone(),
            limiter: rate.map(RateLimiter::new),
        };
        let present = to.have(&job.order.packs).await?;
        job.info.packs_sent = present.iter().filter(|&&p| p).count() as u64;
        for (id, here) in job.order.packs.clone().iter().zip(present) {
            if here {
                continue;
            }
            let (s, id) = (source.clone(), *id);
            let data = blocking_io(move || s.get_pack(&id).map_err(io::Error::other))
                .await
                .map_err(|e| NetError::Protocol(format!("pack {id} isn't here: {e}")))?;
            to.put_pack(&id, &data).await?;
            job.info.packs_sent += 1;
            job.info.bytes_sent += data.len() as u64;
            job.info.updated_unix = unix_now();
            job.info.error = None;
            let _ = queue.update(job).await;
        }
        for id in job.order.snapshots.clone() {
            let s = source.clone();
            let data = blocking_io(move || s.get_snapshot(&id).map_err(io::Error::other))
                .await
                .map_err(|e| NetError::Protocol(format!("snapshot {id} isn't here: {e}")))?;
            to.put_snapshot(&id, &data).await?;
            job.info.bytes_sent += data.len() as u64;
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
    job.info.state = state;
    job.info.error = error;
    job.info.updated_unix = unix_now();
    if let Err(e) = queue.update(job).await {
        tracing::warn!("couldn't save a forwarding order: {e}");
    }
    None
}
