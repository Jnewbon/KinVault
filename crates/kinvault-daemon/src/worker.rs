//! One task per backup set: watches the sources, waits for changes to
//! settle, then runs an incremental backup. Also rescans periodically (to
//! catch anything the watcher missed), retries with backoff on failure, and
//! runs maintenance (prune, verify) when due. While the host it backs up to
//! is offline it waits, and backs up as soon as the host is back. Everything
//! that touches the repository goes through this task, so operations never
//! overlap.

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use kinvault_core::{Backend, Excludes, Index, LocalDirBackend, MasterKey, Repository, SnapshotId};
use kinvault_net::{Endpoint, EndpointAddr, EndpointId, RemoteBackend};
use notify::event::{AccessKind, AccessMode};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::api::{BackupSummary, Event, PruneSummary, SetState, VerifySummary};
use crate::config::{SetConfig, StoredTarget, write_private};
use crate::reachability::{HostTarget, Hosts};

/// A burst of changes never delays a backup by more than this.
const MAX_CHANGE_DELAY: Duration = Duration::from_secs(10 * 60);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30 * 60);
const PRUNE_INTERVAL_SECS: i64 = 24 * 60 * 60;
const VERIFY_INTERVAL_SECS: i64 = 7 * 24 * 60 * 60;
/// Data downloaded per scheduled verification; runs rotate through all packs.
pub(crate) const VERIFY_BUDGET_BYTES: u64 = 256 << 20;

type Reply<T> = oneshot::Sender<Result<T, String>>;

/// The set's open repository, shared so stopping can wait until it's closed.
type RepoSlot = Arc<Mutex<Option<Repository<Box<dyn Backend>>>>>;

pub(crate) enum Trigger {
    Changed,
    Now(Reply<BackupSummary>),
    Prune(Reply<PruneSummary>),
    Verify(u64, Reply<VerifySummary>),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Maintenance {
    /// When maintenance scheduling started for this set; the first prune and
    /// verify are due one interval after it, not straight after the first upload.
    #[serde(default)]
    pub since_unix: i64,
    pub last_prune: Option<PruneSummary>,
    pub last_verify: Option<VerifySummary>,
}

#[derive(Clone, Debug)]
pub(crate) struct RunStatus {
    pub state: SetState,
    pub last_backup: Option<BackupSummary>,
    pub last_error: Option<String>,
    pub maintenance: Maintenance,
}

/// Everything needed to open a set's repository.
#[derive(Clone)]
pub(crate) struct SetEnv {
    pub set: SetConfig,
    pub set_dir: PathBuf,
    pub endpoint: Endpoint,
    pub runtime: Handle,
    pub excludes: Vec<PathBuf>,
    pub events: broadcast::Sender<Event>,
    pub hosts: Arc<Hosts>,
}

pub(crate) fn master_key_path(set_dir: &Path) -> PathBuf {
    set_dir.join("master.key")
}

pub(crate) fn write_master_key(set_dir: &Path, key: &MasterKey) -> Result<()> {
    write_private(
        &master_key_path(set_dir),
        hex::encode(key.to_bytes()).as_bytes(),
    )
}

pub(crate) fn read_master_key(set_dir: &Path) -> Result<MasterKey> {
    let text = fs::read_to_string(master_key_path(set_dir)).context("reading set key")?;
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(text.trim(), &mut bytes).context("set key is corrupt")?;
    Ok(MasterKey::from_bytes(bytes))
}

pub(crate) fn peer_addr(id: &str, addrs: &[std::net::SocketAddr]) -> Result<EndpointAddr> {
    let id = EndpointId::from_str(id).with_context(|| format!("invalid peer id {id:?}"))?;
    Ok(addrs
        .iter()
        .fold(EndpointAddr::new(id), |a, s| a.with_ip_addr(*s)))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl SetEnv {
    /// Opens the set's repository. Blocking; call from a blocking context.
    /// The set's exclude patterns (checked when they were saved).
    pub fn exclude_patterns(&self) -> Excludes {
        Excludes::parse(&self.set.excludes).unwrap_or_else(|e| {
            tracing::warn!(set = %self.set.name, "ignoring exclude patterns: {e}");
            Excludes::default()
        })
    }

    pub fn open_repository(&self) -> Result<Repository<Box<dyn Backend>>> {
        let master = read_master_key(&self.set_dir)?;
        let backend: Box<dyn Backend> = match &self.set.target {
            StoredTarget::Local { path } => Box::new(LocalDirBackend::open(path)?),
            StoredTarget::Peer {
                id,
                repo,
                addrs,
                hosts,
            } => Box::new(
                RemoteBackend::new(
                    self.endpoint.clone(),
                    peer_addr(id, addrs)?,
                    repo,
                    self.runtime.clone(),
                )?
                .with_upload_limit(self.set.upload_limit)
                .with_hosts(hosts.clone()),
            ),
        };
        let index = Index::open(&self.set_dir.join("index.db"))?;
        let mut repo = Repository::open(backend, &master, index);
        repo.set_excludes(self.excludes.clone());
        repo.set_exclude_patterns(self.exclude_patterns());
        Ok(repo)
    }

    /// The host the set backs up to, unless it's a local folder.
    pub fn host(&self) -> Option<HostTarget> {
        match &self.set.target {
            StoredTarget::Peer {
                id, addrs, hosts, ..
            } => Some(HostTarget {
                id: id.clone(),
                addrs: addrs.clone(),
                hosts: hosts.clone(),
            }),
            StoredTarget::Local { .. } => None,
        }
    }

    fn last_backup_path(&self) -> PathBuf {
        self.set_dir.join("last_backup.json")
    }

    fn maintenance_path(&self) -> PathBuf {
        self.set_dir.join("maintenance.json")
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

pub(crate) struct SetHandle {
    pub env: SetEnv,
    pub status: Arc<Mutex<RunStatus>>,
    pub tx: mpsc::Sender<Trigger>,
    task: JoinHandle<()>,
    repo: RepoSlot,
    _watcher: Option<RecommendedWatcher>,
}

impl SetHandle {
    pub fn start(env: SetEnv) -> Self {
        let status = Arc::new(Mutex::new(RunStatus {
            state: if env.set.paused {
                SetState::Paused
            } else {
                SetState::Idle
            },
            last_backup: read_json(&env.last_backup_path()),
            last_error: None,
            maintenance: read_json(&env.maintenance_path()).unwrap_or_else(|| {
                let m = Maintenance {
                    since_unix: unix_now(),
                    ..Default::default()
                };
                if let Ok(json) = serde_json::to_string(&m) {
                    let _ = fs::write(env.maintenance_path(), json);
                }
                m
            }),
        }));
        let (tx, rx) = mpsc::channel(64);
        let watcher = if env.set.paused {
            None
        } else {
            start_watcher(&env, tx.clone())
        };
        let repo = RepoSlot::default();
        let task = tokio::spawn(run(env.clone(), status.clone(), repo.clone(), rx));
        Self {
            env,
            status,
            tx,
            task,
            repo,
            _watcher: watcher,
        }
    }

    /// Stops the set's task without waiting. An operation already under way
    /// finishes in the background.
    pub fn abort(self) {
        self.task.abort();
    }

    /// Stops the set's task and closes its repository, waiting for an
    /// operation already under way to finish (aborting doesn't stop it).
    /// Afterwards nothing holds files in the set's directory open, so it can
    /// be deleted (Windows refuses while a file in it is open).
    pub async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
        let repo = self.repo;
        let _ = tokio::task::spawn_blocking(move || {
            repo.lock().unwrap_or_else(|e| e.into_inner()).take();
        })
        .await;
    }
}

fn is_change(kind: &EventKind) -> bool {
    match kind {
        // Our own backup reads files; only writes count as changes.
        EventKind::Access(AccessKind::Close(AccessMode::Write)) => true,
        EventKind::Access(_) => false,
        _ => true,
    }
}

fn start_watcher(env: &SetEnv, tx: mpsc::Sender<Trigger>) -> Option<RecommendedWatcher> {
    let excludes = env.excludes.clone();
    let patterns = env.exclude_patterns();
    let handler = move |res: notify::Result<notify::Event>| {
        let relevant = match res {
            // E.g. a build rewriting its output doesn't call for a backup.
            Ok(ev) => {
                is_change(&ev.kind)
                    && !ev.paths.iter().all(|p| {
                        excludes.iter().any(|e| p.starts_with(e)) || patterns.excludes_any(p)
                    })
            }
            // Events may have been lost; a backup rescans everything anyway.
            Err(_) => true,
        };
        if relevant {
            // A full queue already holds a pending change.
            let _ = tx.try_send(Trigger::Changed);
        }
    };
    let mut watcher = match notify::recommended_watcher(handler) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(set = %env.set.name, "file watching unavailable, relying on rescans: {e}");
            return None;
        }
    };
    for path in &env.set.paths {
        if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
            tracing::warn!(set = %env.set.name, "cannot watch {}: {e}; relying on rescans", path.display());
        }
    }
    Some(watcher)
}

/// Updates the set's state, telling subscribers if it changed.
fn set_state(env: &SetEnv, status: &Mutex<RunStatus>, state: SetState) {
    let mut st = status.lock().unwrap();
    if st.state != state {
        st.state = state;
        let _ = env.events.send(Event::SetState {
            set: env.set.id.clone(),
            state,
        });
    }
}

/// Forwards backup progress to subscribers, at most four times a second.
fn progress_reporter(env: &SetEnv) -> kinvault_core::ProgressFn {
    let events = env.events.clone();
    let set = env.set.id.clone();
    let last = Mutex::new(std::time::Instant::now() - Duration::from_secs(1));
    Arc::new(move |p: &kinvault_core::BackupProgress| {
        let mut last = last.lock().unwrap();
        if last.elapsed() >= Duration::from_millis(250) {
            *last = std::time::Instant::now();
            let _ = events.send(Event::Progress {
                set: set.clone(),
                files: p.files,
                total_bytes: p.total_bytes,
                bytes_read: p.bytes_read,
                bytes_uploaded: p.bytes_uploaded,
            });
        }
    })
}

fn retry_delay(failures: u32) -> Duration {
    Duration::from_secs(60)
        .saturating_mul(1 << failures.saturating_sub(1).min(10))
        .min(MAX_RETRY_DELAY)
}

struct Worker {
    env: SetEnv,
    status: Arc<Mutex<RunStatus>>,
    repo: RepoSlot,
}

impl Worker {
    /// Runs `f` on the repository in a blocking thread, opening it if needed.
    async fn with_repo<T: Send + 'static>(
        &mut self,
        f: impl FnOnce(&mut Repository<Box<dyn Backend>>) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let slot = self.repo.clone();
        let env = self.env.clone();
        tokio::task::spawn_blocking(move || {
            // Held for the whole operation; see `SetHandle::stop`.
            let mut slot = slot.lock().unwrap_or_else(|e| e.into_inner());
            let repo = match &mut *slot {
                Some(r) => r,
                empty => empty.insert(env.open_repository()?),
            };
            f(repo)
        })
        .await?
    }

    async fn backup(&mut self) -> Result<BackupSummary> {
        if self.env.set.paused {
            bail!(
                "set {:?} is paused; resume it to back up",
                self.env.set.name
            );
        }
        let paths = self.env.set.paths.clone();
        let previous = self
            .status
            .lock()
            .unwrap()
            .last_backup
            .as_ref()
            .and_then(|b| SnapshotId::from_hex(&b.snapshot).ok());
        let progress = progress_reporter(&self.env);
        let (id, stats) = self
            .with_repo(move |repo| {
                let host = gethostname::gethostname().to_string_lossy().into_owned();
                repo.set_progress(Some(progress));
                let result = repo.backup_if_changed(&paths, &host, previous.as_ref());
                repo.set_progress(None);
                Ok(result?)
            })
            .await?;
        Ok(BackupSummary {
            snapshot: id.to_hex(),
            time_ns: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as i64,
            files: stats.files,
            files_changed: stats.files_changed,
            total_bytes: stats.total_bytes,
            bytes_uploaded: stats.bytes_uploaded,
            warnings: stats.warnings,
        })
    }

    async fn prune(&mut self) -> Result<PruneSummary> {
        let policy = self.env.set.retention;
        let s = self.with_repo(move |repo| Ok(repo.prune(&policy)?)).await?;
        let summary = PruneSummary {
            time_unix: unix_now(),
            snapshots_kept: s.snapshots_kept,
            snapshots_removed: s.snapshots_removed,
            packs_deleted: s.packs_deleted,
            packs_repacked: s.packs_repacked,
            bytes_deleted: s.bytes_deleted,
            bytes_downloaded: s.bytes_downloaded,
            bytes_uploaded: s.bytes_uploaded,
        };
        self.save_maintenance(|m| m.last_prune = Some(summary.clone()));
        tracing::info!(set = %self.env.set.name, removed = s.snapshots_removed, freed = s.bytes_deleted, "prune complete");
        Ok(summary)
    }

    async fn verify(&mut self, max_bytes: u64) -> Result<VerifySummary> {
        let r = self
            .with_repo(move |repo| Ok(repo.verify(max_bytes)?))
            .await?;
        let summary = VerifySummary {
            time_unix: unix_now(),
            ok: r.is_ok(),
            snapshots: r.snapshots,
            packs_checked: r.packs_checked,
            bytes_checked: r.bytes_checked,
            missing_chunks: r.missing_chunks,
            damaged_packs: r.damaged_packs.len() as u64,
            errors: r.errors,
        };
        self.save_maintenance(|m| m.last_verify = Some(summary.clone()));
        if summary.ok {
            tracing::info!(set = %self.env.set.name, checked = r.bytes_checked, "verification passed");
        } else {
            tracing::warn!(set = %self.env.set.name, "verification found problems: {:?}", summary.errors);
        }
        Ok(summary)
    }

    fn save_maintenance(&self, update: impl FnOnce(&mut Maintenance)) {
        let mut st = self.status.lock().unwrap();
        update(&mut st.maintenance);
        if let Ok(json) = serde_json::to_string(&st.maintenance) {
            let _ = fs::write(self.env.maintenance_path(), json);
        }
        let _ = self.env.events.send(Event::SetsChanged);
    }

    /// Runs prune and verify if they are due. Returns true if a backup should
    /// follow soon (verification removed damaged data that can be re-uploaded).
    async fn maintenance_if_due(&mut self) -> bool {
        let (last_prune, last_verify) = {
            let st = self.status.lock().unwrap();
            (
                st.maintenance
                    .last_prune
                    .as_ref()
                    .map_or(0, |p| p.time_unix)
                    .max(st.maintenance.since_unix),
                st.maintenance
                    .last_verify
                    .as_ref()
                    .map_or(0, |v| v.time_unix)
                    .max(st.maintenance.since_unix),
            )
        };
        let now = unix_now();
        let mut heal = false;
        if now - last_prune >= PRUNE_INTERVAL_SECS
            && let Err(e) = self.prune().await
        {
            tracing::warn!(set = %self.env.set.name, "prune failed: {e:#}");
        }
        if now - last_verify >= VERIFY_INTERVAL_SECS {
            match self.verify(VERIFY_BUDGET_BYTES).await {
                Ok(v) => heal = !v.ok,
                Err(e) => {
                    tracing::warn!(set = %self.env.set.name, "verification failed to run: {e:#}")
                }
            }
        }
        heal
    }
}

async fn run(
    env: SetEnv,
    status: Arc<Mutex<RunStatus>>,
    repo: RepoSlot,
    mut rx: mpsc::Receiver<Trigger>,
) {
    let debounce = Duration::from_secs(env.set.debounce_secs);
    let rescan = Duration::from_secs(env.set.rescan_secs);
    let paused = env.set.paused;
    let host = env.host();
    let mut host_events = env.events.subscribe();
    let mut worker = Worker {
        env,
        status: status.clone(),
        repo,
    };
    let mut waiters: Vec<Reply<BackupSummary>> = Vec::new();
    let mut failures = 0u32;
    // Back up right away to pick up changes made while the daemon was stopped.
    // A paused set only acts on explicit requests.
    let far = Instant::now() + Duration::from_secs(100 * 365 * 24 * 3600);
    let mut scheduled = if paused { far } else { Instant::now() };
    let mut change_deadline: Option<Instant> = None;
    let mut first_change: Option<Instant> = None;
    let mut waiting_for_window = false;
    let mut waiting_for_host = false;

    loop {
        set_state(
            &worker.env,
            &status,
            if paused {
                SetState::Paused
            } else if change_deadline.is_some() {
                SetState::ChangesPending
            } else if waiting_for_window {
                SetState::WaitingForWindow
            } else if waiting_for_host {
                SetState::WaitingForHost
            } else {
                SetState::Idle
            },
        );
        let next = change_deadline.map_or(scheduled, |c| c.min(scheduled));
        let run_now = tokio::select! {
            msg = rx.recv() => match msg {
                None => return,
                Some(Trigger::Changed) => {
                    let now = Instant::now();
                    let first = *first_change.get_or_insert(now);
                    change_deadline = Some((now + debounce).min(first + MAX_CHANGE_DELAY));
                    false
                }
                Some(Trigger::Now(reply)) => {
                    waiters.push(reply);
                    true
                }
                Some(Trigger::Prune(reply)) => {
                    set_state(&worker.env, &status, SetState::Running);
                    let _ = reply.send(worker.prune().await.map_err(|e| format!("{e:#}")));
                    false
                }
                Some(Trigger::Verify(max_bytes, reply)) => {
                    set_state(&worker.env, &status, SetState::Running);
                    let result = worker.verify(max_bytes).await;
                    if matches!(&result, Ok(v) if !v.ok) && !paused {
                        scheduled = Instant::now();
                    }
                    let _ = reply.send(result.map_err(|e| format!("{e:#}")));
                    false
                }
            },
            ev = host_events.recv(), if host.is_some() => {
                let id = host.as_ref().map(|h| h.id.as_str()).unwrap_or_default();
                let back = match ev {
                    Ok(Event::PeerOnline { id: peer, online }) => online && peer == id,
                    // Missed events; it may have come back meanwhile.
                    Err(broadcast::error::RecvError::Lagged(_)) => !worker.env.hosts.is_offline(id),
                    _ => false,
                };
                // Back up now rather than at the next retry.
                if back && (waiting_for_host || failures > 0) && !paused {
                    waiting_for_host = false;
                    scheduled = Instant::now();
                }
                false
            }
            _ = tokio::time::sleep_until(next) => true,
        };
        if !run_now {
            continue;
        }
        change_deadline = None;
        first_change = None;
        // Automatic runs wait for the window; explicit requests don't.
        if waiters.is_empty()
            && let Some(window) = worker.env.set.window
        {
            let wait = window.until_open();
            if !wait.is_zero() {
                waiting_for_window = true;
                scheduled = Instant::now() + wait;
                continue;
            }
        }
        waiting_for_window = false;
        // Don't keep dialling a host that is known to be away; it is checked
        // regularly and we hear when it's back. Explicit requests still try.
        if waiters.is_empty()
            && let Some(h) = &host
            && worker.env.hosts.is_offline(&h.id)
        {
            waiting_for_host = true;
            scheduled = Instant::now() + MAX_RETRY_DELAY;
            continue;
        }
        waiting_for_host = false;
        set_state(&worker.env, &status, SetState::Running);

        let result = worker.backup().await;
        match result {
            Ok(summary) => {
                failures = 0;
                if let Some(h) = &host {
                    worker.env.hosts.record(&h.id, true);
                }
                scheduled = if paused { far } else { Instant::now() + rescan };
                tracing::info!(
                    set = %worker.env.set.name,
                    snapshot = %&summary.snapshot[..16],
                    changed = summary.files_changed,
                    uploaded = summary.bytes_uploaded,
                    "backup complete"
                );
                if let Ok(json) = serde_json::to_string(&summary) {
                    let _ = fs::write(worker.env.last_backup_path(), json);
                }
                {
                    let mut st = status.lock().unwrap();
                    st.last_backup = Some(summary.clone());
                    st.last_error = None;
                }
                let _ = worker.env.events.send(Event::BackupFinished {
                    set: worker.env.set.id.clone(),
                    summary: summary.clone(),
                });
                for w in waiters.drain(..) {
                    let _ = w.send(Ok(summary.clone()));
                }
                if worker.maintenance_if_due().await {
                    scheduled = Instant::now();
                }
            }
            Err(e) => {
                let mut msg = format!("{e:#}");
                // A host that went away isn't a problem to report: wait for it.
                let offline = match &host {
                    Some(h) => !worker.env.hosts.check(&worker.env.endpoint, h).await,
                    None => false,
                };
                if offline {
                    msg = format!(
                        "the backup host can't be reached right now; \
                         backing up resumes once it's online ({msg})"
                    );
                    if !paused {
                        waiting_for_host = true;
                        scheduled = Instant::now() + MAX_RETRY_DELAY;
                        tracing::info!(set = %worker.env.set.name, "backup host is offline; waiting for it");
                        status.lock().unwrap().last_error = None;
                    }
                } else if !paused {
                    failures += 1;
                    let delay = retry_delay(failures);
                    scheduled = Instant::now() + delay;
                    tracing::warn!(set = %worker.env.set.name, "backup failed (retrying in {}s): {msg}", delay.as_secs());
                    status.lock().unwrap().last_error = Some(msg.clone());
                }
                if !offline {
                    let _ = worker.env.events.send(Event::BackupFailed {
                        set: worker.env.set.id.clone(),
                        error: msg.clone(),
                    });
                }
                for w in waiters.drain(..) {
                    let _ = w.send(Err(msg.clone()));
                }
            }
        }
    }
}
