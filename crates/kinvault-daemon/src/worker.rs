//! One task per backup set: watches the sources, waits for changes to
//! settle, then runs an incremental backup. Also rescans periodically (to
//! catch anything the watcher missed), retries with backoff on failure, and
//! runs maintenance (prune, verify) when due. While the host it backs up to
//! is offline it waits, and backs up as soon as the host is back. Everything
//! that touches the repository goes through this task, so operations never
//! overlap.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use kinvault_core::{
    Backend, Excludes, Index, LocalDirBackend, MasterKey, PackId, Repository, SnapshotId,
};
use kinvault_net::protocol::{Delegation, Deletion, ForwardOrder, ForwardState};
use kinvault_net::{Endpoint, EndpointAddr, EndpointId, RemoteBackend};
use notify::event::{AccessKind, AccessMode};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::api::{self, BackupSummary, Event, PruneSummary, SetState, VerifySummary};
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
    /// Prune the main place (`None`) or an extra one, by id.
    Prune(Option<String>, Reply<PruneSummary>),
    Verify(u64, Option<String>, Reply<VerifySummary>),
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

/// How copying to, and maintaining, one of a set's extra places went.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct ExtraState {
    /// When this place was first seen; maintenance is due an interval later.
    #[serde(default)]
    pub since_unix: i64,
    pub last_copy: Option<api::CopySummary>,
    pub last_error: Option<String>,
    pub last_prune: Option<PruneSummary>,
    pub last_verify: Option<VerifySummary>,
    /// For a place copies are forwarded to: orders the relay hasn't
    /// finished, and versions it has delivered (`(id, time in ns)`).
    #[serde(default)]
    pub orders: Vec<OrderRecord>,
    #[serde(default)]
    pub delivered: Vec<(String, i64)>,
    #[serde(default)]
    pub forwarding: Option<api::ForwardProgress>,
}

/// A forwarding order sent to the relay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OrderRecord {
    pub id: String,
    /// `(id, time in ns)`, oldest first.
    pub snapshots: Vec<(String, i64)>,
    pub packs: Vec<String>,
    /// Versions and packs it has the place delete, once it's delivered.
    #[serde(default)]
    pub deletes: Vec<String>,
    #[serde(default)]
    pub dropped_packs: Vec<String>,
}

/// How long a relay may deliver with a permission given in one order.
const DELEGATION_SECS: i64 = 60 * 24 * 60 * 60;
/// How often to ask the relay how orders are going while some are open.
pub(crate) const FORWARD_POLL: Duration = Duration::from_secs(2 * 60);

#[derive(Clone, Debug)]
pub(crate) struct RunStatus {
    pub state: SetState,
    pub last_backup: Option<BackupSummary>,
    pub last_error: Option<String>,
    pub maintenance: Maintenance,
    /// By extra place id.
    pub extras: BTreeMap<String, ExtraState>,
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

/// The key new sets use unless they ask for their own; see [`shared_key`].
pub(crate) fn shared_key_path(state_dir: &Path) -> PathBuf {
    state_dir.join("shared.key")
}

pub(crate) fn write_master_key(set_dir: &Path, key: &MasterKey) -> Result<()> {
    write_key(&master_key_path(set_dir), key)
}

pub(crate) fn read_master_key(set_dir: &Path) -> Result<MasterKey> {
    read_key(&master_key_path(set_dir)).context("reading set key")
}

/// The instance's shared set key, created the first time it's needed.
/// Each set using it still keeps its own copy in `master.key`.
pub(crate) fn shared_key(state_dir: &Path) -> Result<MasterKey> {
    let path = shared_key_path(state_dir);
    if path.exists() {
        return read_key(&path).context("reading the shared key");
    }
    let key = MasterKey::generate()?;
    write_key(&path, &key)?;
    Ok(key)
}

pub(crate) fn write_key(path: &Path, key: &MasterKey) -> Result<()> {
    write_private(path, hex::encode(key.to_bytes()).as_bytes())
}

fn read_key(path: &Path) -> Result<MasterKey> {
    let text = fs::read_to_string(path)?;
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(text.trim(), &mut bytes).context("key is corrupt")?;
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

    /// Opens the repository in the set's main place.
    pub fn open_repository(&self) -> Result<Repository<Box<dyn Backend>>> {
        self.open_place(None)
    }

    /// Opens the repository in the main place (`None`) or an extra one, by
    /// id. Each place has an index of its own.
    pub fn open_place(&self, extra: Option<&str>) -> Result<Repository<Box<dyn Backend>>> {
        let master = read_master_key(&self.set_dir)?;
        let (target, upload_limit) = match extra {
            None => (&self.set.target, self.set.upload_limit),
            Some(id) => {
                let t = self
                    .set
                    .extra_target(id)
                    .with_context(|| format!("{} has no extra place {id:?}", self.set.name))?;
                (&t.target, t.upload_limit)
            }
        };
        let backend: Box<dyn Backend> = match target {
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
                .with_upload_limit(upload_limit)
                .with_hosts(hosts.clone()),
            ),
        };
        let index = Index::open(&self.set_dir.join(index_file(extra)))?;
        let mut repo = Repository::open(backend, &master, index);
        repo.set_excludes(self.excludes.clone());
        repo.set_exclude_patterns(self.exclude_patterns());
        Ok(repo)
    }

    /// The host the set backs up to, unless it's a local folder.
    pub fn host(&self) -> Option<HostTarget> {
        host_of(&self.set.target)
    }

    /// The main place's host, for asking it to forward copies.
    pub fn main_remote(&self) -> Result<RemoteBackend> {
        let StoredTarget::Peer {
            id,
            repo,
            addrs,
            hosts,
        } = &self.set.target
        else {
            bail!("copies can only be forwarded when the main place is another computer");
        };
        Ok(RemoteBackend::new(
            self.endpoint.clone(),
            peer_addr(id, addrs)?,
            repo,
            self.runtime.clone(),
        )?
        .with_hosts(hosts.clone()))
    }

    fn extras_path(&self) -> PathBuf {
        self.set_dir.join("extras.json")
    }

    fn last_backup_path(&self) -> PathBuf {
        self.set_dir.join("last_backup.json")
    }

    fn maintenance_path(&self) -> PathBuf {
        self.set_dir.join("maintenance.json")
    }
}

/// The index file of the set's main place (`None`) or an extra one.
pub(crate) fn index_file(extra: Option<&str>) -> String {
    match extra {
        None => "index.db".into(),
        Some(id) => format!("index-{id}.db"),
    }
}

/// The host a place is on, unless it's a local folder.
pub(crate) fn host_of(target: &StoredTarget) -> Option<HostTarget> {
    match target {
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

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

pub(crate) struct SetHandle {
    pub env: SetEnv,
    pub status: Arc<Mutex<RunStatus>>,
    pub tx: mpsc::Sender<Trigger>,
    task: JoinHandle<()>,
    repo: RepoSlot,
    /// Tells an operation under way to stop; see [`Repository::set_cancel`].
    cancel: Arc<AtomicBool>,
    _watcher: Option<RecommendedWatcher>,
}

impl SetHandle {
    pub fn start(env: SetEnv) -> Self {
        Self::start_after(env, None)
    }

    /// Starts the set's task once `previous` (the same set's old task, e.g.
    /// before a settings change) has stopped, so two never use the set's
    /// backups at once.
    pub fn start_after(env: SetEnv, previous: Option<SetHandle>) -> Self {
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
            extras: {
                let mut extras: BTreeMap<String, ExtraState> =
                    read_json(&env.extras_path()).unwrap_or_default();
                // Forget places that were removed; start the clock on new ones.
                extras.retain(|id, _| env.set.extra_target(id).is_some());
                for t in &env.set.extra_targets {
                    extras.entry(t.id.clone()).or_insert_with(|| ExtraState {
                        since_unix: unix_now(),
                        ..Default::default()
                    });
                }
                extras
            },
        }));
        let (tx, rx) = mpsc::channel(64);
        let watcher = if env.set.paused {
            None
        } else {
            start_watcher(&env, tx.clone())
        };
        // Shared with the previous task, so stopping this one also waits for
        // work the previous one still has under way, even if this task is
        // aborted before it finishes waiting for it. Told to stop now.
        let repo = match &previous {
            Some(p) => {
                p.cancel.store(true, Ordering::Relaxed);
                p.task.abort();
                p.repo.clone()
            }
            None => RepoSlot::default(),
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let run = run(
            env.clone(),
            status.clone(),
            repo.clone(),
            cancel.clone(),
            rx,
        );
        let task = tokio::spawn(async move {
            if let Some(previous) = previous {
                previous.stop().await;
            }
            run.await
        });
        Self {
            env,
            status,
            tx,
            task,
            repo,
            cancel,
            _watcher: watcher,
        }
    }

    /// Stops the set's task without waiting. An operation already under way
    /// stops soon after, in the background.
    pub fn abort(self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.task.abort();
    }

    /// Stops the set's task and closes its repository, waiting for an
    /// operation already under way to stop (it is cancelled; aborting the
    /// task alone doesn't stop it). Afterwards nothing holds files in the
    /// set's directory open, so it can be deleted (Windows refuses while a
    /// file in it is open).
    pub async fn stop(self) {
        self.cancel.store(true, Ordering::Relaxed);
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

/// Forwards maintenance progress to subscribers, at most four times a
/// second (and always when a step starts or ends).
fn maintenance_reporter(
    env: &SetEnv,
) -> impl FnMut(&kinvault_core::MaintenanceProgress) + Send + use<> {
    let events = env.events.clone();
    let set = env.set.id.clone();
    let mut last: Option<(kinvault_core::MaintenanceStep, std::time::Instant)> = None;
    move |p| {
        let edge = p.done == 0 || p.done == p.total;
        let due = match last {
            Some((step, at)) => {
                step != p.step || edge || at.elapsed() >= Duration::from_millis(250)
            }
            None => true,
        };
        if due {
            last = Some((p.step, std::time::Instant::now()));
            let _ = events.send(Event::MaintenanceProgress {
                set: set.clone(),
                step: p.step.into(),
                done: p.done,
                total: p.total,
            });
        }
    }
}

/// Forwards backup progress to subscribers, at most four times a second,
/// but always when the backup moves to another step (sending a pack can
/// take a while on a slow link) and the final totals once every file has
/// been looked at.
fn progress_reporter(env: &SetEnv) -> kinvault_core::ProgressFn {
    use kinvault_core::BackupStep as S;
    let events = env.events.clone();
    let set = env.set.id.clone();
    let last = Mutex::new((
        std::time::Instant::now() - Duration::from_secs(1),
        api::BackupStep::Checking,
    ));
    Arc::new(move |p: &kinvault_core::BackupProgress| {
        let (step, sending_bytes) = match p.step {
            S::Checking => (api::BackupStep::Checking, 0),
            S::Reading => (api::BackupStep::Reading, 0),
            S::Sending { bytes } => (api::BackupStep::Sending, bytes),
        };
        let mut last = last.lock().unwrap();
        if p.scanned || step != last.1 || last.0.elapsed() >= Duration::from_millis(250) {
            *last = (std::time::Instant::now(), step);
            let _ = events.send(Event::Progress {
                set: set.clone(),
                files: p.files,
                total_bytes: p.total_bytes,
                bytes_read: p.bytes_read,
                bytes_uploaded: p.bytes_uploaded,
                step,
                file: p.file.clone(),
                sending_bytes,
                file_size: p.file_size,
                file_read: p.file_read,
            });
        }
    })
}

/// What copying to the extra places left to do.
#[derive(Default)]
struct ExtrasOutcome {
    /// Until the soonest skipped place's time window opens.
    wait: Option<Duration>,
    /// A place was skipped or failed; try again when its host is back.
    pending: bool,
}

/// A clean-up done by passing deletions through the relay.
fn relay_prune(kept: usize, removed: usize, packs: usize, bytes: u64) -> PruneSummary {
    PruneSummary {
        time_unix: unix_now(),
        snapshots_kept: kept as u64,
        snapshots_removed: removed as u64,
        packs_deleted: packs as u64,
        packs_repacked: 0,
        bytes_deleted: bytes,
        bytes_downloaded: 0,
        bytes_uploaded: 0,
    }
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
    cancel: Arc<AtomicBool>,
}

impl Worker {
    /// Runs `f` on the repository in a blocking thread, opening it if needed.
    async fn with_repo<T: Send + 'static>(
        &mut self,
        f: impl FnOnce(&mut Repository<Box<dyn Backend>>) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let slot = self.repo.clone();
        let env = self.env.clone();
        let cancel = self.cancel.clone();
        // Tags what the repository and the network log with the set's name.
        let span = tracing::debug_span!("set", name = %self.env.set.name);
        tokio::task::spawn_blocking(move || {
            let _span = span.entered();
            // Held for the whole operation; see `SetHandle::stop`.
            let mut slot = slot.lock().unwrap_or_else(|e| e.into_inner());
            let repo = match &mut *slot {
                Some(r) => r,
                empty => {
                    let mut repo = env.open_repository()?;
                    repo.set_cancel(Some(cancel));
                    empty.insert(repo)
                }
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

    /// Runs `f` on an extra place's repository in a blocking thread.
    async fn with_extra<T: Send + 'static>(
        &self,
        id: String,
        f: impl FnOnce(&mut Repository<Box<dyn Backend>>) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let env = self.env.clone();
        let cancel = self.cancel.clone();
        let slot = self.repo.clone();
        let span = tracing::debug_span!("set", name = %self.env.set.name, place = %id);
        tokio::task::spawn_blocking(move || {
            let _span = span.entered();
            // Held so `SetHandle::stop` waits for this too.
            let _held = slot.lock().unwrap_or_else(|e| e.into_inner());
            let mut repo = env.open_place(Some(&id))?;
            repo.set_cancel(Some(cancel));
            f(&mut repo)
        })
        .await?
    }

    fn extra(&self, id: &str) -> Result<crate::config::ExtraTarget> {
        self.env
            .set
            .extra_target(id)
            .cloned()
            .with_context(|| format!("{} has no extra place {id:?}", self.env.set.name))
    }

    /// Prunes the main place (`None`) or an extra one with its own policy.
    async fn prune(&mut self, from: Option<String>) -> Result<PruneSummary> {
        let policy = match &from {
            None => self.env.set.retention,
            Some(id) => self.extra(id)?.retention,
        };
        set_state(&self.env, &self.status, SetState::Pruning);
        let mut progress = maintenance_reporter(&self.env);
        let prune = move |repo: &mut Repository<Box<dyn Backend>>| {
            Ok(repo.prune_with_progress(&policy, &mut progress)?)
        };
        let s = match from.clone() {
            None => self.with_repo(prune).await?,
            Some(id) => self.with_extra(id, prune).await?,
        };
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
        match &from {
            None => self.save_maintenance(|m| m.last_prune = Some(summary.clone())),
            Some(id) => self.save_extra(id, |e| e.last_prune = Some(summary.clone())),
        }
        tracing::info!(set = %self.env.set.name, place = ?from, removed = s.snapshots_removed, freed = s.bytes_deleted, "prune complete");
        Ok(summary)
    }

    async fn verify(&mut self, max_bytes: u64, from: Option<String>) -> Result<VerifySummary> {
        if let Some(id) = &from {
            self.extra(id)?;
        }
        set_state(&self.env, &self.status, SetState::Verifying);
        let mut progress = maintenance_reporter(&self.env);
        let verify = move |repo: &mut Repository<Box<dyn Backend>>| {
            Ok(repo.verify_with_progress(max_bytes, &mut progress)?)
        };
        let r = match from.clone() {
            None => self.with_repo(verify).await?,
            Some(id) => self.with_extra(id, verify).await?,
        };
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
        match &from {
            None => self.save_maintenance(|m| m.last_verify = Some(summary.clone())),
            Some(id) => self.save_extra(id, |e| e.last_verify = Some(summary.clone())),
        }
        if summary.ok {
            tracing::info!(set = %self.env.set.name, place = ?from, checked = r.bytes_checked, "verification passed");
        } else {
            tracing::warn!(set = %self.env.set.name, place = ?from, "verification found problems: {:?}", summary.errors);
        }
        Ok(summary)
    }

    fn save_extra(&self, id: &str, update: impl FnOnce(&mut ExtraState)) {
        let mut st = self.status.lock().unwrap();
        update(st.extras.entry(id.to_string()).or_default());
        if let Ok(json) = serde_json::to_string(&st.extras) {
            let _ = fs::write(self.env.extras_path(), json);
        }
        let _ = self.env.events.send(Event::SetsChanged);
    }

    /// Copies to each extra place the versions it keeps but doesn't have
    /// yet, then cleans up or checks there when due. Automatic runs skip
    /// places outside their time window or whose host is offline;
    /// `explicit` ones (asked for by the user) try them all.
    async fn copy_to_extras(&mut self, explicit: bool) -> ExtrasOutcome {
        let mut outcome = ExtrasOutcome::default();
        for t in self.env.set.extra_targets.clone() {
            // Orders for the relay can be sent any time; it keeps the
            // place's hours, and waits for it to be online.
            if !explicit
                && !t.relay
                && let Some(window) = t.window
            {
                let wait = window.until_open();
                if !wait.is_zero() {
                    tracing::debug!(set = %self.env.set.name, place = t.id, "outside its time window; copying in {}s", wait.as_secs());
                    outcome.wait = Some(outcome.wait.map_or(wait, |w| w.min(wait)));
                    continue;
                }
            }
            if !explicit
                && !t.relay
                && let Some(h) = host_of(&t.target)
                && self.env.hosts.is_offline(&h.id)
            {
                tracing::debug!(set = %self.env.set.name, place = t.id, "its host is offline; copying once it's back");
                outcome.pending = true;
                continue;
            }
            set_state(&self.env, &self.status, SetState::Copying);
            let copied = if t.relay {
                self.forward_to(&t).await
            } else {
                self.copy_to(&t).await
            };
            match copied {
                Ok(copied) => {
                    if let Some(c) = &copied {
                        tracing::info!(set = %self.env.set.name, place = t.id, versions = c.snapshots, bytes = c.bytes, "copied versions");
                    }
                    self.save_extra(&t.id, |e| {
                        if copied.is_some() {
                            e.last_copy = copied;
                        }
                        e.last_error = None;
                    });
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    tracing::warn!(set = %self.env.set.name, place = t.id, "copying failed: {msg}");
                    self.save_extra(&t.id, |e| e.last_error = Some(msg));
                    outcome.pending = true;
                    continue;
                }
            }
            let (pruned, verified, since) = {
                let st = self.status.lock().unwrap();
                let e = st.extras.get(&t.id).cloned().unwrap_or_default();
                (
                    e.last_prune.map_or(0, |p| p.time_unix),
                    e.last_verify.map_or(0, |v| v.time_unix),
                    e.since_unix,
                )
            };
            // Cleaning up and checking need to reach the place from here.
            if t.relay
                && host_of(&t.target).is_none_or(|h| self.env.hosts.get(&h.id).online != Some(true))
            {
                continue;
            }
            let now = unix_now();
            if now - pruned.max(since) >= PRUNE_INTERVAL_SECS
                && let Err(e) = self.prune(Some(t.id.clone())).await
            {
                tracing::warn!(set = %self.env.set.name, place = t.id, "prune failed: {e:#}");
                self.save_extra(&t.id, |s| {
                    s.last_error = Some(format!("cleaning up: {e:#}"))
                });
            }
            if now - verified.max(since) >= VERIFY_INTERVAL_SECS
                && let Err(e) = self.verify(VERIFY_BUDGET_BYTES, Some(t.id.clone())).await
            {
                tracing::warn!(set = %self.env.set.name, place = t.id, "verification failed to run: {e:#}");
            }
        }
        outcome
    }

    /// For a place copies are forwarded to: learns from the relay which
    /// orders it finished. Returns what was delivered since last time;
    /// fails if an order failed (it's planned again next time).
    async fn update_orders(
        &mut self,
        t: &crate::config::ExtraTarget,
    ) -> Result<Option<api::CopySummary>> {
        let relay = self.env.main_remote()?;
        let infos = relay.forward_status(&t.id).await?;
        let mut state = self.extra_state(&t.id);
        let mut delivered: Option<api::CopySummary> = None;
        let mut forget: Vec<String> = Vec::new();
        let mut failure: Option<String> = None;
        let mut progress = api::ForwardProgress::default();
        let mut pending = Vec::new();
        for order in std::mem::take(&mut state.orders) {
            match infos.iter().find(|i| i.id == order.id) {
                Some(i) if i.state == ForwardState::Done => {
                    if !order.snapshots.is_empty() {
                        let d = delivered.get_or_insert(api::CopySummary {
                            time_unix: i.updated_unix,
                            snapshot: String::new(),
                            snapshots: 0,
                            bytes: 0,
                        });
                        d.time_unix = d.time_unix.max(i.updated_unix);
                        d.snapshots += order.snapshots.len() as u64;
                        d.bytes += i.bytes_sent;
                        if let Some((newest, _)) = order.snapshots.last() {
                            d.snapshot = newest.clone();
                        }
                    }
                    state.delivered.extend(order.snapshots);
                    state
                        .delivered
                        .retain(|(id, _)| !order.deletes.contains(id));
                    forget.extend(order.dropped_packs);
                }
                Some(i) if i.state == ForwardState::Pending => {
                    progress.orders += 1;
                    progress.packs_sent += i.packs_sent;
                    progress.packs_total += i.packs_total;
                    progress.bytes_sent += i.bytes_sent;
                    if i.error.is_some() {
                        progress.note = i.error.clone();
                    }
                    pending.push(order);
                }
                found => {
                    failure = Some(match found.and_then(|i| i.error.clone()) {
                        Some(e) => format!("the relay couldn't deliver: {e}"),
                        None => "the relay lost track of copies it was sending".into(),
                    });
                    // Not there after all: forget them, so they're sent again.
                    forget.extend(order.packs);
                }
            }
        }
        state.orders = pending;
        state.forwarding = (progress.orders > 0).then_some(progress);
        if !forget.is_empty() {
            let path = self.env.set_dir.join(index_file(Some(&t.id)));
            let slot = self.repo.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                let _held = slot.lock().unwrap_or_else(|e| e.into_inner());
                let mut sent = Index::open(&path)?;
                for p in forget {
                    sent.remove_pack(&PackId::from_hex(&p)?)?;
                }
                Ok(())
            })
            .await??;
        }
        self.save_extra(&t.id, |e| *e = state);
        match failure {
            Some(failure) => bail!(failure),
            None => Ok(delivered),
        }
    }

    fn extra_state(&self, id: &str) -> ExtraState {
        self.status
            .lock()
            .unwrap()
            .extras
            .get(id)
            .cloned()
            .unwrap_or_default()
    }

    /// For a place copies are forwarded to: catches up with the relay, then
    /// orders the versions the place should get next, and, when it's due
    /// and the place can't be reached from here to clean it up directly,
    /// deletions of what it no longer keeps.
    async fn forward_to(
        &mut self,
        t: &crate::config::ExtraTarget,
    ) -> Result<Option<api::CopySummary>> {
        let delivered = self.update_orders(t).await?;
        let mut state = self.extra_state(&t.id);
        let held: Vec<(SnapshotId, i64)> = state
            .delivered
            .iter()
            .chain(state.orders.iter().flat_map(|o| &o.snapshots))
            .filter_map(|(id, time)| Some((SnapshotId::from_hex(id).ok()?, *time)))
            .collect();
        let reachable =
            host_of(&t.target).is_some_and(|h| self.env.hosts.get(&h.id).online == Some(true));
        let cleaning = state
            .orders
            .iter()
            .any(|o| !o.deletes.is_empty() || !o.dropped_packs.is_empty());
        let since = state
            .last_prune
            .as_ref()
            .map_or(0, |p| p.time_unix)
            .max(state.since_unix);
        let prune = !reachable && !cleaning && unix_now() - since >= PRUNE_INTERVAL_SECS;
        let delivered_ids: Vec<SnapshotId> = state
            .delivered
            .iter()
            .filter_map(|(id, _)| SnapshotId::from_hex(id).ok())
            .collect();

        let policy = t.retention;
        let index_path = self.env.set_dir.join(index_file(Some(&t.id)));
        let path = index_path.clone();
        let plan = self
            .with_repo(move |main| {
                let source = main.snapshot_times()?;
                let wanted = policy.to_copy(&source, &held);
                let mut sent = Index::open(&path)?;
                let packs = if wanted.is_empty() {
                    Vec::new()
                } else {
                    main.plan_copy(&mut sent, &wanted)?
                };
                let snapshots: Vec<(SnapshotId, i64)> = wanted
                    .iter()
                    .filter_map(|id| source.iter().find(|(s, _)| s == id).copied())
                    .collect();
                let mut cleanup = None;
                if prune {
                    // What the place keeps once the new versions are there.
                    let mut all = held.clone();
                    all.extend(snapshots.iter().copied());
                    let keep = policy.select(&all);
                    let drop: Vec<SnapshotId> = delivered_ids
                        .iter()
                        .filter(|id| !keep.contains(id))
                        .copied()
                        .collect();
                    let keep: Vec<SnapshotId> = keep.into_iter().collect();
                    // Without every kept version here to read, only drop versions.
                    let unused = main.unused_packs(&sent, &keep)?.unwrap_or_default();
                    let sizes = sent.pack_sizes()?;
                    let bytes = unused.iter().filter_map(|p| sizes.get(p)).sum::<u64>();
                    cleanup = Some((keep.len(), drop, unused, bytes));
                }
                Ok((snapshots, packs, cleanup))
            })
            .await?;
        let (snapshots, packs, cleanup) = plan;
        let (drop, unused) = match &cleanup {
            Some((_, drop, unused, _)) => (drop.clone(), unused.clone()),
            None => (Vec::new(), Vec::new()),
        };
        if snapshots.is_empty() && drop.is_empty() && unused.is_empty() {
            if let Some((kept, ..)) = cleanup {
                // Nothing to delete: cleaning up is done until it's due again.
                self.save_extra(&t.id, |e| e.last_prune = Some(relay_prune(kept, 0, 0, 0)));
            }
            return Ok(delivered);
        }

        let StoredTarget::Peer {
            id: host,
            repo,
            addrs,
            hosts,
        } = &t.target
        else {
            bail!("copies can only be forwarded to another computer");
        };
        let StoredTarget::Peer { id: relay_id, .. } = &self.env.set.target else {
            bail!("copies can only be forwarded when the main place is another computer");
        };
        let host_id = EndpointId::from_str(host)?;
        let owner = self.env.endpoint.secret_key();
        let expires = unix_now() + DELEGATION_SECS;
        let mut deletions = Vec::new();
        let objects: Vec<(Option<SnapshotId>, Option<PackId>)> = drop
            .iter()
            .map(|s| (Some(*s), None))
            .chain(unused.iter().map(|p| (None, Some(*p))))
            .collect();
        for batch in objects.chunks(Deletion::MAX_OBJECTS) {
            deletions.push(Deletion::sign(
                owner,
                host_id,
                repo,
                batch.iter().filter_map(|(s, _)| *s).collect(),
                batch.iter().filter_map(|(_, p)| *p).collect(),
                expires,
            ));
        }
        let order = ForwardOrder {
            id: hex::encode(kinvault_core::crypto::random_bytes::<8>()?),
            place: t.id.clone(),
            delegation: Delegation::sign(
                owner,
                EndpointId::from_str(relay_id)?,
                host_id,
                repo,
                expires,
            ),
            addrs: addrs.clone(),
            hosts: hosts.clone(),
            packs: packs.clone(),
            snapshots: snapshots.iter().map(|(id, _)| *id).collect(),
            upload_limit: t.upload_limit,
            window: t.window,
            deletions,
        };
        tracing::debug!(
            set = %self.env.set.name,
            place = t.id,
            versions = snapshots.len(),
            packs = packs.len(),
            deleting_versions = drop.len(),
            deleting_packs = unused.len(),
            "asking the relay to forward copies"
        );
        let relay = self.env.main_remote()?;
        if let Err(e) = relay.forward(&order).await {
            // Not ordered after all: forget the packs, so they're planned again.
            let slot = self.repo.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                let _held = slot.lock().unwrap_or_else(|e| e.into_inner());
                let mut sent = Index::open(&index_path)?;
                for p in &packs {
                    sent.remove_pack(p)?;
                }
                Ok(())
            })
            .await??;
            return Err(e.into());
        }
        let progress = state.forwarding.get_or_insert_with(Default::default);
        progress.orders += 1;
        progress.packs_total += packs.len() as u64;
        state.orders.push(OrderRecord {
            id: order.id,
            snapshots: snapshots
                .iter()
                .map(|(id, time)| (id.to_hex(), *time))
                .collect(),
            packs: packs.iter().map(|p| p.to_hex()).collect(),
            deletes: drop.iter().map(|s| s.to_hex()).collect(),
            dropped_packs: unused.iter().map(|p| p.to_hex()).collect(),
        });
        if let Some((kept, drop, unused, bytes)) = cleanup {
            state.last_prune = Some(relay_prune(kept, drop.len(), unused.len(), bytes));
        }
        self.save_extra(&t.id, |e| *e = state);
        Ok(delivered)
    }

    /// Asks the relay how open orders are going, for each place that has
    /// some. Returns whether any are still open.
    pub(crate) async fn refresh_forwarding(&mut self) -> bool {
        let mut open = false;
        for t in self.env.set.extra_targets.clone() {
            if !t.relay || self.extra_state(&t.id).orders.is_empty() {
                continue;
            }
            match self.update_orders(&t).await {
                Ok(copied) => self.save_extra(&t.id, |e| {
                    if copied.is_some() {
                        e.last_copy = copied;
                    }
                    e.last_error = None;
                }),
                Err(e) => {
                    tracing::debug!(set = %self.env.set.name, place = t.id, "couldn't check on forwarding: {e:#}");
                    let msg = format!("{e:#}");
                    if msg.contains("couldn't deliver") || msg.contains("lost track") {
                        self.save_extra(&t.id, |e| e.last_error = Some(msg));
                    }
                }
            }
            open |= !self.extra_state(&t.id).orders.is_empty();
        }
        open
    }

    /// Whether any place has orders the relay hasn't finished.
    fn forwarding_open(&self) -> bool {
        self.status
            .lock()
            .unwrap()
            .extras
            .values()
            .any(|e| !e.orders.is_empty())
    }

    /// While the main place's host is offline: backs up straight to each
    /// extra place that wants a new version now (by its own rules, hours
    /// and limits), so copies elsewhere don't fall behind meanwhile.
    async fn fallback_backup(&mut self, explicit: bool) {
        for t in self.env.set.extra_targets.clone() {
            if !explicit && t.window.is_some_and(|w| !w.is_open_now()) {
                continue;
            }
            if host_of(&t.target).is_some_and(|h| self.env.hosts.is_offline(&h.id)) {
                continue;
            }
            set_state(&self.env, &self.status, SetState::Running);
            match self.backup_to(&t).await {
                Ok(None) => {}
                Ok(Some((copy, time_ns))) => {
                    tracing::info!(
                        set = %self.env.set.name,
                        place = t.id,
                        uploaded = copy.bytes,
                        "backed up straight to an extra place while the main one is offline"
                    );
                    self.save_extra(&t.id, |e| {
                        // So the relay isn't asked for another one this period.
                        if t.relay {
                            e.delivered.push((copy.snapshot.clone(), time_ns));
                        }
                        e.last_copy = Some(copy);
                        e.last_error = None;
                    });
                }
                Err(e) => {
                    let msg = format!("backing up here while the main place is offline: {e:#}");
                    tracing::warn!(set = %self.env.set.name, place = t.id, "{msg}");
                    self.save_extra(&t.id, |e| e.last_error = Some(msg));
                }
            }
        }
    }

    /// Backs up straight to an extra place if it wants a new version now.
    /// Returns what was stored and the new version's time.
    async fn backup_to(
        &mut self,
        t: &crate::config::ExtraTarget,
    ) -> Result<Option<(api::CopySummary, i64)>> {
        let paths = self.env.set.paths.clone();
        let policy = t.retention;
        let progress = progress_reporter(&self.env);
        self.with_extra(t.id.clone(), move |repo| {
            let held = repo.snapshot_times()?;
            let now_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as i64;
            // Would a version taken now be one it keeps?
            if policy
                .to_copy(&[(SnapshotId([0; 32]), now_ns)], &held)
                .is_empty()
            {
                return Ok(None);
            }
            let previous = held.iter().max_by_key(|(_, t)| *t).map(|(id, _)| *id);
            let host = gethostname::gethostname().to_string_lossy().into_owned();
            repo.set_progress(Some(progress));
            let result = repo.backup_if_changed(&paths, &host, previous.as_ref());
            repo.set_progress(None);
            let (id, stats) = result?;
            if Some(id) == previous {
                return Ok(None);
            }
            Ok(Some((
                api::CopySummary {
                    time_unix: unix_now(),
                    snapshot: id.to_hex(),
                    snapshots: 1,
                    bytes: stats.bytes_uploaded,
                },
                now_ns,
            )))
        })
        .await
    }

    /// Copies to one extra place what it should have; `None` if nothing.
    async fn copy_to(
        &mut self,
        t: &crate::config::ExtraTarget,
    ) -> Result<Option<api::CopySummary>> {
        let env = self.env.clone();
        let cancel = self.cancel.clone();
        let id = t.id.clone();
        let policy = t.retention;
        let events = self.env.events.clone();
        let set = self.env.set.id.clone();
        self.with_repo(move |main| {
            let _span = tracing::debug_span!("copy", place = %id).entered();
            let mut dest = env.open_place(Some(&id))?;
            dest.set_cancel(Some(cancel));
            let held = dest.snapshot_times()?;
            let wanted = policy.to_copy(&main.snapshot_times()?, &held);
            let Some(newest) = wanted.last().copied() else {
                return Ok(None);
            };
            tracing::debug!(versions = wanted.len(), "copying versions");
            let mut last = std::time::Instant::now() - Duration::from_secs(1);
            let stats = main.copy_snapshots_to(&mut dest, &wanted, &mut |done, total| {
                if done == 0 || done == total || last.elapsed() >= Duration::from_millis(250) {
                    last = std::time::Instant::now();
                    let _ = events.send(Event::CopyProgress {
                        set: set.clone(),
                        target: id.clone(),
                        done,
                        total,
                    });
                }
            })?;
            Ok(Some(api::CopySummary {
                time_unix: unix_now(),
                snapshot: newest.to_hex(),
                snapshots: stats.snapshots,
                bytes: stats.bytes,
            }))
        })
        .await
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
            && let Err(e) = self.prune(None).await
        {
            tracing::warn!(set = %self.env.set.name, "prune failed: {e:#}");
        }
        if now - last_verify >= VERIFY_INTERVAL_SECS {
            match self.verify(VERIFY_BUDGET_BYTES, None).await {
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
    cancel: Arc<AtomicBool>,
    mut rx: mpsc::Receiver<Trigger>,
) {
    let debounce = Duration::from_secs(env.set.debounce_secs);
    let rescan = Duration::from_secs(env.set.rescan_secs);
    let paused = env.set.paused;
    let host = env.host();
    // Hosts of extra places: one coming back may have copies waiting.
    let extra_hosts: Vec<String> = env
        .set
        .extra_targets
        .iter()
        .filter_map(|t| host_of(&t.target).map(|h| h.id))
        .collect();
    let mut extras_pending = false;
    let mut host_events = env.events.subscribe();
    let mut worker = Worker {
        env,
        status: status.clone(),
        repo,
        cancel,
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
    // While the relay has open orders, ask it now and then how they're going.
    let mut forward_check = worker
        .forwarding_open()
        .then(|| Instant::now() + FORWARD_POLL);

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
                    if change_deadline.is_none() {
                        tracing::debug!(
                            set = %worker.env.set.name,
                            "files changed; backing up after {}s without further changes",
                            debounce.as_secs()
                        );
                    }
                    let now = Instant::now();
                    let first = *first_change.get_or_insert(now);
                    change_deadline = Some((now + debounce).min(first + MAX_CHANGE_DELAY));
                    false
                }
                Some(Trigger::Now(reply)) => {
                    waiters.push(reply);
                    true
                }
                Some(Trigger::Prune(from, reply)) => {
                    let _ = reply.send(worker.prune(from).await.map_err(|e| format!("{e:#}")));
                    false
                }
                Some(Trigger::Verify(max_bytes, from, reply)) => {
                    let result = worker.verify(max_bytes, from).await;
                    // Damaged data was removed; the next run puts it back
                    // (backing up for the main place, copying for others).
                    if matches!(&result, Ok(v) if !v.ok) && !paused {
                        scheduled = Instant::now();
                    }
                    let _ = reply.send(result.map_err(|e| format!("{e:#}")));
                    false
                }
            },
            ev = host_events.recv(), if host.is_some() || !extra_hosts.is_empty() => {
                let id = host.as_ref().map(|h| h.id.as_str()).unwrap_or_default();
                let (back, extra_back) = match ev {
                    Ok(Event::PeerOnline { id: peer, online }) => {
                        (online && peer == id, online && extra_hosts.contains(&peer))
                    }
                    // Missed events; one may have come back meanwhile.
                    Err(broadcast::error::RecvError::Lagged(_)) => (
                        host.is_some() && !worker.env.hosts.is_offline(id),
                        extra_hosts.iter().any(|h| !worker.env.hosts.is_offline(h)),
                    ),
                    _ => (false, false),
                };
                // Back up (and copy) now rather than at the next retry.
                if back && (waiting_for_host || failures > 0) && !paused {
                    waiting_for_host = false;
                    scheduled = Instant::now();
                }
                if extra_back && extras_pending && !paused && !waiting_for_host {
                    scheduled = Instant::now();
                }
                false
            }
            _ = tokio::time::sleep_until(forward_check.unwrap_or(far)), if forward_check.is_some() => {
                forward_check = worker
                    .refresh_forwarding()
                    .await
                    .then(|| Instant::now() + FORWARD_POLL);
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
                tracing::debug!(
                    set = %worker.env.set.name,
                    "outside the backup window {window}; waiting {}s for it to open",
                    wait.as_secs()
                );
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
            tracing::debug!(
                set = %worker.env.set.name,
                "the backup host is offline; waiting for it to come back"
            );
            waiting_for_host = true;
            scheduled = Instant::now() + MAX_RETRY_DELAY;
            if !paused && !worker.env.set.extra_targets.is_empty() {
                worker.fallback_backup(false).await;
            }
            continue;
        }
        waiting_for_host = false;
        set_state(&worker.env, &status, SetState::Running);
        tracing::debug!(
            set = %worker.env.set.name,
            paths = ?worker.env.set.paths,
            "backup started"
        );

        // Asked for by the user: copies go out even outside their windows.
        let explicit = !waiters.is_empty();
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
                if !worker.env.set.extra_targets.is_empty() {
                    let outcome = worker.copy_to_extras(explicit).await;
                    forward_check = worker
                        .forwarding_open()
                        .then(|| Instant::now() + FORWARD_POLL);
                    extras_pending = outcome.pending;
                    if let Some(wait) = outcome.wait
                        && !paused
                    {
                        scheduled = scheduled.min(Instant::now() + wait);
                    }
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
                    if !worker.env.set.extra_targets.is_empty() && (!paused || explicit) {
                        worker.fallback_backup(explicit).await;
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
