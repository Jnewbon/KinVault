//! One task per backup set: watches the sources, waits for changes to
//! settle, then runs an incremental backup. Also rescans periodically (to
//! catch anything the watcher missed) and retries with backoff on failure.

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use kinvault_core::{Backend, Index, LocalDirBackend, MasterKey, Repository};
use kinvault_net::{Endpoint, EndpointAddr, EndpointId, RemoteBackend};
use notify::event::{AccessKind, AccessMode};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::api::{BackupSummary, SetState};
use crate::config::{SetConfig, StoredTarget, write_private};

/// A burst of changes never delays a backup by more than this.
const MAX_CHANGE_DELAY: Duration = Duration::from_secs(10 * 60);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30 * 60);

pub(crate) type BackupReply = oneshot::Sender<Result<BackupSummary, String>>;

pub(crate) enum Trigger {
    Changed,
    Now(BackupReply),
}

#[derive(Clone, Debug)]
pub(crate) struct RunStatus {
    pub state: SetState,
    pub last_backup: Option<BackupSummary>,
    pub last_error: Option<String>,
}

/// Everything needed to open a set's repository.
#[derive(Clone)]
pub(crate) struct SetEnv {
    pub set: SetConfig,
    pub set_dir: PathBuf,
    pub endpoint: Endpoint,
    pub runtime: Handle,
    pub excludes: Vec<PathBuf>,
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

pub(crate) fn peer_addr(id: &str, addrs: &[std::net::SocketAddr]) -> Result<EndpointAddr> {
    let id = EndpointId::from_str(id).with_context(|| format!("invalid peer id {id:?}"))?;
    Ok(addrs
        .iter()
        .fold(EndpointAddr::new(id), |a, s| a.with_ip_addr(*s)))
}

impl SetEnv {
    /// Opens the set's repository. Blocking; call from a blocking context.
    pub fn open_repository(&self) -> Result<Repository<Box<dyn Backend>>> {
        let text = fs::read_to_string(master_key_path(&self.set_dir)).context("reading set key")?;
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(text.trim(), &mut bytes).context("set key is corrupt")?;
        let master = MasterKey::from_bytes(bytes);
        let backend: Box<dyn Backend> = match &self.set.target {
            StoredTarget::Local { path } => Box::new(LocalDirBackend::open(path)?),
            StoredTarget::Peer { id, repo, addrs } => Box::new(
                RemoteBackend::new(
                    self.endpoint.clone(),
                    peer_addr(id, addrs)?,
                    repo,
                    self.runtime.clone(),
                )?
                .with_upload_limit(self.set.upload_limit),
            ),
        };
        let index = Index::open(&self.set_dir.join("index.db"))?;
        let mut repo = Repository::open(backend, &master, index);
        repo.set_excludes(self.excludes.clone());
        Ok(repo)
    }

    fn last_backup_path(&self) -> PathBuf {
        self.set_dir.join("last_backup.json")
    }
}

pub(crate) struct SetHandle {
    pub env: SetEnv,
    pub status: Arc<Mutex<RunStatus>>,
    pub tx: mpsc::Sender<Trigger>,
    task: JoinHandle<()>,
    _watcher: Option<RecommendedWatcher>,
}

impl SetHandle {
    pub fn start(env: SetEnv) -> Self {
        let last_backup = fs::read_to_string(env.last_backup_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok());
        let status = Arc::new(Mutex::new(RunStatus {
            state: SetState::Idle,
            last_backup,
            last_error: None,
        }));
        let (tx, rx) = mpsc::channel(64);
        let watcher = start_watcher(&env, tx.clone());
        let task = tokio::spawn(run(env.clone(), status.clone(), rx));
        Self {
            env,
            status,
            tx,
            task,
            _watcher: watcher,
        }
    }

    pub fn stop(self) {
        self.task.abort();
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
    let handler = move |res: notify::Result<notify::Event>| {
        let relevant = match res {
            Ok(ev) => {
                is_change(&ev.kind)
                    && !ev
                        .paths
                        .iter()
                        .all(|p| excludes.iter().any(|e| p.starts_with(e)))
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

fn retry_delay(failures: u32) -> Duration {
    Duration::from_secs(60)
        .saturating_mul(1 << failures.saturating_sub(1).min(10))
        .min(MAX_RETRY_DELAY)
}

async fn run(env: SetEnv, status: Arc<Mutex<RunStatus>>, mut rx: mpsc::Receiver<Trigger>) {
    let debounce = Duration::from_secs(env.set.debounce_secs);
    let rescan = Duration::from_secs(env.set.rescan_secs);
    let mut repo = None;
    let mut waiters: Vec<BackupReply> = Vec::new();
    let mut failures = 0u32;
    // Back up right away to pick up changes made while the daemon was stopped.
    let mut scheduled = Instant::now();
    let mut change_deadline: Option<Instant> = None;
    let mut first_change: Option<Instant> = None;
    let mut waiting_for_window = false;

    loop {
        status.lock().unwrap().state = if change_deadline.is_some() {
            SetState::ChangesPending
        } else if waiting_for_window {
            SetState::WaitingForWindow
        } else {
            SetState::Idle
        };
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
            },
            _ = tokio::time::sleep_until(next) => true,
        };
        if !run_now {
            continue;
        }
        change_deadline = None;
        first_change = None;
        // Automatic runs wait for the window; explicit requests don't.
        if waiters.is_empty()
            && let Some(window) = env.set.window
        {
            let wait = window.until_open();
            if !wait.is_zero() {
                waiting_for_window = true;
                scheduled = Instant::now() + wait;
                continue;
            }
        }
        waiting_for_window = false;
        status.lock().unwrap().state = SetState::Running;

        let result = backup(&env, &mut repo).await;
        let mut st = status.lock().unwrap();
        match result {
            Ok(summary) => {
                failures = 0;
                scheduled = Instant::now() + rescan;
                tracing::info!(
                    set = %env.set.name,
                    snapshot = %&summary.snapshot[..16],
                    changed = summary.files_changed,
                    uploaded = summary.bytes_uploaded,
                    "backup complete"
                );
                if let Ok(json) = serde_json::to_string(&summary) {
                    let _ = fs::write(env.last_backup_path(), json);
                }
                st.last_backup = Some(summary.clone());
                st.last_error = None;
                for w in waiters.drain(..) {
                    let _ = w.send(Ok(summary.clone()));
                }
            }
            Err(e) => {
                failures += 1;
                let delay = retry_delay(failures);
                scheduled = Instant::now() + delay;
                let msg = format!("{e:#}");
                tracing::warn!(set = %env.set.name, "backup failed (retrying in {}s): {msg}", delay.as_secs());
                st.last_error = Some(msg.clone());
                for w in waiters.drain(..) {
                    let _ = w.send(Err(msg.clone()));
                }
            }
        }
    }
}

async fn backup(
    env: &SetEnv,
    slot: &mut Option<Repository<Box<dyn Backend>>>,
) -> Result<BackupSummary> {
    let existing = slot.take();
    let env2 = env.clone();
    let (repo, result) = tokio::task::spawn_blocking(move || {
        let mut repo = match existing {
            Some(r) => r,
            None => match env2.open_repository() {
                Ok(r) => r,
                Err(e) => return (None, Err(e)),
            },
        };
        let host = gethostname::gethostname().to_string_lossy().into_owned();
        let result = repo
            .backup(&env2.set.paths, &host)
            .map_err(anyhow::Error::from);
        (Some(repo), result)
    })
    .await?;
    *slot = repo;
    let (id, stats) = result?;
    Ok(BackupSummary {
        snapshot: id.to_hex(),
        time_ns: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        files: stats.files,
        files_changed: stats.files_changed,
        total_bytes: stats.total_bytes,
        bytes_uploaded: stats.bytes_uploaded,
        warnings: stats.warnings,
    })
}
