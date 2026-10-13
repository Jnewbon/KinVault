//! Restores that run in the background, so clients aren't left waiting on a
//! long request: they get progress events and a final result instead.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, ensure};

use super::{Daemon, blocking};
use crate::api::{Event, Reply, RestoreJob, RestoreSummary};

/// Progress events are sent at most this often per restore.
const PROGRESS_EVERY: Duration = Duration::from_millis(250);

pub(super) struct Running {
    job: RestoreJob,
    cancel: Arc<AtomicBool>,
}

impl Daemon {
    pub(super) async fn start_restore(
        &self,
        set: &str,
        snapshot: String,
        target: PathBuf,
        include: Option<String>,
    ) -> Result<Reply> {
        ensure!(
            !target.as_os_str().is_empty(),
            "choose a folder to restore into"
        );
        let env = self.find_readable_set(set).await?;
        let id = hex::encode(kinvault_core::crypto::random_bytes::<4>()?);
        let job = RestoreJob {
            id: id.clone(),
            set: env.set.id.clone(),
            set_name: env.set.name.clone(),
            snapshot: snapshot.clone(),
            target: target.clone(),
            files: 0,
            bytes: 0,
            total_files: 0,
            total_bytes: 0,
        };
        let cancel = Arc::new(AtomicBool::new(false));
        self.inner.restores.lock().unwrap().push(Running {
            job: job.clone(),
            cancel: cancel.clone(),
        });
        self.notify(Event::RestoreProgress(job.clone()));
        tracing::info!(set = job.set_name, target = %target.display(), "restore started");

        let daemon = self.clone();
        tokio::spawn(async move {
            let progress = daemon.clone();
            let job_id = job.id.clone();
            let result = blocking(move || {
                let mut repo = env.open_repository()?;
                let snapshot = repo.find_snapshot(&snapshot)?;
                let mut last_sent: Option<Instant> = None;
                Ok(repo.restore_with_progress(
                    &snapshot,
                    &target,
                    include.as_deref(),
                    &mut |p| {
                        if cancel.load(Ordering::Relaxed) {
                            return false;
                        }
                        if last_sent.is_none_or(|t| t.elapsed() >= PROGRESS_EVERY) {
                            last_sent = Some(Instant::now());
                            progress.restore_progressed(&job_id, p);
                        }
                        true
                    },
                )?)
            })
            .await;
            daemon
                .inner
                .restores
                .lock()
                .unwrap()
                .retain(|r| r.job.id != job.id);
            let event = match result {
                Ok(stats) => {
                    tracing::info!(set = job.set_name, files = stats.files, "restore finished");
                    Event::RestoreFinished {
                        id: job.id,
                        set: job.set,
                        summary: RestoreSummary {
                            files: stats.files,
                            dirs: stats.dirs,
                            symlinks: stats.symlinks,
                            bytes: stats.bytes,
                        },
                    }
                }
                Err(e) => {
                    let cancelled = matches!(
                        e.downcast_ref::<kinvault_core::Error>(),
                        Some(kinvault_core::Error::Cancelled)
                    );
                    if cancelled {
                        tracing::info!(set = job.set_name, "restore cancelled");
                    } else {
                        tracing::warn!(set = job.set_name, "restore failed: {e:#}");
                    }
                    Event::RestoreFailed {
                        id: job.id,
                        set: job.set,
                        error: format!("{e:#}"),
                        cancelled,
                    }
                }
            };
            daemon.notify(event);
        });
        Ok(Reply::RestoreStarted { id })
    }

    fn restore_progressed(&self, id: &str, p: &kinvault_core::RestoreProgress) {
        let job = {
            let mut restores = self.inner.restores.lock().unwrap();
            let Some(r) = restores.iter_mut().find(|r| r.job.id == id) else {
                return;
            };
            r.job.files = p.files;
            r.job.bytes = p.bytes;
            r.job.total_files = p.total_files;
            r.job.total_bytes = p.total_bytes;
            r.job.clone()
        };
        self.notify(Event::RestoreProgress(job));
    }

    pub(super) fn cancel_restore(&self, id: &str) -> Result<Reply> {
        let restores = self.inner.restores.lock().unwrap();
        let r = restores
            .iter()
            .find(|r| r.job.id == id)
            .ok_or_else(|| anyhow!("no restore {id:?} is running"))?;
        r.cancel.store(true, Ordering::Relaxed);
        Ok(Reply::Done)
    }

    pub(super) fn restore_jobs(&self) -> Vec<RestoreJob> {
        let restores = self.inner.restores.lock().unwrap();
        restores.iter().map(|r| r.job.clone()).collect()
    }

    /// Whether a background restore from this set is running.
    pub(super) fn restoring(&self, set_id: &str) -> bool {
        let restores = self.inner.restores.lock().unwrap();
        restores.iter().any(|r| r.job.set == set_id)
    }

    /// Asks every running restore to stop (e.g. when shutting down).
    pub(super) fn cancel_all_restores(&self) {
        for r in self.inner.restores.lock().unwrap().iter() {
            r.cancel.store(true, Ordering::Relaxed);
        }
    }
}
