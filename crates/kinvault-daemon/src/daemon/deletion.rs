//! Deleting a backup set for good. The set's key is erased at once; its
//! backups are erased a week later, by the host they're stored on or, for a
//! local folder, by this daemon. A host that can't be reached doesn't stop the
//! deletion: it is asked again until it answers or a month has passed.

use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use kinvault_net::{NetError, REPO_DELETE_DELAY, RemoteBackend};

use super::{Daemon, unix_now};
use crate::api::{DeletedSet, Reply};
use crate::config::{PendingDeletion, StoredTarget};
use crate::worker::peer_addr;

/// How often hosts that couldn't be reached are asked again.
pub(super) const RETRY_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Give up on a host that hasn't answered (or a folder that hasn't been
/// reachable) for this long.
const GIVE_UP_SECS: i64 = 30 * 24 * 60 * 60;
/// How long to wait for a host while the user waits, and in the background.
const ASK_NOW_TIMEOUT: Duration = Duration::from_secs(10);
const ASK_TIMEOUT: Duration = Duration::from_secs(30);

/// How far erasing a deleted set's backups got.
struct Progress {
    /// Nothing more to do (erased, scheduled with the host, or given up).
    finished: bool,
    erase_after_unix: Option<i64>,
    error: Option<String>,
}

impl Daemon {
    pub(super) async fn delete_set(&self, key: &str) -> Result<Reply> {
        let set = self.find_set(key).await?.set;
        let now = unix_now();
        let pending = PendingDeletion {
            set_id: set.id.clone(),
            set_name: set.name.clone(),
            erase_after_unix: matches!(set.target, StoredTarget::Local { .. })
                .then(|| now + REPO_DELETE_DELAY.as_secs() as i64),
            target: set.target,
            requested_unix: now,
        };
        let mut config = self.inner.config.lock().await;
        config.sets.retain(|s| s.id != set.id);
        config.pending_deletions.push(pending.clone());
        config.save(&self.config_path())?;
        drop(config);
        if let Some(handle) = self.inner.sets.lock().await.remove(&set.id) {
            handle.stop();
        }
        // Without its key, nothing backed up can be read any more.
        match fs::remove_dir_all(self.set_dir(&set.id)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        tracing::info!(set = set.name, "deleted backup set");

        let progress = self.erase(&pending, ASK_NOW_TIMEOUT).await;
        if progress.finished {
            self.forget_deletion(&pending.set_id).await?;
        }
        Ok(Reply::SetDeleted(DeletedSet {
            erase_after_unix: progress.erase_after_unix,
            retrying: !progress.finished && progress.error.is_some(),
            error: progress.error,
        }))
    }

    /// Works through deleted sets whose backups still need erasing.
    pub(super) async fn process_deletions(&self) -> Result<()> {
        let pending = self.inner.config.lock().await.pending_deletions.clone();
        // At once, so a host that doesn't answer doesn't hold up the others.
        let mut tasks = tokio::task::JoinSet::new();
        for p in pending {
            let daemon = self.clone();
            tasks.spawn(async move {
                daemon
                    .erase(&p, ASK_TIMEOUT)
                    .await
                    .finished
                    .then_some(p.set_id)
            });
        }
        while let Some(done) = tasks.join_next().await {
            if let Some(set_id) = done? {
                self.forget_deletion(&set_id).await?;
            }
        }
        Ok(())
    }

    async fn forget_deletion(&self, set_id: &str) -> Result<()> {
        let mut config = self.inner.config.lock().await;
        config.pending_deletions.retain(|p| p.set_id != set_id);
        config.save(&self.config_path())
    }

    async fn erase(&self, p: &PendingDeletion, timeout: Duration) -> Progress {
        let now = unix_now();
        match &p.target {
            StoredTarget::Peer {
                id,
                repo,
                addrs,
                hosts,
            } => {
                let ask = async {
                    let remote = RemoteBackend::new(
                        self.inner.endpoint.clone(),
                        peer_addr(id, addrs).map_err(|e| NetError::Protocol(e.to_string()))?,
                        repo,
                        self.inner.runtime.clone(),
                    )?
                    .with_hosts(hosts.clone());
                    remote.delete_repo().await
                };
                let result = tokio::time::timeout(timeout, ask)
                    .await
                    .unwrap_or_else(|_| Err(NetError::Transport("no answer".into())));
                match result {
                    Ok(erase_after_unix) => {
                        tracing::info!(
                            set = p.set_name,
                            "host will erase the deleted set's backups"
                        );
                        Progress {
                            finished: true,
                            erase_after_unix: Some(erase_after_unix),
                            error: None,
                        }
                    }
                    // Offline or gone: ask again later, for a while.
                    Err(NetError::Transport(e)) => {
                        let give_up = now - p.requested_unix > GIVE_UP_SECS;
                        if give_up {
                            tracing::warn!(
                                set = p.set_name,
                                "gave up asking the host to erase a deleted set: {e}"
                            );
                        }
                        Progress {
                            finished: give_up,
                            erase_after_unix: None,
                            error: Some(e),
                        }
                    }
                    // The host no longer stores our backups (or refuses): nothing to ask.
                    Err(e) => {
                        tracing::warn!(set = p.set_name, "host didn't erase a deleted set: {e}");
                        Progress {
                            finished: true,
                            erase_after_unix: None,
                            error: Some(e.to_string()),
                        }
                    }
                }
            }
            StoredTarget::Local { path } => {
                let due = p.erase_after_unix.unwrap_or(p.requested_unix);
                if now < due {
                    return Progress {
                        finished: false,
                        erase_after_unix: Some(due),
                        error: None,
                    };
                }
                match erase_local(path) {
                    Ok(()) => {
                        tracing::info!(set = p.set_name, "erased a deleted set's backup folder");
                        Progress {
                            finished: true,
                            erase_after_unix: Some(due),
                            error: None,
                        }
                    }
                    // E.g. an external drive that isn't plugged in.
                    Err(e) => Progress {
                        finished: now - due > GIVE_UP_SECS,
                        erase_after_unix: Some(due),
                        error: Some(format!("couldn't erase {}: {e}", path.display())),
                    },
                }
            }
        }
    }
}

/// Erases the repository in a backup folder, leaving anything else there.
fn erase_local(path: &Path) -> io::Result<()> {
    if !path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the folder isn't there",
        ));
    }
    for dir in ["packs", "snapshots", "trash"] {
        match fs::remove_dir_all(path.join(dir)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
}
