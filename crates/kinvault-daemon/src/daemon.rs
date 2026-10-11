use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail, ensure};
use kinvault_core::{KeyFile, LocalDirBackend, MasterKey};
use kinvault_net::{Endpoint, EndpointId, Grant, Receiver, RemoteBackend};
use tokio::runtime::Handle;
use tokio::sync::{Mutex, oneshot};

use crate::api::{self, Reply, Request};
use crate::config::{Config, PeerEntry, SetConfig, StoredTarget};
use crate::worker::{SetEnv, SetHandle, Trigger, peer_addr, write_master_key};

const DEFAULT_DEBOUNCE_SECS: u64 = 30;
const DEFAULT_RESCAN_SECS: u64 = 6 * 60 * 60;

pub struct DaemonOptions {
    pub state_dir: PathBuf,
    /// Use this endpoint instead of binding one from the stored identity
    /// (tests use local-only endpoints).
    pub endpoint: Option<Endpoint>,
}

#[derive(Clone)]
pub struct Daemon {
    inner: Arc<Inner>,
}

struct Inner {
    state_dir: PathBuf,
    endpoint: Endpoint,
    router: kinvault_net::Router,
    receiver: Receiver,
    hosting_store: PathBuf,
    runtime: Handle,
    // Lock order: config, then sets.
    config: Mutex<Config>,
    sets: Mutex<HashMap<String, SetHandle>>,
}

impl Daemon {
    pub async fn start(opts: DaemonOptions) -> Result<Self> {
        let state_dir = opts.state_dir;
        create_private_dir(&state_dir)?;
        let config = Config::load(&state_dir.join("config.json"))?;
        let endpoint = match opts.endpoint {
            Some(ep) => ep,
            None => {
                let secret = kinvault_net::load_or_create_secret(&state_dir.join("identity.key"))?;
                kinvault_net::bind(secret).await?
            }
        };

        let hosting_store = config
            .hosting_store
            .clone()
            .unwrap_or_else(|| state_dir.join("hosted"));
        fs::create_dir_all(&hosting_store)?;
        let receiver = Receiver::new(&hosting_store);
        for peer in &config.peers {
            match EndpointId::from_str(&peer.id) {
                Ok(id) => receiver.allow(
                    id,
                    Grant {
                        quota_bytes: peer.quota_bytes,
                    },
                ),
                Err(e) => tracing::warn!("ignoring invalid peer id {:?}: {e}", peer.id),
            }
        }
        let router = kinvault_net::serve(endpoint.clone(), receiver.clone());

        let daemon = Self {
            inner: Arc::new(Inner {
                state_dir,
                endpoint,
                router,
                receiver,
                hosting_store,
                runtime: Handle::current(),
                sets: Mutex::new(HashMap::new()),
                config: Mutex::new(config.clone()),
            }),
        };
        let mut sets = daemon.inner.sets.lock().await;
        for set in config.sets {
            sets.insert(set.id.clone(), SetHandle::start(daemon.set_env(set)));
        }
        drop(sets);
        Ok(daemon)
    }

    pub fn id(&self) -> EndpointId {
        self.inner.endpoint.id()
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.inner.endpoint
    }

    pub async fn shutdown(&self) {
        for (_, set) in self.inner.sets.lock().await.drain() {
            set.stop();
        }
        if let Err(e) = self.inner.router.shutdown().await {
            tracing::warn!("error shutting down network: {e}");
        }
    }

    fn config_path(&self) -> PathBuf {
        self.inner.state_dir.join("config.json")
    }

    fn set_dir(&self, id: &str) -> PathBuf {
        self.inner.state_dir.join("sets").join(id)
    }

    fn set_env(&self, set: SetConfig) -> SetEnv {
        // Never back up our own state or other people's hosted data.
        let excludes = [&self.inner.state_dir, &self.inner.hosting_store]
            .iter()
            .filter_map(|p| fs::canonicalize(p).ok())
            .collect();
        SetEnv {
            set_dir: self.set_dir(&set.id),
            set,
            endpoint: self.inner.endpoint.clone(),
            runtime: self.inner.runtime.clone(),
            excludes,
        }
    }

    /// Finds a set by id or name.
    async fn find_set(&self, key: &str) -> Result<SetEnv> {
        let sets = self.inner.sets.lock().await;
        sets.get(key)
            .or_else(|| sets.values().find(|s| s.env.set.name == key))
            .map(|s| s.env.clone())
            .ok_or_else(|| anyhow!("no backup set named {key:?}"))
    }

    pub async fn handle(&self, req: Request) -> Result<Reply, String> {
        self.dispatch(req).await.map_err(|e| format!("{e:#}"))
    }

    async fn dispatch(&self, req: Request) -> Result<Reply> {
        match req {
            Request::Status => self.status().await,
            Request::CreateSet(create) => self.create_set(create).await,
            Request::RemoveSet { set } => self.remove_set(&set).await,
            Request::BackupNow { set } => {
                let env = self.find_set(&set).await?;
                let tx = self
                    .inner
                    .sets
                    .lock()
                    .await
                    .get(&env.set.id)
                    .map(|s| s.tx.clone());
                let tx = tx.ok_or_else(|| anyhow!("set was removed"))?;
                let (reply, wait) = oneshot::channel();
                tx.send(Trigger::Now(reply))
                    .await
                    .map_err(|_| anyhow!("set was removed"))?;
                let summary = wait.await.map_err(|_| anyhow!("set was removed"))?;
                Ok(Reply::Backup(summary.map_err(|e| anyhow!(e))?))
            }
            Request::ListSnapshots { set } => {
                let env = self.find_set(&set).await?;
                let snapshots =
                    blocking(move || Ok(env.open_repository()?.list_snapshots()?)).await?;
                Ok(Reply::Snapshots(
                    snapshots
                        .into_iter()
                        .map(|(id, s)| api::SnapshotInfo {
                            id: id.to_hex(),
                            time_ns: s.time_ns,
                            hostname: s.hostname,
                            paths: s.paths,
                            file_count: s.file_count,
                            total_bytes: s.total_bytes,
                        })
                        .collect(),
                ))
            }
            Request::Restore {
                set,
                snapshot,
                target,
                include,
            } => {
                let env = self.find_set(&set).await?;
                let stats = blocking(move || {
                    let mut repo = env.open_repository()?;
                    let id = repo.find_snapshot(&snapshot)?;
                    Ok(repo.restore(&id, &target, include.as_deref())?)
                })
                .await?;
                Ok(Reply::Restored(api::RestoreSummary {
                    files: stats.files,
                    dirs: stats.dirs,
                    symlinks: stats.symlinks,
                    bytes: stats.bytes,
                }))
            }
            Request::RemoteUsage { set } => {
                let env = self.find_set(&set).await?;
                let StoredTarget::Peer { id, repo, addrs } = &env.set.target else {
                    bail!("set {:?} is stored locally, not on a peer", env.set.name);
                };
                let remote = RemoteBackend::new(
                    env.endpoint.clone(),
                    peer_addr(id, addrs)?,
                    repo,
                    env.runtime.clone(),
                )?;
                let status = remote.status().await?;
                Ok(Reply::Usage {
                    used_bytes: status.used_bytes,
                    quota_bytes: status.quota_bytes,
                })
            }
            Request::PeerAllow {
                id,
                name,
                quota_bytes,
            } => {
                let peer =
                    EndpointId::from_str(&id).with_context(|| format!("invalid peer id {id:?}"))?;
                ensure!(peer != self.id(), "that is this instance's own id");
                let mut config = self.inner.config.lock().await;
                config.peers.retain(|p| p.id != id);
                config.peers.push(PeerEntry {
                    id,
                    name,
                    quota_bytes,
                });
                config.save(&self.config_path())?;
                self.inner.receiver.allow(peer, Grant { quota_bytes });
                Ok(Reply::Done)
            }
            Request::PeerRevoke { id } => {
                let peer =
                    EndpointId::from_str(&id).with_context(|| format!("invalid peer id {id:?}"))?;
                let mut config = self.inner.config.lock().await;
                let before = config.peers.len();
                config.peers.retain(|p| p.id != id);
                ensure!(config.peers.len() < before, "{id} is not an allowed peer");
                config.save(&self.config_path())?;
                self.inner.receiver.revoke(&peer);
                Ok(Reply::Done)
            }
            Request::PeerList => {
                let peers = self.inner.config.lock().await.peers.clone();
                let mut out = Vec::with_capacity(peers.len());
                for p in peers {
                    let used_bytes = match EndpointId::from_str(&p.id) {
                        Ok(id) => self.inner.receiver.usage(&id).await.unwrap_or(0),
                        Err(_) => 0,
                    };
                    out.push(api::PeerInfo {
                        id: p.id,
                        name: p.name,
                        quota_bytes: p.quota_bytes,
                        used_bytes,
                    });
                }
                Ok(Reply::Peers(out))
            }
        }
    }

    async fn status(&self) -> Result<Reply> {
        let sets = self.inner.sets.lock().await;
        let mut out: Vec<api::SetStatus> = sets
            .values()
            .map(|h| {
                let st = h.status.lock().unwrap().clone();
                api::SetStatus {
                    id: h.env.set.id.clone(),
                    name: h.env.set.name.clone(),
                    paths: h.env.set.paths.clone(),
                    target: h.env.set.target.to_api(),
                    state: st.state,
                    last_backup: st.last_backup,
                    last_error: st.last_error,
                }
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Reply::Status(api::DaemonStatus {
            id: self.id().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            hosting_store: self.inner.hosting_store.clone(),
            sets: out,
        }))
    }

    async fn create_set(&self, req: api::CreateSet) -> Result<Reply> {
        let name = req.name.trim().to_string();
        ensure!(!name.is_empty(), "set name must not be empty");
        ensure!(
            !req.paths.is_empty(),
            "choose at least one file or folder to back up"
        );
        ensure!(
            req.recovery_passphrase.chars().count() >= 8,
            "recovery passphrase must be at least 8 characters"
        );
        let paths = req
            .paths
            .iter()
            .map(|p| fs::canonicalize(p).with_context(|| format!("cannot back up {}", p.display())))
            .collect::<Result<Vec<_>>>()?;
        let target = match req.target {
            api::Target::Local { path } => {
                LocalDirBackend::create(&path)?;
                StoredTarget::Local {
                    path: fs::canonicalize(&path)?,
                }
            }
            api::Target::Peer { id, addrs } => {
                let peer = peer_addr(&id, &addrs)?;
                ensure!(
                    peer.id != self.id(),
                    "a set can't be stored on this same instance"
                );
                let repo = hex::encode(kinvault_core::crypto::random_bytes::<12>()?);
                StoredTarget::Peer { id, repo, addrs }
            }
        };

        let mut config = self.inner.config.lock().await;
        ensure!(
            !config.sets.iter().any(|s| s.name == name),
            "a set named {name:?} already exists"
        );
        let set = SetConfig {
            id: hex::encode(kinvault_core::crypto::random_bytes::<8>()?),
            name,
            paths,
            target,
            debounce_secs: req.debounce_secs.unwrap_or(DEFAULT_DEBOUNCE_SECS),
            rescan_secs: req.rescan_secs.unwrap_or(DEFAULT_RESCAN_SECS),
        };

        let set_dir = self.set_dir(&set.id);
        create_private_dir(&set_dir)?;
        let master = MasterKey::generate()?;
        write_master_key(&set_dir, &master)?;
        let passphrase = req.recovery_passphrase;
        let keyfile =
            tokio::task::spawn_blocking(move || KeyFile::create(&master, &passphrase)).await??;
        crate::config::write_private(
            &set_dir.join("keyfile.json"),
            serde_json::to_string_pretty(&keyfile)?.as_bytes(),
        )?;

        config.sets.push(set.clone());
        config.save(&self.config_path())?;
        let id = set.id.clone();
        self.inner
            .sets
            .lock()
            .await
            .insert(id.clone(), SetHandle::start(self.set_env(set)));
        Ok(Reply::SetCreated { id })
    }

    async fn remove_set(&self, key: &str) -> Result<Reply> {
        let id = self.find_set(key).await?.set.id;
        let mut config = self.inner.config.lock().await;
        config.sets.retain(|s| s.id != id);
        config.save(&self.config_path())?;
        if let Some(handle) = self.inner.sets.lock().await.remove(&id) {
            handle.stop();
        }
        // Keep the key: it's the only way to read what was already backed up.
        let removed = self.inner.state_dir.join("removed-sets");
        fs::create_dir_all(&removed)?;
        fs::rename(self.set_dir(&id), removed.join(&id))?;
        Ok(Reply::Done)
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f).await?
}

fn create_private_dir(path: &std::path::Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
