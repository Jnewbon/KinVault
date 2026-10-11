use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail, ensure};
use kinvault_core::{KeyFile, LocalDirBackend, MasterKey};
use kinvault_net::{
    Endpoint, EndpointId, InviteAccepted, InviteRedemption, InviteTicket, Offer, Receiver,
    RemoteBackend,
};
use tokio::runtime::Handle;
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;

use crate::api::{self, GrantSpec, HostOffer, Reply, Request};
use crate::config::{Config, PendingInvite, SetConfig, StoredTarget};
use crate::worker::{
    SetEnv, SetHandle, Trigger, VERIFY_BUDGET_BYTES, peer_addr, read_master_key, write_master_key,
};

pub(crate) const DEFAULT_DEBOUNCE_SECS: u64 = 30;
pub(crate) const DEFAULT_RESCAN_SECS: u64 = 6 * 60 * 60;
const DEFAULT_INVITE_SECS: u64 = 7 * 24 * 60 * 60;
const TRASH_PURGE_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

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
    background: std::sync::Mutex<Vec<JoinHandle<()>>>,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
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
            let Some(grant) = peer.grant else { continue };
            match EndpointId::from_str(&peer.id) {
                Ok(id) => receiver.allow(id, grant.to_grant()),
                Err(e) => tracing::warn!("ignoring invalid peer id {:?}: {e}", peer.id),
            }
        }
        let router = kinvault_net::serve(endpoint.clone(), receiver.clone());
        let grace = Duration::from_secs(config.trash_grace_days * 24 * 60 * 60);

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
                background: Default::default(),
            }),
        };

        let weak = Arc::downgrade(&daemon.inner);
        daemon.inner.receiver.set_invite_handler(Arc::new(move |r| {
            let weak = weak.clone();
            Box::pin(async move {
                let inner = weak.upgrade().ok_or("host is shutting down")?;
                Daemon { inner }.accept_invite(r).await
            })
        }));

        let receiver = daemon.inner.receiver.clone();
        let purge = tokio::spawn(async move {
            loop {
                match receiver.purge_trash(grace).await {
                    Ok(0) => {}
                    Ok(freed) => tracing::info!(
                        "removed {freed} bytes of data peers deleted over the grace period ago"
                    ),
                    Err(e) => tracing::warn!("purging deleted peer data failed: {e}"),
                }
                tokio::time::sleep(TRASH_PURGE_INTERVAL).await;
            }
        });
        daemon.inner.background.lock().unwrap().push(purge);

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
        for task in self.inner.background.lock().unwrap().drain(..) {
            task.abort();
        }
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

    fn instance_name(config: &Config) -> String {
        config
            .name
            .clone()
            .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().into_owned())
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
            Request::SetInstanceName { name } => {
                let name = name.trim().to_string();
                ensure!(!name.is_empty(), "name must not be empty");
                let mut config = self.inner.config.lock().await;
                config.name = Some(name);
                config.save(&self.config_path())?;
                Ok(Reply::Done)
            }
            Request::CreateSet(create) => self.create_set(create).await,
            Request::RemoveSet { set } => self.remove_set(&set).await,
            Request::SetLimits {
                set,
                upload_limit,
                window,
            } => {
                self.update_set(&set, |s| {
                    s.upload_limit = upload_limit;
                    s.window = window;
                    Ok(())
                })
                .await
            }
            Request::SetRetention { set, policy } => {
                self.update_set(&set, |s| {
                    s.retention = policy;
                    Ok(())
                })
                .await
            }
            Request::PauseSet { set } => {
                self.update_set(&set, |s| {
                    s.paused = true;
                    Ok(())
                })
                .await
            }
            Request::ResumeSet { set, paths } => {
                let paths = match paths {
                    Some(p) => Some(canonical_paths(&p)?),
                    None => None,
                };
                self.update_set(&set, |s| {
                    if let Some(paths) = paths {
                        s.paths = paths;
                    }
                    for p in &s.paths {
                        ensure!(
                            p.exists(),
                            "{} doesn't exist here; resume with the paths to back up",
                            p.display()
                        );
                    }
                    s.paused = false;
                    Ok(())
                })
                .await
            }
            Request::BackupNow { set } => {
                Ok(Reply::Backup(self.ask_worker(&set, Trigger::Now).await?))
            }
            Request::Prune { set } => {
                Ok(Reply::Pruned(self.ask_worker(&set, Trigger::Prune).await?))
            }
            Request::Verify { set, max_bytes } => {
                let budget = max_bytes.unwrap_or(VERIFY_BUDGET_BYTES);
                let summary = self
                    .ask_worker(&set, |reply| Trigger::Verify(budget, reply))
                    .await?;
                Ok(Reply::Verified(summary))
            }
            Request::ExportRecoveryKit { passphrase } => {
                let config = self.inner.config.lock().await.clone();
                let mut set_keys = Vec::new();
                for set in &config.sets {
                    set_keys.push((set.clone(), read_master_key(&self.set_dir(&set.id))?));
                }
                let identity = self.inner.endpoint.secret_key().clone();
                let kit = blocking(move || {
                    crate::recovery::build(&config, &identity, &set_keys, &passphrase)
                })
                .await?;
                Ok(Reply::RecoveryKit {
                    json: serde_json::to_string_pretty(&kit)?,
                })
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
            Request::PeerAllow { id, name, grant } => {
                let mut config = self.inner.config.lock().await;
                let id = resolve_peer(&config, &id)?.0;
                let peer = self.parse_peer_id(&id)?;
                let entry = config.peer_mut(&id);
                entry.grant = Some(grant);
                if name.is_some() {
                    entry.name = name;
                }
                config.save(&self.config_path())?;
                self.inner.receiver.allow(peer, grant.to_grant());
                Ok(Reply::Done)
            }
            Request::PeerRevoke { id } => {
                let mut config = self.inner.config.lock().await;
                let id = resolve_peer(&config, &id)?.0;
                let peer = self.parse_peer_id(&id)?;
                let entry = config.peer_mut(&id);
                ensure!(
                    entry.grant.take().is_some(),
                    "{id} is not allowed to store data here"
                );
                if entry.hosts_us.is_none() {
                    config.peers.retain(|p| p.id != id);
                }
                config.save(&self.config_path())?;
                self.inner.receiver.revoke(&peer);
                Ok(Reply::Done)
            }
            Request::PeerList => {
                let peers = self.inner.config.lock().await.peers.clone();
                let mut out = Vec::with_capacity(peers.len());
                for p in peers {
                    let used_bytes = match EndpointId::from_str(&p.id) {
                        Ok(id) if p.grant.is_some() => {
                            self.inner.receiver.usage(&id).await.unwrap_or(0)
                        }
                        _ => 0,
                    };
                    out.push(api::PeerInfo {
                        id: p.id,
                        name: p.name,
                        grant: p.grant,
                        used_bytes,
                        hosts_us: p.hosts_us,
                    });
                }
                Ok(Reply::Peers(out))
            }
            Request::CreateInvite(invite) => self.create_invite(invite).await,
            Request::ListInvites => {
                let mut config = self.inner.config.lock().await;
                let now = unix_now();
                config.invites.retain(|i| i.expires_unix > now);
                Ok(Reply::Invites(
                    config
                        .invites
                        .iter()
                        .map(|i| api::InviteInfo {
                            id: i.id.clone(),
                            name: i.name.clone(),
                            grant: i.grant,
                            ask_reciprocal: i.ask_reciprocal,
                            expires_unix: i.expires_unix,
                        })
                        .collect(),
                ))
            }
            Request::CancelInvite { id } => {
                let mut config = self.inner.config.lock().await;
                let before = config.invites.len();
                config.invites.retain(|i| i.id != id);
                ensure!(config.invites.len() < before, "no invite with id {id:?}");
                config.save(&self.config_path())?;
                Ok(Reply::Done)
            }
            Request::RedeemInvite {
                ticket,
                name,
                offer,
            } => self.redeem_invite(&ticket, name, offer).await,
        }
    }

    /// Sends a request to a set's worker and waits for its answer.
    async fn ask_worker<T>(
        &self,
        set: &str,
        make: impl FnOnce(oneshot::Sender<Result<T, String>>) -> Trigger,
    ) -> Result<T> {
        let id = self.find_set(set).await?.set.id;
        let tx = self.inner.sets.lock().await.get(&id).map(|s| s.tx.clone());
        let tx = tx.ok_or_else(|| anyhow!("set was removed"))?;
        let (reply, wait) = oneshot::channel();
        tx.send(make(reply))
            .await
            .map_err(|_| anyhow!("set was removed"))?;
        wait.await
            .map_err(|_| anyhow!("set was removed"))?
            .map_err(|e| anyhow!(e))
    }

    /// Changes a set's configuration and restarts its worker with it.
    async fn update_set(
        &self,
        key: &str,
        change: impl FnOnce(&mut SetConfig) -> Result<()>,
    ) -> Result<Reply> {
        let id = self.find_set(key).await?.set.id;
        let mut config = self.inner.config.lock().await;
        let entry = config
            .sets
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or_else(|| anyhow!("set was removed"))?;
        change(entry)?;
        let updated = entry.clone();
        config.save(&self.config_path())?;
        let mut sets = self.inner.sets.lock().await;
        if let Some(old) = sets.remove(&id) {
            old.stop();
        }
        sets.insert(id, SetHandle::start(self.set_env(updated)));
        Ok(Reply::Done)
    }

    fn parse_peer_id(&self, id: &str) -> Result<EndpointId> {
        let peer = EndpointId::from_str(id).with_context(|| format!("invalid peer id {id:?}"))?;
        ensure!(peer != self.id(), "that is this instance's own id");
        Ok(peer)
    }

    async fn status(&self) -> Result<Reply> {
        let name = Self::instance_name(&*self.inner.config.lock().await);
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
                    upload_limit: h.env.set.upload_limit,
                    window: h.env.set.window,
                    retention: h.env.set.retention,
                    state: st.state,
                    last_backup: st.last_backup,
                    last_error: st.last_error,
                    last_prune: st.maintenance.last_prune,
                    last_verify: st.maintenance.last_verify,
                }
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Reply::Status(api::DaemonStatus {
            id: self.id().to_string(),
            name,
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
        let paths = canonical_paths(&req.paths)?;

        let mut config = self.inner.config.lock().await;
        let target = match req.target {
            api::Target::Local { path } => {
                LocalDirBackend::create(&path)?;
                StoredTarget::Local {
                    path: fs::canonicalize(&path)?,
                }
            }
            api::Target::Peer { id, addrs } => {
                let (id, known) = resolve_peer(&config, &id)?;
                self.parse_peer_id(&id)
                    .context("a set can't be stored on this same instance")?;
                let addrs = if addrs.is_empty() { known } else { addrs };
                let repo = hex::encode(kinvault_core::crypto::random_bytes::<12>()?);
                StoredTarget::Peer { id, repo, addrs }
            }
        };
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
            upload_limit: req.upload_limit,
            window: req.window,
            retention: req
                .retention
                .unwrap_or_else(api::RetentionPolicy::recommended),
            paused: false,
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

    async fn create_invite(&self, req: api::CreateInvite) -> Result<Reply> {
        let token: [u8; 16] = kinvault_core::crypto::random_bytes()?;
        let token_hash = blake3::hash(&token).to_hex().to_string();
        let id = token_hash[..8].to_string();
        let expires_unix = unix_now() + req.expires_secs.unwrap_or(DEFAULT_INVITE_SECS) as i64;
        let mut config = self.inner.config.lock().await;
        let ticket = InviteTicket {
            host: self.inner.endpoint.addr(),
            host_name: Self::instance_name(&config),
            token,
            quota_bytes: req.grant.quota_bytes,
            ask_reciprocal: req.ask_reciprocal,
            expires_unix,
        };
        config.invites.push(PendingInvite {
            id: id.clone(),
            token_hash,
            name: req.name,
            grant: req.grant,
            ask_reciprocal: req.ask_reciprocal,
            expires_unix,
        });
        config.save(&self.config_path())?;
        Ok(Reply::Invite {
            id,
            ticket: ticket.encode(),
            expires_unix,
        })
    }

    /// Host side: a friend presents an invite token.
    async fn accept_invite(&self, r: InviteRedemption) -> Result<InviteAccepted, String> {
        let invalid = || "this invite is invalid, expired or already used".to_string();
        let hash = blake3::hash(&r.token).to_hex().to_string();
        let mut config = self.inner.config.lock().await;
        let now = unix_now();
        config.invites.retain(|i| i.expires_unix > now);
        let pos = config
            .invites
            .iter()
            .position(|i| i.token_hash == hash)
            .ok_or_else(invalid)?;
        let invite = config.invites.remove(pos);
        let peer_id = r.peer.to_string();

        let entry = config.peer_mut(&peer_id);
        entry.grant = Some(invite.grant);
        entry.name = invite.name.clone().or(r.name.clone()).or(entry.name.take());
        if let Some(offer) = r.offer {
            entry.hosts_us = Some(HostOffer {
                quota_bytes: offer.quota_bytes,
            });
        }
        config
            .save(&self.config_path())
            .map_err(|e| format!("host could not save the invite: {e:#}"))?;
        self.inner.receiver.allow(r.peer, invite.grant.to_grant());
        tracing::info!(peer = %peer_id, name = ?entry_name(&config, &peer_id), "invite redeemed");
        Ok(InviteAccepted {
            host_name: Self::instance_name(&config),
            quota_bytes: invite.grant.quota_bytes,
        })
    }

    /// Friend side: claim a host's invite, optionally offering storage back.
    async fn redeem_invite(
        &self,
        ticket: &str,
        name: Option<String>,
        offer: Option<GrantSpec>,
    ) -> Result<Reply> {
        let ticket = InviteTicket::decode(ticket)?;
        ensure!(
            ticket.expires_unix > unix_now(),
            "this invite has expired; ask for a new one"
        );
        ensure!(
            ticket.host.id != self.id(),
            "this invite was created by this instance"
        );
        let my_name = Self::instance_name(&*self.inner.config.lock().await);
        let accepted = kinvault_net::redeem_invite(
            &self.inner.endpoint,
            &ticket,
            Some(my_name),
            offer.map(|g| Offer {
                quota_bytes: g.quota_bytes,
            }),
        )
        .await?;

        let host_id = ticket.host.id.to_string();
        let mut config = self.inner.config.lock().await;
        let entry = config.peer_mut(&host_id);
        entry.name = name.or(Some(accepted.host_name.clone()));
        entry.addrs = ticket.host.ip_addrs().copied().collect();
        entry.hosts_us = Some(HostOffer {
            quota_bytes: accepted.quota_bytes,
        });
        if let Some(grant) = offer {
            entry.grant = Some(grant);
            self.inner.receiver.allow(ticket.host.id, grant.to_grant());
        }
        config.save(&self.config_path())?;
        Ok(Reply::Redeemed {
            host_id,
            host_name: accepted.host_name,
            quota_bytes: accepted.quota_bytes,
            ask_reciprocal: ticket.ask_reciprocal,
        })
    }
}

fn entry_name(config: &Config, id: &str) -> Option<String> {
    config
        .peers
        .iter()
        .find(|p| p.id == id)
        .and_then(|p| p.name.clone())
}

/// Resolves a peer id or a known peer's name to its id and known addresses.
fn resolve_peer(config: &Config, key: &str) -> Result<(String, Vec<SocketAddr>)> {
    if let Some(p) = config.peers.iter().find(|p| p.id == key) {
        return Ok((p.id.clone(), p.addrs.clone()));
    }
    let named: Vec<_> = config
        .peers
        .iter()
        .filter(|p| p.name.as_deref() == Some(key))
        .collect();
    match named.as_slice() {
        [p] => Ok((p.id.clone(), p.addrs.clone())),
        [] if EndpointId::from_str(key).is_ok() => Ok((key.to_string(), Vec::new())),
        [] => bail!("no peer with id or name {key:?}"),
        _ => bail!("more than one peer is named {key:?}; use its id"),
    }
}

fn canonical_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    ensure!(
        !paths.is_empty(),
        "choose at least one file or folder to back up"
    );
    paths
        .iter()
        .map(|p| fs::canonicalize(p).with_context(|| format!("cannot back up {}", p.display())))
        .collect()
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
