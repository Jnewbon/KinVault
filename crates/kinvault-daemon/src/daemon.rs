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
    Endpoint, EndpointId, HostAddr, InviteAccepted, InviteRedemption, InviteTicket, Offer,
    Receiver, RemoteBackend,
};
use tokio::runtime::Handle;
use tokio::sync::{Mutex, broadcast, oneshot};
use tokio::task::JoinHandle;

use crate::api::{self, Event, GrantSpec, HostOffer, Reply, Request};
use crate::config::{Config, PendingInvite, SetConfig, StoredTarget};
mod deletion;
mod nearby;
mod restores;

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
    /// Where to look for the user's other devices on the local network.
    pub nearby: kinvault_net::nearby::NearbyOptions,
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
    /// The `listen_port` the endpoint was bound with.
    listen_port: Option<u16>,
    runtime: Handle,
    // Lock order: config, then sets.
    config: Mutex<Config>,
    sets: Mutex<HashMap<String, SetHandle>>,
    background: std::sync::Mutex<Vec<JoinHandle<()>>>,
    events: broadcast::Sender<Event>,
    nearby_opts: kinvault_net::nearby::NearbyOptions,
    /// Set while looking for nearby devices.
    nearby: std::sync::Mutex<Option<nearby::Session>>,
    restores: std::sync::Mutex<Vec<restores::Running>>,
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
                kinvault_net::bind(secret, config.listen_port).await?
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
                listen_port: config.listen_port,
                runtime: Handle::current(),
                sets: Mutex::new(HashMap::new()),
                config: Mutex::new(config.clone()),
                background: Default::default(),
                events: broadcast::channel(256).0,
                nearby_opts: opts.nearby,
                nearby: Default::default(),
                restores: Default::default(),
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
        let weak = Arc::downgrade(&daemon.inner);
        daemon.inner.receiver.set_pair_handler(Arc::new(move |r| {
            let weak = weak.clone();
            Box::pin(async move {
                let inner = weak.upgrade().ok_or("host is shutting down")?;
                Daemon { inner }.accept_pair(r).await
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

        // Keep asking hosts to erase deleted sets' backups.
        let weak = Arc::downgrade(&daemon.inner);
        let deletions = tokio::spawn(async move {
            loop {
                let Some(inner) = weak.upgrade() else { return };
                if let Err(e) = (Daemon { inner }).process_deletions().await {
                    tracing::warn!("erasing deleted sets' backups failed: {e:#}");
                }
                tokio::time::sleep(deletion::RETRY_INTERVAL).await;
            }
        });
        daemon.inner.background.lock().unwrap().push(deletions);

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
        self.inner.nearby.lock().unwrap().take();
        self.cancel_all_restores();
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
            events: self.inner.events.clone(),
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
        let event = match &req {
            Request::SetInstanceName { .. }
            | Request::CreateSet(_)
            | Request::RemoveSet { .. }
            | Request::DeleteSet { .. }
            | Request::SetLimits { .. }
            | Request::SetExcludes { .. }
            | Request::SetRetention { .. }
            | Request::PauseSet { .. }
            | Request::ResumeSet { .. } => Some(Event::SetsChanged),
            Request::PeerAllow { .. }
            | Request::PeerRevoke { .. }
            | Request::PeerSetMine { .. }
            | Request::PeerRemove { .. }
            | Request::CreateInvite(_)
            | Request::CancelInvite { .. }
            | Request::RedeemInvite { .. } => Some(Event::PeersChanged),
            Request::SetNetwork(_) => Some(Event::NetworkChanged),
            _ => None,
        };
        let result = self.dispatch(req).await.map_err(|e| format!("{e:#}"));
        if result.is_ok()
            && let Some(event) = event
        {
            self.notify(event);
        }
        result
    }

    async fn dispatch(&self, req: Request) -> Result<Reply> {
        match req {
            Request::Status => self.status().await,
            Request::Subscribe => bail!("subscribing is only possible over the control socket"),
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
            Request::DeleteSet { set } => self.delete_set(&set).await,
            Request::StartRestore {
                set,
                snapshot,
                target,
                include,
            } => self.start_restore(&set, snapshot, target, include).await,
            Request::CancelRestore { id } => self.cancel_restore(&id),
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
            Request::SetExcludes { set, excludes } => {
                let excludes = clean_excludes(excludes)?;
                self.update_set(&set, |s| {
                    s.excludes = excludes;
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
                let StoredTarget::Peer {
                    id,
                    repo,
                    addrs,
                    hosts,
                } = &env.set.target
                else {
                    bail!("set {:?} is stored locally, not on a peer", env.set.name);
                };
                let remote = RemoteBackend::new(
                    env.endpoint.clone(),
                    peer_addr(id, addrs)?,
                    repo,
                    env.runtime.clone(),
                )?
                .with_hosts(hosts.clone());
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
                    // Also for peers no longer allowed here: what they left is still stored.
                    let usage = match EndpointId::from_str(&p.id) {
                        Ok(id) => self
                            .inner
                            .receiver
                            .usage_detail(&id)
                            .await
                            .unwrap_or_default(),
                        _ => Default::default(),
                    };
                    out.push(api::PeerInfo {
                        id: p.id,
                        name: p.name,
                        grant: p.grant,
                        used_bytes: usage.used_bytes,
                        deleting_bytes: usage.deleting_bytes,
                        hosts_us: p.hosts_us,
                        mine: p.mine,
                    });
                }
                Ok(Reply::Peers(out))
            }
            Request::PeerRemove { id } => {
                let mut config = self.inner.config.lock().await;
                let id = resolve_peer(&config, &id)?.0;
                let peer = self.parse_peer_id(&id)?;
                let name = entry_name(&config, &id).unwrap_or_else(|| id.clone());
                ensure!(
                    config.peers.iter().any(|p| p.id == id),
                    "{id} is not a known peer"
                );
                let using: Vec<&str> = config
                    .sets
                    .iter()
                    .filter(|s| matches!(&s.target, StoredTarget::Peer { id: p, .. } if *p == id))
                    .map(|s| s.name.as_str())
                    .collect();
                ensure!(
                    using.is_empty(),
                    "{name} still keeps these backups: {}. Delete them first.",
                    using.join(", ")
                );
                config.peers.retain(|p| p.id != id);
                config.save(&self.config_path())?;
                drop(config);
                self.inner.receiver.remove_peer(&peer).await?;
                tracing::info!(peer = %id, name, "removed peer");
                Ok(Reply::Done)
            }
            Request::PeerSetMine { id, mine } => {
                let mut config = self.inner.config.lock().await;
                let id = resolve_peer(&config, &id)?.0;
                ensure!(
                    config.peers.iter().any(|p| p.id == id),
                    "{id} is not a known peer"
                );
                let peer = self.parse_peer_id(&id)?;
                let entry = config.peer_mut(&id);
                entry.mine = mine;
                // Your own devices may store as much as they like.
                let grant = mine.then(GrantSpec::default);
                if let Some(grant) = grant {
                    entry.grant = Some(grant);
                }
                config.save(&self.config_path())?;
                if let Some(grant) = grant {
                    self.inner.receiver.allow(peer, grant.to_grant());
                }
                Ok(Reply::Done)
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
                            mine: i.mine,
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
            Request::GetNetwork => self.network().await,
            Request::SetNetwork(mut settings) => {
                ensure!(
                    settings.listen_port != Some(0),
                    "the port must be from 1 to 65535"
                );
                let mut hosts = Vec::new();
                for entry in &settings.public_hosts {
                    let host = entry.parse::<HostAddr>()?.to_string();
                    if !hosts.contains(&host) {
                        hosts.push(host);
                    }
                }
                settings.public_hosts = hosts;
                let mut config = self.inner.config.lock().await;
                config.listen_port = settings.listen_port;
                config.public_hosts = settings.public_hosts;
                config.save(&self.config_path())?;
                drop(config);
                self.network().await
            }
            Request::RedeemInvite {
                ticket,
                name,
                offer,
                mine,
            } => {
                let offer = if mine {
                    Some(GrantSpec::default())
                } else {
                    offer
                };
                self.redeem_invite(&ticket, name, offer, mine).await
            }
            Request::FindNearby => self.find_nearby().await,
            Request::StopNearby => Ok(self.stop_nearby()),
            Request::NearbyStatus => self.nearby_status().await,
            Request::PairNearby { id } => self.pair_nearby(&id).await,
        }
    }

    /// Live events: set states, backup progress and configuration changes.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
    }

    fn notify(&self, event: Event) {
        let _ = self.inner.events.send(event);
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
                    excludes: h.env.set.excludes.clone(),
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
            restores: self.restore_jobs(),
        }))
    }

    async fn network(&self) -> Result<Reply> {
        let config = self.inner.config.lock().await;
        Ok(Reply::Network(api::NetworkInfo {
            settings: api::NetworkSettings {
                listen_port: config.listen_port,
                public_hosts: config.public_hosts.clone(),
            },
            bound: self.inner.endpoint.bound_sockets(),
            restart_required: config.listen_port != self.inner.listen_port,
        }))
    }

    /// The configured public addresses, with the port this instance is
    /// actually listening on filled in where none was given.
    fn public_hosts(&self, config: &Config) -> Vec<String> {
        let bound = self.inner.endpoint.bound_sockets();
        let port = bound
            .iter()
            .find(|a| a.is_ipv4())
            .or(bound.first())
            .map(|a| a.port());
        config
            .public_hosts
            .iter()
            .filter_map(|h| h.parse::<HostAddr>().ok())
            .filter_map(|h| match (h.port(), port) {
                (Some(_), _) => Some(h.to_string()),
                (None, Some(port)) => Some(h.or_port(port).to_string()),
                (None, None) => None,
            })
            .collect()
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
                let hosts = config
                    .peers
                    .iter()
                    .find(|p| p.id == id)
                    .map(|p| p.hosts.clone())
                    .unwrap_or_default();
                self.parse_peer_id(&id)
                    .context("a set can't be stored on this same instance")?;
                let addrs = if addrs.is_empty() { known } else { addrs };
                let repo = hex::encode(kinvault_core::crypto::random_bytes::<12>()?);
                StoredTarget::Peer {
                    id,
                    repo,
                    addrs,
                    hosts,
                }
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
            excludes: clean_excludes(req.excludes)?,
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

    async fn create_invite(&self, mut req: api::CreateInvite) -> Result<Reply> {
        if req.mine {
            req.grant = GrantSpec::default();
            req.ask_reciprocal = true;
        }
        let token: [u8; 16] = kinvault_core::crypto::random_bytes()?;
        let token_hash = blake3::hash(&token).to_hex().to_string();
        let id = token_hash[..8].to_string();
        let expires_unix = unix_now() + req.expires_secs.unwrap_or(DEFAULT_INVITE_SECS) as i64;
        let mut config = self.inner.config.lock().await;
        let ticket = InviteTicket {
            host: self.inner.endpoint.addr(),
            hosts: self.public_hosts(&config),
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
            mine: req.mine,
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
        entry.mine |= invite.mine;
        if !r.hosts.is_empty() {
            entry.hosts = r.hosts.clone();
        }
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
        self.notify(Event::PeersChanged);
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
        mine: bool,
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
        let (my_name, my_hosts) = {
            let config = self.inner.config.lock().await;
            (Self::instance_name(&config), self.public_hosts(&config))
        };
        let accepted = kinvault_net::redeem_invite(
            &self.inner.endpoint,
            &ticket,
            Some(my_name),
            offer.map(|g| Offer {
                quota_bytes: g.quota_bytes,
            }),
            my_hosts,
        )
        .await?;

        let host_id = ticket.host.id.to_string();
        let mut config = self.inner.config.lock().await;
        let entry = config.peer_mut(&host_id);
        entry.name = name.or(Some(accepted.host_name.clone()));
        entry.mine |= mine;
        entry.addrs = ticket.host.ip_addrs().copied().collect();
        entry.hosts = ticket.hosts.clone();
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
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Only the owner may change permissions. A directory we can write to
        // but don't own (e.g. a NAS dataset shared through an ACL) keeps the
        // access its owner gave it.
        match fs::set_permissions(path, fs::Permissions::from_mode(0o700)) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => tracing::warn!(
                "couldn't make {} private ({e}); make sure only KinVault's user can read it",
                path.display()
            ),
            other => other.with_context(|| format!("making {} private", path.display()))?,
        }
    }
    Ok(())
}

/// Trims patterns, drops blank ones and checks the rest are valid.
fn clean_excludes(patterns: Vec<String>) -> Result<Vec<String>> {
    let patterns: Vec<String> = patterns
        .into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    kinvault_core::Excludes::parse(&patterns)?;
    Ok(patterns)
}
