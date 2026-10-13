//! Pairing with the user's other devices on the local network. For a few
//! minutes the daemon announces itself and lists the devices it hears. When
//! the user confirms one (after checking the code matches on both screens),
//! the daemon asks it to pair over an authenticated connection; the other
//! device agrees only once its user has confirmed this one too. Both then
//! list each other as their own, without limits.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use kinvault_net::nearby::{Beacon, NearbySocket, pairing_code};
use kinvault_net::{EndpointAddr, EndpointId, NetError, PairRequest};

use super::{Daemon, Inner, unix_now};
use crate::api::{Event, GrantSpec, HostOffer, NearbyDevice, NearbyState, NearbyStatus, Reply};

/// How long the daemon looks for nearby devices after the user asks.
const NEARBY_SECS: i64 = 3 * 60;
const ANNOUNCE_EVERY: Duration = Duration::from_secs(2);
const PAIR_TIMEOUT: Duration = Duration::from_secs(20);

pub(super) struct Session {
    until_unix: i64,
    /// In the order they were found.
    devices: Vec<Found>,
    task: tokio::task::JoinHandle<()>,
}

struct Found {
    addr: EndpointAddr,
    name: String,
    confirmed: bool,
    paired: bool,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Daemon {
    pub(super) async fn find_nearby(&self) -> Result<Reply> {
        let until_unix = unix_now() + NEARBY_SECS;
        {
            let mut session = self.inner.nearby.lock().unwrap();
            if let Some(s) = session.as_mut() {
                s.until_unix = until_unix;
            } else {
                let socket = NearbySocket::bind(&self.inner.nearby_opts).map_err(|e| {
                    anyhow!(
                        "can't look for nearby devices on UDP port {}: {e}",
                        self.inner.nearby_opts.port
                    )
                })?;
                let task = tokio::spawn(run(Arc::downgrade(&self.inner), socket));
                *session = Some(Session {
                    until_unix,
                    devices: Vec::new(),
                    task,
                });
                tracing::info!("looking for nearby devices");
            }
        }
        self.notify(Event::NearbyChanged);
        self.nearby_status().await
    }

    pub(super) fn stop_nearby(&self) -> Reply {
        if self.inner.nearby.lock().unwrap().take().is_some() {
            tracing::info!("stopped looking for nearby devices");
            self.notify(Event::NearbyChanged);
        }
        Reply::Done
    }

    pub(super) async fn nearby_status(&self) -> Result<Reply> {
        let mine: Vec<String> = {
            let config = self.inner.config.lock().await;
            config
                .peers
                .iter()
                .filter(|p| p.mine)
                .map(|p| p.id.clone())
                .collect()
        };
        let me = self.id();
        let session = self.inner.nearby.lock().unwrap();
        let Some(session) = session.as_ref() else {
            return Ok(Reply::Nearby(NearbyStatus::default()));
        };
        let devices = session
            .devices
            .iter()
            .map(|d| {
                let id = d.addr.id.to_string();
                let state = if d.paired || mine.contains(&id) {
                    NearbyState::Paired
                } else if d.confirmed {
                    NearbyState::Waiting
                } else {
                    NearbyState::Found
                };
                NearbyDevice {
                    code: pairing_code(&me, &d.addr.id),
                    id,
                    name: d.name.clone(),
                    state,
                }
            })
            .collect();
        Ok(Reply::Nearby(NearbyStatus {
            until_unix: Some(session.until_unix),
            devices,
        }))
    }

    /// The user confirmed a nearby device: ask it to pair.
    pub(super) async fn pair_nearby(&self, id: &str) -> Result<Reply> {
        let id = EndpointId::from_str(id).map_err(|_| anyhow!("invalid device id {id:?}"))?;
        let (addr, name) = {
            let mut session = self.inner.nearby.lock().unwrap();
            let session = session
                .as_mut()
                .ok_or_else(|| anyhow!("not looking for nearby devices any more"))?;
            let device = session
                .devices
                .iter_mut()
                .find(|d| d.addr.id == id)
                .ok_or_else(|| anyhow!("that device is no longer nearby"))?;
            device.confirmed = true;
            (device.addr.clone(), device.name.clone())
        };
        self.notify(Event::NearbyChanged);

        let (my_name, my_hosts) = {
            let config = self.inner.config.lock().await;
            (Self::instance_name(&config), self.public_hosts(&config))
        };
        let attempt = kinvault_net::pair(&self.inner.endpoint, addr.clone(), my_name, my_hosts);
        match tokio::time::timeout(PAIR_TIMEOUT, attempt).await {
            Ok(Ok(_their_name)) => self.add_own_device(&addr, &name, Vec::new()).await?,
            // Not confirmed on the other device yet; it pairs with us when it is.
            Ok(Err(NetError::Denied(_))) => {}
            Ok(Err(e)) => bail!("couldn't reach {name}: {e}"),
            Err(_) => bail!("couldn't reach {name}: no answer"),
        }
        self.nearby_status().await
    }

    /// A nearby device asks to pair; agree if the user confirmed it here.
    pub(super) async fn accept_pair(&self, r: PairRequest) -> Result<String, String> {
        let waiting = || "not confirmed on this device yet".to_string();
        let (addr, name) = {
            let session = self.inner.nearby.lock().unwrap();
            let device = session
                .as_ref()
                .and_then(|s| s.devices.iter().find(|d| d.addr.id == r.peer))
                .filter(|d| d.confirmed)
                .ok_or_else(waiting)?;
            (device.addr.clone(), device.name.clone())
        };
        self.add_own_device(&addr, &name, r.hosts)
            .await
            .map_err(|e| format!("could not save the pairing: {e:#}"))?;
        let config = self.inner.config.lock().await;
        Ok(Self::instance_name(&config))
    }

    /// Records a paired device as one of the user's own: each stores the
    /// other's backups without limits.
    async fn add_own_device(
        &self,
        addr: &EndpointAddr,
        name: &str,
        hosts: Vec<String>,
    ) -> Result<()> {
        let id = addr.id.to_string();
        let mut config = self.inner.config.lock().await;
        let entry = config.peer_mut(&id);
        if entry.name.is_none() {
            entry.name = Some(name.to_string());
        }
        entry.addrs = addr.ip_addrs().copied().collect();
        if !hosts.is_empty() {
            entry.hosts = hosts;
        }
        entry.mine = true;
        entry.grant = Some(GrantSpec::default());
        entry.hosts_us = Some(HostOffer { quota_bytes: None });
        config.save(&self.config_path())?;
        drop(config);
        self.inner
            .receiver
            .allow(addr.id, GrantSpec::default().to_grant());
        if let Some(d) = self
            .inner
            .nearby
            .lock()
            .unwrap()
            .as_mut()
            .and_then(|s| s.devices.iter_mut().find(|d| d.addr.id == addr.id))
        {
            d.paired = true;
        }
        tracing::info!(peer = %id, name, "paired with a nearby device");
        self.notify(Event::PeersChanged);
        self.notify(Event::NearbyChanged);
        Ok(())
    }
}

/// Announces this daemon and collects others' beacons until the session
/// ends or is stopped (which aborts this task).
async fn run(inner: std::sync::Weak<Inner>, socket: NearbySocket) {
    let daemon = || inner.upgrade().map(|inner| Daemon { inner });
    let mut announce = tokio::time::interval(ANNOUNCE_EVERY);
    loop {
        tokio::select! {
            _ = announce.tick() => {
                let Some(daemon) = daemon() else { return };
                let expired = daemon
                    .inner
                    .nearby
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_none_or(|s| s.until_unix <= unix_now());
                if expired {
                    // Dropping the session aborts this task, which ends here anyway.
                    daemon.stop_nearby();
                    return;
                }
                let name = Daemon::instance_name(&*daemon.inner.config.lock().await);
                let beacon = Beacon { addr: daemon.inner.endpoint.addr(), name };
                socket.announce(&beacon).await;
            }
            received = socket.recv() => match received {
                Ok(beacon) => {
                    let Some(daemon) = daemon() else { return };
                    daemon.found(beacon);
                }
                Err(e) => {
                    tracing::warn!("listening for nearby devices failed: {e}");
                    tokio::time::sleep(ANNOUNCE_EVERY).await;
                }
            },
        }
    }
}

impl Daemon {
    fn found(&self, beacon: Beacon) {
        if beacon.addr.id == self.id() {
            return;
        }
        let changed = {
            let mut session = self.inner.nearby.lock().unwrap();
            let Some(session) = session.as_mut() else {
                return;
            };
            match session
                .devices
                .iter_mut()
                .find(|d| d.addr.id == beacon.addr.id)
            {
                Some(d) => {
                    let changed = d.name != beacon.name;
                    d.name = beacon.name;
                    d.addr = beacon.addr;
                    changed
                }
                None => {
                    session.devices.push(Found {
                        addr: beacon.addr,
                        name: beacon.name,
                        confirmed: false,
                        paired: false,
                    });
                    true
                }
            }
        };
        if changed {
            self.notify(Event::NearbyChanged);
        }
    }
}
