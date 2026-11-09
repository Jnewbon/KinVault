//! Pairing with the user's other devices on the local network. For a few
//! minutes the daemon announces itself and lists the devices it hears. When
//! the user confirms one (after checking the code matches on both screens),
//! the daemon asks it to pair over an authenticated connection; the other
//! device agrees only once its user has confirmed this one too. Both then
//! list each other as their own, without limits.

use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use kinvault_net::nearby::{Beacon, NearbySocket, pairing_code};
use kinvault_net::protocol::PeerName;
use kinvault_net::{EndpointAddr, EndpointId, NetError, PairRequest};

use super::{Daemon, Inner, unix_now};
use crate::api::{Event, GrantSpec, HostOffer, NearbyDevice, NearbyState, NearbyStatus, Reply};

/// How long the daemon looks for nearby devices after the user asks.
const NEARBY_SECS: i64 = 3 * 60;
const ANNOUNCE_EVERY: Duration = Duration::from_secs(2);
const PAIR_TIMEOUT: Duration = Duration::from_secs(20);
/// Most devices listed at once. Anyone on the network can send beacons,
/// so this keeps a flood of made-up ones from growing the list forever.
const MAX_DEVICES: usize = 64;
/// Most devices listed from one sender address, so one machine can't fill
/// the list on its own.
const MAX_PER_SENDER: usize = 4;
/// A device not heard from for this long has gone (they announce every
/// [`ANNOUNCE_EVERY`]), and makes way for new ones.
const STALE_AFTER: Duration = Duration::from_secs(10);

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
    last_seen: Instant,
}

impl Found {
    /// Confirmed and paired devices stay listed until the session ends.
    fn evictable(&self) -> bool {
        !self.confirmed && !self.paired
    }
}

/// Adds or updates the device a beacon is from. Returns whether the list
/// changed. When it is full, gone devices make way first, then the one
/// heard from least recently, so made-up beacons can't keep a real device
/// out for the whole session.
fn record(devices: &mut Vec<Found>, beacon: Beacon, now: Instant) -> bool {
    if let Some(d) = devices.iter_mut().find(|d| d.addr.id == beacon.addr.id) {
        let changed = d.name != beacon.name.as_str();
        d.name = beacon.name.into_string();
        d.addr = beacon.addr;
        d.last_seen = now;
        return changed;
    }
    let before = devices.len();
    devices.retain(|d| !d.evictable() || now.duration_since(d.last_seen) < STALE_AFTER);
    let changed = devices.len() != before;
    // NearbySocket::recv sets the beacon's addresses to where it came from.
    let sender: Vec<_> = beacon.addr.ip_addrs().map(|a| a.ip()).collect();
    let from_sender = devices
        .iter()
        .filter(|d| d.addr.ip_addrs().any(|a| sender.contains(&a.ip())))
        .count();
    if from_sender >= MAX_PER_SENDER {
        return changed;
    }
    if devices.len() >= MAX_DEVICES {
        let oldest = devices
            .iter()
            .enumerate()
            .filter(|(_, d)| d.evictable())
            .min_by_key(|(_, d)| d.last_seen)
            .map(|(i, _)| i);
        match oldest {
            Some(i) => {
                devices.remove(i);
            }
            None => return changed, // all confirmed or paired
        }
    }
    devices.push(Found {
        addr: beacon.addr,
        name: beacon.name.into_string(),
        confirmed: false,
        paired: false,
        last_seen: now,
    });
    true
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
                let beacon = Beacon {
                    addr: daemon.inner.endpoint.addr(),
                    name: PeerName::lossy(&name),
                };
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
            record(&mut session.devices, beacon, Instant::now())
        };
        if changed {
            self.notify(Event::NearbyChanged);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use kinvault_net::SecretKey;

    use super::*;

    /// A beacon from a new device, as received from `ip`.
    fn beacon(ip: [u8; 4]) -> Beacon {
        let addr = EndpointAddr::new(SecretKey::generate().public())
            .with_ip_addr(SocketAddr::new(IpAddr::from(ip), 4433));
        Beacon {
            addr,
            name: PeerName::lossy("device"),
        }
    }

    /// Fills the list from distinct senders, all seen at `at`.
    fn fill(devices: &mut Vec<Found>, at: Instant) {
        for i in 0..MAX_DEVICES {
            assert!(record(
                devices,
                beacon([10, 0, (i / 250) as u8, (i % 250) as u8]),
                at
            ));
        }
        assert_eq!(devices.len(), MAX_DEVICES);
    }

    #[test]
    fn a_flood_cant_keep_a_real_device_out() {
        let start = Instant::now();
        let mut devices = Vec::new();
        fill(&mut devices, start);
        // Made-up devices that stop sending go stale and make way.
        let real = beacon([192, 168, 1, 20]);
        let id = real.addr.id;
        assert!(record(&mut devices, real, start + STALE_AFTER));
        assert!(devices.iter().any(|d| d.addr.id == id));
        assert_eq!(devices.len(), 1);
    }

    #[test]
    fn a_full_list_replaces_the_least_recently_seen() {
        let start = Instant::now();
        let mut devices = Vec::new();
        fill(&mut devices, start);
        let oldest = devices[0].addr.id;
        // Everyone but the first device sends again, a little later.
        let later = start + Duration::from_secs(1);
        for d in devices.iter_mut().skip(1) {
            d.last_seen = later;
        }
        let real = beacon([192, 168, 1, 20]);
        let id = real.addr.id;
        assert!(record(&mut devices, real, later));
        assert_eq!(devices.len(), MAX_DEVICES);
        assert!(devices.iter().any(|d| d.addr.id == id));
        assert!(!devices.iter().any(|d| d.addr.id == oldest));
    }

    #[test]
    fn confirmed_and_paired_devices_are_kept() {
        let start = Instant::now();
        let mut devices = Vec::new();
        fill(&mut devices, start);
        for d in &mut devices {
            d.confirmed = true;
        }
        let much_later = start + STALE_AFTER * 10;
        assert!(!record(&mut devices, beacon([192, 168, 1, 20]), much_later));
        assert_eq!(devices.len(), MAX_DEVICES);
        assert!(devices.iter().all(|d| d.confirmed));
    }

    #[test]
    fn one_sender_lists_only_a_few_devices() {
        let now = Instant::now();
        let mut devices = Vec::new();
        for _ in 0..MAX_PER_SENDER {
            assert!(record(&mut devices, beacon([10, 0, 0, 1]), now));
        }
        assert!(!record(&mut devices, beacon([10, 0, 0, 1]), now));
        assert_eq!(devices.len(), MAX_PER_SENDER);
        assert!(record(&mut devices, beacon([10, 0, 0, 2]), now));
    }

    #[test]
    fn known_devices_are_updated_not_added() {
        let now = Instant::now();
        let mut devices = Vec::new();
        let mut b = beacon([10, 0, 0, 1]);
        assert!(record(&mut devices, b.clone(), now));
        b.name = PeerName::lossy("renamed");
        let later = now + Duration::from_secs(2);
        assert!(record(&mut devices, b.clone(), later));
        assert!(!record(&mut devices, b, later));
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "renamed");
        assert_eq!(devices[0].last_seen, later);
    }
}
