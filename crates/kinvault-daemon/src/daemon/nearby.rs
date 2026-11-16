//! Pairing with the user's other devices on the local network. For a few
//! minutes the daemon announces itself and lists the devices it hears. For
//! each, the two devices agree a code over an authenticated connection, with
//! fresh randomness from both (see [`pairing_code`]); it's shown only once
//! that's done. When the user confirms one (after checking the code matches
//! on both screens),
//! the daemon asks it to pair over an authenticated connection; the other
//! device agrees only once its user has confirmed this one too. Both then
//! list each other as their own, without limits.

use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use kinvault_net::nearby::{
    Beacon, NearbySocket, PairNonce, pair_commitment, pair_nonce, pairing_code, starts_check,
};
use kinvault_net::protocol::PeerName;
use kinvault_net::{
    EndpointAddr, EndpointId, NetError, PairCheckFailed, PairCheckHandler, PairRequest,
};

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
/// Tries at agreeing a code with one device per session. Whoever reveals
/// its nonce last learns the code first and could drop the exchange and try
/// again for a code it likes, so tries are few.
const CHECK_ATTEMPTS: u8 = 3;
/// Code checks started or answered per session, across all devices, so
/// made-up devices can't buy unlimited tries.
const MAX_CHECKS: usize = 2 * MAX_DEVICES;

pub(super) struct Session {
    until_unix: i64,
    /// In the order they were found.
    devices: Vec<Found>,
    /// Code checks started or answered so far (see [`MAX_CHECKS`]).
    checks: usize,
    task: tokio::task::JoinHandle<()>,
}

struct Found {
    addr: EndpointAddr,
    name: String,
    confirmed: bool,
    paired: bool,
    last_seen: Instant,
    /// When the newest beacon accepted from it was sent (its clock).
    sent_unix: i64,
    /// Agreeing the code shown for it.
    check: Check,
    /// Code checks tried with it so far (see [`CHECK_ATTEMPTS`]).
    attempts: u8,
}

/// How agreeing a pairing code with a device is going.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Check {
    NotStarted,
    /// This side started it; `attempt` tells this try's result from a
    /// stale one's.
    Starting {
        attempt: u64,
    },
    /// The other side committed to its nonce; this side answered with `nonce`.
    Answered {
        commitment: [u8; 32],
        nonce: PairNonce,
    },
    Done {
        code: String,
    },
    /// Out of tries, or the other side cheated.
    Failed,
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
        // Beacons are signed, but an old one could be replayed to bring
        // back a name or ports the device no longer uses.
        if beacon.sent_unix < d.sent_unix {
            return false;
        }
        d.sent_unix = beacon.sent_unix;
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
        sent_unix: beacon.sent_unix,
        check: Check::NotStarted,
        attempts: 0,
    });
    true
}

/// Starting a code check: the device must be listed, have tries left, and
/// the session must have checks left. Counts the try.
fn take_attempt<'a>(session: &'a mut Session, id: &EndpointId) -> Result<&'a mut Found, String> {
    if session.checks >= MAX_CHECKS {
        return Err("too many pairing attempts; stop and look again".into());
    }
    let device = session
        .devices
        .iter_mut()
        .find(|d| d.addr.id == *id)
        .ok_or("not listed on this device")?;
    if device.attempts >= CHECK_ATTEMPTS {
        device.check = Check::Failed;
        return Err("too many attempts at a code with this device".into());
    }
    device.attempts += 1;
    session.checks += 1;
    Ok(device)
}

/// Answers the other side's commitment; returns this side's nonce.
fn answer_check(
    session: &mut Session,
    me: &EndpointId,
    peer: &EndpointId,
    commitment: [u8; 32],
) -> Result<PairNonce, String> {
    if starts_check(me, peer) {
        return Err("this device starts the code check".into());
    }
    if let Some(d) = session.devices.iter().find(|d| d.addr.id == *peer)
        && matches!(d.check, Check::Done { .. } | Check::Failed)
    {
        return Err("the code with this device is already settled".into());
    }
    let device = take_attempt(session, peer)?;
    let nonce = pair_nonce();
    device.check = Check::Answered { commitment, nonce };
    Ok(nonce)
}

/// The other side revealed its nonce: checks it against its commitment and
/// settles the code.
fn finish_check(
    session: &mut Session,
    me: &EndpointId,
    peer: &EndpointId,
    revealed: PairNonce,
) -> Result<(), String> {
    let device = session
        .devices
        .iter_mut()
        .find(|d| d.addr.id == *peer)
        .ok_or("not listed on this device")?;
    let Check::Answered { commitment, nonce } = device.check else {
        return Err("no code check under way".into());
    };
    if pair_commitment(&revealed) != commitment {
        device.check = Check::Failed;
        return Err("that isn't the value committed to".into());
    }
    device.check = Check::Done {
        code: pairing_code(peer, me, &revealed, &nonce),
    };
    Ok(())
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
                    checks: 0,
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
                    code: match &d.check {
                        Check::Done { code } => Some(code.clone()),
                        _ => None,
                    },
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
            // The user can only have compared a code that's been agreed.
            match device.check {
                Check::Done { .. } => {}
                Check::Failed => bail!("couldn't agree a code with that device"),
                _ => bail!("still agreeing a code with that device; try again in a moment"),
            }
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
                .filter(|d| d.confirmed && matches!(d.check, Check::Done { .. }))
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
            .allow(addr.id, GrantSpec::default().to_grant(true));
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
                let beacon = Beacon::new(daemon.inner.endpoint.addr(), PeerName::lossy(&name));
                socket.announce(&beacon, daemon.inner.endpoint.secret_key()).await;
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
        let me = self.id();
        let id = beacon.addr.id;
        if id == me {
            return;
        }
        let (changed, start) = {
            let mut session = self.inner.nearby.lock().unwrap();
            let Some(session) = session.as_mut() else {
                return;
            };
            let changed = record(&mut session.devices, beacon, Instant::now());
            // The device with the smaller id starts agreeing the code.
            let start = starts_check(&me, &id)
                && session
                    .devices
                    .iter()
                    .any(|d| d.addr.id == id && d.check == Check::NotStarted)
                && take_attempt(session, &id).is_ok();
            let start = start.then(|| {
                let attempt = NEXT_ATTEMPT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let d = session.devices.iter_mut().find(|d| d.addr.id == id);
                let d = d.expect("just found");
                d.check = Check::Starting { attempt };
                (d.addr.clone(), attempt)
            });
            (changed, start)
        };
        if changed {
            self.notify(Event::NearbyChanged);
        }
        if let Some((addr, attempt)) = start {
            let weak = Arc::downgrade(&self.inner);
            tokio::spawn(async move {
                let Some(inner) = weak.upgrade() else { return };
                let endpoint = inner.endpoint.clone();
                drop(inner);
                let result =
                    tokio::time::timeout(PAIR_TIMEOUT, kinvault_net::pair_check(&endpoint, addr))
                        .await;
                let Some(inner) = weak.upgrade() else { return };
                Daemon { inner }.check_finished(id, attempt, result);
            });
        }
    }

    /// Records how a code check this side started went. A failed try is
    /// tried again on the device's next beacon, while tries are left.
    fn check_finished(
        &self,
        id: EndpointId,
        attempt: u64,
        result: Result<Result<String, PairCheckFailed>, tokio::time::error::Elapsed>,
    ) {
        {
            let mut session = self.inner.nearby.lock().unwrap();
            let Some(session) = session.as_mut() else {
                return;
            };
            let Some(device) = session.devices.iter_mut().find(|d| d.addr.id == id) else {
                return;
            };
            if device.check != (Check::Starting { attempt }) {
                return; // from an earlier session, or replaced
            }
            device.check = match result {
                Ok(Ok(code)) => Check::Done { code },
                Ok(Err(e)) => {
                    tracing::debug!(peer = %id, "agreeing a pairing code failed: {e}");
                    // The other device wasn't ready (it may not have heard
                    // this one yet): that try doesn't count.
                    if !e.answered {
                        device.attempts -= 1;
                        session.checks -= 1;
                    }
                    Check::NotStarted
                }
                // It may have answered; count the try.
                Err(_) => Check::NotStarted,
            };
            if device.check == Check::NotStarted && device.attempts >= CHECK_ATTEMPTS {
                device.check = Check::Failed;
            }
        }
        self.notify(Event::NearbyChanged);
    }
}

/// Tells code-check tries apart, across sessions.
static NEXT_ATTEMPT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Answers nearby devices agreeing a pairing code with this one.
pub(super) struct PairChecks(pub(super) std::sync::Weak<Inner>);

impl PairCheckHandler for PairChecks {
    fn start(&self, peer: EndpointId, commitment: [u8; 32]) -> Result<PairNonce, String> {
        let inner = self.0.upgrade().ok_or("host is shutting down")?;
        let me = inner.endpoint.id();
        let mut session = inner.nearby.lock().unwrap();
        let session = session.as_mut().ok_or("not looking for nearby devices")?;
        answer_check(session, &me, &peer, commitment)
    }

    fn reveal(&self, peer: EndpointId, nonce: PairNonce) -> Result<(), String> {
        let inner = self.0.upgrade().ok_or("host is shutting down")?;
        let me = inner.endpoint.id();
        let result = {
            let mut session = inner.nearby.lock().unwrap();
            let session = session.as_mut().ok_or("not looking for nearby devices")?;
            finish_check(session, &me, &peer, nonce)
        };
        Daemon { inner }.notify(Event::NearbyChanged);
        result
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
        Beacon::new(addr, PeerName::lossy("device"))
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
        b.sent_unix += 2;
        let later = now + Duration::from_secs(2);
        assert!(record(&mut devices, b.clone(), later));
        assert!(!record(&mut devices, b, later));
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "renamed");
        assert_eq!(devices[0].last_seen, later);
    }

    /// A session listing one device, `peer`, as heard by `me`; `me` is the
    /// side that answers code checks.
    fn answering_session() -> (Session, EndpointId, EndpointId) {
        let (mut me, mut peer) = (SecretKey::generate().public(), beacon([10, 0, 0, 1]));
        while starts_check(&me, &peer.addr.id) {
            me = SecretKey::generate().public();
            peer = beacon([10, 0, 0, 1]);
        }
        let id = peer.addr.id;
        let mut session = Session {
            until_unix: i64::MAX,
            devices: Vec::new(),
            checks: 0,
            task: tokio::spawn(async {}),
        };
        record(&mut session.devices, peer, Instant::now());
        (session, me, id)
    }

    #[tokio::test]
    async fn a_code_is_agreed_with_a_commitment() {
        let (mut session, me, peer) = answering_session();
        let theirs = pair_nonce();
        let mine = answer_check(&mut session, &me, &peer, pair_commitment(&theirs)).unwrap();
        // Only the side with the smaller id starts.
        assert!(answer_check(&mut session, &peer, &me, [0; 32]).is_err());
        finish_check(&mut session, &me, &peer, theirs).unwrap();
        assert_eq!(
            session.devices[0].check,
            Check::Done {
                code: pairing_code(&peer, &me, &theirs, &mine)
            }
        );
        // Settled for the rest of the session.
        assert!(answer_check(&mut session, &me, &peer, [0; 32]).is_err());
    }

    #[tokio::test]
    async fn a_reveal_that_breaks_the_commitment_fails_the_check() {
        let (mut session, me, peer) = answering_session();
        answer_check(&mut session, &me, &peer, pair_commitment(&pair_nonce())).unwrap();
        assert!(finish_check(&mut session, &me, &peer, pair_nonce()).is_err());
        assert_eq!(session.devices[0].check, Check::Failed);
        assert!(answer_check(&mut session, &me, &peer, [0; 32]).is_err());
    }

    #[tokio::test]
    async fn tries_at_a_code_are_limited() {
        // Dropping exchanges after seeing the nonce, to retry for a chosen code.
        let (mut session, me, peer) = answering_session();
        for _ in 0..CHECK_ATTEMPTS {
            answer_check(&mut session, &me, &peer, [1; 32]).unwrap();
        }
        assert!(answer_check(&mut session, &me, &peer, [1; 32]).is_err());
        assert_eq!(session.devices[0].check, Check::Failed);

        // And across devices, per session.
        let (mut session, me, _) = answering_session();
        session.checks = MAX_CHECKS;
        let id = session.devices[0].addr.id;
        assert!(answer_check(&mut session, &me, &id, [1; 32]).is_err());
    }

    #[tokio::test]
    async fn unlisted_devices_cant_start_a_check() {
        let (mut session, me, _) = answering_session();
        let mut stranger = SecretKey::generate().public();
        while starts_check(&me, &stranger) {
            stranger = SecretKey::generate().public();
        }
        assert!(answer_check(&mut session, &me, &stranger, [1; 32]).is_err());
        assert!(finish_check(&mut session, &me, &stranger, [1; 32]).is_err());
        assert_eq!(session.checks, 0);
    }

    #[test]
    fn older_beacons_dont_undo_newer_ones() {
        let now = Instant::now();
        let mut devices = Vec::new();
        let old = beacon([10, 0, 0, 1]);
        let mut new = old.clone();
        new.name = PeerName::lossy("renamed");
        new.sent_unix += 60;
        assert!(record(&mut devices, new, now));
        // A replay of the earlier beacon (still validly signed) is ignored.
        assert!(!record(&mut devices, old, now));
        assert_eq!(devices[0].name, "renamed");
    }
}
