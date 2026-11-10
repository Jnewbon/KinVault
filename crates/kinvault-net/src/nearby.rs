//! Finding the user's other devices on the local network, so they can be
//! paired without copying an invite code. While pairing, each instance
//! broadcasts a small beacon with its id, addresses and name, and listens for
//! the beacons of others. Each beacon is signed with the sender's endpoint
//! key, so nobody else can send one under its id to change the name or
//! addresses shown for it. Anyone can still announce made-up devices of their
//! own: the actual pairing runs over an authenticated connection, and users
//! compare a [`pairing_code`] shown on both devices before confirming.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use iroh::{EndpointAddr, EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::protocol::PeerName;

/// UDP port beacons are sent to and received on.
pub const NEARBY_PORT: u16 = 47101;
/// Administratively scoped multicast group, for networks that drop broadcasts.
const MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 71, 1);
/// Version 2 beacons are signed; version 1 beacons are ignored.
const MAGIC: &[u8] = b"KVNEAR2";
const MAX_BEACON_LEN: usize = 2048;
/// Beacons sent longer ago than this (or this far in the future, by the
/// receiver's clock) are ignored, so ones recorded in an earlier session
/// can't be replayed. Generous, so devices whose clocks are a little off
/// still find each other.
pub const MAX_BEACON_AGE_SECS: i64 = 60 * 60;

/// Where beacons go and which port to listen on.
#[derive(Clone, Debug)]
pub struct NearbyOptions {
    pub port: u16,
    pub targets: Vec<SocketAddr>,
}

impl Default for NearbyOptions {
    fn default() -> Self {
        Self {
            port: NEARBY_PORT,
            targets: vec![
                SocketAddrV4::new(Ipv4Addr::BROADCAST, NEARBY_PORT).into(),
                SocketAddrV4::new(MULTICAST_GROUP, NEARBY_PORT).into(),
            ],
        }
    }
}

/// An instance announcing that it is looking for its owner's other devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Beacon {
    pub addr: EndpointAddr,
    pub name: PeerName,
    /// When it was sent (Unix seconds, by the sender's clock).
    pub sent_unix: i64,
}

/// A beacon as sent: the fields, signed by `addr.id`'s key.
#[derive(Serialize, Deserialize)]
struct SignedBeacon {
    addr: EndpointAddr,
    name: PeerName,
    sent_unix: i64,
    signature: Vec<u8>,
}

fn signed_bytes(addr: &EndpointAddr, name: &PeerName, sent_unix: i64) -> Vec<u8> {
    postcard::to_allocvec(&("kinvault beacon v2", addr, name, sent_unix))
        .expect("serialising plain fields")
}

impl Beacon {
    /// A beacon sent now.
    pub fn new(addr: EndpointAddr, name: PeerName) -> Self {
        Self {
            addr,
            name,
            sent_unix: unix_now(),
        }
    }

    /// Signs and encodes the beacon. `secret` must be `addr.id`'s key, or
    /// receivers ignore it.
    pub fn encode(&self, secret: &SecretKey) -> Vec<u8> {
        debug_assert_eq!(
            secret.public(),
            self.addr.id,
            "signing someone else's beacon"
        );
        let signature = secret
            .sign(&signed_bytes(&self.addr, &self.name, self.sent_unix))
            .to_bytes()
            .to_vec();
        let signed = SignedBeacon {
            addr: self.addr.clone(),
            name: self.name.clone(),
            sent_unix: self.sent_unix,
            signature,
        };
        let mut out = MAGIC.to_vec();
        out.extend(postcard::to_allocvec(&signed).expect("beacon serializes"));
        out
    }

    /// Decodes a beacon received at `now_unix`. Returns `None` unless its
    /// sender signed it and it was sent within [`MAX_BEACON_AGE_SECS`].
    /// Relay URLs are dropped: devices on the same network reach each
    /// other directly, and a relay named in a beacon could be anyone's.
    pub fn decode(bytes: &[u8], now_unix: i64) -> Option<Self> {
        let body = bytes.strip_prefix(MAGIC)?;
        // The name is checked while decoding (see PeerName).
        let b: SignedBeacon = postcard::from_bytes(body).ok()?;
        if now_unix.abs_diff(b.sent_unix) > MAX_BEACON_AGE_SECS as u64 {
            return None;
        }
        let signature: [u8; 64] = b.signature.as_slice().try_into().ok()?;
        b.addr
            .id
            .verify(
                &signed_bytes(&b.addr, &b.name, b.sent_unix),
                &Signature::from_bytes(&signature),
            )
            .ok()?;
        let mut addr = EndpointAddr::new(b.addr.id);
        for ip in b.addr.ip_addrs() {
            addr = addr.with_ip_addr(*ip);
        }
        Some(Self {
            addr,
            name: b.name,
            sent_unix: b.sent_unix,
        })
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// The socket beacons are sent and received on.
pub struct NearbySocket {
    socket: UdpSocket,
    targets: Vec<SocketAddr>,
}

impl NearbySocket {
    pub fn bind(opts: &NearbyOptions) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        // Other KinVault instances on this machine may be pairing too.
        socket.set_reuse_address(true)?;
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        socket.set_reuse_port(true)?;
        socket.set_broadcast(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, opts.port).into())?;
        if let Err(e) = socket.join_multicast_v4(&MULTICAST_GROUP, &Ipv4Addr::UNSPECIFIED) {
            tracing::debug!("not receiving multicast beacons: {e}");
        }
        Ok(Self {
            socket: UdpSocket::from_std(socket.into())?,
            targets: opts.targets.clone(),
        })
    }

    /// Signs the beacon with `secret` (its sender's key) and sends it to
    /// every target; unreachable ones are skipped.
    pub async fn announce(&self, beacon: &Beacon, secret: &SecretKey) {
        let bytes = beacon.encode(secret);
        for target in &self.targets {
            if let Err(e) = self.socket.send_to(&bytes, target).await {
                tracing::debug!("sending beacon to {target} failed: {e}");
            }
        }
    }

    /// Waits for the next valid beacon. Its addresses include the one it was
    /// sent from, at each of the sender's listening ports. That one isn't
    /// covered by the signature (whoever forwards a beacon adds their own),
    /// but the signed addresses are always kept alongside it.
    pub async fn recv(&self) -> io::Result<Beacon> {
        let mut buf = vec![0u8; MAX_BEACON_LEN];
        loop {
            let (len, from) = self.socket.recv_from(&mut buf).await?;
            let Some(mut beacon) = Beacon::decode(&buf[..len], unix_now()) else {
                continue;
            };
            let ports: Vec<u16> = beacon.addr.ip_addrs().map(|a| a.port()).collect();
            for port in ports {
                beacon.addr = beacon.addr.with_ip_addr(SocketAddr::new(from.ip(), port));
            }
            return Ok(beacon);
        }
    }
}

/// A six-digit code, the same on both devices, that users compare before
/// pairing so a stranger on the network can't pose as one of their devices.
pub fn pairing_code(a: &EndpointId, b: &EndpointId) -> String {
    let (first, second) = if a.as_bytes() <= b.as_bytes() {
        (a, b)
    } else {
        (b, a)
    };
    let mut hasher = blake3::Hasher::new_derive_key("kinvault 2026 pairing code");
    hasher.update(first.as_bytes());
    hasher.update(second.as_bytes());
    let hash = hasher.finalize();
    let n = u32::from_le_bytes(hash.as_bytes()[..4].try_into().unwrap()) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A beacon from a new device, and that device's key.
    fn beacon(name: &str) -> (Beacon, SecretKey) {
        let secret = SecretKey::generate();
        let addr =
            EndpointAddr::new(secret.public()).with_ip_addr("192.0.2.1:4433".parse().unwrap());
        (Beacon::new(addr, PeerName::lossy(name)), secret)
    }

    #[test]
    fn beacon_roundtrip() {
        let (beacon, secret) = beacon("laptop");
        let now = beacon.sent_unix;
        assert_eq!(Beacon::decode(&beacon.encode(&secret), now), Some(beacon));
        assert_eq!(Beacon::decode(b"hello", now), None);
        assert_eq!(Beacon::decode(b"KVNEAR2garbage", now), None);
    }

    #[test]
    fn beacons_must_be_signed_by_their_sender() {
        let (beacon, secret) = beacon("laptop");
        let now = beacon.sent_unix;
        // Someone else's key, claiming the laptop's id.
        let forger = SecretKey::generate();
        let mut forged = MAGIC.to_vec();
        let signature = forger
            .sign(&signed_bytes(&beacon.addr, &beacon.name, now))
            .to_bytes()
            .to_vec();
        forged.extend(
            postcard::to_allocvec(&SignedBeacon {
                addr: beacon.addr.clone(),
                name: beacon.name.clone(),
                sent_unix: now,
                signature,
            })
            .unwrap(),
        );
        assert_eq!(Beacon::decode(&forged, now), None);

        // A genuine beacon with the name changed in transit.
        let mut renamed = beacon.clone();
        renamed.name = PeerName::lossy("Old NAS");
        let genuine = beacon.encode(&secret);
        let tampered = renamed.encode(&secret);
        // The genuine signature (the last 64 bytes) on the renamed fields.
        let mut swapped = tampered[..tampered.len() - 64].to_vec();
        swapped.extend_from_slice(&genuine[genuine.len() - 64..]);
        assert_eq!(Beacon::decode(&swapped, now), None);

        // Version 1 (unsigned) beacons are ignored.
        let mut v1 = b"KVNEAR1".to_vec();
        v1.extend(postcard::to_allocvec(&(&beacon.addr, &beacon.name)).unwrap());
        assert_eq!(Beacon::decode(&v1, now), None);
    }

    #[test]
    fn old_and_future_beacons_are_ignored() {
        let (beacon, secret) = beacon("laptop");
        let bytes = beacon.encode(&secret);
        let sent = beacon.sent_unix;
        assert!(Beacon::decode(&bytes, sent + MAX_BEACON_AGE_SECS).is_some());
        assert!(Beacon::decode(&bytes, sent - MAX_BEACON_AGE_SECS).is_some());
        assert!(Beacon::decode(&bytes, sent + MAX_BEACON_AGE_SECS + 1).is_none());
        assert!(Beacon::decode(&bytes, sent - MAX_BEACON_AGE_SECS - 1).is_none());
    }

    #[test]
    fn relay_urls_are_dropped() {
        let secret = SecretKey::generate();
        let relay: iroh::RelayUrl = "https://relay.example.org".parse().unwrap();
        let addr = EndpointAddr::new(secret.public())
            .with_ip_addr("192.0.2.1:4433".parse().unwrap())
            .with_relay_url(relay);
        let beacon = Beacon::new(addr, PeerName::lossy("laptop"));
        let got = Beacon::decode(&beacon.encode(&secret), beacon.sent_unix).unwrap();
        assert_eq!(got.addr.relay_urls().count(), 0);
        let ips: Vec<_> = got.addr.ip_addrs().copied().collect();
        assert_eq!(ips, ["192.0.2.1:4433".parse().unwrap()]);
    }

    #[test]
    fn beacons_with_bad_names_are_ignored() {
        // Built by hand: PeerName can't hold these, so encode the raw fields.
        let (beacon, secret) = beacon("laptop");
        let now = beacon.sent_unix;
        for name in ["evil\n\u{1b}[2J".to_string(), "x".repeat(257)] {
            let signature = secret
                .sign(
                    &postcard::to_allocvec(&("kinvault beacon v2", &beacon.addr, &name, now))
                        .unwrap(),
                )
                .to_bytes()
                .to_vec();
            let mut bytes = MAGIC.to_vec();
            bytes.extend(postcard::to_allocvec(&(&beacon.addr, &name, now, signature)).unwrap());
            assert_eq!(Beacon::decode(&bytes, now), None, "{name:?}");
        }
    }

    #[test]
    fn default_options_broadcast_and_multicast() {
        let opts = NearbyOptions::default();
        assert_eq!(opts.port, NEARBY_PORT);
        assert_eq!(opts.targets.len(), 2);
    }

    #[test]
    fn code_is_symmetric_and_specific() {
        let a = iroh::SecretKey::generate().public();
        let b = iroh::SecretKey::generate().public();
        let c = iroh::SecretKey::generate().public();
        assert_eq!(pairing_code(&a, &b), pairing_code(&b, &a));
        assert_ne!(pairing_code(&a, &b), pairing_code(&a, &c));
        assert_eq!(pairing_code(&a, &b).len(), 7);
    }

    #[tokio::test]
    async fn beacons_reach_a_listener() {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let opts = NearbyOptions {
            port,
            // An IPv6 target can't be reached from this socket; it's skipped.
            targets: vec![
                "[::1]:9".parse().unwrap(),
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            ],
        };
        let socket = NearbySocket::bind(&opts).unwrap();
        // Stray traffic on the port is ignored.
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .send_to(b"not a beacon", (Ipv4Addr::LOCALHOST, port))
            .unwrap();
        let (beacon, secret) = beacon("nas");
        socket.announce(&beacon, &secret).await;
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.name.as_str(), "nas");
        let addrs: Vec<_> = got.addr.ip_addrs().copied().collect();
        assert!(addrs.contains(&"192.0.2.1:4433".parse().unwrap()));
        assert!(addrs.contains(&"127.0.0.1:4433".parse().unwrap()));
    }
}
