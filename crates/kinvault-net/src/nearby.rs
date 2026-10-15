//! Finding the user's other devices on the local network, so they can be
//! paired without copying an invite code. While pairing, each instance
//! broadcasts a small beacon with its id, addresses and name, and listens for
//! the beacons of others. Beacons are unauthenticated: the actual pairing runs
//! over an authenticated connection, and users compare a [`pairing_code`]
//! shown on both devices before confirming.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use iroh::{EndpointAddr, EndpointId};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

/// UDP port beacons are sent to and received on.
pub const NEARBY_PORT: u16 = 47101;
/// Administratively scoped multicast group, for networks that drop broadcasts.
const MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 71, 1);
const MAGIC: &[u8] = b"KVNEAR1";
const MAX_BEACON_LEN: usize = 2048;

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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Beacon {
    pub addr: EndpointAddr,
    pub name: String,
}

impl Beacon {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend(postcard::to_allocvec(self).expect("beacon serializes"));
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let body = bytes.strip_prefix(MAGIC)?;
        let beacon: Self = postcard::from_bytes(body).ok()?;
        (beacon.name.len() <= 256).then_some(beacon)
    }
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

    /// Sends the beacon to every target; unreachable ones are skipped.
    pub async fn announce(&self, beacon: &Beacon) {
        let bytes = beacon.encode();
        for target in &self.targets {
            if let Err(e) = self.socket.send_to(&bytes, target).await {
                tracing::debug!("sending beacon to {target} failed: {e}");
            }
        }
    }

    /// Waits for the next valid beacon. Its addresses include the one it was
    /// sent from, at each of the sender's listening ports.
    pub async fn recv(&self) -> io::Result<Beacon> {
        let mut buf = vec![0u8; MAX_BEACON_LEN];
        loop {
            let (len, from) = self.socket.recv_from(&mut buf).await?;
            let Some(mut beacon) = Beacon::decode(&buf[..len]) else {
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

    #[test]
    fn beacon_roundtrip() {
        let addr = EndpointAddr::new(iroh::SecretKey::generate().public())
            .with_ip_addr("192.0.2.1:4433".parse().unwrap());
        let beacon = Beacon {
            addr,
            name: "laptop".into(),
        };
        assert_eq!(Beacon::decode(&beacon.encode()), Some(beacon));
        assert_eq!(Beacon::decode(b"hello"), None);
        assert_eq!(Beacon::decode(b"KVNEAR1garbage"), None);
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
        let id = iroh::SecretKey::generate().public();
        let beacon = Beacon {
            addr: EndpointAddr::new(id).with_ip_addr("192.0.2.1:4433".parse().unwrap()),
            name: "nas".into(),
        };
        socket.announce(&beacon).await;
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.name, "nas");
        let addrs: Vec<_> = got.addr.ip_addrs().copied().collect();
        assert!(addrs.contains(&"192.0.2.1:4433".parse().unwrap()));
        assert!(addrs.contains(&"127.0.0.1:4433".parse().unwrap()));
    }
}
