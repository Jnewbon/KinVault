//! Nearby-device beacons: UDP from anyone on the LAN. Random input never
//! carries a valid signature, so besides decoding raw bytes this also
//! signs a beacon built from the input and checks that changing any byte
//! can't produce a different beacon that still verifies.
#![no_main]
use std::sync::LazyLock;

use iroh::{EndpointAddr, SecretKey};
use kinvault_net::nearby::{Beacon, MAX_BEACON_AGE_SECS};
use kinvault_net::protocol::PeerName;
use libfuzzer_sys::fuzz_target;

static KEY: LazyLock<SecretKey> = LazyLock::new(|| SecretKey::from_bytes(&[9; 32]));
const NOW: i64 = 1_800_000_000;

fn check(beacon: &Beacon) {
    // Decoding must only ever produce valid names and no relay URLs.
    assert!(PeerName::new(beacon.name.as_str()).is_ok());
    assert_eq!(beacon.addr.relay_urls().count(), 0);
    assert!(NOW.abs_diff(beacon.sent_unix) <= MAX_BEACON_AGE_SECS as u64);
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 2048 {
        return;
    }
    if let Some(beacon) = Beacon::decode(data, NOW) {
        check(&beacon);
    }

    // A genuine beacon built from the input.
    let Some((&flip, rest)) = data.split_first() else {
        return;
    };
    let mut addr = EndpointAddr::new(KEY.public());
    for port in rest.chunks_exact(2).take(4) {
        let port = u16::from_le_bytes([port[0], port[1]]);
        addr = addr.with_ip_addr(([192, 0, 2, 1], port).into());
    }
    let name = PeerName::lossy(&String::from_utf8_lossy(rest));
    let beacon = Beacon {
        addr,
        name,
        sent_unix: NOW - (flip as i64),
    };
    let bytes = beacon.encode(&KEY);
    let got = Beacon::decode(&bytes, NOW).expect("a genuine beacon decodes");
    check(&got);
    assert_eq!(got, beacon);

    // Any single changed byte either fails or decodes to the same beacon.
    let mut tampered = bytes.clone();
    let i = (flip as usize * 7) % tampered.len();
    tampered[i] ^= 1 | flip;
    if let Some(t) = Beacon::decode(&tampered, NOW) {
        assert_eq!(t, beacon, "a changed beacon still verified");
    }
});
