//! Nearby-device beacons: unauthenticated UDP from anyone on the LAN.
#![no_main]
use kinvault_net::nearby::Beacon;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 2048 {
        return;
    }
    if let Some(mut beacon) = Beacon::decode(data) {
        assert!(beacon.name.len() <= 256);
        // As NearbySocket::recv does with the sender's address.
        let from: std::net::IpAddr = [192, 168, 1, 2].into();
        let ports: Vec<u16> = beacon.addr.ip_addrs().map(|a| a.port()).collect();
        for port in ports {
            beacon.addr = beacon.addr.with_ip_addr((from, port).into());
        }
        let _ = kinvault_net::nearby::pairing_code(&beacon.addr.id, &beacon.addr.id);
        // Relay URLs may be normalised on the way, so only check it decodes.
        let again = Beacon::decode(&beacon.encode()).expect("re-encoded beacon decodes");
        assert_eq!(again.name, beacon.name);
        assert_eq!(again.addr.id, beacon.addr.id);
    }
});
