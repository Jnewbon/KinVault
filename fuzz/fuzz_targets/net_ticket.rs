//! Invite codes pasted in by the user, from someone else.
#![no_main]
use kinvault_net::{HostAddr, InviteTicket};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(t) = InviteTicket::decode(s) {
        // Decoding must only ever produce valid hosts and names.
        assert!(t.hosts.len() <= kinvault_net::protocol::MAX_PEER_HOSTS);
        for h in t.hosts.iter() {
            h.parse::<HostAddr>().expect("decoded host is valid");
        }
        assert!(kinvault_net::protocol::PeerName::new(t.host_name.as_str()).is_ok());
        assert_eq!(InviteTicket::decode(&t.encode()).unwrap(), t);
    }
    // Also try the body without needing the fuzzer to find the prefix.
    let _ = InviteTicket::decode(&format!("kvinvite1{s}"));
});
