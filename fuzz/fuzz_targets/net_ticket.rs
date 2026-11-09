//! Invite codes pasted in by the user, from someone else.
#![no_main]
use kinvault_net::{HostAddr, InviteTicket};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(t) = InviteTicket::decode(s) {
        for h in &t.hosts {
            let _ = h.parse::<HostAddr>();
        }
        assert_eq!(InviteTicket::decode(&t.encode()).unwrap(), t);
    }
    // Also try the body without needing the fuzzer to find the prefix.
    let _ = InviteTicket::decode(&format!("kvinvite1{s}"));
});
