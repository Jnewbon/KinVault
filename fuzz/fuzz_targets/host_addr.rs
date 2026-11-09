//! Host addresses, which peers send in invites and pairing requests.
#![no_main]
use kinvault_net::HostAddr;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(a) = s.parse::<HostAddr>() {
        let again: HostAddr = a.to_string().parse().expect("displayed address parses");
        assert_eq!(again.to_string(), a.to_string());
    }
    let _ = kinvault_net::TimeWindow::parse(s);
});
