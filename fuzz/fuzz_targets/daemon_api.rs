//! Requests from the desktop app, the CLI's control socket and the web UI.
#![no_main]
use kinvault_daemon::api::Request;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = serde_json::from_slice::<Request>(data) {
        let s = serde_json::to_string(&req).unwrap();
        serde_json::from_str::<Request>(&s).unwrap();
    }
});
