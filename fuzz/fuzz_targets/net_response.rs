//! What a host (possibly a malicious one) sends back to a client.
#![no_main]
use kinvault_net::protocol::Response;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(resp) = postcard::from_bytes::<Response>(data) {
        let bytes = postcard::to_allocvec(&resp).unwrap();
        postcard::from_bytes::<Response>(&bytes).unwrap();
    }
});
