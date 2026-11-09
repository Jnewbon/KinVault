//! What any peer, known or not, can send a host: a request, then for
//! `Forward` a forwarding order. Decoding, the signature checks and the
//! repository name check must never panic.
#![no_main]
use kinvault_net::protocol::{ForwardOrder, Op, Request, valid_repo_name};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let me = iroh::SecretKey::from_bytes(&[7; 32]).public();
    if let Ok(req) = postcard::from_bytes::<Request>(data) {
        let _ = valid_repo_name(&req.repo);
        if let Op::Deliver { delegation, item } = &req.op {
            let _ = delegation.check(&me, &me, &req.repo, 0);
            if let kinvault_net::protocol::Delivery::Delete(d) = item {
                let _ = d.check(&me, &req.repo, 0);
            }
        }
        // Whatever decodes must encode again.
        let bytes = postcard::to_allocvec(&req).unwrap();
        postcard::from_bytes::<Request>(&bytes).unwrap();
    }
    if let Ok(order) = postcard::from_bytes::<ForwardOrder>(data) {
        let d = &order.delegation;
        let _ = d.check(&me, &d.host, &d.repo, 0);
        for del in &order.deletions {
            let _ = del.check(&d.host, &d.repo, 0);
        }
    }
});
