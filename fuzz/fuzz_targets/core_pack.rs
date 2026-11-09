//! Packs fetched back from a host: the trailer and length handling run
//! before decryption, and entries must never point outside the pack.
#![no_main]
use kinvault_core::MasterKey;
use kinvault_core::pack::{BlobEntry, blob_bytes, header_tail_len, read_header_tail};
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

static KEYS: LazyLock<kinvault_core::Keys> =
    LazyLock::new(|| MasterKey::from_bytes([3; 32]).derive_keys());

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let (len, rest) = data.split_at(8);
    let pack_len = u64::from_le_bytes(len.try_into().unwrap());
    let _ = header_tail_len(rest);
    let _ = read_header_tail(&KEYS, pack_len, rest);
    let _ = read_header_tail(&KEYS, rest.len() as u64, rest);
    // Entries as if from a decrypted header, against the same bytes.
    if let Ok(entries) = postcard::from_bytes::<Vec<BlobEntry>>(rest) {
        for e in &entries {
            let _ = blob_bytes(rest, e);
        }
    }
});
