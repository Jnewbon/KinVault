//! Packs fetched back from a host. Three paths:
//! - raw bytes through the trailer and header-length handling, which run
//!   before decryption;
//! - real, correctly encrypted packs read back with a fuzzer-chosen pack
//!   length and tail size, so the entry bounds loop in read_header_tail
//!   runs (random bytes never get past decryption);
//! - arbitrary entries through the bounds checks directly, including
//!   offsets near u64::MAX that a real pack never holds.
#![no_main]
use std::sync::LazyLock;

use kinvault_core::MasterKey;
use kinvault_core::pack::{
    BlobEntry, BlobKind, PackBuilder, blob_bytes, check_entries, header_tail_len, read_header,
    read_header_tail,
};
use libfuzzer_sys::fuzz_target;

static KEYS: LazyLock<kinvault_core::Keys> =
    LazyLock::new(|| MasterKey::from_bytes([3; 32]).derive_keys());

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    let (head, rest) = data.split_at(9);
    let pack_len = u64::from_le_bytes(head[..8].try_into().unwrap());

    // Raw bytes.
    let _ = header_tail_len(rest);
    let _ = read_header_tail(&KEYS, pack_len, rest);

    // A real pack built from the input, read back with fuzzed lengths.
    let mut builder = PackBuilder::new();
    for blob in rest.chunks(64).take(16) {
        builder
            .add(&KEYS, KEYS.chunk_id(blob), BlobKind::Data, blob)
            .unwrap();
    }
    let pack = builder.finish(&KEYS).unwrap();
    let entries = read_header(&KEYS, &pack.data).expect("a real pack reads back");
    assert_eq!(entries, pack.entries);
    for e in &entries {
        blob_bytes(&pack.data, e).expect("real entries are in bounds");
    }
    // Shorter tails and wrong pack lengths must fail cleanly, never panic.
    let tail_len = (head[8] as usize * 64).min(pack.data.len());
    let tail = &pack.data[pack.data.len() - tail_len..];
    let _ = read_header_tail(&KEYS, pack_len % (2 * pack.data.len() as u64 + 1), tail);

    // Arbitrary entries.
    if let Ok(entries) = postcard::from_bytes::<Vec<BlobEntry>>(rest) {
        let _ = check_entries(&entries, pack_len);
        for e in &entries {
            let _ = blob_bytes(rest, e);
        }
    }
});
