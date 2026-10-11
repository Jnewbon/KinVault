//! Pack files bundle many encrypted blobs so a storage host sees only a few
//! large opaque files instead of one object per chunk.
//!
//! Layout: `blob* || sealed_header || header_len: u32 LE || MAGIC`.
//! The header (blob ids, kinds, offsets) is encrypted with the metadata key.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::crypto::Keys;
use crate::error::{Error, Result};
use crate::ids::{ChunkId, PackId};

const MAGIC: &[u8; 8] = b"KVPACK01";
const TRAILER_LEN: usize = 4 + MAGIC.len();
const HEADER_AAD: &[u8] = b"kinvault pack header v1";
const FRAME_RAW: u8 = 0;
const FRAME_ZSTD: u8 = 1;
const ZSTD_LEVEL: i32 = 3;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlobKind {
    Data,
    Tree,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlobEntry {
    pub id: ChunkId,
    pub kind: BlobKind,
    /// Byte offset of the encrypted blob within the pack.
    pub offset: u64,
    /// Length of the encrypted blob.
    pub len: u32,
}

pub struct FinishedPack {
    pub id: PackId,
    pub data: Vec<u8>,
    pub entries: Vec<BlobEntry>,
}

#[derive(Default)]
pub struct PackBuilder {
    buf: Vec<u8>,
    entries: Vec<BlobEntry>,
    ids: HashSet<ChunkId>,
}

impl PackBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, id: &ChunkId) -> bool {
        self.ids.contains(id)
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn add(
        &mut self,
        keys: &Keys,
        id: ChunkId,
        kind: BlobKind,
        plaintext: &[u8],
    ) -> Result<()> {
        if !self.ids.insert(id) {
            return Ok(());
        }
        let blob = encode_blob(keys, &id, plaintext)?;
        let len =
            u32::try_from(blob.len()).map_err(|_| Error::Invalid("blob exceeds 4 GiB".into()))?;
        self.entries.push(BlobEntry {
            id,
            kind,
            offset: self.buf.len() as u64,
            len,
        });
        self.buf.extend_from_slice(&blob);
        Ok(())
    }

    pub fn finish(mut self, keys: &Keys) -> Result<FinishedPack> {
        let header = postcard::to_allocvec(&self.entries)?;
        let sealed = keys.seal_meta(HEADER_AAD, &header)?;
        self.buf.extend_from_slice(&sealed);
        self.buf
            .extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(MAGIC);
        let id = PackId(*blake3::hash(&self.buf).as_bytes());
        Ok(FinishedPack {
            id,
            data: self.buf,
            entries: self.entries,
        })
    }
}

fn encode_blob(keys: &Keys, id: &ChunkId, plaintext: &[u8]) -> Result<Vec<u8>> {
    let compressed = zstd::bulk::compress(plaintext, ZSTD_LEVEL)?;
    let mut framed = Vec::with_capacity(1 + compressed.len().min(plaintext.len()));
    if compressed.len() < plaintext.len() {
        framed.push(FRAME_ZSTD);
        framed.extend_from_slice(&compressed);
    } else {
        framed.push(FRAME_RAW);
        framed.extend_from_slice(plaintext);
    }
    keys.seal_data(&id.0, &framed)
}

/// Decrypts and decompresses a blob, verifying it hashes to `id`.
pub fn decode_blob(keys: &Keys, id: &ChunkId, blob: &[u8]) -> Result<Vec<u8>> {
    let framed = keys.open_data(&id.0, blob)?;
    let plaintext = match framed.split_first() {
        Some((&FRAME_RAW, rest)) => rest.to_vec(),
        Some((&FRAME_ZSTD, rest)) => zstd::stream::decode_all(rest)?,
        _ => return Err(Error::Corrupt(format!("unknown blob framing in {id:?}"))),
    };
    if keys.chunk_id(&plaintext) != *id {
        return Err(Error::Corrupt(format!(
            "blob {id:?} content does not match its id"
        )));
    }
    Ok(plaintext)
}

pub fn read_header(keys: &Keys, pack: &[u8]) -> Result<Vec<BlobEntry>> {
    if pack.len() < TRAILER_LEN || &pack[pack.len() - MAGIC.len()..] != MAGIC {
        return Err(Error::Corrupt("not a KinVault pack".into()));
    }
    let len_at = pack.len() - TRAILER_LEN;
    let header_len = u32::from_le_bytes(pack[len_at..len_at + 4].try_into().unwrap()) as usize;
    let header_start = len_at
        .checked_sub(header_len)
        .ok_or_else(|| Error::Corrupt("pack header length out of range".into()))?;
    let header = keys.open_meta(HEADER_AAD, &pack[header_start..len_at])?;
    let entries: Vec<BlobEntry> = postcard::from_bytes(&header)?;
    for e in &entries {
        if e.offset + e.len as u64 > header_start as u64 {
            return Err(Error::Corrupt("pack entry points outside blob area".into()));
        }
    }
    Ok(entries)
}

pub fn blob_bytes<'a>(pack: &'a [u8], entry: &BlobEntry) -> Result<&'a [u8]> {
    let start = entry.offset as usize;
    pack.get(start..start + entry.len as usize)
        .ok_or_else(|| Error::Corrupt(format!("blob {:?} outside pack bounds", entry.id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MasterKey;

    #[test]
    fn pack_roundtrip() {
        let keys = MasterKey::generate().unwrap().derive_keys();
        let mut b = PackBuilder::new();
        let blobs: Vec<Vec<u8>> = vec![
            b"aaaaaaaaaaaaaaaaaaaaaaaa".to_vec(),
            vec![7u8; 10_000],
            b"x".to_vec(),
        ];
        for (i, data) in blobs.iter().enumerate() {
            let kind = if i == 1 {
                BlobKind::Tree
            } else {
                BlobKind::Data
            };
            b.add(&keys, keys.chunk_id(data), kind, data).unwrap();
        }
        // Duplicate adds are ignored.
        b.add(&keys, keys.chunk_id(&blobs[0]), BlobKind::Data, &blobs[0])
            .unwrap();
        let pack = b.finish(&keys).unwrap();
        assert_eq!(pack.id, PackId(*blake3::hash(&pack.data).as_bytes()));

        let entries = read_header(&keys, &pack.data).unwrap();
        assert_eq!(entries, pack.entries);
        assert_eq!(entries.len(), 3);
        for (e, data) in entries.iter().zip(&blobs) {
            let got = decode_blob(&keys, &e.id, blob_bytes(&pack.data, e).unwrap()).unwrap();
            assert_eq!(&got, data);
        }
    }

    #[test]
    fn wrong_key_cannot_read_header() {
        let keys = MasterKey::generate().unwrap().derive_keys();
        let other = MasterKey::generate().unwrap().derive_keys();
        let mut b = PackBuilder::new();
        b.add(&keys, keys.chunk_id(b"secret"), BlobKind::Data, b"secret")
            .unwrap();
        let pack = b.finish(&keys).unwrap();
        assert!(matches!(
            read_header(&other, &pack.data),
            Err(Error::Decrypt)
        ));
    }
}
