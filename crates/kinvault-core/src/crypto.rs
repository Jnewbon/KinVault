use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::ids::ChunkId;

pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const KEYFILE_AAD: &[u8] = b"kinvault keyfile v1";

pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| Error::Rng)?;
    Ok(buf)
}

/// Root secret of a backup set. Never leaves the sending instance except
/// inside a passphrase-wrapped [`KeyFile`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(random_bytes()?))
    }

    pub fn derive_keys(&self) -> Keys {
        Keys {
            chunk_id: blake3::derive_key("kinvault v1 chunk-id key", &self.0),
            data: blake3::derive_key("kinvault v1 data key", &self.0),
            meta: blake3::derive_key("kinvault v1 metadata key", &self.0),
        }
    }
}

/// Purpose-separated sub-keys derived from a [`MasterKey`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Keys {
    chunk_id: [u8; KEY_LEN],
    data: [u8; KEY_LEN],
    meta: [u8; KEY_LEN],
}

impl Keys {
    pub fn chunk_id(&self, plaintext: &[u8]) -> ChunkId {
        ChunkId(*blake3::keyed_hash(&self.chunk_id, plaintext).as_bytes())
    }

    pub fn seal_data(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        seal(&self.data, aad, plaintext)
    }

    pub fn open_data(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        open(&self.data, aad, sealed)
    }

    pub fn seal_meta(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        seal(&self.meta, aad, plaintext)
    }

    pub fn open_meta(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        open(&self.meta, aad, sealed)
    }
}

/// XChaCha20-Poly1305 with a random nonce; output is `nonce || ciphertext || tag`.
pub fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce: [u8; NONCE_LEN] = random_bytes()?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Invalid("plaintext too large to encrypt".into()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(key: &[u8; KEY_LEN], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Decrypt);
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::Decrypt)
}

/// A [`MasterKey`] wrapped with an Argon2id-derived key. Safe to write to disk
/// and to include in a recovery kit; useless without the passphrase.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyFile {
    pub version: u32,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: String,
    pub wrapped: String,
}

impl KeyFile {
    pub fn create(master: &MasterKey, passphrase: &str) -> Result<Self> {
        Self::create_with_params(master, passphrase, 64 * 1024, 3, 1)
    }

    pub fn create_with_params(
        master: &MasterKey,
        passphrase: &str,
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<Self> {
        let salt: [u8; 16] = random_bytes()?;
        let mut kek = derive_kek(passphrase, &salt, m_cost_kib, t_cost, p_cost)?;
        let wrapped = seal(&kek, KEYFILE_AAD, &master.0);
        kek.zeroize();
        Ok(Self {
            version: 1,
            m_cost_kib,
            t_cost,
            p_cost,
            salt: hex::encode(salt),
            wrapped: hex::encode(wrapped?),
        })
    }

    pub fn unlock(&self, passphrase: &str) -> Result<MasterKey> {
        if self.version != 1 {
            return Err(Error::Invalid(format!(
                "unsupported keyfile version {}",
                self.version
            )));
        }
        let salt =
            hex::decode(&self.salt).map_err(|e| Error::Corrupt(format!("keyfile salt: {e}")))?;
        let wrapped =
            hex::decode(&self.wrapped).map_err(|e| Error::Corrupt(format!("keyfile key: {e}")))?;
        let mut kek = derive_kek(passphrase, &salt, self.m_cost_kib, self.t_cost, self.p_cost)?;
        let opened = open(&kek, KEYFILE_AAD, &wrapped);
        kek.zeroize();
        let mut raw = opened.map_err(|_| Error::WrongPassphrase)?;
        let key: [u8; KEY_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| Error::Corrupt("keyfile key has wrong length".into()))?;
        raw.zeroize();
        Ok(MasterKey(key))
    }
}

fn derive_kek(passphrase: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(m, t, p, Some(KEY_LEN)).map_err(|e| Error::Invalid(e.to_string()))?;
    let mut out = [0u8; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_tamper() {
        let keys = MasterKey::generate().unwrap().derive_keys();
        let sealed = keys.seal_data(b"aad", b"hello").unwrap();
        assert_eq!(keys.open_data(b"aad", &sealed).unwrap(), b"hello");
        assert!(matches!(
            keys.open_data(b"other", &sealed),
            Err(Error::Decrypt)
        ));
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(matches!(keys.open_data(b"aad", &bad), Err(Error::Decrypt)));
        // Data and metadata keys are separated.
        assert!(keys.open_meta(b"aad", &sealed).is_err());
    }

    #[test]
    fn keyfile_unlock() {
        let master = MasterKey::generate().unwrap();
        let kf = KeyFile::create_with_params(&master, "correct horse", 64, 1, 1).unwrap();
        let unlocked = kf.unlock("correct horse").unwrap();
        assert_eq!(unlocked.0, master.0);
        assert!(matches!(kf.unlock("wrong"), Err(Error::WrongPassphrase)));
    }

    #[test]
    fn chunk_ids_depend_on_key() {
        let a = MasterKey::generate().unwrap().derive_keys();
        let b = MasterKey::generate().unwrap().derive_keys();
        assert_eq!(a.chunk_id(b"x"), a.chunk_id(b"x"));
        assert_ne!(a.chunk_id(b"x"), b.chunk_id(b"x"));
    }
}
