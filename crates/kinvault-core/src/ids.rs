use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            pub fn from_hex(s: &str) -> Result<Self> {
                let mut out = [0u8; 32];
                hex::decode_to_slice(s, &mut out)
                    .map_err(|e| Error::Invalid(format!("bad {} {s:?}: {e}", stringify!($name))))?;
                Ok(Self(out))
            }

            pub fn from_slice(bytes: &[u8]) -> Result<Self> {
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| Error::Corrupt(format!("{} must be 32 bytes", stringify!($name))))?;
                Ok(Self(arr))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), &self.to_hex()[..12])
            }
        }
    };
}

id_type!(
    /// Keyed BLAKE3 hash of a blob's plaintext. Keyed so a storage host can't
    /// test whether a known file is present.
    ChunkId
);
id_type!(
    /// BLAKE3 hash of a pack's ciphertext; lets a host verify integrity without keys.
    PackId
);
id_type!(
    /// BLAKE3 hash of an encrypted snapshot record.
    SnapshotId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_bytes_are_checked() {
        let id = PackId([0xab; 32]);
        assert_eq!(PackId::from_hex(&id.to_hex()).unwrap(), id);
        assert!(matches!(PackId::from_hex("abc"), Err(Error::Invalid(_))));
        assert_eq!(PackId::from_slice(&[0xab; 32]).unwrap(), id);
        assert!(matches!(
            PackId::from_slice(&[0; 31]),
            Err(Error::Corrupt(_))
        ));
        assert_eq!(format!("{id}"), "ab".repeat(32));
        assert_eq!(format!("{id:?}"), "PackId(abababababab)");
    }
}
