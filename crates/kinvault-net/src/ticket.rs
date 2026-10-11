//! Invite codes: everything a friend needs to reach a host and claim access.

use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};

use crate::error::NetError;

const PREFIX: &str = "kvinvite1";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct InviteTicket {
    pub host: EndpointAddr,
    pub host_name: String,
    /// One-time secret; the host only stores its hash.
    pub token: [u8; 16],
    /// Storage the host offers, `None` for unlimited.
    pub quota_bytes: Option<u64>,
    /// The host would like the friend to store its backups in return.
    pub ask_reciprocal: bool,
    pub expires_unix: i64,
}

impl InviteTicket {
    pub fn encode(&self) -> String {
        let bytes = postcard::to_allocvec(self).expect("ticket serializes");
        format!(
            "{PREFIX}{}",
            data_encoding::BASE32_NOPAD
                .encode(&bytes)
                .to_ascii_lowercase()
        )
    }

    pub fn decode(s: &str) -> Result<Self, NetError> {
        let invalid = || NetError::Protocol("this is not a valid KinVault invite code".into());
        let body = s.trim().strip_prefix(PREFIX).ok_or_else(invalid)?;
        let bytes = data_encoding::BASE32_NOPAD
            .decode(body.to_ascii_uppercase().as_bytes())
            .map_err(|_| invalid())?;
        postcard::from_bytes(&bytes).map_err(|_| invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let addr = EndpointAddr::new(iroh::SecretKey::generate().public())
            .with_ip_addr("192.0.2.1:4433".parse().unwrap());
        let t = InviteTicket {
            host: addr,
            host_name: "alice-nas".into(),
            token: [7; 16],
            quota_bytes: Some(1 << 40),
            ask_reciprocal: true,
            expires_unix: 1_800_000_000,
        };
        let code = t.encode();
        assert!(code.starts_with("kvinvite1"));
        assert_eq!(InviteTicket::decode(&code).unwrap(), t);
        assert_eq!(
            InviteTicket::decode(&code.to_uppercase().replace("KVINVITE1", "kvinvite1")).unwrap(),
            t
        );
        assert!(InviteTicket::decode("kvinvite1abc").is_err());
        assert!(InviteTicket::decode("hello").is_err());
    }
}
