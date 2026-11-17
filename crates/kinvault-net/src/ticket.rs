//! Invite codes: everything a friend needs to reach a host and claim access.

use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};

use crate::error::NetError;
use crate::protocol::{PeerHosts, PeerName};

const PREFIX: &str = "kvinvite1";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct InviteTicket {
    pub host: EndpointAddr,
    /// Addresses the host's owner configured (IPs or domain names, with ports).
    /// Both come from whoever made the invite, and are checked while decoding.
    pub hosts: PeerHosts,
    pub host_name: PeerName,
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
        let mut ticket: Self = postcard::from_bytes(&bytes).map_err(|_| invalid())?;
        ticket.host = trusted_relays_only(ticket.host);
        Ok(ticket)
    }
}

/// Drops relay servers other than iroh's default ones from an address
/// someone else made, so an invite can't have this instance contact a
/// server of the sender's choosing. The host is still found through its
/// home relay by discovery.
fn trusted_relays_only(addr: EndpointAddr) -> EndpointAddr {
    let defaults = iroh::defaults::prod::default_relay_map();
    let mut kept = EndpointAddr::new(addr.id);
    for ip in addr.ip_addrs() {
        kept = kept.with_ip_addr(*ip);
    }
    for relay in addr.relay_urls() {
        if defaults.contains(relay) {
            kept = kept.with_relay_url(relay.clone());
        } else {
            tracing::debug!("ignoring relay {relay} named in an invite");
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_default_relays_are_kept() {
        let ours = iroh::defaults::prod::default_relay_map()
            .urls::<Vec<iroh::RelayUrl>>()
            .remove(0);
        let theirs: iroh::RelayUrl = "https://relay.attacker.example".parse().unwrap();
        let addr = EndpointAddr::new(iroh::SecretKey::generate().public())
            .with_ip_addr("192.0.2.1:4433".parse().unwrap())
            .with_relay_url(ours.clone())
            .with_relay_url(theirs);
        let t = InviteTicket {
            host: addr,
            hosts: PeerHosts::lossy(Vec::new()),
            host_name: PeerName::lossy("nas"),
            token: [1; 16],
            quota_bytes: None,
            ask_reciprocal: false,
            expires_unix: 0,
        };
        let got = InviteTicket::decode(&t.encode()).unwrap();
        let relays: Vec<_> = got.host.relay_urls().cloned().collect();
        assert_eq!(relays, [ours]);
        assert_eq!(got.host.ip_addrs().count(), 1);
    }

    #[test]
    fn roundtrip() {
        let addr = EndpointAddr::new(iroh::SecretKey::generate().public())
            .with_ip_addr("192.0.2.1:4433".parse().unwrap());
        let t = InviteTicket {
            host: addr,
            hosts: PeerHosts::lossy(vec!["backup.example.org:4433".into()]),
            host_name: PeerName::lossy("alice-nas"),
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
