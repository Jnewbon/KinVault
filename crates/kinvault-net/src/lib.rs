//! Instance-to-instance transport. Instances are addressed by their iroh
//! public key; iroh handles hole-punching and falls back to relays, so no
//! port forwarding is needed. Senders use [`RemoteBackend`] as a
//! `kinvault_core::Backend`; hosts run a [`Receiver`] that stores each
//! authorised peer's opaque objects in its own directory.

mod client;
mod error;
mod hosts;
mod identity;
mod limits;
pub mod nearby;
pub mod protocol;
mod receiver;
mod ticket;

pub use client::{RemoteBackend, RemoteStatus, pair, ping, redeem_invite};
pub use error::NetError;
pub use hosts::{HostAddr, InvalidHostAddr, with_hosts};
pub use identity::load_or_create_secret;
pub use iroh::protocol::Router;
pub use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
pub use limits::{RateLimiter, TimeWindow};
pub use protocol::Offer;
pub use receiver::{
    Grant, InviteAccepted, InviteHandler, InviteRedemption, PairHandler, PairRequest, PeerUsage,
    REPO_DELETE_DELAY, Receiver,
};
pub use ticket::InviteTicket;

use std::net::{Ipv4Addr, Ipv6Addr};

use iroh::endpoint::{BindOpts, presets};

/// Binds an endpoint with the default discovery and relay servers. With a
/// `port`, it listens on that UDP port (so it can be forwarded on a router)
/// instead of a random one.
pub async fn bind(secret: SecretKey, port: Option<u16>) -> Result<Endpoint, NetError> {
    let mut builder = Endpoint::builder(presets::N0).secret_key(secret);
    if let Some(port) = port {
        builder = builder
            .bind_addr((Ipv4Addr::UNSPECIFIED, port))
            .map_err(error::transport)?
            // Not every machine has IPv6; carry on with IPv4 alone then.
            .bind_addr_with_opts(
                (Ipv6Addr::UNSPECIFIED, port),
                BindOpts::default().set_is_required(false),
            )
            .map_err(error::transport)?;
    }
    builder.bind().await.map_err(error::transport)
}

/// Starts accepting KinVault connections on `endpoint`.
pub fn serve(endpoint: Endpoint, receiver: Receiver) -> Router {
    Router::builder(endpoint)
        .accept(protocol::ALPN, receiver)
        .spawn()
}
