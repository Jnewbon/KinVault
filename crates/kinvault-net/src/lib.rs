//! Instance-to-instance transport. Instances are addressed by their iroh
//! public key; iroh handles hole-punching and falls back to relays, so no
//! port forwarding is needed. Senders use [`RemoteBackend`] as a
//! `kinvault_core::Backend`; hosts run a [`Receiver`] that stores each
//! authorised peer's opaque objects in its own directory.

mod client;
mod error;
mod identity;
pub mod protocol;
mod receiver;

pub use client::{RemoteBackend, RemoteStatus};
pub use error::NetError;
pub use identity::load_or_create_secret;
pub use iroh::protocol::Router;
pub use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
pub use receiver::{Grant, Receiver};

use iroh::endpoint::presets;

/// Binds an endpoint with the default discovery and relay servers.
pub async fn bind(secret: SecretKey) -> Result<Endpoint, NetError> {
    Endpoint::builder(presets::N0)
        .secret_key(secret)
        .bind()
        .await
        .map_err(error::transport)
}

/// Starts accepting KinVault connections on `endpoint`.
pub fn serve(endpoint: Endpoint, receiver: Receiver) -> Router {
    Router::builder(endpoint)
        .accept(protocol::ALPN, receiver)
        .spawn()
}
