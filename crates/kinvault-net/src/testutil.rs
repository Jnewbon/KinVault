//! Helpers for tests that talk the protocol over localhost, including hosts
//! and clients that break it on purpose.

use std::sync::atomic::{AtomicUsize, Ordering};

use iroh::endpoint::{Connection, presets};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, SecretKey};

use crate::error::{NetError, transport};
use crate::protocol::{ALPN, Request, Response, read_msg, write_msg};

/// An endpoint on 127.0.0.1 without relays or discovery.
pub async fn local_endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap()
}

pub fn addr_of(router: &Router) -> EndpointAddr {
    let ep = router.endpoint();
    EndpointAddr::new(ep.id()).with_ip_addr(ep.bound_sockets()[0])
}

/// A request as it goes on the wire.
pub fn encode(req: &Request) -> Vec<u8> {
    let body = postcard::to_allocvec(req).unwrap();
    let mut out = (body.len() as u32).to_le_bytes().to_vec();
    out.extend(body);
    out
}

/// Sends `bytes` on a new stream and reads the host's response.
pub async fn raw_call(
    ep: &Endpoint,
    addr: EndpointAddr,
    bytes: &[u8],
) -> Result<Response, NetError> {
    let conn = ep.connect(addr, ALPN).await.map_err(transport)?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(transport)?;
    // The host may stop reading early; its response says why.
    let _ = send.write_all(bytes).await;
    let _ = send.finish();
    read_msg(&mut recv).await
}

#[derive(Debug)]
pub enum Misbehave {
    /// Answers every request with this response.
    Reply(Response),
    /// Announces a response far larger than any message may be.
    HugeMessage,
    /// Closes the first connection mid-request, then answers `Ok`.
    DropFirstConnection,
}

/// A host that breaks the protocol in one particular way.
#[derive(Debug)]
pub struct FakeHost {
    behaviour: Misbehave,
    connections: AtomicUsize,
}

impl FakeHost {
    pub async fn serve(behaviour: Misbehave) -> Router {
        let host = Self {
            behaviour,
            connections: AtomicUsize::new(0),
        };
        Router::builder(local_endpoint().await)
            .accept(ALPN, host)
            .spawn()
    }
}

impl ProtocolHandler for FakeHost {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let first = self.connections.fetch_add(1, Ordering::SeqCst) == 0;
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let _: Request = read_msg(&mut recv).await.unwrap();
            match &self.behaviour {
                Misbehave::Reply(resp) => write_msg(&mut send, resp).await.unwrap(),
                Misbehave::HugeMessage => send.write_all(&u32::MAX.to_le_bytes()).await.unwrap(),
                Misbehave::DropFirstConnection if first => {
                    conn.close(0u32.into(), b"gone");
                    return Ok(());
                }
                Misbehave::DropFirstConnection => {
                    write_msg(&mut send, &Response::Ok).await.unwrap()
                }
            }
            send.finish().unwrap();
        }
        Ok(())
    }
}
