use std::future::Future;
use std::sync::Arc;

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr};
use kinvault_core::{Backend, PackId, SnapshotId};
use tokio::runtime::Handle;
use tokio::sync::Mutex;

use crate::error::{NetError, transport};
use crate::hosts::with_hosts;
use crate::limits::RateLimiter;
use crate::protocol::{
    ALPN, MAX_OBJECT_LEN, Offer, Op, Request, Response, read_msg, read_payload, valid_repo_name,
    write_msg, write_payload,
};
use crate::receiver::InviteAccepted;
use crate::ticket::InviteTicket;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteStatus {
    pub used_bytes: u64,
    pub quota_bytes: Option<u64>,
}

/// A repository stored on another KinVault instance.
///
/// Implements the synchronous [`Backend`] trait by blocking on `runtime`, so
/// its `Backend` methods must be called from outside the async runtime
/// (e.g. inside `spawn_blocking`). The async methods can be used directly.
pub struct RemoteBackend {
    endpoint: Endpoint,
    addr: EndpointAddr,
    repo: String,
    runtime: Handle,
    hosts: Vec<String>,
    conn: Mutex<Option<Connection>>,
    upload_limit: Option<Arc<RateLimiter>>,
}

impl RemoteBackend {
    pub fn new(
        endpoint: Endpoint,
        addr: impl Into<EndpointAddr>,
        repo: &str,
        runtime: Handle,
    ) -> Result<Self, NetError> {
        if !valid_repo_name(repo) {
            return Err(NetError::Protocol(format!(
                "invalid repository name {repo:?}"
            )));
        }
        Ok(Self {
            endpoint,
            addr: addr.into(),
            repo: repo.to_string(),
            runtime,
            hosts: Vec::new(),
            conn: Mutex::new(None),
            upload_limit: None,
        })
    }

    /// Paces uploads to at most `bytes_per_sec`.
    pub fn with_upload_limit(mut self, bytes_per_sec: Option<u64>) -> Self {
        self.upload_limit = bytes_per_sec.map(|r| Arc::new(RateLimiter::new(r)));
        self
    }

    /// Also dials these configured addresses (see [`crate::HostAddr`]),
    /// resolved afresh for every connection.
    pub fn with_hosts(mut self, hosts: Vec<String>) -> Self {
        self.hosts = hosts;
        self
    }

    pub async fn status(&self) -> Result<RemoteStatus, NetError> {
        match self.call(Op::Status, None).await?.0 {
            Response::Status {
                used_bytes,
                quota_bytes,
            } => Ok(RemoteStatus {
                used_bytes,
                quota_bytes,
            }),
            other => Err(unexpected(&other)),
        }
    }

    /// Asks the host to erase this repository. It is hidden at once and
    /// erased at the returned time (Unix seconds).
    pub async fn delete_repo(&self) -> Result<i64, NetError> {
        match self.call(Op::DeleteRepo, None).await?.0 {
            Response::DeleteScheduled { erase_after_unix } => Ok(erase_after_unix),
            other => Err(unexpected(&other)),
        }
    }

    async fn connection(&self) -> Result<Connection, NetError> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref()
            && conn.close_reason().is_none()
        {
            return Ok(conn.clone());
        }
        let conn = self
            .endpoint
            .connect(with_hosts(self.addr.clone(), &self.hosts).await, ALPN)
            .await
            .map_err(transport)?;
        *guard = Some(conn.clone());
        Ok(conn)
    }

    async fn call(
        &self,
        op: Op,
        payload: Option<&[u8]>,
    ) -> Result<(Response, Option<Vec<u8>>), NetError> {
        let req = Request {
            repo: self.repo.clone(),
            op,
        };
        let mut attempt = 0;
        loop {
            let conn = self.connection().await?;
            match call_once(&conn, &req, payload, self.upload_limit.as_deref()).await {
                // The cached connection went away (idle timeout, network change): reconnect once.
                Err(NetError::Transport(_)) if attempt == 0 && conn.close_reason().is_some() => {
                    attempt += 1;
                    *self.conn.lock().await = None;
                }
                Ok((Response::Error { code, message }, _)) => {
                    return Err(NetError::from_code(code, message));
                }
                result => return result,
            }
        }
    }

    async fn expect_ok(&self, op: Op, payload: Option<&[u8]>) -> Result<(), NetError> {
        match self.call(op, payload).await?.0 {
            Response::Ok => Ok(()),
            other => Err(unexpected(&other)),
        }
    }

    async fn get_data(&self, op: Op) -> Result<Vec<u8>, NetError> {
        match self.call(op, None).await? {
            (Response::Data { .. }, Some(data)) => Ok(data),
            (other, _) => Err(unexpected(&other)),
        }
    }

    fn block<T>(&self, fut: impl Future<Output = Result<T, NetError>>) -> kinvault_core::Result<T> {
        self.runtime.block_on(fut).map_err(Into::into)
    }
}

async fn call_once(
    conn: &Connection,
    req: &Request,
    payload: Option<&[u8]>,
    limiter: Option<&RateLimiter>,
) -> Result<(Response, Option<Vec<u8>>), NetError> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(transport)?;
    let sent = async {
        write_msg(&mut send, req).await?;
        if let Some(data) = payload {
            write_payload(&mut send, data, limiter).await?;
        }
        send.finish().map_err(transport)
    }
    .await;
    // The host may reject an upload before reading it and stop our stream;
    // its response explains why, so prefer it over the write error.
    let resp: Response = match read_msg(&mut recv).await {
        Ok(resp) => resp,
        Err(e) => return Err(sent.err().unwrap_or(e)),
    };
    let data = match resp {
        Response::Data { len } | Response::Tail { len, .. } => {
            Some(read_payload(&mut recv, len, None).await?)
        }
        _ => None,
    };
    Ok((resp, data))
}

/// Claims an invite on the host it was issued by. On success this peer may
/// store backups there. `hosts` are this peer's configured addresses.
pub async fn redeem_invite(
    endpoint: &Endpoint,
    ticket: &InviteTicket,
    name: Option<String>,
    offer: Option<Offer>,
    hosts: Vec<String>,
) -> Result<InviteAccepted, NetError> {
    let conn = endpoint
        .connect(with_hosts(ticket.host.clone(), &ticket.hosts).await, ALPN)
        .await
        .map_err(transport)?;
    let req = Request {
        repo: "invite".into(),
        op: Op::RedeemInvite {
            token: ticket.token,
            name,
            offer,
            hosts,
        },
    };
    let result = call_once(&conn, &req, None, None).await;
    conn.close(0u32.into(), b"done");
    match result?.0 {
        Response::Redeemed {
            host_name,
            quota_bytes,
        } => Ok(InviteAccepted {
            host_name,
            quota_bytes,
        }),
        Response::Error { code, message } => Err(NetError::from_code(code, message)),
        other => Err(unexpected(&other)),
    }
}

/// Asks a nearby peer to pair as one of its owner's devices. Fails with
/// [`NetError::Denied`] until its owner has confirmed this instance too.
/// Returns the peer's name.
pub async fn pair(
    endpoint: &Endpoint,
    addr: EndpointAddr,
    name: String,
    hosts: Vec<String>,
) -> Result<String, NetError> {
    let conn = endpoint.connect(addr, ALPN).await.map_err(transport)?;
    let req = Request {
        repo: "pair".into(),
        op: Op::Pair { name, hosts },
    };
    let result = call_once(&conn, &req, None, None).await;
    conn.close(0u32.into(), b"done");
    match result?.0 {
        Response::Paired { host_name } => Ok(host_name),
        Response::Error { code, message } => Err(NetError::from_code(code, message)),
        other => Err(unexpected(&other)),
    }
}

fn unexpected(resp: &Response) -> NetError {
    NetError::Protocol(format!("unexpected response {resp:?}"))
}

fn object_len(data: &[u8]) -> kinvault_core::Result<u64> {
    let len = data.len() as u64;
    if len > MAX_OBJECT_LEN {
        return Err(kinvault_core::Error::Invalid(format!(
            "object of {len} bytes is too large to send"
        )));
    }
    Ok(len)
}

impl Backend for RemoteBackend {
    fn put_pack(&self, id: &PackId, data: &[u8]) -> kinvault_core::Result<()> {
        let op = Op::PutPack {
            id: *id,
            len: object_len(data)?,
        };
        self.block(self.expect_ok(op, Some(data)))
    }

    fn get_pack(&self, id: &PackId) -> kinvault_core::Result<Vec<u8>> {
        self.block(self.get_data(Op::GetPack { id: *id }))
    }

    fn get_pack_tail(&self, id: &PackId, max_len: u64) -> kinvault_core::Result<(u64, Vec<u8>)> {
        self.block(async {
            match self
                .call(Op::GetPackTail { id: *id, max_len }, None)
                .await?
            {
                (Response::Tail { total_len, .. }, Some(tail)) => Ok((total_len, tail)),
                (other, _) => Err(unexpected(&other)),
            }
        })
    }

    fn list_packs(&self) -> kinvault_core::Result<Vec<PackId>> {
        self.block(async {
            match self.call(Op::ListPacks, None).await?.0 {
                Response::PackIds(ids) => Ok(ids),
                other => Err(unexpected(&other)),
            }
        })
    }

    fn delete_pack(&self, id: &PackId) -> kinvault_core::Result<()> {
        self.block(self.expect_ok(Op::DeletePack { id: *id }, None))
    }

    fn put_snapshot(&self, id: &SnapshotId, data: &[u8]) -> kinvault_core::Result<()> {
        let op = Op::PutSnapshot {
            id: *id,
            len: object_len(data)?,
        };
        self.block(self.expect_ok(op, Some(data)))
    }

    fn get_snapshot(&self, id: &SnapshotId) -> kinvault_core::Result<Vec<u8>> {
        self.block(self.get_data(Op::GetSnapshot { id: *id }))
    }

    fn list_snapshots(&self) -> kinvault_core::Result<Vec<SnapshotId>> {
        self.block(async {
            match self.call(Op::ListSnapshots, None).await?.0 {
                Response::SnapshotIds(ids) => Ok(ids),
                other => Err(unexpected(&other)),
            }
        })
    }

    fn delete_snapshot(&self, id: &SnapshotId) -> kinvault_core::Result<()> {
        self.block(self.expect_ok(Op::DeleteSnapshot { id: *id }, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receiver::{Grant, Receiver};
    use crate::testutil::{FakeHost, Misbehave, addr_of, local_endpoint};

    async fn remote(router: &iroh::protocol::Router) -> RemoteBackend {
        RemoteBackend::new(
            local_endpoint().await,
            addr_of(router),
            "repo",
            Handle::current(),
        )
        .unwrap()
    }

    fn ticket(router: &iroh::protocol::Router) -> InviteTicket {
        InviteTicket {
            host: addr_of(router),
            hosts: Vec::new(),
            host_name: "host".into(),
            token: [0; 16],
            quota_bytes: None,
            ask_reciprocal: false,
            expires_unix: i64::MAX,
        }
    }

    /// Runs the blocking `Backend` calls off the async runtime.
    async fn blocking<T: Send + 'static>(
        remote: &Arc<RemoteBackend>,
        f: impl FnOnce(&RemoteBackend) -> T + Send + 'static,
    ) -> T {
        let remote = remote.clone();
        tokio::task::spawn_blocking(move || f(&remote))
            .await
            .unwrap()
    }

    fn is_protocol_error<T>(r: kinvault_core::Result<T>) -> bool {
        matches!(r, Err(kinvault_core::Error::Backend(m)) if m.starts_with("protocol error"))
    }

    #[tokio::test]
    async fn repository_names_are_checked() {
        let ep = local_endpoint().await;
        let addr = EndpointAddr::new(ep.id());
        let err = RemoteBackend::new(ep, addr, "../x", Handle::current()).err();
        assert!(matches!(err, Some(NetError::Protocol(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unexpected_responses_are_protocol_errors() {
        let host = FakeHost::serve(Misbehave::Reply(Response::Ok)).await;
        let r = Arc::new(remote(&host).await);
        assert!(matches!(r.status().await, Err(NetError::Protocol(_))));
        assert!(matches!(r.delete_repo().await, Err(NetError::Protocol(_))));
        let id = PackId([1; 32]);
        assert!(blocking(&r, move |r| is_protocol_error(r.get_pack(&id))).await);
        assert!(blocking(&r, move |r| is_protocol_error(r.get_pack_tail(&id, 1))).await);
        assert!(blocking(&r, |r| is_protocol_error(r.list_packs())).await);
        assert!(blocking(&r, |r| is_protocol_error(r.list_snapshots())).await);

        let ep = local_endpoint().await;
        let err = pair(&ep, addr_of(&host), "me".into(), Vec::new()).await;
        assert!(matches!(err, Err(NetError::Protocol(_))));
        let err = redeem_invite(&ep, &ticket(&host), None, None, Vec::new()).await;
        assert!(matches!(err, Err(NetError::Protocol(_))));

        let host = FakeHost::serve(Misbehave::Reply(Response::PackIds(Vec::new()))).await;
        let r = Arc::new(remote(&host).await);
        assert!(blocking(&r, move |r| is_protocol_error(r.delete_pack(&id))).await);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oversized_messages_and_objects_are_refused() {
        let host = FakeHost::serve(Misbehave::HugeMessage).await;
        let err = remote(&host).await.status().await.unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");

        let len = MAX_OBJECT_LEN + 1;
        let host = FakeHost::serve(Misbehave::Reply(Response::Data { len })).await;
        let r = Arc::new(remote(&host).await);
        let id = PackId([1; 32]);
        assert!(blocking(&r, move |r| is_protocol_error(r.get_pack(&id))).await);

        // Refused before anything is sent. Zeroed memory is only reserved, not touched.
        let huge = vec![0u8; len as usize];
        let err = blocking(&r, move |r| r.put_pack(&id, &huge)).await;
        assert!(matches!(err, Err(kinvault_core::Error::Invalid(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_dropped_connection_is_retried_once() {
        let host = FakeHost::serve(Misbehave::DropFirstConnection).await;
        let r = Arc::new(remote(&host).await);
        blocking(&r, |r| r.delete_pack(&PackId([1; 32])))
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn uploads_can_be_paced() {
        let tmp = tempfile::tempdir().unwrap();
        let receiver = Receiver::new(tmp.path());
        let host = crate::serve(local_endpoint().await, receiver.clone());
        let ep = local_endpoint().await;
        receiver.allow(ep.id(), Grant::default());
        let r = RemoteBackend::new(ep, addr_of(&host), "repo", Handle::current())
            .unwrap()
            .with_upload_limit(Some(10_000_000))
            .with_hosts(vec!["not an address".into()]);
        let r = Arc::new(r);
        let data = vec![7u8; 200_000];
        let id = PackId(*blake3::hash(&data).as_bytes());
        blocking(&r, move |r| r.put_pack(&id, &data)).await.unwrap();
        assert_eq!(blocking(&r, |r| r.list_packs()).await.unwrap(), vec![id]);
        // Error codes from the host come through as such.
        let missing = PackId([2; 32]);
        let err = blocking(&r, move |r| r.get_pack(&missing)).await;
        assert!(matches!(err, Err(kinvault_core::Error::NotFound(_))));
    }
}
