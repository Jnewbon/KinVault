use std::future::Future;

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr};
use kinvault_core::{Backend, PackId, SnapshotId};
use tokio::runtime::Handle;
use tokio::sync::Mutex;

use crate::error::{NetError, transport};
use crate::protocol::{
    ALPN, MAX_OBJECT_LEN, Op, Request, Response, read_msg, read_payload, valid_repo_name, write_msg,
};

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
    conn: Mutex<Option<Connection>>,
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
            conn: Mutex::new(None),
        })
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

    async fn connection(&self) -> Result<Connection, NetError> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref()
            && conn.close_reason().is_none()
        {
            return Ok(conn.clone());
        }
        let conn = self
            .endpoint
            .connect(self.addr.clone(), ALPN)
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
            match call_once(&conn, &req, payload).await {
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
) -> Result<(Response, Option<Vec<u8>>), NetError> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(transport)?;
    let sent = async {
        write_msg(&mut send, req).await?;
        if let Some(data) = payload {
            send.write_all(data).await.map_err(transport)?;
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
            Some(read_payload(&mut recv, len).await?)
        }
        _ => None,
    };
    Ok((resp, data))
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
