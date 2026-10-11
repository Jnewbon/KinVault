//! Local control socket: a Unix socket on Unix (inside the private state
//! directory, mode 0600), a named pipe on Windows. Each line sent is a JSON
//! [`Request`]; each line received is a JSON `Result<Reply, String>`.
//! Requests on one connection are answered in order.

use std::io;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::api::{Reply, Request};
use crate::daemon::Daemon;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("kinvaultd is not running (could not connect to {0})")]
    NotRunning(String),
    #[error("lost connection to kinvaultd: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Daemon(String),
}

/// Unix socket paths must fit in `sockaddr_un.sun_path` (104 bytes on macOS).
#[cfg(unix)]
const MAX_SOCKET_PATH: usize = 100;

#[cfg(unix)]
pub fn endpoint_name(state_dir: &Path) -> PathBuf {
    let path = state_dir.join("kinvaultd.sock");
    if path.as_os_str().len() <= MAX_SOCKET_PATH {
        return path;
    }
    // Too long for a socket: use a per-state-dir name in the user's runtime
    // directory instead. The socket itself is still created with mode 0600.
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let hash = fnv1a(state_dir.to_string_lossy().as_bytes());
    dir.join(format!("kinvaultd-{hash:016x}.sock"))
}

#[cfg(windows)]
pub fn endpoint_name(state_dir: &Path) -> PathBuf {
    let hash = fnv1a(state_dir.to_string_lossy().as_bytes());
    PathBuf::from(format!(r"\\.\pipe\kinvaultd-{hash:016x}"))
}

fn fnv1a(data: &[u8]) -> u64 {
    // FNV-1a; only needs to separate state directories, not resist attackers.
    data.iter().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ *b as u64).wrapping_mul(0x100000001b3)
    })
}

async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin>(
    daemon: Daemon,
    stream: S,
) -> io::Result<()> {
    let (read, mut write) = tokio::io::split(stream);
    let mut lines = BufReader::new(read).lines();
    while let Some(line) = lines.next_line().await? {
        let reply = match serde_json::from_str::<Request>(&line) {
            Ok(req) => daemon.handle(req).await,
            Err(e) => Err(format!("malformed request: {e}")),
        };
        let mut out = serde_json::to_string(&reply).map_err(io::Error::other)?;
        out.push('\n');
        write.write_all(out.as_bytes()).await?;
    }
    Ok(())
}

/// The daemon's control socket. Binding it doubles as the single-instance
/// lock, so it is done before anything else starts.
pub struct Listener {
    #[cfg(unix)]
    inner: tokio::net::UnixListener,
    #[cfg(windows)]
    inner: tokio::net::windows::named_pipe::NamedPipeServer,
    path: PathBuf,
}

impl Listener {
    #[cfg(unix)]
    pub async fn bind(path: &Path) -> io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            if tokio::net::UnixStream::connect(path).await.is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "kinvaultd is already running",
                ));
            }
            std::fs::remove_file(path)?;
        }
        let inner = tokio::net::UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            inner,
            path: path.to_path_buf(),
        })
    }

    #[cfg(windows)]
    pub async fn bind(path: &Path) -> io::Result<Self> {
        use tokio::net::windows::named_pipe::ServerOptions;
        let inner = ServerOptions::new()
            .first_pipe_instance(true)
            .create(path.as_os_str())
            .map_err(|e| {
                io::Error::new(e.kind(), format!("kinvaultd may already be running: {e}"))
            })?;
        Ok(Self {
            inner,
            path: path.to_path_buf(),
        })
    }

    /// Accepts control connections until the future is dropped.
    #[cfg(unix)]
    pub async fn serve(self, daemon: Daemon) -> io::Result<()> {
        loop {
            let (stream, _) = self.inner.accept().await?;
            let daemon = daemon.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_connection(daemon, stream).await {
                    tracing::debug!("control connection ended: {e}");
                }
            });
        }
    }

    #[cfg(windows)]
    pub async fn serve(mut self, daemon: Daemon) -> io::Result<()> {
        use tokio::net::windows::named_pipe::ServerOptions;
        loop {
            self.inner.connect().await?;
            let next = ServerOptions::new().create(self.path.as_os_str())?;
            let connected = std::mem::replace(&mut self.inner, next);
            let daemon = daemon.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_connection(daemon, connected).await {
                    tracing::debug!("control connection ended: {e}");
                }
            });
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Connection to a running daemon.
pub struct Client {
    #[cfg(unix)]
    stream: BufReader<tokio::net::UnixStream>,
    #[cfg(windows)]
    stream: BufReader<tokio::net::windows::named_pipe::NamedPipeClient>,
}

impl Client {
    pub async fn connect(state_dir: &Path) -> Result<Self, ClientError> {
        let path = endpoint_name(state_dir);
        let not_running = |_| ClientError::NotRunning(path.display().to_string());
        #[cfg(unix)]
        let stream = tokio::net::UnixStream::connect(&path)
            .await
            .map_err(not_running)?;
        #[cfg(windows)]
        let stream = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(path.as_os_str())
            .map_err(not_running)?;
        Ok(Self {
            stream: BufReader::new(stream),
        })
    }

    pub async fn call(&mut self, request: &Request) -> Result<Reply, ClientError> {
        let mut line = serde_json::to_string(request).map_err(io::Error::other)?;
        line.push('\n');
        self.stream.get_mut().write_all(line.as_bytes()).await?;
        let mut response = String::new();
        if self.stream.read_line(&mut response).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "daemon closed the connection",
            )
            .into());
        }
        let reply: Result<Reply, String> =
            serde_json::from_str(&response).map_err(io::Error::other)?;
        reply.map_err(ClientError::Daemon)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn long_state_dirs_get_short_socket_paths() {
        let short = Path::new("/home/me/.local/share/KinVault");
        assert_eq!(endpoint_name(short), short.join("kinvaultd.sock"));
        let long = PathBuf::from(format!("/tmp/{}", "x".repeat(150)));
        let name = endpoint_name(&long);
        assert!(name.as_os_str().len() <= MAX_SOCKET_PATH + 40, "{name:?}");
        assert_ne!(name, endpoint_name(&long.join("other")));
    }
}
