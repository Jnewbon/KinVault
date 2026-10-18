//! Local control socket: a Unix socket on Unix (inside the private state
//! directory, mode 0600), a named pipe on Windows (named with a secret kept
//! in the state directory; see [`listen_name`]). Each line sent is a JSON
//! [`Request`]; each line received is a JSON `Result<Reply, String>`.
//! Requests on one connection are answered in order.

use std::io;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::api::{Event, Reply, Request};
use crate::daemon::Daemon;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("kinvaultd is not running for {0}")]
    NotRunning(String),
    #[error("lost connection to kinvaultd: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Daemon(String),
}

/// Unix socket paths must fit in `sockaddr_un.sun_path` (104 bytes on macOS).
#[cfg(unix)]
const MAX_SOCKET_PATH: usize = 100;

/// File in the state directory holding the random part of the control
/// endpoint's name, when the endpoint lives outside the state directory.
/// That name can't be guessed without reading the (private) state
/// directory, so another local user can't create the endpoint first and
/// pose as the daemon.
const NAME_FILE: &str = "ipc-name";

/// The control endpoint a client connects to, or `None` if no daemon has
/// ever served `state_dir`.
pub fn endpoint_name(state_dir: &Path) -> Option<PathBuf> {
    #[cfg(unix)]
    if let Some(path) = socket_in_state_dir(state_dir) {
        return Some(path);
    }
    let secret = std::fs::read_to_string(state_dir.join(NAME_FILE)).ok()?;
    let secret = secret.trim();
    valid_secret(secret).then(|| shared_endpoint(secret))
}

/// The control endpoint the daemon serving `state_dir` listens on, creating
/// its name the first time.
pub fn listen_name(state_dir: &Path) -> io::Result<PathBuf> {
    #[cfg(unix)]
    if let Some(path) = socket_in_state_dir(state_dir) {
        return Ok(path);
    }
    if old_daemon_running(state_dir) {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "an older kinvaultd is still running for this state directory; \
             stop it (or restart the computer) before starting this one",
        ));
    }
    if let Some(path) = endpoint_name(state_dir) {
        return Ok(path);
    }
    let secret =
        hex::encode(kinvault_core::crypto::random_bytes::<16>().map_err(io::Error::other)?);
    // Write it whole under a temporary name, then link it into place, which
    // fails if another daemon got there first: then use its name instead.
    let path = state_dir.join(NAME_FILE);
    let tmp = state_dir.join(format!("{NAME_FILE}.{secret}.tmp"));
    crate::config::write_private(&tmp, secret.as_bytes()).map_err(io::Error::other)?;
    let linked = std::fs::hard_link(&tmp, &path);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(shared_endpoint(&secret)),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => endpoint_name(state_dir)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "damaged ipc-name file")),
        Err(e) => Err(e),
    }
}

/// The endpoint used outside the state directory before the secret name: a
/// hash of its path, which anyone could work out.
fn old_endpoint_name(state_dir: &Path) -> PathBuf {
    // FNV-1a.
    let hash = state_dir
        .to_string_lossy()
        .bytes()
        .fold(0xcbf29ce484222325u64, |h, b| {
            (h ^ b as u64).wrapping_mul(0x100000001b3)
        });
    #[cfg(unix)]
    return std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("kinvaultd-{hash:016x}.sock"));
    #[cfg(windows)]
    return PathBuf::from(format!(r"\\.\pipe\kinvaultd-{hash:016x}"));
}

/// Whether something answers on the old, guessable endpoint for
/// `state_dir`. That is most likely a daemon from before the upgrade still
/// running, which new clients can no longer find: starting a second daemon
/// beside it could damage the state directory, so refuse instead. (Another
/// user squatting the old name can only stop the daemon starting this way,
/// not pose as it.)
fn old_daemon_running(state_dir: &Path) -> bool {
    let path = old_endpoint_name(state_dir);
    #[cfg(unix)]
    return std::os::unix::net::UnixStream::connect(path).is_ok();
    #[cfg(windows)]
    {
        // ERROR_PIPE_BUSY: it exists, but every instance is in use.
        const ERROR_PIPE_BUSY: i32 = 231;
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
        {
            Ok(_) => true,
            Err(e) => e.raw_os_error() == Some(ERROR_PIPE_BUSY),
        }
    }
}

fn valid_secret(secret: &str) -> bool {
    secret.len() == 32 && secret.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The socket inside the private state directory, if its path is short
/// enough for a socket.
#[cfg(unix)]
fn socket_in_state_dir(state_dir: &Path) -> Option<PathBuf> {
    let path = state_dir.join("kinvaultd.sock");
    (path.as_os_str().len() <= MAX_SOCKET_PATH).then_some(path)
}

/// A state directory's path is too long for a socket: use a secretly named
/// one in the user's runtime directory instead. The socket itself is still
/// created with mode 0600.
#[cfg(unix)]
fn shared_endpoint(secret: &str) -> PathBuf {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    dir.join(format!("kinvaultd-{secret}.sock"))
}

#[cfg(windows)]
fn shared_endpoint(secret: &str) -> PathBuf {
    PathBuf::from(format!(r"\\.\pipe\kinvaultd-{secret}"))
}

/// Whether a daemon is serving `state_dir` (blocking check).
pub fn daemon_running(state_dir: &Path) -> bool {
    let Some(path) = endpoint_name(state_dir) else {
        return false;
    };
    #[cfg(unix)]
    return std::os::unix::net::UnixStream::connect(path).is_ok();
    #[cfg(windows)]
    return std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .is_ok();
}

async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin>(
    daemon: Daemon,
    stream: S,
) -> io::Result<()> {
    let (read, mut write) = tokio::io::split(stream);
    let mut lines = BufReader::new(read).lines();
    while let Some(line) = lines.next_line().await? {
        let request = serde_json::from_str::<Request>(&line);
        if matches!(request, Ok(Request::Subscribe)) {
            let events = daemon.subscribe();
            write_line(&mut write, &Ok::<Reply, String>(Reply::Subscribed)).await?;
            return stream_events(events, &mut write, lines).await;
        }
        let reply = match request {
            Ok(req) => daemon.handle(req).await,
            Err(e) => Err(format!("malformed request: {e}")),
        };
        write_line(&mut write, &reply).await?;
    }
    Ok(())
}

async fn write_line<W: AsyncWrite + Unpin, T: serde::Serialize>(
    write: &mut W,
    value: &T,
) -> io::Result<()> {
    let mut out = serde_json::to_string(value).map_err(io::Error::other)?;
    out.push('\n');
    write.write_all(out.as_bytes()).await
}

/// Sends events until the client goes away.
async fn stream_events<W: AsyncWrite + Unpin, R: tokio::io::AsyncBufRead + Unpin>(
    mut events: tokio::sync::broadcast::Receiver<Event>,
    write: &mut W,
    mut lines: tokio::io::Lines<R>,
) -> io::Result<()> {
    use tokio::sync::broadcast::error::RecvError;
    loop {
        tokio::select! {
            event = events.recv() => match event {
                Ok(event) => write_line(write, &event).await?,
                // Too slow to keep up: tell the client to refresh everything.
                Err(RecvError::Lagged(_)) => {
                    write_line(write, &Event::SetsChanged).await?;
                    write_line(write, &Event::PeersChanged).await?;
                }
                Err(RecvError::Closed) => return Ok(()),
            },
            // The client closed its side.
            line = lines.next_line() => if line?.is_none() { return Ok(()) },
        }
    }
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
            .map_err(|e| match e.kind() {
                // Another process holds the first instance of this pipe.
                io::ErrorKind::PermissionDenied => {
                    io::Error::new(io::ErrorKind::AddrInUse, "kinvaultd is already running")
                }
                _ => e,
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
        let Some(path) = endpoint_name(state_dir) else {
            return Err(ClientError::NotRunning(state_dir.display().to_string()));
        };
        // Names the state directory rather than the endpoint, whose name is
        // meant to stay private.
        let not_running = |_| ClientError::NotRunning(state_dir.display().to_string());
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

    /// Turns this connection into a stream of daemon events.
    pub async fn subscribe(mut self) -> Result<EventStream, ClientError> {
        self.call(&Request::Subscribe).await?;
        Ok(EventStream { client: self })
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
    fn short_state_dirs_keep_their_socket_inside() {
        let short = Path::new("/home/me/.local/share/KinVault");
        assert_eq!(endpoint_name(short), Some(short.join("kinvaultd.sock")));
        assert_eq!(listen_name(short).unwrap(), short.join("kinvaultd.sock"));
    }

    #[test]
    fn long_state_dirs_get_secret_socket_names() {
        let tmp = tempfile::tempdir().unwrap();
        let long = tmp.path().join("x".repeat(150));
        std::fs::create_dir_all(&long).unwrap();
        // Nothing to connect to until a daemon has picked a name.
        assert_eq!(endpoint_name(&long), None);
        let name = listen_name(&long).unwrap();
        assert!(name.as_os_str().len() <= MAX_SOCKET_PATH + 40, "{name:?}");
        assert_eq!(listen_name(&long).unwrap(), name);
        assert_eq!(endpoint_name(&long), Some(name.clone()));
        // The name comes from the state directory, not from its path.
        let other = tmp.path().join("y".repeat(150));
        std::fs::create_dir_all(&other).unwrap();
        assert_ne!(listen_name(&other).unwrap(), name);
        // Only the name file is left behind.
        let files: Vec<_> = std::fs::read_dir(&long)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(files, vec![std::ffi::OsString::from(NAME_FILE)]);
        // A damaged name file doesn't point anywhere.
        std::fs::write(long.join(NAME_FILE), "../../somewhere").unwrap();
        assert_eq!(endpoint_name(&long), None);
    }

    #[test]
    fn an_old_daemon_still_running_blocks_a_new_one() {
        let tmp = tempfile::tempdir().unwrap();
        let long = tmp.path().join("z".repeat(150));
        std::fs::create_dir_all(&long).unwrap();
        let old = old_endpoint_name(&long);
        let _ = std::fs::remove_file(&old);
        let listener = std::os::unix::net::UnixListener::bind(&old).unwrap();
        let err = listen_name(&long).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        // A leftover socket nobody answers on doesn't count.
        drop(listener);
        assert!(listen_name(&long).is_ok());
        let _ = std::fs::remove_file(&old);
    }
}

/// Events from [`Client::subscribe`].
pub struct EventStream {
    client: Client,
}

impl EventStream {
    /// The next event, or `None` once the daemon has gone away.
    pub async fn next(&mut self) -> Option<Event> {
        loop {
            let mut line = String::new();
            match self.client.stream.read_line(&mut line).await {
                Ok(0) | Err(_) => return None,
                Ok(_) => match serde_json::from_str(&line) {
                    Ok(event) => return Some(event),
                    Err(e) => tracing::debug!("ignoring unknown event: {e}"),
                },
            }
        }
    }
}
