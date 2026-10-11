use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::api;

/// Persistent daemon configuration (`config.json` in the state directory).
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Config {
    /// Name friends see for this instance (defaults to the hostname).
    #[serde(default)]
    pub name: Option<String>,
    /// Where hosted peers' data is stored; defaults to `<state>/hosted`.
    #[serde(default)]
    pub hosting_store: Option<PathBuf>,
    /// Days that data a peer deletes is kept before it is really removed.
    #[serde(default = "default_grace_days")]
    pub trash_grace_days: u64,
    /// Fixed UDP port to listen on (random if unset), for port forwarding.
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Addresses (IPs or domain names, optional port) put in invite codes.
    #[serde(default)]
    pub public_hosts: Vec<String>,
    #[serde(default)]
    pub peers: Vec<PeerEntry>,
    #[serde(default)]
    pub invites: Vec<PendingInvite>,
    #[serde(default)]
    pub sets: Vec<SetConfig>,
}

fn default_grace_days() -> u64 {
    30
}

/// Another instance we know, in either direction.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerEntry {
    pub id: String,
    pub name: Option<String>,
    /// Known direct addresses (from an invite); discovery is used otherwise.
    #[serde(default)]
    pub addrs: Vec<SocketAddr>,
    /// Addresses its owner configured (`host:port`), resolved at each connection.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Set if this peer may store backups here.
    #[serde(default)]
    pub grant: Option<api::GrantSpec>,
    /// Set if this peer agreed to store our backups.
    #[serde(default)]
    pub hosts_us: Option<api::HostOffer>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PendingInvite {
    pub id: String,
    /// BLAKE3 of the token, so a leaked config can't be used to redeem it.
    pub token_hash: String,
    pub name: Option<String>,
    pub grant: api::GrantSpec,
    pub ask_reciprocal: bool,
    pub expires_unix: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SetConfig {
    pub id: String,
    pub name: String,
    pub paths: Vec<PathBuf>,
    pub target: StoredTarget,
    pub debounce_secs: u64,
    pub rescan_secs: u64,
    #[serde(default)]
    pub upload_limit: Option<u64>,
    #[serde(default)]
    pub window: Option<api::TimeWindow>,
    #[serde(default = "api::RetentionPolicy::recommended")]
    pub retention: api::RetentionPolicy,
    /// Paused sets don't back up automatically.
    #[serde(default)]
    pub paused: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoredTarget {
    Local {
        path: PathBuf,
    },
    Peer {
        id: String,
        /// Random repository name on the host, so it learns nothing from it.
        repo: String,
        #[serde(default)]
        addrs: Vec<SocketAddr>,
        #[serde(default)]
        hosts: Vec<String>,
    },
}

impl StoredTarget {
    pub fn to_api(&self) -> api::Target {
        match self {
            Self::Local { path } => api::Target::Local { path: path.clone() },
            Self::Peer { id, addrs, .. } => api::Target::Peer {
                id: id.clone(),
                addrs: addrs.clone(),
            },
        }
    }
}

impl Config {
    pub fn peer_mut(&mut self, id: &str) -> &mut PeerEntry {
        let pos = match self.peers.iter().position(|p| p.id == id) {
            Some(pos) => pos,
            None => {
                self.peers.push(PeerEntry {
                    id: id.to_string(),
                    name: None,
                    addrs: Vec::new(),
                    hosts: Vec::new(),
                    grant: None,
                    hosts_us: None,
                });
                self.peers.len() - 1
            }
        };
        &mut self.peers[pos]
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => Ok(serde_json::from_str(&text)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        write_private(path, serde_json::to_string_pretty(self)?.as_bytes())
    }
}

/// Atomically writes a file readable only by the current user.
pub fn write_private(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}
