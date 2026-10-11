use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::api;

/// Persistent daemon configuration (`config.json` in the state directory).
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Config {
    /// Where hosted peers' data is stored; defaults to `<state>/hosted`.
    #[serde(default)]
    pub hosting_store: Option<PathBuf>,
    #[serde(default)]
    pub peers: Vec<PeerEntry>,
    #[serde(default)]
    pub sets: Vec<SetConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerEntry {
    pub id: String,
    pub name: Option<String>,
    pub quota_bytes: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SetConfig {
    pub id: String,
    pub name: String,
    pub paths: Vec<PathBuf>,
    pub target: StoredTarget,
    pub debounce_secs: u64,
    pub rescan_secs: u64,
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
