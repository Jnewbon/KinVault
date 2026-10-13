use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::api;

/// Persistent daemon configuration (`config.json` in the state directory).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    /// Name friends see for this instance (defaults to the hostname).
    #[serde(default)]
    pub name: Option<String>,
    /// Where hosted peers' data is stored; defaults to `<state>/hosted`.
    #[serde(default)]
    pub hosting_store: Option<PathBuf>,
    /// Days that deleted data is kept before it is really removed: data a
    /// peer deletes here, and our own sets that were stopped.
    #[serde(default = "default_grace_days")]
    pub keep_deleted_days: u64,
    /// What older versions saved instead. New installs saved 0 by mistake
    /// (meaning "erase at once"), so only a value chosen by hand carries over.
    #[serde(default, rename = "trash_grace_days", skip_serializing)]
    legacy_trash_grace_days: Option<u64>,
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
    /// Deleted sets whose backups still need erasing.
    #[serde(default)]
    pub pending_deletions: Vec<PendingDeletion>,
    /// Sets that stopped backing up. They can still be restored from until
    /// `keep_deleted_days` have passed; then their backups are erased.
    #[serde(default)]
    pub stopped_sets: Vec<StoppedSet>,
}

/// A set that no longer backs up. Its key is in `removed-sets/<id>`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoppedSet {
    pub set: SetConfig,
    pub stopped_unix: i64,
}

/// A deleted set's backups: a host still to be told to erase them, or a
/// local folder to erase once `erase_after_unix` has passed.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PendingDeletion {
    pub set_id: String,
    pub set_name: String,
    pub target: StoredTarget,
    pub requested_unix: i64,
    #[serde(default)]
    pub erase_after_unix: Option<i64>,
}

pub const DEFAULT_GRACE_DAYS: u64 = 30;

fn default_grace_days() -> u64 {
    DEFAULT_GRACE_DAYS
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
    /// One of this user's own devices rather than a friend's.
    #[serde(default)]
    pub mine: bool,
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
    #[serde(default)]
    pub mine: bool,
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
    /// Files and folders to leave out; see [`kinvault_core::Excludes`].
    #[serde(default)]
    pub excludes: Vec<String>,
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

impl Default for Config {
    /// The same defaults as a config file that sets nothing.
    fn default() -> Self {
        serde_json::from_str("{}").expect("every field has a default")
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
                    mine: false,
                });
                self.peers.len() - 1
            }
        };
        &mut self.peers[pos]
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => {
                let mut config: Self = serde_json::from_str(&text)?;
                if let Some(days) = config.legacy_trash_grace_days.take()
                    && days > 0
                {
                    config.keep_deleted_days = days;
                }
                Ok(config)
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deleted_data_is_kept_for_30_days_by_default() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.json");
        assert_eq!(Config::default().keep_deleted_days, DEFAULT_GRACE_DAYS);
        assert_eq!(Config::load(&path).unwrap().keep_deleted_days, 30);

        // Older versions saved 0 for new installs by mistake; that isn't kept.
        fs::write(&path, r#"{"trash_grace_days": 0}"#).unwrap();
        assert_eq!(Config::load(&path).unwrap().keep_deleted_days, 30);
        // A value chosen by hand is.
        fs::write(&path, r#"{"trash_grace_days": 14}"#).unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.keep_deleted_days, 14);
        config.save(&path).unwrap();
        let saved = fs::read_to_string(&path).unwrap();
        assert!(!saved.contains("trash_grace_days"), "{saved}");
        assert_eq!(Config::load(&path).unwrap().keep_deleted_days, 14);
    }
}
