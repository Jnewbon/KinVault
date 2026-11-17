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

/// A set that no longer backs up. Its key stays in `sets/<id>` until its
/// backups are erased.
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
    /// Which of the set's places this is: `None` for the main one, else an
    /// [`ExtraTarget`]'s id.
    #[serde(default)]
    pub target_id: Option<String>,
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
    /// Encrypted with the instance's shared key rather than one of its own.
    /// Sets made before keys could be shared each have their own.
    #[serde(default)]
    pub shared_key: bool,
    /// More places that keep copies of the set's backups, each with its own
    /// retention and limits. `target` above is the main one: backups go
    /// there, and the others get copies of the versions they keep.
    #[serde(default)]
    pub extra_targets: Vec<ExtraTarget>,
}

impl SetConfig {
    pub fn extra_target(&self, key: &str) -> Option<&ExtraTarget> {
        self.extra_targets.iter().find(|t| t.id == key)
    }

    /// Every place the set's backups are kept: the main one (`None`), then
    /// the extra ones by id.
    pub fn all_targets(&self) -> impl Iterator<Item = (Option<&str>, &StoredTarget)> {
        std::iter::once((None, &self.target)).chain(
            self.extra_targets
                .iter()
                .map(|t| (Some(t.id.as_str()), &t.target)),
        )
    }
}

/// Another place a set's backups are copied to.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExtraTarget {
    /// Short random id, unique within the set.
    pub id: String,
    pub target: StoredTarget,
    #[serde(default = "api::RetentionPolicy::recommended")]
    pub retention: api::RetentionPolicy,
    #[serde(default)]
    pub upload_limit: Option<u64>,
    /// Only copy automatically inside this daily window (local time).
    #[serde(default)]
    pub window: Option<api::TimeWindow>,
    /// Copies go through the main place's host, which forwards them on its
    /// own (even while this computer is off), instead of from here.
    #[serde(default)]
    pub relay: bool,
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

/// Atomically writes a file readable only by the current user. The data
/// goes to a new temporary file first (never one left over, which could
/// have wider permissions), then replaces `path`.
pub fn write_private(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (mut f, tmp) = loop {
        let suffix = hex::encode(kinvault_core::crypto::random_bytes::<6>()?);
        let tmp = path.with_file_name(format!("{name}.{suffix}.tmp"));
        match opts.open(&tmp) {
            Ok(f) => break (f, tmp),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    };
    let written = f.write_all(data).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = written.and_then(|()| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Creates a directory (and its parents) and makes it readable only by
/// the current user.
pub fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    use anyhow::Context;
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Only the owner may change permissions. A directory we can write to
        // but don't own (e.g. a NAS dataset shared through an ACL) keeps the
        // access its owner gave it.
        match fs::set_permissions(path, fs::Permissions::from_mode(0o700)) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => tracing::warn!(
                "couldn't make {} private ({e}); make sure only KinVault's user can read it",
                path.display()
            ),
            other => other.with_context(|| format!("making {} private", path.display()))?,
        }
    }
    Ok(())
}

/// Like [`create_private_dir`], but leaves an existing directory as it is.
pub fn create_dir_private_if_new(path: &Path) -> anyhow::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    create_private_dir(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn private_files_and_dirs_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("secret");
        // A file (or leftover temporary file) with wider permissions isn't reused.
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(tmp.path().join("secret.tmp"), b"").unwrap();
        fs::set_permissions(
            tmp.path().join("secret.tmp"),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        write_private(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 2);

        let dir = tmp.path().join("state/sets/x");
        create_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
        // An existing folder the user chose keeps its permissions.
        let chosen = tmp.path().join("chosen");
        fs::create_dir(&chosen).unwrap();
        fs::set_permissions(&chosen, fs::Permissions::from_mode(0o750)).unwrap();
        create_dir_private_if_new(&chosen).unwrap();
        assert_eq!(mode(&chosen), 0o750);
        let new = tmp.path().join("hosted");
        create_dir_private_if_new(&new).unwrap();
        assert_eq!(mode(&new), 0o700);
    }

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
