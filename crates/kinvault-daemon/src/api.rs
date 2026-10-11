//! Requests and replies of the local control API. Sent as one JSON object per
//! line over the daemon's socket; see [`crate::ipc`].

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    Status,
    CreateSet(CreateSet),
    /// Stops a backup set. Its keys are kept locally; remote data is untouched.
    RemoveSet {
        set: String,
    },
    /// Runs a backup now and waits for it to finish.
    BackupNow {
        set: String,
    },
    ListSnapshots {
        set: String,
    },
    Restore {
        set: String,
        snapshot: String,
        target: PathBuf,
        include: Option<String>,
    },
    /// Storage used by a set's owner on the host it backs up to.
    RemoteUsage {
        set: String,
    },
    PeerAllow {
        id: String,
        name: Option<String>,
        quota_bytes: Option<u64>,
    },
    PeerRevoke {
        id: String,
    },
    PeerList,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateSet {
    pub name: String,
    pub paths: Vec<PathBuf>,
    pub target: Target,
    /// Wraps the set's key in a recovery file; needed to restore on a new machine.
    pub recovery_passphrase: String,
    /// Quiet period after a change before backing up (default 30 s).
    pub debounce_secs: Option<u64>,
    /// Interval between full rescans that catch missed changes (default 6 h).
    pub rescan_secs: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    Local {
        path: PathBuf,
    },
    Peer {
        id: String,
        /// Known direct addresses; optional, the peer is otherwise found by id.
        #[serde(default)]
        addrs: Vec<SocketAddr>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Reply {
    Status(DaemonStatus),
    SetCreated {
        id: String,
    },
    Done,
    Backup(BackupSummary),
    Snapshots(Vec<SnapshotInfo>),
    Restored(RestoreSummary),
    Usage {
        used_bytes: u64,
        quota_bytes: Option<u64>,
    },
    Peers(Vec<PeerInfo>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DaemonStatus {
    /// This instance's id; peers use it to allow it or to back up to it.
    pub id: String,
    pub version: String,
    pub hosting_store: PathBuf,
    pub sets: Vec<SetStatus>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SetStatus {
    pub id: String,
    pub name: String,
    pub paths: Vec<PathBuf>,
    pub target: Target,
    pub state: SetState,
    pub last_backup: Option<BackupSummary>,
    pub last_error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SetState {
    Idle,
    /// Changes seen; waiting for them to settle before backing up.
    ChangesPending,
    Running,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BackupSummary {
    pub snapshot: String,
    pub time_ns: i64,
    pub files: u64,
    pub files_changed: u64,
    pub total_bytes: u64,
    pub bytes_uploaded: u64,
    pub warnings: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SnapshotInfo {
    pub id: String,
    pub time_ns: i64,
    pub hostname: String,
    pub paths: Vec<String>,
    pub file_count: u64,
    pub total_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RestoreSummary {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub bytes: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerInfo {
    pub id: String,
    pub name: Option<String>,
    pub quota_bytes: Option<u64>,
    pub used_bytes: u64,
}
