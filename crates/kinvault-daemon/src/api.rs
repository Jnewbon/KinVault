//! Requests and replies of the local control API. Sent as one JSON object per
//! line over the daemon's socket; see [`crate::ipc`].

use std::net::SocketAddr;
use std::path::PathBuf;

pub use kinvault_core::RetentionPolicy;
pub use kinvault_net::{HostAddr, TimeWindow};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    Status,
    /// Sets the name friends see for this instance.
    SetInstanceName {
        name: String,
    },
    CreateSet(CreateSet),
    /// Stops a backup set. It can still be restored from until the grace
    /// period (`keep_deleted_days`) is over; then its backups are erased, as
    /// for [`Request::DeleteSet`], and its key once they're gone.
    RemoveSet {
        set: String,
    },
    /// Deletes a set (running or stopped) and its backups for good: its key
    /// is erased here, and the place it backs up to erases the backups a
    /// week later. Succeeds even if that place can't be reached; it is asked
    /// again later.
    DeleteSet {
        set: String,
    },
    /// Sets how many days deleted data is kept before it's erased: data
    /// peers delete here, and sets stopped with [`Request::RemoveSet`].
    SetKeepDeletedDays {
        days: u64,
    },
    /// Changes a set's upload limit and time window.
    SetLimits {
        set: String,
        upload_limit: Option<u64>,
        window: Option<TimeWindow>,
    },
    /// Changes which files and folders a set leaves out, from its next
    /// backup on. Earlier snapshots keep them until retention removes them.
    SetExcludes {
        set: String,
        excludes: Vec<String>,
    },
    /// Changes which snapshots a set keeps; takes effect at the next prune.
    SetRetention {
        set: String,
        policy: RetentionPolicy,
    },
    /// Stops automatic backups of a set (restores still work).
    PauseSet {
        set: String,
    },
    /// Resumes automatic backups, optionally backing up different paths
    /// (e.g. after restoring onto a new machine).
    ResumeSet {
        set: String,
        paths: Option<Vec<PathBuf>>,
    },
    /// Runs a backup now (ignoring the set's time window) and waits for it to finish.
    BackupNow {
        set: String,
    },
    /// Removes snapshots the retention policy doesn't keep and frees their space.
    Prune {
        set: String,
    },
    /// Checks the set's backups; downloads up to `max_bytes` of data to decrypt and check.
    Verify {
        set: String,
        max_bytes: Option<u64>,
    },
    /// Everything needed to restore this instance's backups on a new machine,
    /// with all keys encrypted under `passphrase`.
    ExportRecoveryKit {
        passphrase: String,
    },
    /// Turns this connection into a stream of [`Event`]s, one JSON object per
    /// line, after a `Subscribed` reply.
    Subscribe,
    ListSnapshots {
        set: String,
    },
    Restore {
        set: String,
        snapshot: String,
        target: PathBuf,
        include: Option<String>,
    },
    /// Starts restoring in the background and answers at once with
    /// `RestoreStarted`; progress and the result arrive as events.
    StartRestore {
        set: String,
        snapshot: String,
        target: PathBuf,
        include: Option<String>,
    },
    /// Stops a background restore. Files restored so far are kept.
    CancelRestore {
        id: String,
    },
    /// Storage used by a set's owner on the host it backs up to.
    RemoteUsage {
        set: String,
    },
    /// Lets a peer store backups here (or updates its limits).
    PeerAllow {
        id: String,
        name: Option<String>,
        grant: GrantSpec,
    },
    /// Stops accepting backups from a peer; what it stored is kept.
    PeerRevoke {
        id: String,
    },
    PeerList,
    /// Forgets a peer: it can no longer store backups here, and what it
    /// stored is erased a week later. Refused while a set backs up to it.
    PeerRemove {
        id: String,
    },
    /// Moves a peer to or from "mine" (this user's own devices). Marking it
    /// mine also lets it store backups here without limits.
    PeerSetMine {
        id: String,
        mine: bool,
    },
    /// Creates a one-time invite code a friend can redeem to store backups here.
    CreateInvite(CreateInvite),
    ListInvites,
    CancelInvite {
        id: String,
    },
    /// This instance's listening port and the addresses it puts in invites.
    GetNetwork,
    /// Changes them. A new port takes effect when the daemon restarts.
    SetNetwork(NetworkSettings),
    /// Redeems a friend's invite code, optionally offering them storage in return.
    RedeemInvite {
        ticket: String,
        /// What to call the host locally (defaults to the name it gives).
        name: Option<String>,
        offer: Option<GrantSpec>,
        /// The host is one of this user's own devices: offer it unlimited
        /// storage (instead of `offer`) and list it under "mine".
        #[serde(default)]
        mine: bool,
    },
    /// Looks for this user's other devices on the local network for a few
    /// minutes (restarting the countdown if already looking).
    FindNearby,
    StopNearby,
    NearbyStatus,
    /// Confirms a nearby device as one of this user's own. They are paired
    /// once it has been confirmed on the other device too.
    PairNearby {
        id: String,
    },
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
    /// Maximum upload rate in bytes per second.
    #[serde(default)]
    pub upload_limit: Option<u64>,
    /// Only back up automatically inside this daily window (local time).
    #[serde(default)]
    pub window: Option<TimeWindow>,
    /// Which snapshots to keep (default: [`RetentionPolicy::recommended`]).
    #[serde(default)]
    pub retention: Option<RetentionPolicy>,
    /// Files and folders to leave out, e.g. `*.o` or `target/...`; see
    /// [`kinvault_core::Excludes`].
    #[serde(default)]
    pub excludes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CreateInvite {
    /// What to call the friend once they join.
    pub name: Option<String>,
    pub grant: GrantSpec,
    /// Ask the friend to store this instance's backups in return.
    pub ask_reciprocal: bool,
    /// Validity period (default 7 days).
    pub expires_secs: Option<u64>,
    /// For one of this user's own devices: it may store backups here without
    /// limits (instead of `grant`), is asked to do the same, and is listed
    /// under "mine".
    #[serde(default)]
    pub mine: bool,
}

/// Limits for a peer storing backups on this instance.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GrantSpec {
    #[serde(default)]
    pub quota_bytes: Option<u64>,
    /// Maximum upload rate in bytes per second.
    #[serde(default)]
    pub upload_limit: Option<u64>,
    /// Only accept uploads inside this daily window (local time).
    #[serde(default)]
    pub window: Option<TimeWindow>,
}

impl GrantSpec {
    pub fn to_grant(self) -> kinvault_net::Grant {
        kinvault_net::Grant {
            quota_bytes: self.quota_bytes,
            upload_limit: self.upload_limit,
            window: self.window,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    Local {
        path: PathBuf,
    },
    Peer {
        /// Peer id, or the name of a known peer.
        id: String,
        /// Known direct addresses; optional, the peer is otherwise found by id.
        #[serde(default)]
        addrs: Vec<SocketAddr>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkSettings {
    /// Fixed UDP port to listen on; `None` picks a random free port at start.
    pub listen_port: Option<u16>,
    /// IPs or domain names, each with an optional `:port` (default: the
    /// listening port), that invite codes tell friends to try.
    pub public_hosts: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkInfo {
    #[serde(flatten)]
    pub settings: NetworkSettings,
    /// Local addresses the daemon is listening on right now.
    pub bound: Vec<SocketAddr>,
    /// The listening port was changed; restart the daemon to use it.
    pub restart_required: bool,
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
    Invite {
        id: String,
        ticket: String,
        expires_unix: i64,
    },
    Invites(Vec<InviteInfo>),
    Redeemed {
        host_id: String,
        host_name: String,
        quota_bytes: Option<u64>,
        ask_reciprocal: bool,
    },
    Pruned(PruneSummary),
    Verified(VerifySummary),
    RecoveryKit {
        json: String,
    },
    Subscribed,
    Network(NetworkInfo),
    Nearby(NearbyStatus),
    SetDeleted(DeletedSet),
    RestoreStarted {
        id: String,
    },
}

/// What happened to a deleted set's backups.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeletedSet {
    /// When the backups are erased, if known (Unix seconds).
    pub erase_after_unix: Option<i64>,
    /// Why the backups' host couldn't be told (yet).
    pub error: Option<String>,
    /// The host couldn't be reached; it will be asked again.
    pub retrying: bool,
}

/// Something changed in the daemon; streamed to subscribers.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    SetState {
        set: String,
        state: SetState,
    },
    Progress {
        set: String,
        files: u64,
        total_bytes: u64,
        bytes_read: u64,
        bytes_uploaded: u64,
    },
    /// How far cleaning up old versions or checking the backups got.
    MaintenanceProgress {
        set: String,
        step: MaintenanceStep,
        /// Done and total in this step: bytes for `Repacking` and
        /// `Checking`, otherwise items.
        done: u64,
        total: u64,
    },
    BackupFinished {
        set: String,
        summary: BackupSummary,
    },
    BackupFailed {
        set: String,
        error: String,
    },
    /// Sets were created, removed or reconfigured, or maintenance ran.
    SetsChanged,
    /// Peers or invites changed.
    PeersChanged,
    /// The listening port or public addresses changed.
    NetworkChanged,
    /// A host that keeps backups went offline or came back online.
    PeerOnline {
        id: String,
        online: bool,
    },
    /// Finding nearby devices started or stopped, or found or paired one.
    NearbyChanged,
    /// A background restore started or made progress.
    RestoreProgress(RestoreJob),
    RestoreFinished {
        id: String,
        set: String,
        summary: RestoreSummary,
    },
    RestoreFailed {
        id: String,
        set: String,
        error: String,
        /// The user cancelled it.
        cancelled: bool,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DaemonStatus {
    /// This instance's id; peers use it to allow it or to back up to it.
    pub id: String,
    pub name: String,
    pub version: String,
    pub hosting_store: PathBuf,
    pub sets: Vec<SetStatus>,
    /// Sets that no longer back up but can still be restored from.
    #[serde(default)]
    pub stopped_sets: Vec<StoppedSetStatus>,
    /// Days deleted data is kept before it's erased.
    #[serde(default)]
    pub keep_deleted_days: u64,
    /// Restores running in the background.
    #[serde(default)]
    pub restores: Vec<RestoreJob>,
}

/// A restore running in the background.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RestoreJob {
    pub id: String,
    /// The set's id.
    pub set: String,
    pub set_name: String,
    pub snapshot: String,
    pub target: PathBuf,
    pub files: u64,
    pub bytes: u64,
    /// What it restores in total; 0 until known.
    pub total_files: u64,
    pub total_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SetStatus {
    pub id: String,
    pub name: String,
    pub paths: Vec<PathBuf>,
    pub target: Target,
    pub upload_limit: Option<u64>,
    pub window: Option<TimeWindow>,
    pub retention: RetentionPolicy,
    #[serde(default)]
    pub excludes: Vec<String>,
    pub state: SetState,
    /// Whether the host it backs up to is reachable; `None` for a local
    /// folder or a host not checked yet.
    #[serde(default)]
    pub target_online: Option<bool>,
    pub last_backup: Option<BackupSummary>,
    pub last_error: Option<String>,
    pub last_prune: Option<PruneSummary>,
    pub last_verify: Option<VerifySummary>,
}

/// A set that stopped backing up, kept for restoring until `erase_after_unix`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoppedSetStatus {
    pub id: String,
    pub name: String,
    pub paths: Vec<PathBuf>,
    pub target: Target,
    pub stopped_unix: i64,
    /// When its backups are due to be erased (Unix seconds).
    pub erase_after_unix: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SetState {
    Idle,
    /// Changes seen; waiting for them to settle before backing up.
    ChangesPending,
    /// Outside the set's time window; will back up when it opens.
    WaitingForWindow,
    /// Not backing up automatically (e.g. restored from a recovery kit).
    Paused,
    /// The host it backs up to can't be reached; will back up when it's back.
    WaitingForHost,
    Running,
    /// Removing old versions the retention policy doesn't keep.
    Pruning,
    /// Checking the backups are complete and intact.
    Verifying,
}

/// A step of cleaning up (`Listings`, `Repacking`, `Deleting`) or checking
/// (`Listings`, `Checking`).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceStep {
    /// Reading the folder listings of every version. The total counts every
    /// listing stored, so the step may end short of it.
    Listings,
    /// Rewriting partly-used data so the unused part can be freed.
    Repacking,
    /// Deleting data no version uses any more.
    Deleting,
    /// Downloading and decrypting data to check it.
    Checking,
}

impl From<kinvault_core::MaintenanceStep> for MaintenanceStep {
    fn from(step: kinvault_core::MaintenanceStep) -> Self {
        use kinvault_core::MaintenanceStep as S;
        match step {
            S::Listings => Self::Listings,
            S::Repacking => Self::Repacking,
            S::Deleting => Self::Deleting,
            S::Checking => Self::Checking,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PruneSummary {
    pub time_unix: i64,
    pub snapshots_kept: u64,
    pub snapshots_removed: u64,
    pub packs_deleted: u64,
    pub packs_repacked: u64,
    pub bytes_deleted: u64,
    pub bytes_downloaded: u64,
    pub bytes_uploaded: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifySummary {
    pub time_unix: i64,
    pub ok: bool,
    pub snapshots: u64,
    pub packs_checked: u64,
    pub bytes_checked: u64,
    pub missing_chunks: u64,
    pub damaged_packs: u64,
    pub errors: Vec<String>,
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
    /// Set if this peer may store backups here.
    pub grant: Option<GrantSpec>,
    /// Bytes this peer stores here.
    pub used_bytes: u64,
    /// Of those, bytes it deleted that are erased once their grace period is over.
    #[serde(default)]
    pub deleting_bytes: u64,
    /// Set if this peer agreed to store our backups (and how much).
    pub hosts_us: Option<HostOffer>,
    /// One of this user's own devices rather than a friend's.
    pub mine: bool,
    /// Whether it's reachable, for hosts that keep (or may keep) our
    /// backups; `None` for other peers and before the first check.
    #[serde(default)]
    pub online: Option<bool>,
    /// When it was last reachable (Unix seconds).
    #[serde(default)]
    pub last_seen_unix: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOffer {
    pub quota_bytes: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InviteInfo {
    pub id: String,
    pub name: Option<String>,
    pub grant: GrantSpec,
    pub ask_reciprocal: bool,
    pub expires_unix: i64,
    pub mine: bool,
}

/// Looking for this user's other devices on the local network.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct NearbyStatus {
    /// When looking stops; `None` when not looking.
    pub until_unix: Option<i64>,
    pub devices: Vec<NearbyDevice>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NearbyDevice {
    pub id: String,
    pub name: String,
    /// Shown on both devices; the user checks they match before confirming.
    pub code: String,
    pub state: NearbyState,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NearbyState {
    Found,
    /// Confirmed here; waiting for it to be confirmed on the other device.
    Waiting,
    /// One of this user's devices (paired now or before).
    Paired,
}
