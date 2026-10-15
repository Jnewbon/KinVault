//! Core of KinVault: client-side encryption, content-defined chunking, the
//! pack/snapshot repository format and the local index. No networking lives
//! here; remote instances plug in through the [`Backend`] trait.

pub mod backend;
pub mod crypto;
pub mod error;
pub mod exclude;
pub mod ids;
pub mod index;
pub mod pack;
pub mod repo;
pub mod retention;
pub mod snapshot;

pub use backend::{Backend, LocalDirBackend};
pub use crypto::{KeyFile, Keys, MasterKey};
pub use error::{Error, Result};
pub use exclude::Excludes;
pub use ids::{ChunkId, PackId, SnapshotId};
pub use index::Index;
pub use repo::{
    BackupProgress, BackupStats, MaintenanceProgress, MaintenanceStep, ProgressFn, PruneStats,
    Repository, RestoreProgress, RestoreStats, VerifyReport, snapshot_root_name,
};
pub use retention::RetentionPolicy;
pub use snapshot::Snapshot;
