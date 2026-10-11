//! The KinVault background service (`kinvaultd`) and the local API that the
//! CLI and GUI use to control it.
//!
//! One daemon per user runs every configured backup set (watching its
//! sources and backing up incrementally after changes) and hosts encrypted
//! backups for the peers it has allowed.

pub mod api;
pub mod config;
mod daemon;
pub mod ipc;
pub mod recovery;
pub mod service;
#[cfg(feature = "web")]
pub mod web;
mod worker;

use std::path::PathBuf;

pub use daemon::{Daemon, DaemonOptions};

/// Per-user directory holding identity, configuration, keys and indexes.
pub fn default_state_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "KinVault").map(|d| d.data_dir().to_path_buf())
}
