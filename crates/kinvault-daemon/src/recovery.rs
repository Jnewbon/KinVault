//! Recovery kits: one file that lets a new machine take over this instance's
//! backups. It holds the instance identity (hosts know our backups by it)
//! and every set's key, each wrapped with a passphrase-derived key, plus the
//! non-secret configuration needed to find the data again.
//!
//! A kit is imported offline, before `kinvaultd` first starts on the new
//! machine; imported sets start paused so nothing is overwritten until the
//! user has restored what they need and resumes them.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use kinvault_core::{KeyFile, MasterKey, RetentionPolicy};
use kinvault_net::{SecretKey, TimeWindow};
use serde::{Deserialize, Serialize};

use crate::config::{Config, PeerEntry, SetConfig, StoredTarget, write_private};
use crate::worker::write_master_key;

const KIT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecoveryKit {
    pub kinvault_recovery_kit: u32,
    pub created_unix: i64,
    pub instance_name: Option<String>,
    pub instance_id: String,
    pub identity: KeyFile,
    pub sets: Vec<KitSet>,
    pub peers: Vec<PeerEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KitSet {
    pub name: String,
    pub paths: Vec<PathBuf>,
    pub target: StoredTarget,
    pub upload_limit: Option<u64>,
    pub window: Option<TimeWindow>,
    pub retention: RetentionPolicy,
    pub key: KeyFile,
}

/// Builds a kit. Blocking: each key is wrapped with Argon2id.
pub(crate) fn build(
    config: &Config,
    identity: &SecretKey,
    set_keys: &[(SetConfig, MasterKey)],
    passphrase: &str,
) -> Result<RecoveryKit> {
    ensure!(
        passphrase.chars().count() >= 8,
        "passphrase must be at least 8 characters"
    );
    let identity_key = MasterKey::from_bytes(identity.to_bytes());
    let mut sets = Vec::with_capacity(set_keys.len());
    for (set, key) in set_keys {
        sets.push(KitSet {
            name: set.name.clone(),
            paths: set.paths.clone(),
            target: set.target.clone(),
            upload_limit: set.upload_limit,
            window: set.window,
            retention: set.retention,
            key: KeyFile::create(key, passphrase)?,
        });
    }
    Ok(RecoveryKit {
        kinvault_recovery_kit: KIT_VERSION,
        created_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
        instance_name: config.name.clone(),
        instance_id: identity.public().to_string(),
        identity: KeyFile::create(&identity_key, passphrase)?,
        sets,
        peers: config.peers.clone(),
    })
}

#[derive(Debug)]
pub struct ImportSummary {
    pub instance_id: String,
    /// Names of the imported sets (all paused).
    pub sets: Vec<String>,
}

/// Writes a kit's identity, sets and peers into `state_dir`. The daemon must
/// not be running. Refuses to replace an instance that already has sets or
/// peers unless `force` is set.
pub fn import_offline(
    state_dir: &Path,
    kit_json: &str,
    passphrase: &str,
    force: bool,
) -> Result<ImportSummary> {
    let kit: RecoveryKit =
        serde_json::from_str(kit_json).context("this is not a KinVault recovery kit")?;
    ensure!(
        kit.kinvault_recovery_kit == KIT_VERSION,
        "unsupported recovery kit version {}",
        kit.kinvault_recovery_kit
    );
    ensure!(
        !crate::ipc::daemon_running(state_dir),
        "stop kinvaultd before importing a recovery kit"
    );

    // Unlock everything before writing anything.
    let identity = kit
        .identity
        .unlock(passphrase)
        .context("could not unlock the recovery kit")?;
    let identity = SecretKey::from_bytes(&identity.to_bytes());
    ensure!(
        identity.public().to_string() == kit.instance_id,
        "recovery kit identity does not match its id"
    );
    let keys = kit
        .sets
        .iter()
        .map(|s| {
            s.key
                .unlock(passphrase)
                .with_context(|| format!("could not unlock set {:?}", s.name))
        })
        .collect::<Result<Vec<_>>>()?;

    fs::create_dir_all(state_dir)?;
    let config_path = state_dir.join("config.json");
    let mut config = Config::load(&config_path)?;
    if !force && (!config.sets.is_empty() || !config.peers.is_empty()) {
        bail!(
            "this instance already has backup sets or peers, and importing replaces its identity; \
             use a fresh state directory or pass --force"
        );
    }
    write_private(
        &state_dir.join("identity.key"),
        hex::encode(identity.to_bytes()).as_bytes(),
    )?;

    let mut imported = Vec::new();
    for (set, key) in kit.sets.iter().zip(&keys) {
        let mut name = set.name.clone();
        while config.sets.iter().any(|s| s.name == name) {
            name.push_str("-restored");
        }
        let id = hex::encode(kinvault_core::crypto::random_bytes::<8>()?);
        let set_dir = state_dir.join("sets").join(&id);
        fs::create_dir_all(&set_dir)?;
        write_master_key(&set_dir, key)?;
        write_private(
            &set_dir.join("keyfile.json"),
            serde_json::to_string_pretty(&set.key)?.as_bytes(),
        )?;
        config.sets.push(SetConfig {
            id,
            name: name.clone(),
            paths: set.paths.clone(),
            target: set.target.clone(),
            debounce_secs: crate::daemon::DEFAULT_DEBOUNCE_SECS,
            rescan_secs: crate::daemon::DEFAULT_RESCAN_SECS,
            upload_limit: set.upload_limit,
            window: set.window,
            retention: set.retention,
            paused: true,
        });
        imported.push(name);
    }
    for peer in &kit.peers {
        config.peers.retain(|p| p.id != peer.id);
        config.peers.push(peer.clone());
    }
    if config.name.is_none() {
        config.name = kit.instance_name.clone();
    }
    config.save(&config_path)?;
    Ok(ImportSummary {
        instance_id: kit.instance_id,
        sets: imported,
    })
}
