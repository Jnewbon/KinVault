//! Recovery kits: one file that lets a new machine take over this instance's
//! backups. It holds the instance identity (hosts know our backups by it)
//! and every set's key, each wrapped with a passphrase-derived key, plus the
//! non-secret configuration needed to find the data again.
//!
//! A kit is imported offline, before `kinvaultd` first starts on the new
//! machine; imported sets start paused so nothing is overwritten until the
//! user has restored what they need and resumes them.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use kinvault_core::{KeyFile, MasterKey, RetentionPolicy};
use kinvault_net::{SecretKey, TimeWindow};
use serde::{Deserialize, Serialize};

use crate::config::{Config, ExtraTarget, PeerEntry, SetConfig, StoredTarget, write_private};
use crate::worker::{shared_key_path, write_key, write_master_key};

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
    #[serde(default)]
    pub excludes: Vec<String>,
    /// Its key is the instance's shared key (kits made before keys could be
    /// shared have none).
    #[serde(default)]
    pub shared_key: bool,
    /// More places that keep copies (kits made before there could be more
    /// have none).
    #[serde(default)]
    pub extra_targets: Vec<ExtraTarget>,
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
            excludes: set.excludes.clone(),
            shared_key: set.shared_key,
            extra_targets: set.extra_targets.clone(),
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

/// Largest recovery kit read, and most backup sets one may hold. A kit is
/// a few KiB per set; these keep a crafted file from tying up the import.
pub const MAX_KIT_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_KIT_SETS: usize = 256;

/// Reads a recovery kit file, refusing one far larger than a kit can be.
pub fn read_kit(path: &Path) -> Result<String> {
    use std::io::Read;
    let file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut json = String::new();
    file.take(MAX_KIT_BYTES + 1)
        .read_to_string(&mut json)
        .with_context(|| format!("reading {}", path.display()))?;
    ensure!(
        json.len() as u64 <= MAX_KIT_BYTES,
        "{} is too large to be a recovery kit",
        path.display()
    );
    Ok(json)
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
    ensure!(
        kit_json.len() as u64 <= MAX_KIT_BYTES,
        "this is too large to be a recovery kit"
    );
    let kit: RecoveryKit =
        serde_json::from_str(kit_json).context("this is not a KinVault recovery kit")?;
    ensure!(
        kit.sets.len() <= MAX_KIT_SETS,
        "this recovery kit lists {} backups; at most {MAX_KIT_SETS} can be imported",
        kit.sets.len()
    );
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

    crate::config::create_private_dir(state_dir)?;
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

    // New sets made after the import share the key the kit's sets shared.
    if let Some((_, key)) = kit.sets.iter().zip(&keys).find(|(s, _)| s.shared_key) {
        write_key(&shared_key_path(state_dir), key)?;
    }

    let mut imported = Vec::new();
    for (set, key) in kit.sets.iter().zip(&keys) {
        let mut name = set.name.clone();
        while config.sets.iter().any(|s| s.name == name) {
            name.push_str("-restored");
        }
        let id = hex::encode(kinvault_core::crypto::random_bytes::<8>()?);
        let set_dir = state_dir.join("sets").join(&id);
        crate::config::create_private_dir(&set_dir)?;
        write_master_key(&set_dir, key)?;
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
            excludes: set.excludes.clone(),
            shared_key: set.shared_key,
            extra_targets: set.extra_targets.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_key() -> KeyFile {
        KeyFile {
            version: 1,
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
            salt: "00".repeat(16),
            wrapped: "00".repeat(56),
        }
    }

    #[test]
    fn oversized_kits_are_refused_before_any_work() {
        let tmp = tempfile::tempdir().unwrap();
        let set = KitSet {
            name: "s".into(),
            paths: Vec::new(),
            target: StoredTarget::Local {
                path: "/nowhere".into(),
            },
            upload_limit: None,
            window: None,
            retention: RetentionPolicy::default(),
            excludes: Vec::new(),
            shared_key: false,
            extra_targets: Vec::new(),
            key: dummy_key(),
        };
        let kit = RecoveryKit {
            kinvault_recovery_kit: KIT_VERSION,
            created_unix: 0,
            instance_name: None,
            instance_id: String::new(),
            identity: dummy_key(),
            sets: vec![set; MAX_KIT_SETS + 1],
            peers: Vec::new(),
        };
        let json = serde_json::to_string(&kit).unwrap();
        let started = std::time::Instant::now();
        let err = import_offline(tmp.path(), &json, "passphrase", false).unwrap_err();
        assert!(err.to_string().contains("at most"), "{err:#}");
        // Refused without deriving a single key.
        assert!(started.elapsed() < std::time::Duration::from_secs(2));

        let huge = " ".repeat(MAX_KIT_BYTES as usize + 1);
        let err = import_offline(tmp.path(), &huge, "passphrase", false).unwrap_err();
        assert!(err.to_string().contains("too large"), "{err:#}");
        let path = tmp.path().join("kit.json");
        std::fs::write(&path, &huge).unwrap();
        assert!(read_kit(&path).is_err());
        std::fs::write(&path, &json).unwrap();
        assert_eq!(read_kit(&path).unwrap(), json);
    }
}
