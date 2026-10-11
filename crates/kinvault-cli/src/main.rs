//! `kinvault` command-line tool. For now it drives a repository directly;
//! once the daemon exists this becomes a thin client of its IPC API.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use kinvault_core::{Index, KeyFile, LocalDirBackend, MasterKey, Repository};
use serde::{Deserialize, Serialize};

const PASSPHRASE_ENV: &str = "KINVAULT_PASSPHRASE";

#[derive(Parser)]
#[command(
    name = "kinvault",
    version,
    about = "Self-hosted encrypted backups between friends"
)]
struct Cli {
    /// Directory holding this instance's keys and index.
    #[arg(long, global = true, env = "KINVAULT_STATE")]
    state: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new encrypted repository in a directory and generate its key.
    Init { repo: PathBuf },
    /// Back up files and directories into a new snapshot.
    Backup {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// List snapshots.
    Snapshots,
    /// Restore a snapshot (id prefix or "latest") into a target directory.
    Restore {
        snapshot: String,
        target: PathBuf,
        /// Only restore this path (as shown in the snapshot, e.g. home/me/Documents).
        #[arg(long)]
        include: Option<String>,
    },
}

#[derive(Serialize, Deserialize)]
struct StateConfig {
    repo: PathBuf,
}

struct State {
    dir: PathBuf,
}

impl State {
    fn config_path(&self) -> PathBuf {
        self.dir.join("repo.json")
    }
    fn keyfile_path(&self) -> PathBuf {
        self.dir.join("keyfile.json")
    }
    fn index_path(&self) -> PathBuf {
        self.dir.join("index.db")
    }

    fn open_repo(&self) -> Result<Repository<LocalDirBackend>> {
        let config: StateConfig = read_json(&self.config_path())
            .context("no repository configured; run `kinvault init <dir>` first")?;
        let keyfile: KeyFile = read_json(&self.keyfile_path())?;
        let master = keyfile.unlock(&passphrase(false)?)?;
        let backend = LocalDirBackend::open(&config.repo)?;
        Ok(Repository::open(
            backend,
            &master,
            Index::open(&self.index_path())?,
        ))
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

fn passphrase(confirm: bool) -> Result<String> {
    if let Ok(p) = std::env::var(PASSPHRASE_ENV) {
        return Ok(p);
    }
    let p = rpassword::prompt_password("Passphrase: ")?;
    if confirm {
        if p.len() < 8 {
            bail!("passphrase must be at least 8 characters");
        }
        if rpassword::prompt_password("Repeat passphrase: ")? != p {
            bail!("passphrases do not match");
        }
    }
    Ok(p)
}

fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let dir = match cli.state {
        Some(d) => d,
        None => directories::ProjectDirs::from("", "", "KinVault")
            .context("could not determine a data directory; pass --state")?
            .data_dir()
            .to_path_buf(),
    };
    fs::create_dir_all(&dir)?;
    let state = State { dir };

    match cli.command {
        Command::Init { repo } => {
            if state.keyfile_path().exists() {
                bail!(
                    "{} already holds a key; refusing to overwrite it",
                    state.dir.display()
                );
            }
            LocalDirBackend::create(&repo)?;
            let master = MasterKey::generate()?;
            let keyfile = KeyFile::create(&master, &passphrase(true)?)?;
            fs::write(
                state.keyfile_path(),
                serde_json::to_string_pretty(&keyfile)?,
            )?;
            let repo = fs::canonicalize(&repo)?;
            fs::write(
                state.config_path(),
                serde_json::to_string_pretty(&StateConfig { repo: repo.clone() })?,
            )?;
            println!("Initialised encrypted repository at {}", repo.display());
            println!(
                "Keep a copy of {} and your passphrase: without both, backups cannot be restored.",
                state.keyfile_path().display()
            );
        }
        Command::Backup { paths } => {
            let mut repo = state.open_repo()?;
            let host = gethostname::gethostname().to_string_lossy().into_owned();
            let (id, stats) = repo.backup(&paths, &host)?;
            for w in &stats.warnings {
                eprintln!("warning: {w}");
            }
            println!("snapshot {}", &id.to_hex()[..16]);
            println!(
                "  {} files ({}), {} changed, read {}, uploaded {} in {} pack(s)",
                stats.files,
                format_bytes(stats.total_bytes),
                stats.files_changed,
                format_bytes(stats.bytes_read),
                format_bytes(stats.bytes_uploaded),
                stats.packs_uploaded
            );
        }
        Command::Snapshots => {
            let repo = state.open_repo()?;
            for (id, s) in repo.list_snapshots()? {
                let secs = s.time_ns / 1_000_000_000;
                println!(
                    "{}  t={}  {}  {} files  {}  {}",
                    &id.to_hex()[..16],
                    secs,
                    s.hostname,
                    s.file_count,
                    format_bytes(s.total_bytes),
                    s.paths.join(", ")
                );
            }
        }
        Command::Restore {
            snapshot,
            target,
            include,
        } => {
            let mut repo = state.open_repo()?;
            let id = repo.find_snapshot(&snapshot)?;
            let stats = repo.restore(&id, &target, include.as_deref())?;
            println!(
                "restored {} files, {} dirs, {} symlinks ({}) to {}",
                stats.files,
                stats.dirs,
                stats.symlinks,
                format_bytes(stats.bytes),
                target.display()
            );
        }
    }
    Ok(())
}
