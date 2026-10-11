//! `kinvault` command-line tool. For now it drives repositories directly;
//! once the daemon exists this becomes a thin client of its IPC API.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use kinvault_core::{Backend, Index, KeyFile, LocalDirBackend, MasterKey, Repository};
use kinvault_net::{Endpoint, EndpointAddr, EndpointId, Grant, Receiver, RemoteBackend};
use serde::{Deserialize, Serialize};

const PASSPHRASE_ENV: &str = "KINVAULT_PASSPHRASE";

#[derive(Parser)]
#[command(
    name = "kinvault",
    version,
    about = "Self-hosted encrypted backups between friends"
)]
struct Cli {
    /// Directory holding this instance's identity, keys and index.
    #[arg(long, global = true, env = "KINVAULT_STATE")]
    state: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print this instance's id (give it to hosts so they can allow you).
    Id,
    /// Create a new encrypted backup set and generate its key.
    Init {
        /// Store backups in a local directory (external disk, NAS mount).
        #[arg(long, conflicts_with = "peer", required_unless_present = "peer")]
        local: Option<PathBuf>,
        /// Store backups on another KinVault instance, by its id.
        #[arg(long)]
        peer: Option<String>,
        /// Known direct address of the peer (optional; it is found by id otherwise).
        #[arg(long, requires = "peer")]
        peer_addr: Vec<SocketAddr>,
    },
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
    /// Show storage used on the remote host.
    Status,
    /// Host backups for allowed peers until interrupted.
    Serve {
        /// Where peers' encrypted data is stored.
        #[arg(long)]
        store: PathBuf,
    },
    /// Manage which peers may store backups on this instance.
    #[command(subcommand)]
    Peer(PeerCommand),
}

#[derive(Subcommand)]
enum PeerCommand {
    /// Allow a peer to store backups here.
    Allow {
        id: String,
        #[arg(long)]
        name: Option<String>,
        /// Storage limit, e.g. 500G or 2T.
        #[arg(long, value_parser = parse_size)]
        quota: Option<u64>,
    },
    /// Stop accepting backups from a peer (stored data is kept).
    Revoke {
        id: String,
    },
    List,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Target {
    Local {
        path: PathBuf,
    },
    Peer {
        id: String,
        /// Random name for this set on the host, so it learns nothing from it.
        repo: String,
        #[serde(default)]
        addrs: Vec<SocketAddr>,
    },
}

#[derive(Serialize, Deserialize)]
struct StateConfig {
    target: Target,
}

#[derive(Serialize, Deserialize, Default)]
struct Peers {
    peers: Vec<PeerEntry>,
}

#[derive(Serialize, Deserialize)]
struct PeerEntry {
    id: String,
    name: Option<String>,
    quota_bytes: Option<u64>,
}

struct State {
    dir: PathBuf,
}

impl State {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    async fn endpoint(&self) -> Result<Endpoint> {
        let secret = kinvault_net::load_or_create_secret(&self.path("identity.key"))?;
        Ok(kinvault_net::bind(secret).await?)
    }

    fn config(&self) -> Result<StateConfig> {
        read_json(&self.path("repo.json"))
            .context("no backup set configured; run `kinvault init` first")
    }

    fn peers(&self) -> Result<Peers> {
        let path = self.path("peers.json");
        if !path.exists() {
            return Ok(Peers::default());
        }
        read_json(&path)
    }

    fn save_peers(&self, peers: &Peers) -> Result<()> {
        Ok(fs::write(
            self.path("peers.json"),
            serde_json::to_string_pretty(peers)?,
        )?)
    }

    /// Opens the configured backup set. The returned endpoint (if any) should
    /// be closed once the repository is no longer needed.
    async fn open_repo(&self) -> Result<(Repository<Box<dyn Backend>>, Option<Endpoint>)> {
        let config = self.config()?;
        let keyfile: KeyFile = read_json(&self.path("keyfile.json"))?;
        let master = keyfile.unlock(&passphrase(false)?)?;
        let (backend, endpoint): (Box<dyn Backend>, _) = match config.target {
            Target::Local { path } => (Box::new(LocalDirBackend::open(path)?), None),
            Target::Peer { id, repo, addrs } => {
                let endpoint = self.endpoint().await?;
                let addr = peer_addr(&id, &addrs)?;
                let remote = RemoteBackend::new(
                    endpoint.clone(),
                    addr,
                    &repo,
                    tokio::runtime::Handle::current(),
                )?;
                (Box::new(remote), Some(endpoint))
            }
        };
        let index = Index::open(&self.path("index.db"))?;
        Ok((Repository::open(backend, &master, index), endpoint))
    }
}

fn peer_addr(id: &str, addrs: &[SocketAddr]) -> Result<EndpointAddr> {
    let id = EndpointId::from_str(id).with_context(|| format!("invalid peer id {id:?}"))?;
    Ok(addrs
        .iter()
        .fold(EndpointAddr::new(id), |a, s| a.with_ip_addr(*s)))
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

fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let num: u64 = num.parse().map_err(|_| format!("invalid size {s:?}"))?;
    let shift = match unit
        .trim()
        .to_ascii_uppercase()
        .trim_end_matches("IB")
        .trim_end_matches('B')
    {
        "" => 0,
        "K" => 10,
        "M" => 20,
        "G" => 30,
        "T" => 40,
        _ => return Err(format!("unknown size unit in {s:?}")),
    };
    num.checked_mul(1 << shift)
        .ok_or_else(|| format!("size {s:?} is too large"))
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

/// Runs blocking repository work off the async runtime.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f).await?
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,iroh=error,kinvault_net=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
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
        Command::Id => {
            let secret = kinvault_net::load_or_create_secret(&state.path("identity.key"))?;
            println!("{}", secret.public());
        }
        Command::Init {
            local,
            peer,
            peer_addr: addrs,
        } => {
            if state.path("keyfile.json").exists() {
                bail!(
                    "{} already holds a key; refusing to overwrite it",
                    state.dir.display()
                );
            }
            let target = match (local, peer) {
                (Some(path), _) => {
                    LocalDirBackend::create(&path)?;
                    Target::Local {
                        path: fs::canonicalize(&path)?,
                    }
                }
                (None, Some(id)) => {
                    self::peer_addr(&id, &addrs)?;
                    let repo = hex::encode(kinvault_core::crypto::random_bytes::<12>()?);
                    Target::Peer { id, repo, addrs }
                }
                (None, None) => unreachable!("clap requires --local or --peer"),
            };
            let master = MasterKey::generate()?;
            let keyfile = KeyFile::create(&master, &passphrase(true)?)?;
            fs::write(
                state.path("keyfile.json"),
                serde_json::to_string_pretty(&keyfile)?,
            )?;
            fs::write(
                state.path("repo.json"),
                serde_json::to_string_pretty(&StateConfig { target })?,
            )?;
            println!("Initialised encrypted backup set.");
            println!(
                "Keep a copy of {} and your passphrase: without both, backups cannot be restored.",
                state.path("keyfile.json").display()
            );
        }
        Command::Backup { paths } => {
            let (mut repo, endpoint) = state.open_repo().await?;
            let host = gethostname::gethostname().to_string_lossy().into_owned();
            let (id, stats) = blocking(move || Ok(repo.backup(&paths, &host)?)).await?;
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
            close(endpoint).await;
        }
        Command::Snapshots => {
            let (repo, endpoint) = state.open_repo().await?;
            let snapshots = blocking(move || Ok(repo.list_snapshots()?)).await?;
            for (id, s) in snapshots {
                println!(
                    "{}  t={}  {}  {} files  {}  {}",
                    &id.to_hex()[..16],
                    s.time_ns / 1_000_000_000,
                    s.hostname,
                    s.file_count,
                    format_bytes(s.total_bytes),
                    s.paths.join(", ")
                );
            }
            close(endpoint).await;
        }
        Command::Restore {
            snapshot,
            target,
            include,
        } => {
            let (mut repo, endpoint) = state.open_repo().await?;
            let shown = target.clone();
            let stats = blocking(move || {
                let id = repo.find_snapshot(&snapshot)?;
                Ok(repo.restore(&id, &target, include.as_deref())?)
            })
            .await?;
            println!(
                "restored {} files, {} dirs, {} symlinks ({}) to {}",
                stats.files,
                stats.dirs,
                stats.symlinks,
                format_bytes(stats.bytes),
                shown.display()
            );
            close(endpoint).await;
        }
        Command::Status => {
            let Target::Peer { id, repo, addrs } = state.config()?.target else {
                bail!("status is only available for backup sets stored on a peer");
            };
            let endpoint = state.endpoint().await?;
            let remote = RemoteBackend::new(
                endpoint.clone(),
                peer_addr(&id, &addrs)?,
                &repo,
                tokio::runtime::Handle::current(),
            )?;
            let status = remote.status().await?;
            match status.quota_bytes {
                Some(q) => println!(
                    "using {} of {} on {id}",
                    format_bytes(status.used_bytes),
                    format_bytes(q)
                ),
                None => println!(
                    "using {} on {id} (no quota)",
                    format_bytes(status.used_bytes)
                ),
            }
            close(Some(endpoint)).await;
        }
        Command::Serve { store } => {
            let receiver = Receiver::new(&store);
            let peers = state.peers()?;
            for p in &peers.peers {
                receiver.allow(
                    EndpointId::from_str(&p.id)?,
                    Grant {
                        quota_bytes: p.quota_bytes,
                    },
                );
            }
            let endpoint = state.endpoint().await?;
            println!("Serving as {}", endpoint.id());
            println!(
                "Storing data for {} allowed peer(s) in {}",
                peers.peers.len(),
                store.display()
            );
            let router = kinvault_net::serve(endpoint, receiver);
            tokio::signal::ctrl_c().await?;
            router.shutdown().await?;
        }
        Command::Peer(cmd) => {
            let mut peers = state.peers()?;
            match cmd {
                PeerCommand::Allow { id, name, quota } => {
                    EndpointId::from_str(&id).with_context(|| format!("invalid peer id {id:?}"))?;
                    peers.peers.retain(|p| p.id != id);
                    peers.peers.push(PeerEntry {
                        id,
                        name,
                        quota_bytes: quota,
                    });
                    state.save_peers(&peers)?;
                    println!("Allowed. Restart `kinvault serve` to apply.");
                }
                PeerCommand::Revoke { id } => {
                    let before = peers.peers.len();
                    peers.peers.retain(|p| p.id != id);
                    if peers.peers.len() == before {
                        bail!("{id} is not an allowed peer");
                    }
                    state.save_peers(&peers)?;
                    println!(
                        "Revoked. Their stored data is kept. Restart `kinvault serve` to apply."
                    );
                }
                PeerCommand::List => {
                    for p in &peers.peers {
                        let quota = p
                            .quota_bytes
                            .map(format_bytes)
                            .unwrap_or_else(|| "no quota".into());
                        println!("{}  {}  {quota}", p.id, p.name.as_deref().unwrap_or("-"));
                    }
                }
            }
        }
    }
    Ok(())
}

async fn close(endpoint: Option<Endpoint>) {
    if let Some(ep) = endpoint {
        ep.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::parse_size;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("512"), Ok(512));
        assert_eq!(parse_size("2K"), Ok(2048));
        assert_eq!(parse_size("500G"), Ok(500 << 30));
        assert_eq!(parse_size("1TiB"), Ok(1 << 40));
        assert_eq!(parse_size("3mb"), Ok(3 << 20));
        assert!(parse_size("1X").is_err());
        assert!(parse_size("G").is_err());
    }
}
