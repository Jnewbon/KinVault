//! `kinvault` command-line tool: a thin client of the `kinvaultd` daemon.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use kinvault_daemon::api::{CreateSet, Reply, Request, SetState, Target};
use kinvault_daemon::ipc::Client;

const PASSPHRASE_ENV: &str = "KINVAULT_PASSPHRASE";

#[derive(Parser)]
#[command(
    name = "kinvault",
    version,
    about = "Self-hosted encrypted backups between friends"
)]
struct Cli {
    /// The daemon's state directory (defaults to the per-user data directory).
    #[arg(long, global = true, env = "KINVAULT_STATE")]
    state: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show this instance's id and the state of every backup set.
    Status,
    /// Print this instance's id (give it to hosts so they can allow you).
    Id,
    /// Manage backup sets.
    #[command(subcommand)]
    Set(SetCommand),
    /// Back up a set now and wait for it to finish.
    Backup { set: String },
    /// List a set's snapshots.
    Snapshots { set: String },
    /// Restore a snapshot (id prefix or "latest") into a target directory.
    Restore {
        set: String,
        snapshot: String,
        target: PathBuf,
        /// Only restore this path (as stored in the snapshot, e.g. home/me/Documents).
        #[arg(long)]
        include: Option<String>,
    },
    /// Show how much space a set's owner uses on the host it backs up to.
    Usage { set: String },
    /// Manage which peers may store backups on this instance.
    #[command(subcommand)]
    Peer(PeerCommand),
}

#[derive(Subcommand)]
enum SetCommand {
    /// Create a backup set; it is backed up immediately and kept up to date.
    Create {
        name: String,
        /// Files or folders to back up.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Store backups in a local directory (external disk, NAS mount).
        #[arg(long, conflicts_with = "peer", required_unless_present = "peer")]
        local: Option<PathBuf>,
        /// Store backups on another KinVault instance, by its id.
        #[arg(long)]
        peer: Option<String>,
        /// Known direct address of the peer (optional; it is found by id otherwise).
        #[arg(long, requires = "peer")]
        peer_addr: Vec<SocketAddr>,
        /// Seconds without changes before backing up.
        #[arg(long)]
        debounce: Option<u64>,
    },
    /// Stop backing up a set. Existing backups and the set's key are kept.
    Remove { set: String },
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
    /// Stop accepting backups from a peer (data already stored is kept).
    Revoke {
        id: String,
    },
    List,
}

fn recovery_passphrase() -> Result<String> {
    if let Ok(p) = std::env::var(PASSPHRASE_ENV) {
        return Ok(p);
    }
    println!("Choose a recovery passphrase. With it and the set's recovery file you can");
    println!("restore on a new machine; without both, the backups can't be decrypted.");
    let p = rpassword::prompt_password("Recovery passphrase: ")?;
    if p.chars().count() < 8 {
        bail!("passphrase must be at least 8 characters");
    }
    if rpassword::prompt_password("Repeat passphrase: ")? != p {
        bail!("passphrases do not match");
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

/// Formats nanoseconds since the Unix epoch as a UTC date and time.
fn format_time(time_ns: i64) -> String {
    let secs = time_ns.div_euclid(1_000_000_000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn describe_target(t: &Target) -> String {
    match t {
        Target::Local { path } => format!("local {}", path.display()),
        Target::Peer { id, .. } => format!("peer {}…", &id[..id.len().min(16)]),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let state = match cli.state {
        Some(d) => d,
        None => kinvault_daemon::default_state_dir()
            .context("could not determine a data directory; pass --state")?,
    };
    let mut client = Client::connect(&state).await?;

    match cli.command {
        Command::Status => {
            let Reply::Status(s) = client.call(&Request::Status).await? else {
                bail!("unexpected reply")
            };
            println!("instance {}", s.id);
            println!("hosting store {}", s.hosting_store.display());
            if s.sets.is_empty() {
                println!("no backup sets; create one with `kinvault set create`");
            }
            for set in s.sets {
                let state = match set.state {
                    SetState::Idle => "up to date",
                    SetState::ChangesPending => "changes pending",
                    SetState::Running => "backing up",
                };
                println!(
                    "\n{} ({state}) -> {}",
                    set.name,
                    describe_target(&set.target)
                );
                for p in &set.paths {
                    println!("  {}", p.display());
                }
                match set.last_backup {
                    Some(b) => println!(
                        "  last backup {}: {} files ({}), {} changed, uploaded {}",
                        format_time(b.time_ns),
                        b.files,
                        format_bytes(b.total_bytes),
                        b.files_changed,
                        format_bytes(b.bytes_uploaded)
                    ),
                    None => println!("  not backed up yet"),
                }
                if let Some(e) = set.last_error {
                    println!("  last error: {e}");
                }
            }
        }
        Command::Id => {
            let Reply::Status(s) = client.call(&Request::Status).await? else {
                bail!("unexpected reply")
            };
            println!("{}", s.id);
        }
        Command::Set(SetCommand::Create {
            name,
            paths,
            local,
            peer,
            peer_addr,
            debounce,
        }) => {
            let target = match (local, peer) {
                (Some(path), _) => Target::Local { path },
                (None, Some(id)) => Target::Peer {
                    id,
                    addrs: peer_addr,
                },
                (None, None) => unreachable!("clap requires --local or --peer"),
            };
            let req = Request::CreateSet(CreateSet {
                name: name.clone(),
                paths,
                target,
                recovery_passphrase: recovery_passphrase()?,
                debounce_secs: debounce,
                rescan_secs: None,
            });
            let Reply::SetCreated { id } = client.call(&req).await? else {
                bail!("unexpected reply")
            };
            println!("Created set {name:?} ({id}); the first backup is starting.");
            println!(
                "Keep a copy of {} and your passphrase somewhere safe.",
                state.join("sets").join(&id).join("keyfile.json").display()
            );
        }
        Command::Set(SetCommand::Remove { set }) => {
            client.call(&Request::RemoveSet { set }).await?;
            println!("Set removed. Its backups and key were kept.");
        }
        Command::Backup { set } => {
            let Reply::Backup(b) = client.call(&Request::BackupNow { set }).await? else {
                bail!("unexpected reply")
            };
            for w in &b.warnings {
                eprintln!("warning: {w}");
            }
            println!("snapshot {}", &b.snapshot[..16]);
            println!(
                "  {} files ({}), {} changed, uploaded {}",
                b.files,
                format_bytes(b.total_bytes),
                b.files_changed,
                format_bytes(b.bytes_uploaded)
            );
        }
        Command::Snapshots { set } => {
            let Reply::Snapshots(snaps) = client.call(&Request::ListSnapshots { set }).await?
            else {
                bail!("unexpected reply")
            };
            for s in snaps {
                println!(
                    "{}  {}  {}  {} files  {}",
                    &s.id[..16],
                    format_time(s.time_ns),
                    s.hostname,
                    s.file_count,
                    format_bytes(s.total_bytes)
                );
            }
        }
        Command::Restore {
            set,
            snapshot,
            target,
            include,
        } => {
            let shown = target.clone();
            let req = Request::Restore {
                set,
                snapshot,
                target,
                include,
            };
            let Reply::Restored(r) = client.call(&req).await? else {
                bail!("unexpected reply")
            };
            println!(
                "restored {} files, {} dirs, {} symlinks ({}) to {}",
                r.files,
                r.dirs,
                r.symlinks,
                format_bytes(r.bytes),
                shown.display()
            );
        }
        Command::Usage { set } => {
            let Reply::Usage {
                used_bytes,
                quota_bytes,
            } = client.call(&Request::RemoteUsage { set }).await?
            else {
                bail!("unexpected reply")
            };
            match quota_bytes {
                Some(q) => println!("using {} of {}", format_bytes(used_bytes), format_bytes(q)),
                None => println!("using {} (no quota)", format_bytes(used_bytes)),
            }
        }
        Command::Peer(PeerCommand::Allow { id, name, quota }) => {
            client
                .call(&Request::PeerAllow {
                    id,
                    name,
                    quota_bytes: quota,
                })
                .await?;
            println!("Allowed.");
        }
        Command::Peer(PeerCommand::Revoke { id }) => {
            client.call(&Request::PeerRevoke { id }).await?;
            println!("Revoked. Data they already stored is kept.");
        }
        Command::Peer(PeerCommand::List) => {
            let Reply::Peers(peers) = client.call(&Request::PeerList).await? else {
                bail!("unexpected reply")
            };
            for p in peers {
                let quota = p
                    .quota_bytes
                    .map(format_bytes)
                    .unwrap_or_else(|| "no quota".into());
                println!(
                    "{}  {}  using {} of {quota}",
                    p.id,
                    p.name.as_deref().unwrap_or("-"),
                    format_bytes(p.used_bytes)
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{format_time, parse_size};

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

    #[test]
    fn times() {
        assert_eq!(format_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(
            format_time(951_782_400 * 1_000_000_000),
            "2000-02-29 00:00:00 UTC"
        );
        assert_eq!(
            format_time(1_791_743_056 * 1_000_000_000),
            "2026-10-11 18:24:16 UTC"
        );
    }
}
