//! `kinvault` command-line tool: a thin client of the `kinvaultd` daemon.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand};
use kinvault_daemon::api::{
    CreateInvite, CreateSet, GrantSpec, HostAddr, NetworkInfo, NetworkSettings, Reply, Request,
    RetentionPolicy, SetState, Target, TimeWindow,
};
use kinvault_daemon::ipc::Client;

const PASSPHRASE_ENV: &str = "KINVAULT_PASSPHRASE";
/// What users type to confirm deleting a set for good.
const DELETE_CONFIRMATION: &str = "DELETE PERMANENTLY";

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
    /// Show this instance and the state of every backup set.
    Status,
    /// Print this instance's id.
    Id,
    /// Set the name friends see for this instance.
    Name { name: String },
    /// Manage backup sets.
    #[command(subcommand)]
    Set(SetCommand),
    /// Back up a set now (even outside its time window) and wait for it.
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
    /// Show how much space a set uses on the host it backs up to.
    Usage { set: String },
    /// Remove snapshots the set's retention policy doesn't keep, freeing space.
    Prune { set: String },
    /// Check that a set's backups are complete and can be decrypted.
    Verify {
        set: String,
        /// How much data to download and check, e.g. 1G (default 256M).
        #[arg(long, value_parser = parse_size, conflicts_with = "full")]
        max: Option<u64>,
        /// Download and check everything.
        #[arg(long)]
        full: bool,
    },
    /// Show live activity until interrupted.
    Watch,
    /// Show or change how many days deleted data is kept before it's erased:
    /// backups friends delete here, and backups you stop (`set remove`).
    KeepDeleted { days: Option<u64> },
    /// Start kinvaultd automatically when you log in.
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Export or import a recovery kit for restoring on a new machine.
    #[command(subcommand)]
    Recovery(RecoveryCommand),
    /// Invite friends to store backups here, or accept their invites.
    #[command(subcommand)]
    Invite(InviteCommand),
    /// Manage peers: who may store backups here, and who stores ours.
    #[command(subcommand)]
    Peer(PeerCommand),
    /// The port this instance listens on and the addresses invite codes include.
    #[command(subcommand)]
    Network(NetworkCommand),
    /// Pair with your other devices on this network, without an invite code.
    #[command(subcommand)]
    Nearby(NearbyCommand),
}

#[derive(Subcommand)]
enum NearbyCommand {
    /// Look for your other devices for a few minutes and list them as they
    /// appear. Run this on both devices.
    Find,
    /// Confirm a device found by `find` (name or id) as one of your own,
    /// after checking it shows the same code. Do this on both devices.
    Pair { device: String },
    /// Stop looking.
    Stop,
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
        /// Store backups on another instance: a peer's name or id.
        #[arg(long)]
        peer: Option<String>,
        /// Known direct address of the peer (optional).
        #[arg(long, requires = "peer")]
        peer_addr: Vec<SocketAddr>,
        /// Seconds without changes before backing up.
        #[arg(long)]
        debounce: Option<u64>,
        #[command(flatten)]
        limits: SetLimits,
        #[command(flatten)]
        retention: RetentionArgs,
        /// Leave out matching files and folders; repeat for more. Quote
        /// patterns so the shell doesn't expand them. See `set exclude`.
        #[arg(long = "exclude", value_name = "PATTERN")]
        excludes: Vec<String>,
    },
    /// Show or change the files and folders a set leaves out. Changes apply
    /// from the next backup; earlier versions keep what they hold until
    /// they're cleaned up. Quote patterns so the shell doesn't expand them.
    ///
    /// `*.bat` (anywhere), `/media/*.bat` (in /media only),
    /// `/media/.../*.bat` (in /media and below), `/media/*` (files in
    /// /media, not its folders), `/media/...` (everything in /media),
    /// `target/...` or `target/` (every folder named target).
    Exclude {
        set: String,
        /// The new list of patterns, replacing the current one.
        #[arg(value_name = "PATTERN")]
        patterns: Vec<String>,
        /// Leave nothing out.
        #[arg(long, conflicts_with = "patterns")]
        clear: bool,
    },
    /// Change which snapshots a set keeps (applied at the next prune).
    Retention {
        set: String,
        #[command(flatten)]
        retention: RetentionArgs,
    },
    /// Stop backing up a set automatically (restores still work).
    Pause { set: String },
    /// Resume automatic backups, optionally of different paths (e.g. after recovery).
    Resume { set: String, paths: Vec<PathBuf> },
    /// Change a set's upload limit and time window (omitted options are cleared).
    Limits {
        set: String,
        #[command(flatten)]
        limits: SetLimits,
    },
    /// Stop backing up a set. It can still be restored from until deleted
    /// data's grace period is over (see `keep-deleted`); then its backups
    /// are erased.
    Remove { set: String },
    /// Delete a set (running or stopped) and its backups for good. The set's
    /// key is erased now and the backups a week later, wherever they are
    /// stored.
    Delete {
        set: String,
        /// Don't ask to confirm.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum ServiceCommand {
    /// Start kinvaultd now and at every login.
    Install,
    /// Stop starting kinvaultd at login (and stop it).
    Uninstall,
    Status,
}

#[derive(Subcommand)]
enum RecoveryCommand {
    /// Write a recovery kit: this instance's identity and every set's key,
    /// encrypted with a passphrase. Store it away from this machine.
    Export { file: PathBuf },
    /// Set up this machine from a recovery kit. Run before starting kinvaultd;
    /// imported sets start paused so you can restore first.
    Import {
        file: PathBuf,
        /// Replace this instance's identity even though it already has sets or peers.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Args)]
struct RetentionArgs {
    /// Keep the newest N snapshots.
    #[arg(long)]
    keep_last: Option<u32>,
    /// Keep one snapshot for each of the last N hours.
    #[arg(long)]
    keep_hourly: Option<u32>,
    #[arg(long)]
    keep_daily: Option<u32>,
    #[arg(long)]
    keep_weekly: Option<u32>,
    #[arg(long)]
    keep_monthly: Option<u32>,
    #[arg(long)]
    keep_yearly: Option<u32>,
    /// Never remove snapshots.
    #[arg(long, conflicts_with_all = ["keep_last", "keep_hourly", "keep_daily", "keep_weekly", "keep_monthly", "keep_yearly"])]
    keep_all: bool,
}

impl RetentionArgs {
    /// `None` when no option was given.
    fn policy(&self) -> Option<RetentionPolicy> {
        let p = RetentionPolicy {
            last: self.keep_last,
            hourly: self.keep_hourly,
            daily: self.keep_daily,
            weekly: self.keep_weekly,
            monthly: self.keep_monthly,
            yearly: self.keep_yearly,
        };
        (self.keep_all || !p.keeps_everything()).then_some(p)
    }
}

#[derive(Args)]
struct SetLimits {
    /// Maximum upload speed per second, e.g. 2M.
    #[arg(long, value_parser = parse_size)]
    upload_limit: Option<u64>,
    /// Only back up automatically during these hours, e.g. 01:00-07:00.
    #[arg(long, value_parser = TimeWindow::parse)]
    window: Option<TimeWindow>,
}

#[derive(Args)]
struct GrantArgs {
    /// Storage limit, e.g. 500G or 2T.
    #[arg(long, value_parser = parse_size)]
    quota: Option<u64>,
    /// Maximum upload speed per second they may use, e.g. 5M.
    #[arg(long, value_parser = parse_size)]
    upload_limit: Option<u64>,
    /// Only accept their uploads during these hours, e.g. 01:00-07:00.
    #[arg(long, value_parser = TimeWindow::parse)]
    window: Option<TimeWindow>,
}

impl GrantArgs {
    fn spec(&self) -> GrantSpec {
        GrantSpec {
            quota_bytes: self.quota,
            upload_limit: self.upload_limit,
            window: self.window,
        }
    }
}

#[derive(Subcommand)]
enum InviteCommand {
    /// Create a one-time invite code for a friend to store backups here.
    Create {
        /// What to call the friend once they join.
        #[arg(long)]
        name: Option<String>,
        #[command(flatten)]
        grant: GrantArgs,
        /// Ask the friend to store your backups in return.
        #[arg(long)]
        ask_reciprocal: bool,
        /// For one of your own devices: no limits either way, listed as mine.
        #[arg(long, conflicts_with = "ask_reciprocal")]
        mine: bool,
        /// Days until the code expires.
        #[arg(long, default_value_t = 7)]
        expires_days: u64,
    },
    /// List invites that haven't been used yet.
    List,
    Cancel {
        id: String,
    },
    /// Accept a friend's invite code so you can store backups with them.
    Redeem {
        code: String,
        /// What to call this friend locally.
        #[arg(long)]
        name: Option<String>,
        /// Offer them this much storage here in return, e.g. 500G.
        #[arg(long, value_parser = parse_size)]
        offer: Option<u64>,
        /// Offer them unlimited storage here in return.
        #[arg(long, conflicts_with = "offer")]
        offer_unlimited: bool,
        /// The code is from one of your own devices: no limits either way,
        /// listed as mine.
        #[arg(long, conflicts_with_all = ["offer", "offer_unlimited", "offer_upload_limit", "offer_window"])]
        mine: bool,
        /// Maximum upload speed per second for their backups here.
        #[arg(long, value_parser = parse_size)]
        offer_upload_limit: Option<u64>,
        /// Only accept their uploads during these hours.
        #[arg(long, value_parser = TimeWindow::parse)]
        offer_window: Option<TimeWindow>,
    },
}

#[derive(Subcommand)]
enum PeerCommand {
    /// Allow a peer (name or id) to store backups here, or change its limits.
    Allow {
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[command(flatten)]
        grant: GrantArgs,
    },
    /// Stop accepting backups from a peer (name or id); what it stored is kept.
    Revoke {
        peer: String,
    },
    List,
    /// Mark a peer (name or id) as one of your own devices; it may then
    /// store backups here without limits.
    Mine {
        peer: String,
    },
    /// Move a peer (name or id) back from your devices to your friends.
    Friend {
        peer: String,
    },
    /// Remove a peer (name or id). It can no longer store backups here, and
    /// what it stored here is erased in a week. Only possible once none of
    /// your backups are stored on it.
    Remove {
        peer: String,
    },
}

#[derive(Subcommand)]
enum NetworkCommand {
    /// Show the listening port and the addresses put in invite codes.
    Show,
    /// Listen on a fixed UDP port (to forward it on your router), or "auto".
    Port {
        #[arg(value_parser = parse_port)]
        port: PortArg,
    },
    /// Add an IP address or domain name (optionally with :port) to invite codes.
    Add { address: String },
    /// Remove an address from invite codes.
    Remove { address: String },
}

#[derive(Clone, Copy)]
struct PortArg(Option<u16>);

fn parse_port(s: &str) -> Result<PortArg, String> {
    if s.eq_ignore_ascii_case("auto") {
        return Ok(PortArg(None));
    }
    match s.parse::<u16>() {
        Ok(p) if p > 0 => Ok(PortArg(Some(p))),
        _ => Err("expected a port from 1 to 65535, or \"auto\"".into()),
    }
}

fn print_network(info: &NetworkInfo) {
    match info.settings.listen_port {
        Some(port) => println!("listening port  {port} (UDP)"),
        None => println!("listening port  random (set one with `kinvault network port <port>`)"),
    }
    let bound: Vec<String> = info.bound.iter().map(|a| a.to_string()).collect();
    println!("listening on    {}", bound.join(", "));
    if info.restart_required {
        println!("                restart kinvaultd to use the new port");
    }
    if info.settings.public_hosts.is_empty() {
        println!("invite codes    automatic addresses only");
    } else {
        println!("invite codes    automatic addresses, plus:");
        for host in &info.settings.public_hosts {
            println!("  {host}");
        }
        let portless = info
            .settings
            .public_hosts
            .iter()
            .any(|h| h.parse::<HostAddr>().is_ok_and(|h| h.port().is_none()));
        if portless && info.settings.listen_port.is_none() {
            println!(
                "\nAddresses without a port use the listening port, which changes when\n\
                 kinvaultd restarts. Set a fixed one with `kinvault network port <port>`."
            );
        }
    }
}

async fn get_network(client: &mut Client) -> Result<NetworkInfo> {
    match client.call(&Request::GetNetwork).await? {
        Reply::Network(info) => Ok(info),
        _ => bail!("unexpected reply"),
    }
}

async fn set_network(client: &mut Client, settings: NetworkSettings) -> Result<NetworkInfo> {
    match client.call(&Request::SetNetwork(settings)).await? {
        Reply::Network(info) => Ok(info),
        _ => bail!("unexpected reply"),
    }
}

fn kit_passphrase(confirm: bool) -> Result<String> {
    if let Ok(p) = std::env::var(PASSPHRASE_ENV) {
        return Ok(p);
    }
    let p = rpassword::prompt_password("Recovery kit passphrase: ")?;
    if confirm && rpassword::prompt_password("Repeat passphrase: ")? != p {
        bail!("passphrases do not match");
    }
    Ok(p)
}

fn plural_days(days: u64) -> String {
    if days == 1 {
        "1 day".to_string()
    } else {
        format!("{days} days")
    }
}

fn format_unix(secs: i64) -> String {
    format_time(secs * 1_000_000_000)
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

fn describe_grant(g: &GrantSpec) -> String {
    let mut parts = vec![
        g.quota_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "unlimited".into()),
    ];
    if let Some(rate) = g.upload_limit {
        parts.push(format!("max {}/s", format_bytes(rate)));
    }
    if let Some(w) = g.window {
        parts.push(format!("uploads {w}"));
    }
    parts.join(", ")
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let state = match cli.state {
        Some(d) => d,
        None => kinvault_daemon::default_state_dir()
            .context("could not determine a data directory; pass --state")?,
    };
    if let Command::Service(cmd) = &cli.command {
        use kinvault_daemon::service;
        // Only pass --state through when it isn't the default.
        let custom_state = (Some(&state) != kinvault_daemon::default_state_dir().as_ref())
            .then_some(state.as_path());
        match cmd {
            ServiceCommand::Install => {
                let daemon = service::daemon_binary()?;
                service::install(&daemon, custom_state)?;
                println!(
                    "kinvaultd ({}) now starts at login and is running.",
                    daemon.display()
                );
            }
            ServiceCommand::Uninstall => {
                service::uninstall()?;
                println!("kinvaultd no longer starts at login.");
            }
            ServiceCommand::Status => {
                let installed = if service::is_installed() {
                    "starts at login"
                } else {
                    "does not start at login"
                };
                let running = if kinvault_daemon::ipc::daemon_running(&state) {
                    "running"
                } else {
                    "not running"
                };
                println!("kinvaultd {installed}; currently {running}.");
            }
        }
        return Ok(());
    }
    // Importing a recovery kit happens before the daemon runs.
    if let Command::Recovery(RecoveryCommand::Import { file, force }) = &cli.command {
        let json =
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let summary = kinvault_daemon::recovery::import_offline(
            &state,
            &json,
            &kit_passphrase(false)?,
            *force,
        )?;
        println!("Recovered instance {}.", summary.instance_id);
        println!("Imported sets (paused): {}", summary.sets.join(", "));
        println!("\nNext: start kinvaultd, restore with `kinvault restore <set> latest <dir>`,");
        println!("then continue backing up with `kinvault set resume <set> [paths]`.");
        println!("Make sure the old machine is not running with this identity anymore.");
        return Ok(());
    }
    let mut client = Client::connect(&state).await?;

    match cli.command {
        Command::Status => {
            let Reply::Status(s) = client.call(&Request::Status).await? else {
                bail!("unexpected reply")
            };
            println!("instance {} ({})", s.name, s.id);
            println!("hosting store {}", s.hosting_store.display());
            println!(
                "keeps deleted data for {}",
                plural_days(s.keep_deleted_days)
            );
            if s.sets.is_empty() && s.stopped_sets.is_empty() {
                println!("no backup sets; create one with `kinvault set create`");
            }
            for set in s.sets {
                let state = match set.state {
                    SetState::Idle => "up to date",
                    SetState::ChangesPending => "changes pending",
                    SetState::WaitingForWindow => "waiting for its time window",
                    SetState::Paused => "paused",
                    SetState::WaitingForHost => "waiting for its backup host to come online",
                    SetState::Running => "backing up",
                };
                let online = match set.target_online {
                    Some(true) => " (online)",
                    Some(false) => " (offline)",
                    None => "",
                };
                println!(
                    "\n{} ({state}) -> {}{online}",
                    set.name,
                    describe_target(&set.target)
                );
                for p in &set.paths {
                    println!("  {}", p.display());
                }
                if let Some(rate) = set.upload_limit {
                    println!("  upload limit {}/s", format_bytes(rate));
                }
                if let Some(w) = set.window {
                    println!("  backs up automatically during {w}");
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
                println!("  keeps {}", set.retention);
                if !set.excludes.is_empty() {
                    println!("  leaves out {}", set.excludes.join(", "));
                }
                if let Some(p) = set.last_prune {
                    println!(
                        "  last prune {}: removed {} snapshot(s), freed {}",
                        format_unix(p.time_unix),
                        p.snapshots_removed,
                        format_bytes(p.bytes_deleted)
                    );
                }
                if let Some(v) = set.last_verify {
                    let result = if v.ok {
                        "ok".to_string()
                    } else {
                        format!("PROBLEMS: {}", v.errors.join("; "))
                    };
                    println!(
                        "  last check {}: {} ({} checked)",
                        format_unix(v.time_unix),
                        result,
                        format_bytes(v.bytes_checked)
                    );
                }
            }
            for set in s.stopped_sets {
                println!(
                    "\n{} [{}] (stopped {}) -> {}",
                    set.name,
                    set.id,
                    format_unix(set.stopped_unix),
                    describe_target(&set.target)
                );
                println!(
                    "  can be restored until {}; then its backups are erased",
                    format_unix(set.erase_after_unix)
                );
            }
        }
        Command::KeepDeleted { days } => {
            if let Some(days) = days {
                client.call(&Request::SetKeepDeletedDays { days }).await?;
            }
            let Reply::Status(s) = client.call(&Request::Status).await? else {
                bail!("unexpected reply")
            };
            println!(
                "Deleted data is kept for {} before it's erased.",
                plural_days(s.keep_deleted_days)
            );
        }
        Command::Id => {
            let Reply::Status(s) = client.call(&Request::Status).await? else {
                bail!("unexpected reply")
            };
            println!("{}", s.id);
        }
        Command::Name { name } => {
            client.call(&Request::SetInstanceName { name }).await?;
            println!("Name set.");
        }
        Command::Set(SetCommand::Create {
            retention,
            name,
            paths,
            local,
            peer,
            peer_addr,
            debounce,
            limits,
            excludes,
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
                upload_limit: limits.upload_limit,
                window: limits.window,
                retention: retention.policy(),
                excludes,
            });
            let Reply::SetCreated { id } = client.call(&req).await? else {
                bail!("unexpected reply")
            };
            println!("Created set {name:?} ({id}); the first backup is starting.");
            println!("To be able to restore if this machine is lost, export a recovery kit:");
            println!(
                "  kinvault recovery export <file>   (keep it somewhere other than this machine)"
            );
        }
        Command::Set(SetCommand::Exclude {
            set,
            patterns,
            clear,
        }) => {
            if patterns.is_empty() && !clear {
                let Reply::Status(s) = client.call(&Request::Status).await? else {
                    bail!("unexpected reply")
                };
                let found = s
                    .sets
                    .into_iter()
                    .find(|s| s.id == set || s.name == set)
                    .ok_or_else(|| anyhow::anyhow!("no backup set named {set:?}"))?;
                if found.excludes.is_empty() {
                    println!("{} leaves nothing out.", found.name);
                }
                for p in found.excludes {
                    println!("{p}");
                }
                return Ok(());
            }
            client
                .call(&Request::SetExcludes {
                    set,
                    excludes: patterns,
                })
                .await?;
            println!("Saved. Applies from the next backup; earlier versions keep what they hold.");
        }
        Command::Set(SetCommand::Limits { set, limits }) => {
            let req = Request::SetLimits {
                set,
                upload_limit: limits.upload_limit,
                window: limits.window,
            };
            client.call(&req).await?;
            println!("Limits updated.");
        }
        Command::Set(SetCommand::Retention { set, retention }) => {
            let policy = retention
                .policy()
                .context("give at least one --keep-* option, or --keep-all")?;
            client.call(&Request::SetRetention { set, policy }).await?;
            println!("Retention set to: {policy}.");
        }
        Command::Set(SetCommand::Pause { set }) => {
            client.call(&Request::PauseSet { set }).await?;
            println!("Paused.");
        }
        Command::Set(SetCommand::Resume { set, paths }) => {
            let paths = (!paths.is_empty()).then_some(paths);
            client.call(&Request::ResumeSet { set, paths }).await?;
            println!("Resumed; a backup is starting.");
        }
        Command::Prune { set } => {
            let Reply::Pruned(p) = client.call(&Request::Prune { set }).await? else {
                bail!("unexpected reply")
            };
            println!(
                "kept {} snapshot(s), removed {}; deleted {} pack(s), rewrote {}; freed about {}",
                p.snapshots_kept,
                p.snapshots_removed,
                p.packs_deleted,
                p.packs_repacked,
                format_bytes(p.bytes_deleted)
            );
            if p.bytes_deleted > 0 {
                println!(
                    "(a host keeps deleted data for its grace period before the space is free)"
                );
            }
        }
        Command::Verify { set, max, full } => {
            let max_bytes = if full { Some(u64::MAX) } else { max };
            let Reply::Verified(v) = client.call(&Request::Verify { set, max_bytes }).await? else {
                bail!("unexpected reply")
            };
            println!(
                "{} snapshot(s) complete check: {}; checked {} in {} pack(s)",
                v.snapshots,
                if v.missing_chunks == 0 {
                    "ok"
                } else {
                    "MISSING DATA"
                },
                format_bytes(v.bytes_checked),
                v.packs_checked
            );
            for e in &v.errors {
                println!("  problem: {e}");
            }
            if v.ok {
                println!("All good.");
            } else {
                println!(
                    "Damaged data was removed; the next backup re-uploads whatever still exists here."
                );
                std::process::exit(1);
            }
        }
        Command::Recovery(RecoveryCommand::Export { file }) => {
            println!("Choose a passphrase for the recovery kit. You need it to use the kit.");
            let passphrase = kit_passphrase(true)?;
            let Reply::RecoveryKit { json } = client
                .call(&Request::ExportRecoveryKit { passphrase })
                .await?
            else {
                bail!("unexpected reply")
            };
            write_private_file(&file, json.as_bytes())?;
            println!(
                "Wrote {}. Keep it (and the passphrase) somewhere other than this machine.",
                file.display()
            );
            println!("Export again after adding backup sets.");
        }
        Command::Recovery(RecoveryCommand::Import { .. }) | Command::Service(_) => {
            unreachable!("handled before connecting")
        }
        Command::Watch => {
            use kinvault_daemon::api::Event;
            let Reply::Status(s) = client.call(&Request::Status).await? else {
                bail!("unexpected reply")
            };
            let names: std::collections::HashMap<String, String> =
                s.sets.into_iter().map(|set| (set.id, set.name)).collect();
            let name = |id: &String| names.get(id).cloned().unwrap_or_else(|| id.clone());
            let mut events = client.subscribe().await?;
            println!("watching kinvaultd (Ctrl+C to stop)");
            while let Some(event) = events.next().await {
                match event {
                    Event::SetState { set, state } => println!("{}: {state:?}", name(&set)),
                    Event::Progress {
                        set,
                        files,
                        total_bytes,
                        bytes_uploaded,
                        ..
                    } => println!(
                        "{}: {files} files scanned ({}), uploaded {}",
                        name(&set),
                        format_bytes(total_bytes),
                        format_bytes(bytes_uploaded)
                    ),
                    Event::BackupFinished { set, summary } => println!(
                        "{}: backup done, {} changed, uploaded {}",
                        name(&set),
                        summary.files_changed,
                        format_bytes(summary.bytes_uploaded)
                    ),
                    Event::BackupFailed { set, error } => {
                        println!("{}: backup failed: {error}", name(&set))
                    }
                    Event::SetsChanged => println!("(backup sets changed)"),
                    Event::PeersChanged => println!("(peers changed)"),
                    Event::NetworkChanged => println!("(network settings changed)"),
                    Event::NearbyChanged => println!("(nearby devices changed)"),
                    Event::PeerOnline { id, online } => println!(
                        "backup host {}… is {}",
                        &id[..id.len().min(16)],
                        if online { "online" } else { "offline" }
                    ),
                    Event::RestoreProgress(r) => println!(
                        "restoring {}: {} of {} files, {} of {}",
                        r.set_name,
                        r.files,
                        r.total_files,
                        format_bytes(r.bytes),
                        format_bytes(r.total_bytes)
                    ),
                    Event::RestoreFinished { set, summary, .. } => println!(
                        "{}: restored {} files ({})",
                        name(&set),
                        summary.files,
                        format_bytes(summary.bytes)
                    ),
                    Event::RestoreFailed {
                        set,
                        error,
                        cancelled,
                        ..
                    } => {
                        if cancelled {
                            println!("{}: restore cancelled", name(&set))
                        } else {
                            println!("{}: restore failed: {error}", name(&set))
                        }
                    }
                }
            }
            println!("kinvaultd stopped");
        }
        Command::Set(SetCommand::Remove { set }) => {
            client
                .call(&Request::RemoveSet { set: set.clone() })
                .await?;
            let Reply::Status(s) = client.call(&Request::Status).await? else {
                bail!("unexpected reply")
            };
            println!("Stopped backing up {set}.");
            // The newest stopped set of that name is the one just stopped.
            if let Some(stopped) = s
                .stopped_sets
                .iter()
                .filter(|st| st.name == set || st.id == set)
                .max_by_key(|st| st.stopped_unix)
            {
                println!(
                    "Its backups can be restored until {}; then they're erased.",
                    format_unix(stopped.erase_after_unix)
                );
                println!("To erase them sooner: kinvault set delete {}", stopped.id);
            }
        }
        Command::Set(SetCommand::Delete { set, yes }) => {
            if !yes {
                println!(
                    "This deletes {set} and all its backups. They can't be restored afterwards,"
                );
                println!(
                    "not even with a recovery kit. Where they're stored, they're erased in a week."
                );
                print!("Type {DELETE_CONFIRMATION} to confirm: ");
                std::io::Write::flush(&mut std::io::stdout())?;
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                ensure!(line.trim() == DELETE_CONFIRMATION, "not deleted");
            }
            let Reply::SetDeleted(d) = client
                .call(&Request::DeleteSet { set: set.clone() })
                .await?
            else {
                bail!("unexpected reply")
            };
            println!("Deleted {set}.");
            match (d.erase_after_unix, d.error) {
                (Some(t), None) => println!(
                    "Its backups will be erased on {}.",
                    format_time(t * 1_000_000_000)
                ),
                (_, Some(e)) if d.retrying => println!(
                    "The host storing its backups couldn't be reached ({e}).\nKinVault will keep asking it to erase them."
                ),
                (_, Some(e)) => println!("Its backups weren't erased there: {e}"),
                (None, None) => {}
            }
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
        Command::Invite(InviteCommand::Create {
            name,
            grant,
            ask_reciprocal,
            mine,
            expires_days,
        }) => {
            let req = Request::CreateInvite(CreateInvite {
                name,
                grant: grant.spec(),
                ask_reciprocal,
                expires_secs: Some(expires_days * 24 * 60 * 60),
                mine,
            });
            let Reply::Invite {
                ticket,
                expires_unix,
                ..
            } = client.call(&req).await?
            else {
                bail!("unexpected reply")
            };
            println!(
                "Send this code to your friend (valid until {}, single use):\n",
                format_time(expires_unix * 1_000_000_000)
            );
            println!("{ticket}\n");
            if mine {
                println!(
                    "Accept it on your other device with: kinvault invite redeem --mine <code>"
                );
            } else {
                println!("They accept it with: kinvault invite redeem <code>");
            }
        }
        Command::Invite(InviteCommand::List) => {
            let Reply::Invites(invites) = client.call(&Request::ListInvites).await? else {
                bail!("unexpected reply")
            };
            if invites.is_empty() {
                println!("no open invites");
            }
            for i in invites {
                println!(
                    "{}  {}  {}{}  expires {}",
                    i.id,
                    i.name.as_deref().unwrap_or("-"),
                    describe_grant(&i.grant),
                    if i.ask_reciprocal {
                        ", asks for storage back"
                    } else {
                        ""
                    },
                    format_time(i.expires_unix * 1_000_000_000)
                );
                if i.mine {
                    println!("  for one of your devices");
                }
            }
        }
        Command::Invite(InviteCommand::Cancel { id }) => {
            client.call(&Request::CancelInvite { id }).await?;
            println!("Invite cancelled.");
        }
        Command::Invite(InviteCommand::Redeem {
            code,
            name,
            offer,
            offer_unlimited,
            offer_upload_limit,
            offer_window,
            mine,
        }) => {
            let offer = (offer.is_some() || offer_unlimited).then_some(GrantSpec {
                quota_bytes: offer,
                upload_limit: offer_upload_limit,
                window: offer_window,
            });
            let offered = offer.is_some() || mine;
            let Reply::Redeemed {
                host_name,
                quota_bytes,
                ask_reciprocal,
                ..
            } = client
                .call(&Request::RedeemInvite {
                    ticket: code,
                    name,
                    offer,
                    mine,
                })
                .await?
            else {
                bail!("unexpected reply")
            };
            let space = quota_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "unlimited space".into());
            println!("Joined {host_name}: you can store {space} there.");
            println!("Back up to it with: kinvault set create <name> <paths> --peer {host_name}");
            if ask_reciprocal && !offered {
                println!("\n{host_name} asked you to store their backups too. To agree, run:");
                println!("  kinvault peer allow {host_name} --quota <size>");
            } else if offered {
                println!("{host_name} can now store backups here too.");
            }
        }
        Command::Peer(PeerCommand::Allow { id, name, grant }) => {
            client
                .call(&Request::PeerAllow {
                    id,
                    name,
                    grant: grant.spec(),
                })
                .await?;
            println!("Allowed.");
        }
        Command::Peer(PeerCommand::Revoke { peer }) => {
            client.call(&Request::PeerRevoke { id: peer }).await?;
            println!("Revoked. Data they already stored is kept.");
        }
        Command::Peer(PeerCommand::Mine { peer }) => {
            client
                .call(&Request::PeerSetMine {
                    id: peer,
                    mine: true,
                })
                .await?;
            println!("Marked as your device. It may store backups here without limits.");
        }
        Command::Peer(PeerCommand::Friend { peer }) => {
            client
                .call(&Request::PeerSetMine {
                    id: peer,
                    mine: false,
                })
                .await?;
            println!("Moved to your friends. Its storage limits are unchanged.");
        }
        Command::Peer(PeerCommand::Remove { peer }) => {
            client.call(&Request::PeerRemove { id: peer }).await?;
            println!("Removed. Anything it stored here is erased in a week.");
        }
        Command::Peer(PeerCommand::List) => {
            let Reply::Peers(peers) = client.call(&Request::PeerList).await? else {
                bail!("unexpected reply")
            };
            if peers.is_empty() {
                println!("no peers yet; invite a friend with `kinvault invite create`");
            }
            for p in peers {
                let online = match (p.online, p.last_seen_unix) {
                    (Some(true), _) => "  [online]".to_string(),
                    (Some(false), Some(t)) => {
                        format!("  [offline, last seen {}]", format_unix(t))
                    }
                    (Some(false), None) => "  [offline]".to_string(),
                    (None, _) => String::new(),
                };
                println!(
                    "{}  {}{}{online}",
                    p.name.as_deref().unwrap_or("(unnamed)"),
                    p.id,
                    if p.mine { "  (mine)" } else { "" }
                );
                let deleting = if p.deleting_bytes > 0 {
                    format!(" ({} marked for deletion)", format_bytes(p.deleting_bytes))
                } else {
                    String::new()
                };
                match p.grant {
                    Some(g) => println!(
                        "  stores here: using {} of {}{deleting}",
                        format_bytes(p.used_bytes),
                        describe_grant(&g)
                    ),
                    None if p.used_bytes > 0 => println!(
                        "  may not store backups here; {} left here{deleting}",
                        format_bytes(p.used_bytes)
                    ),
                    None => println!("  may not store backups here"),
                }
                if let Some(h) = p.hosts_us {
                    let space = h
                        .quota_bytes
                        .map(format_bytes)
                        .unwrap_or_else(|| "unlimited".into());
                    println!("  hosts our backups: {space}");
                }
            }
        }
        Command::Nearby(NearbyCommand::Find) => {
            use kinvault_daemon::api::NearbyState;
            let Reply::Nearby(mut status) = client.call(&Request::FindNearby).await? else {
                bail!("unexpected reply")
            };
            println!("Looking for your devices on this network. Run this on the other device too.");
            println!("Then pair with: kinvault nearby pair <name>  (on both devices)\n");
            let mut shown = std::collections::HashMap::new();
            while let Some(until) = status.until_unix {
                for d in &status.devices {
                    if shown.get(&d.id) != Some(&d.state) {
                        let state = match d.state {
                            NearbyState::Found => "found",
                            NearbyState::Waiting => "waiting for it to confirm",
                            NearbyState::Paired => "yours",
                        };
                        println!("{}  code {}  {state}  ({})", d.name, d.code, d.id);
                        shown.insert(d.id.clone(), d.state);
                    }
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                if until <= now {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let Reply::Nearby(s) = client.call(&Request::NearbyStatus).await? else {
                    bail!("unexpected reply")
                };
                status = s;
            }
            println!("Stopped looking.");
        }
        Command::Nearby(NearbyCommand::Pair { device }) => {
            use kinvault_daemon::api::NearbyState;
            let Reply::Nearby(status) = client.call(&Request::NearbyStatus).await? else {
                bail!("unexpected reply")
            };
            ensure!(
                status.until_unix.is_some(),
                "not looking for devices; run `kinvault nearby find` first"
            );
            let matches: Vec<_> = status
                .devices
                .iter()
                .filter(|d| d.id == device || d.name == device)
                .collect();
            let d = match matches.as_slice() {
                [d] => *d,
                [] => bail!("no nearby device named {device:?}"),
                _ => bail!("more than one nearby device is named {device:?}; use its id"),
            };
            let Reply::Nearby(status) = client
                .call(&Request::PairNearby { id: d.id.clone() })
                .await?
            else {
                bail!("unexpected reply")
            };
            match status
                .devices
                .iter()
                .find(|x| x.id == d.id)
                .map(|x| x.state)
            {
                Some(NearbyState::Paired) => {
                    println!("Paired with {}. It's now one of your devices.", d.name)
                }
                _ => println!(
                    "Confirmed. Now pair with this device on {} (code {}).",
                    d.name, d.code
                ),
            }
        }
        Command::Nearby(NearbyCommand::Stop) => {
            client.call(&Request::StopNearby).await?;
            println!("Stopped looking.");
        }
        Command::Network(NetworkCommand::Show) => {
            print_network(&get_network(&mut client).await?);
        }
        Command::Network(NetworkCommand::Port { port }) => {
            let mut settings = get_network(&mut client).await?.settings;
            settings.listen_port = port.0;
            print_network(&set_network(&mut client, settings).await?);
        }
        Command::Network(NetworkCommand::Add { address }) => {
            let mut settings = get_network(&mut client).await?.settings;
            settings.public_hosts.push(address);
            print_network(&set_network(&mut client, settings).await?);
        }
        Command::Network(NetworkCommand::Remove { address }) => {
            let address = address.parse::<HostAddr>()?.to_string();
            let mut settings = get_network(&mut client).await?.settings;
            let before = settings.public_hosts.len();
            settings.public_hosts.retain(|h| *h != address);
            if settings.public_hosts.len() == before {
                bail!("{address} is not in the list; see `kinvault network show`");
            }
            print_network(&set_network(&mut client, settings).await?);
        }
    }
    Ok(())
}

fn write_private_file(path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path)
        .and_then(|mut f| f.write_all(data))
        .with_context(|| format!("writing {}", path.display()))
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
