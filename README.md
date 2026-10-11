# KinVault

Self-hosted, encrypted backups between your own machines and your friends'.

- **Encrypted before it leaves your computer.** Hosts store opaque, deduplicated
  packs; they can't read file contents, names or sizes of individual files.
- **Peer to peer.** Instances find each other by id and connect directly (with
  NAT hole-punching, falling back to relays), so no port forwarding is needed.
- **Always up to date, cheaply.** A background service watches your folders and
  backs up only what changed, once changes settle.
- **Friends.** Invite a friend with a one-time code, give them a quota, a speed
  limit and upload hours, and optionally store your backups with them in return.
- **History.** Versioned snapshots with keep rules (hourly, daily, weekly…),
  periodic integrity checks, and a recovery kit to restore onto a new machine.

## Parts

| Crate | Binary | What it is |
|---|---|---|
| `kinvault-core` | | Encryption, chunking, packs, snapshots, prune/verify |
| `kinvault-net` | | Peer-to-peer transport (iroh), hosting, invites, limits |
| `kinvault-daemon` | `kinvaultd` | Background service and its local control API |
| `kinvault-cli` | `kinvault` | Command-line client of the service |
| `kinvault-gui` | `kinvault-gui` | Desktop app (Tauri) with a tray icon |

All backup work happens in `kinvaultd`. The CLI and desktop app only control
it, so closing them never stops backups.

## Building

```sh
cargo build --release            # core, network, daemon and CLI
cargo build --release -p kinvault-gui   # desktop app
```

The desktop app needs the system WebView. On Debian/Ubuntu:

```sh
sudo apt install libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev build-essential
```

Keep `kinvaultd` in the same directory as `kinvault` and `kinvault-gui` (or on
your `PATH`) so they can start it.

## Quick start (CLI)

```sh
kinvault service install          # run kinvaultd now and at every login
kinvault name my-laptop

# On the friend's machine: invite you, offering 500 GB
kinvault invite create --name me --quota 500G --ask-reciprocal

# On yours: accept, offering them 200 GB back
kinvault invite redeem kvinvite1… --offer 200G
kinvault set create documents ~/Documents --peer their-name

kinvault status
kinvault recovery export ~/kinvault-recovery.json   # keep this off this machine
```

Restoring: `kinvault snapshots documents`, then
`kinvault restore documents latest ~/restored`. On a new machine, run
`kinvault recovery import <kit>` before starting `kinvaultd`; imported sets
start paused until you `kinvault set resume <set> [paths]`.

## Development

```sh
cargo test                        # all crates except the GUI
cargo clippy --workspace --all-targets
```

Tests run real instances against each other on localhost, without relays.
