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

## Packaging

Installers are built with the Tauri CLI, pinned in
`crates/kinvault-gui/package.json` (needs Node.js):

```sh
cd crates/kinvault-gui
npm install
npm run bundle
```

Bundles land in `target/release/bundle/`: `.deb`, `.rpm` and an AppImage on
Linux; `.app`/`.dmg` on macOS; `.msi` and an NSIS installer on Windows. Each
platform's installers must be built on that platform. Every bundle ships the
app with `kinvaultd` and the `kinvault` CLI beside it (on Linux packages, all
three in `/usr/bin`). The sidecars are built by `scripts/sidecars.mjs`, which
`tauri.bundle.conf.json` runs before bundling; plain `cargo build` doesn't need
them.

### Releases

GitHub Actions builds installers for every platform (`.github/workflows/release.yml`):

1. Bump `version` in the root `Cargo.toml` and commit.
2. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`.
3. A **draft** release appears with the Linux, macOS (Apple Silicon and Intel)
   and Windows installers attached. Check it, then publish it.

The tag must match the `Cargo.toml` version or the build stops. Running the
workflow by hand from the Actions tab builds everything as downloadable
artifacts without creating a release. `.github/workflows/ci.yml` runs
formatting, clippy and the tests on Linux, macOS and Windows for every push
and pull request.

When run from an AppImage, the app copies `kinvaultd` to
`~/.local/share/KinVault/bin/` before starting it or registering it to run at
login, because the AppImage's own files disappear when the app exits.

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

### Reaching your instance at your own address

Invite codes include the addresses an instance finds by itself. If friends can
reach it some other way, such as a static IP or a (dynamic) DNS name with a
port forwarded on your router, add that address so invite codes include it too:

```sh
kinvault network port 47123             # listen on a fixed UDP port (restart kinvaultd)
kinvault network add home.example.org   # uses the listening port
kinvault network add 203.0.113.7:4433   # or give a port explicitly
kinvault network show
```

Friends who redeem the code remember these addresses and look domain names up
again on every connection, so a dynamic DNS name keeps working when your IP
changes. The same settings are under Settings → Network in the desktop app.

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
