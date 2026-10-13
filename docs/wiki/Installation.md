# Installation

## Desktop (Linux, macOS, Windows)

Download the installer for your system from the
[Releases](https://github.com/Jnewbon/KinVault/releases) page:

| System | Files |
|---|---|
| Linux | `.deb` (Debian, Ubuntu), `.rpm` (Fedora, openSUSE) or `.AppImage` (anything else) |
| macOS | `.dmg`, for Apple Silicon or Intel |
| Windows | `.msi` or the `-setup.exe` installer |

Every installer includes the desktop app, the background service
(`kinvaultd`) and the command line tool (`kinvault`). On Linux packages all
three go in `/usr/bin`.

Open KinVault. If the background service isn't running yet, the app offers to
start it. To have it start whenever you log in, turn on **Settings → Start at
login** (or run `kinvault service install`).

> **AppImage:** the app copies `kinvaultd` to `~/.local/share/KinVault/bin/`
> before starting it, because the AppImage's own files disappear when the app
> closes. That's expected.

## Server or NAS

Use the Docker image. See [[Server and NAS]].

## Building from source

You need [Rust](https://rustup.rs).

```sh
cargo build --release                    # service and command line tool
cargo build --release -p kinvault-gui    # desktop app
```

The desktop app needs the system WebView. On Debian/Ubuntu:

```sh
sudo apt install libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev build-essential
```

Keep `kinvaultd` in the same folder as `kinvault` and `kinvault-gui`, or on
your `PATH`, so they can start it.

## Where KinVault keeps its data

The service keeps its identity, settings and backup keys in a state folder:

| System | Folder |
|---|---|
| Linux | `~/.local/share/KinVault` |
| macOS | `~/Library/Application Support/KinVault` |
| Windows | `%APPDATA%\KinVault\data` |

Use a different folder with `--state <dir>` or the `KINVAULT_STATE`
environment variable (on both `kinvaultd` and `kinvault`).

This folder holds the keys to your backups. Don't share it, and make a
[[Recovery Kit]] so losing it doesn't mean losing your backups.
