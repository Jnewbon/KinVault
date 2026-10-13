# Command Line Reference

`kinvault` controls the background service (`kinvaultd`). Run
`kinvault <command> --help` for the details of any command.

Every command takes `--state <dir>` (or the `KINVAULT_STATE` environment
variable) to use a state folder other than the default (see
[Installation](Installation#where-kinvault-keeps-its-data)).

**Sizes** (`--quota`, `--upload-limit`, `--max`) take `K`, `M`, `G` or `T`,
e.g. `500G`; units are binary (`1G` = 1024 MiB). Upload limits are per second.
**Time windows** (`--window`) are `HH:MM-HH:MM`, e.g. `01:00-07:00`.
**Sets and peers** can be named by name or id.

## This instance

| Command | Does |
|---|---|
| `kinvault status` | This instance and the state of every backup |
| `kinvault watch` | Live activity, until Ctrl+C |
| `kinvault id` | Print this instance's id |
| `kinvault name <name>` | Set the name friends see |
| `kinvault keep-deleted [days]` | Show or set how long deleted data is kept (default 30): backups you stop, and data friends delete here |

## Background service

| Command | Does |
|---|---|
| `kinvault service install` | Start `kinvaultd` now and at every login |
| `kinvault service uninstall` | Stop starting it at login, and stop it (on Windows, it keeps running until you log out) |
| `kinvault service status` | Whether it's installed and running |

It's a systemd user unit on Linux (`~/.config/systemd/user/kinvaultd.service`),
a LaunchAgent on macOS, and a `Run` registry entry on Windows.

## Backups

| Command | Does |
|---|---|
| `kinvault set create <name> <paths>… --peer <peer>` | Back up to a peer |
| `kinvault set create <name> <paths>… --local <dir>` | Back up to a folder |
| `kinvault set exclude <set> [patterns…]` | Show, or replace, what's left out (`--clear` for nothing) |
| `kinvault set retention <set> [--keep-…]` | Change which versions are kept |
| `kinvault set limits <set> [--upload-limit] [--window]` | Change speed limit and hours (omitted ones are cleared) |
| `kinvault set pause <set>` | Stop automatic backups |
| `kinvault set resume <set> [paths…]` | Start them again, optionally from different paths |
| `kinvault set remove <set>` | Stop backing up; it stays restorable for the grace period, then it's erased |
| `kinvault set delete <set> [--yes]` | Delete a running or stopped backup for good (see [[Deleting Backups]]) |
| `kinvault backup <set>` | Back up now, even outside its hours, and wait |
| `kinvault usage <set>` | Space used where it's stored |
| `kinvault prune <set>` | Remove versions the keep rules don't keep |
| `kinvault verify <set> [--max <size> \| --full]` | Check backups are complete and decrypt (default 256M) |

`set create` options:

| Option | Meaning |
|---|---|
| `--peer <peer>` | Store on this peer |
| `--peer-addr <ip:port>` | A known direct address for the peer (optional) |
| `--local <dir>` | Store in this folder |
| `--debounce <seconds>` | Quiet time before backing up (default 30) |
| `--upload-limit <size>` | Maximum upload speed |
| `--window <HH:MM-HH:MM>` | Only back up automatically in these hours |
| `--keep-last`, `--keep-hourly`, `--keep-daily`, `--keep-weekly`, `--keep-monthly`, `--keep-yearly <N>` | Keep rules (default: the recommended set, see [Backups](Backups#keeping-old-versions)) |
| `--keep-all` | Never remove versions |
| `--exclude <pattern>` | Leave out matches; repeat for more |

You're asked for the backup's recovery passphrase (or set
`KINVAULT_PASSPHRASE`).

## Restoring

| Command | Does |
|---|---|
| `kinvault snapshots <set>` | List versions (of a running or stopped backup) |
| `kinvault restore <set> <version> <dir> [--include <path>]` | Restore a version (id prefix or `latest`) into a folder |

## Friends and devices

| Command | Does |
|---|---|
| `kinvault invite create [options]` | Make a one-time code for a friend or device |
| `kinvault invite list` | Codes not used yet |
| `kinvault invite cancel <id>` | Cancel a code |
| `kinvault invite redeem <code> [options]` | Accept a code |
| `kinvault peer list` | All peers |
| `kinvault peer allow <peer> [--name] [--quota] [--upload-limit] [--window]` | Let a peer store backups here, or change its limits |
| `kinvault peer revoke <peer>` | Stop accepting its backups (keeps what it stored) |
| `kinvault peer mine <peer>` | Mark as one of your devices (no limits) |
| `kinvault peer friend <peer>` | Move back to friends |
| `kinvault peer remove <peer>` | Remove; what it stored here is erased in a week |
| `kinvault nearby find` | Look for your devices on this network for a few minutes |
| `kinvault nearby pair <device>` | Pair with a found device, after checking codes match |
| `kinvault nearby stop` | Stop looking |

`invite create` options: `--name`, `--quota`, `--upload-limit`, `--window`,
`--ask-reciprocal`, `--mine`, `--expires-days` (default 7).

`invite redeem` options: `--name`, `--mine`, `--offer <size>`,
`--offer-unlimited`, `--offer-upload-limit`, `--offer-window`.

See [[Friends and Devices]].

## Network

| Command | Does |
|---|---|
| `kinvault network show` | Listening port and addresses in invite codes |
| `kinvault network port <port \| auto>` | Fix the UDP port (applies after a restart) |
| `kinvault network add <address[:port]>` | Add an IP or domain name to invite codes |
| `kinvault network remove <address>` | Remove one |

See [[Networking]].

## Recovery

| Command | Does |
|---|---|
| `kinvault recovery export <file>` | Write a recovery kit |
| `kinvault recovery import <file> [--force]` | Set up this machine from a kit (service must not be running) |

See [[Recovery Kit]].

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `KINVAULT_STATE` | all | State folder |
| `KINVAULT_PASSPHRASE` | `set create`, `recovery` | Passphrase, instead of asking |
| `KINVAULT_LISTEN_PORT` | `kinvaultd` | UDP port, if none is configured yet |
| `KINVAULT_WEB` | `kinvaultd` (web builds) | Serve the web interface on this address |
| `KINVAULT_WEB_PASSWORD` | `kinvaultd` (web builds) | Web sign-in password |
| `RUST_LOG` | `kinvaultd` | Log detail, e.g. `debug` |
