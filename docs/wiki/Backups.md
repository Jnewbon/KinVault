# Backups

A **backup set** (or just "backup") is a group of files and folders that are
backed up together to one place, with their own history of versions.

## Creating a backup

In the app: **Backups → New backup**. On the command line:

```sh
kinvault set create <name> <paths>… (--peer <peer> | --local <folder>) [options]
```

Each backup asks for a **recovery passphrase** (at least 8 characters).
KinVault keeps a second, passphrase-protected copy of the backup's key
(`keyfile.json` in the state folder) alongside the key it uses day to day.
Write the passphrase down. It's separate from the [[Recovery Kit]]
passphrase.

A new backup isn't in recovery kits you made before it, so export a new kit
after creating one.

The first backup starts immediately.

### Where backups are stored

| Destination | App | Command line |
|---|---|---|
| A friend or one of your devices | pick them under **Where to keep the backup** | `--peer <name or id>` |
| Another KinVault instance you haven't connected with | **Another KinVault instance (paste its id)…** | `--peer <id>` (optionally `--peer-addr <ip:port>`) |
| A folder: an external disk, a mounted network share | **Its backup folder** | `--local <folder>` |

Whoever stores your backups only sees encrypted, deduplicated packs. They
can't read your files, their names, or the sizes of individual files.

## When backups run

KinVault watches the folders in each backup. When something changes it waits
until things have been quiet for 30 seconds (change with `--debounce
<seconds>`), then backs up only what changed. A steady stream of changes never
holds a backup off for more than 10 minutes.

If a backup fails it's retried automatically, waiting longer each time, up
to 30 minutes between attempts.

## Destinations that aren't always on

A friend's computer or one of your own devices won't always be switched on.
KinVault checks every couple of minutes whether each computer that keeps your
backups can be reached, and shows it as **Online** or **Offline** next to the
backup, and on the Friends and Mine pages (`kinvault peer list` and
`kinvault status` show it too).

While a destination is offline, its backups show **Waiting for destination**
instead of failing over and over. Changes keep being noticed, and are backed up
as soon as it's reachable again; there's nothing to do. **Back up now** still
tries straight away.

To back up right away: **Back up now** in the app, or

```sh
kinvault backup documents
```

This runs even outside the backup's hours (below) and waits until it's done.

## States

| State | Meaning |
|---|---|
| Up to date | Everything is backed up |
| Changes waiting | Changes noticed, backing up shortly |
| Backing up | A backup is running |
| Cleaning up | Removing old versions it no longer keeps; shows how far it got and roughly how long is left |
| Checking | Checking the stored backups are complete and intact; shows progress the same way |
| Waiting for its hours | Changes are waiting for the backup's time window |
| Waiting for destination | The computer it backs up to is offline; it backs up when it's back |
| Not backed up yet | No backup has finished yet |
| Paused | Automatic backups are off |
| Needs attention | The last backup failed; see its message |
| Problems found | An integrity check found damaged or missing data |

## Leaving files out

Each backup can leave out files and folders matching patterns. In the app,
enter them one per line under **Leave out**. On the command line use
`--exclude` (repeat for more) when creating, or replace the list later:

```sh
kinvault set exclude code 'target/...' '*.o'   # set the list
kinvault set exclude code                       # show it
kinvault set exclude code --clear               # leave nothing out
```

Quote patterns so the shell doesn't expand them.

| Pattern | Leaves out |
|---|---|
| `*.bat` | every `.bat` file, anywhere |
| `/media/*.bat` | `.bat` files directly in `/media` |
| `/media/.../*.bat` | `.bat` files in `/media` and all its subfolders |
| `/media/*` | the files in `/media`, but not its subfolders |
| `/media/...` | everything in `/media` |
| `target/...` or `target/` | every folder named `target`, with its contents |

`*` and `?` match within one name, `...` matches any number of folders, and a
pattern without a leading `/` matches at any depth.

Changes apply from the next backup. Versions already made keep those files
until they're cleaned up.

## Keeping old versions

Every backup makes a new version (a *snapshot*). Keep rules decide which old
ones are kept. Once a day KinVault removes versions no rule keeps, freeing
space.

The app offers three choices:

- **Recommended**: the latest 10, one per hour for a day, one per day for two
  weeks, one per week for 8 weeks, one per month for a year, and one per year
  for 5 years.
- **Daily for a month, then monthly for a year.**
- **Every version** (uses the most space).

On the command line, combine any of these:

```sh
kinvault set retention documents --keep-last 10 --keep-daily 30 --keep-monthly 12
kinvault set retention documents --keep-all
```

| Option | Keeps |
|---|---|
| `--keep-last N` | the newest N versions |
| `--keep-hourly N` | one for each of the last N hours |
| `--keep-daily N` | one for each of the last N days |
| `--keep-weekly N` | one for each of the last N weeks |
| `--keep-monthly N` | one for each of the last N months |
| `--keep-yearly N` | one for each of the last N years |
| `--keep-all` | everything |

New rules apply at the next clean-up. To clean up now: **Clean up old
versions** in the app, or `kinvault prune <set>`.

## Upload speed and hours

To stop a backup using all your bandwidth, or to only back up overnight:

```sh
kinvault set limits documents --upload-limit 2M --window 01:00-07:00
```

In the app these are **Upload speed limit (MB/s)** and **Back up automatically
from … to …** in the backup's **Settings…**. Leave the times empty for any
time.

`kinvault set limits` replaces both settings: an option you leave out is
cleared.

## Integrity checks

Once a week KinVault downloads part of each backup (256 MB, a different part
each time) and checks it decrypts correctly. Over time this covers everything.
To check now: **Check now** in the app, or

```sh
kinvault verify documents             # 256 MB
kinvault verify documents --max 2G
kinvault verify documents --full      # everything
```

## Space used

```sh
kinvault usage documents
```

## Pausing

**Pause** (or `kinvault set pause <set>`) stops automatic backups. Restores
still work. **Resume** (or `kinvault set resume <set>`) starts them again;
you can give different paths when resuming, which is useful after restoring
onto a new machine where your files live somewhere else:

```sh
kinvault set resume documents /home/alex/Documents
```

To stop backing up for good, see [[Deleting Backups]].
