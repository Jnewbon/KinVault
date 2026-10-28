# Backups

A **backup set** (or just "backup") is a group of files and folders that are
backed up together to one place, with their own history of versions.

## Creating a backup

In the app: **Backups → New backup**. On the command line:

```sh
kinvault set create <name> <paths>… (--peer <peer> | --local <folder>) [options]
```

A backup's key is kept in the state folder. To restore on another machine
you need a [[Recovery Kit]], which holds every backup's key under one
passphrase. A new backup isn't in recovery kits you made before it, so
export a new kit after creating one.

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
| Copying | Copying new versions to the backup's other places (see below) |
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

## Keeping copies in more places

A backup can keep copies in more than one place, each with its own keep
rules. For example, a home server can keep every version while a friend's
computer keeps one a day, then one a week and one a month.

In the app: **Also keep copies in…** on the backup, then pick the place and
which versions to keep there. On the command line:

```sh
kinvault set place add documents --peer friend --keep-daily 14 --keep-weekly 8 --keep-monthly 12
```

How it works:

- Backups go to the backup's main place, as before. After each one, every
  other place gets the versions it keeps but doesn't have yet. The data is
  copied exactly as it is: encrypted, with the same key.
- A new place starts with the versions its rules keep. After that, it gets
  the **first** new version of each hour, day, week, month or year it keeps,
  as soon as that version exists. With a "latest N" rule (like
  **Recommended**), it gets every new version.
- Each place cleans up with its own rules, and is checked about once a week.
- Each place has its own upload speed limit and hours. A place whose
  computer is offline catches up when it's back.
- You can restore from any of them: pick it under **Restore from** (or use
  `--from <place>` on the command line).
- Copies are made from the main place, so give the main place the most
  history (for example your home server), and make it one that's quick to
  reach.

Removing a place (**Remove…**, or `kinvault set place remove`) erases what
it holds a week later, like deleting a backup. The backup's other places
aren't affected.

### Sending copies through the main place

When the main place is another computer (say your home server) and so is
the extra place (say a friend's), the copies can go through the home server
instead of from your computer: tick **Send copies through …** (or add
`--relay` to `set place add`). Then:

- After each backup, your computer tells the home server which versions to
  send and which packs they need. The home server sends them on its own, in
  the place's hours and at its speed limit, even while your computer is off,
  and retries while the other place is offline. Your own upload is only
  used once, for the home server.
- The other place stores them as your backup, counted against what it lets
  *you* store. It doesn't need to know the home server.
- The home server can't read anything it forwards, and you give it
  permission only to *add* to that place, for 60 days at a time (renewed
  with each new order): it can't list, read or delete what's there.
- Your computer learns what was delivered the next time it backs up.
  The place's line on the backup shows what's still on its way, and why
  it's waiting if it is.
- Cleaning up and checking that place still need your computer to reach it,
  so they happen when it can.

Both the home server and the other place need this version of KinVault.

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
