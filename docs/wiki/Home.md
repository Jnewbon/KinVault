# KinVault

KinVault makes encrypted backups of your files and stores them on machines you
trust: your own computers and servers, or a friend's. Everything is encrypted
before it leaves your computer, so whoever stores your backups can't read them.

## Where to start

- **New to KinVault?** Read [[Getting Started]].
- **Installing it?** See [[Installation]], or [[Server and NAS]] for a
  headless machine or Docker.
- **Wondering who can see what?** See [[Security and Privacy]].
- **Lost a machine?** See [[Recovery Kit]] and [[Restoring Files]].

## Guides

| Page | What it covers |
|---|---|
| [[Getting Started]] | Your first backup, end to end |
| [[Desktop App]] | A tour of the app, the tray icon and the web interface |
| [[Backups]] | Creating backup sets, where they're stored, leaving files out, keeping old versions, speed limits and hours |
| [[Restoring Files]] | Getting files back from any version |
| [[Friends and Devices]] | Invites, quotas, pairing your own devices |
| [[Hosting for Others]] | Storing friends' backups: limits, space, being reliable |
| [[Networking]] | Ports, port forwarding, dynamic DNS |
| [[Recovery Kit]] | Restoring onto a new machine |
| [[Deleting Backups]] | Stopping, removing and permanently deleting |
| [[Server and NAS]] | Docker, TrueNAS SCALE and the web interface |
| [[Security and Privacy]] | What's encrypted, what hosts can see, what to protect |
| [[Command Line Reference]] | Every `kinvault` command |
| [[FAQ]] | Common questions |
| [[Troubleshooting]] | Common problems and what to do |

## How it fits together

KinVault has three programs:

- **`kinvaultd`**, the background service. It does all the work: watching
  folders, backing up, storing other people's backups, checking and cleaning
  up old versions.
- **The desktop app** (`kinvault-gui`), with a tray icon.
- **The command line tool** (`kinvault`).

The app and the command line only *control* the service. Closing them never
stops your backups.
