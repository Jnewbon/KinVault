# Security and Privacy

KinVault is built so you can store backups with people and machines you
don't fully control. This page explains what's protected, what isn't, and
what you need to look after yourself.

## In short

- Files are **encrypted on your computer** before they're sent anywhere.
- Whoever stores your backups can't read your files, their names, or the
  sizes of individual files.
- They **can** see roughly how much you store and when you back up, and they
  can delete it. KinVault notices if they do (integrity checks) but can't stop
  them.
- The keys live on your computer. **Protect your computer and make a
  [[Recovery Kit]]**.

## What the host can and can't see

| The host **can't** see | The host **can** see |
|---|---|
| File contents | Your instance id and IP address |
| File and folder names | How much you store in total, and how many packs |
| Sizes of individual files | When you back up, and roughly how much changed |
| How many files you have | How many versions (snapshots) you keep |
| Which files changed | Your instance's name |

Files are cut into chunks (256 KB–4 MB, split by content so an edit only
changes nearby chunks), compressed, encrypted, and bundled into packs of
about 32 MB. The host only sees the packs. The list of what's in each pack is
encrypted too.

The same holds for a backup in a local folder (an external disk or network
share): anyone with access to the folder sees only encrypted packs.

## Encryption

| What | How |
|---|---|
| Data and metadata | XChaCha20-Poly1305, with separate keys for data and metadata |
| Chunk ids (for deduplication) | Keyed BLAKE3, so ids reveal nothing without the key |
| Keys | A random 256-bit key per backup set; sub-keys derived with BLAKE3 |
| Passphrase-protected keys (recovery file, recovery kit) | Argon2id (64 MiB, 3 passes) |
| Connections between instances | QUIC (TLS 1.3), authenticated by each instance's key |

Every backup set has its own key, so deduplication only happens within a set.
Two friends backing up the same file store it twice, and a host can't tell
they're the same.

## Connections

Instances are identified by a public key (the instance id). Connections are
encrypted and authenticated end to end, including when they go through a
relay: relays pass traffic along but can't read it or pretend to be you.

A host only accepts uploads from peers it has allowed, within the quota, speed
and hours it set.

### Invite codes

An invite code holds the host's id and addresses, the offered storage, and a
one-time secret (the host only keeps its hash). Anyone who has the code can
use it once, until it expires, so **send it privately**, and cancel codes you
no longer need (`kinvault invite cancel`).

### Pairing nearby devices

**Find nearby devices** shows a six-digit code computed from both devices'
ids. If the codes on both screens match, you're talking to the right device
and not to someone else on the network. **Always compare them** before
confirming.

## Protection against a host, or your own computer, going bad

- **A host deletes your data.** Weekly integrity checks download part of each
  backup and check it decrypts; missing or damaged data shows as **Problems
  found**. Keep important data on more than one host (create a second backup
  set to another friend, device or disk).
- **Your computer is compromised.** An attacker with your computer can ask
  hosts to delete your backups. Hosts don't erase deleted data straight away:
  it's kept for a grace period (30 days by default, set by each host) and
  then erased, so recent history survives a short-lived compromise. Backups
  you stop are also only erased after a grace period. A whole backup set
  deleted with **Delete permanently** is erased after a week.

## What you need to protect

**Your state folder.** It holds each backup's key (readable only by your user
account), your instance's identity, and your settings. Anyone who can read it
can decrypt your backups and act as your instance. Use full-disk encryption on
your computer.

**Your recovery kit and its passphrase.** Together they can decrypt all your
backups. Keep them apart from each other and from your computer, and choose a
long passphrase.

**The web interface** (servers and NAS). It uses plain HTTP and a password.
Only use it on your own network, or behind a reverse proxy with HTTPS. See
[Server and NAS](Server-and-NAS#security-of-the-web-interface).

## What you're trusting your friends with

They can't read your backups, but they can:

- lose them (a disk dies, they wipe the machine, they leave),
- see roughly how much you store and when you're online,
- see your IP address.

And you're trusting them not to fill your disk beyond their quota (KinVault
enforces it) and not to store anything you'd object to: **you can't see what
they store either.**
