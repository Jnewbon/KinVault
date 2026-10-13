Ad# Hosting for Others

When you let a friend (or one of your devices) store backups on your machine,
you're their **host**. This page is about running a good host.

## What you're storing

Each peer's backups go in their own folder under the hosted folder (by
default `hosted` in KinVault's state folder; see **Settings → Friends'
backups stored in**). It's all encrypted: you can't read it, and nor can
anyone who gets your disk.

KinVault does the work in the background. You don't need the app open, but
the background service must be running and your machine reachable for
friends to back up.

## Limits

For friends you set, per friend:

| Limit | Meaning |
|---|---|
| **Quota** | Most they may store. Uploads past it are refused. |
| **Upload speed** | Most bandwidth their uploads may use. |
| **Hours** | Only accept their uploads between these times (your local time). Restores work any time. |

Set them when inviting, or change them later: **Friends → Change limits…**,
or `kinvault peer allow <friend> --quota 1T --upload-limit 5M --window
01:00-07:00`. Your own devices (**Mine**) have no limits.

The **Friends** page shows how much each friend uses of their quota.

### Deleted data still counts for a while

When a friend's KinVault removes old versions, you don't erase that data
straight away. It's kept for a grace period (30 days by default) and then
erased, so that if their computer is compromised, an attacker can't instantly
wipe their backup history. That data **still counts toward their quota**
while it waits. A friend who's close to their quota and prunes a lot may need
a little extra room.

To change the grace period: **Settings → Deleted data → Change…**, or
`kinvault keep-deleted <days>`. A shorter period frees space sooner but gives
less protection; `0` erases deleted data within a few hours. The same setting
controls how long backups *you* stop stay restorable (see
[[Deleting Backups]]).

When a friend deletes a whole backup set, it's erased from your machine a
week later.

## Changing your mind

| To… | Do |
|---|---|
| Give them more or less room | **Change limits…** / `kinvault peer allow` |
| Stop accepting new backups, but keep what they stored | **Stop hosting…** / `kinvault peer revoke <friend>` |
| Remove them completely | **Remove…** / `kinvault peer remove <friend>`; what they stored is erased a week later |

Tell your friend first. Their backups will show **Needs attention** once you
stop accepting them, and they'll need somewhere else to back up.

You can only remove a peer once none of *your* backups are stored on them.

## Putting friends' backups on another disk

On a NAS or server, keep hosted data separate from your own: in Docker,
mount a volume at `/data/hosted` (see [[Server and NAS]]). On a desktop, the
hosted folder lives inside the state folder; to move it, point the state
folder at a bigger disk with `--state` / `KINVAULT_STATE`, or link
`hosted` to a folder on another disk while the service is stopped.

## Being reliable

Your friends are counting on you. A good host:

- runs the background service all the time, or at least during the hours
  you've given them;
- has a fixed, forwarded port and a public address (see [[Networking]]), so
  they connect directly instead of through a relay;
- keeps an eye on disk space: KinVault enforces each quota, but the quotas
  you give can add up to more than you have free;
- tells them before reinstalling, replacing the disk, or leaving.

If you move KinVault to a new machine, use a [[Recovery Kit]] *and* copy the
hosted folder across. The kit holds your identity, so friends keep finding
you, but not the data you host.
