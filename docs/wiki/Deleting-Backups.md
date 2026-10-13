# Deleting Backups

There are three ways to stop a backup, from gentlest to final.

## Pause

**Pause** / `kinvault set pause <set>`

Automatic backups stop. Everything is kept and restores still work. Resume at
any time.

## Stop backing up

**Settings… → Stop backing up this set…** / `kinvault set remove <set>`

Nothing new is backed up, and the backup moves to the **Stopped** list on
the Backups page. For a grace period (30 days by default) you can still
restore from it: it stays where it was stored, and its key stays on this
computer.

When the grace period is over, KinVault deletes it just like **Delete
permanently** (below): the place it's stored is asked to erase it, and once
that's done (or KinVault gives up asking, after a month), the key is erased
too.

`kinvault status` shows stopped backups and the date each is erased.

### Changing the grace period

**Settings → Deleted data → Change…**, or:

```sh
kinvault keep-deleted        # show it
kinvault keep-deleted 90     # keep stopped backups for 90 days
```

It counts from when each backup was stopped, so a change applies to backups
already stopped too: shortening it can make some due for erasing at once. The
same setting controls how long data friends delete from *your* computer is
kept; see [[Hosting for Others]].

### Erasing a stopped backup sooner

Choose **Delete permanently…** on its card (or `kinvault set delete <set>`).

> A new backup can have the same name as a stopped one. Commands then mean
> the running one; use the stopped one's id (shown by `kinvault status`)
> instead.

## Delete permanently

**Settings… → Delete permanently…** (or, for a stopped backup, **Delete
permanently…** on its card) / `kinvault set delete <set>`

You're asked to type `DELETE PERMANENTLY` to confirm (skip this with
`--yes`). Then:

1. The backup's key is erased **at once**. From this moment the backups
   can't be decrypted by anyone, even if a copy survives.
2. Wherever the backups are stored erases them **a week later**. For a backup
   in a local folder, your own KinVault erases it.
3. If the host is offline, or gone, that doesn't stop the deletion: it's
   asked again every hour for up to a month.

A backup can't be deleted while it's being restored from; wait for the
restore to finish or cancel it first. If it's in the middle of backing up,
deleting waits for that to finish.

This can't be undone. Recovery kits made earlier still contain the key, so
destroy those too if you need the backups to be truly unrecoverable.

## Removing a friend or device

See [Friends and Devices](Friends-and-Devices#managing-peers). A peer can only be removed once
none of your backups, running or stopped, are stored on it.
