# FAQ

## General

### Do I need an account or a server?

No. Instances connect to each other directly. When they can't, traffic goes
through public relays run by the makers of [iroh](https://iroh.computer), the
networking library KinVault uses. Relays can't read it (see
[[Security and Privacy]]).

### Is it free?

Yes. KinVault is open source under the GPL-3.0 licence.

### Can my friend read my files?

No. Everything is encrypted on your computer first. They can see roughly how
much you store and when you back up. See [[Security and Privacy]].

### What if my friend's computer is off?

Your backup waits and retries, up to every 30 minutes, until it's back. You
lose nothing already backed up, but new changes aren't protected until then.
For important files, back up to two places.

## Backing up

### How much space will my backups take?

The first backup is about the size of your files, less what compression
saves. After that, each backup only adds what changed. Old versions take
space until the keep rules remove them. Check with `kinvault usage <set>`.

### Can I back up the same folders to two places?

Yes: create two backups with the same folders, each to a different place
(for example one to a friend and one to an external disk).

### Can I change where a backup is stored?

No. Create a new backup to the new place, and once it's finished, stop the
old one. You can still restore old versions from it for 30 days (by
default), then it's erased.

### I stopped a backup by mistake. Can I get it back?

You can restore files from it until its grace period ends (see the
**Stopped** list on the Backups page, or `kinvault status`). It can't be
restarted: create a new backup of the same folders instead.

### If I delete a file, is it deleted from my backups?

Not straight away. The next version won't have it, but older versions still
do, until the keep rules remove them. With the recommended rules a file
remains in a yearly version for up to five years.

### What isn't backed up?

- Files and folders matching your leave-out patterns.
- Files KinVault can't read (no permission, locked). These are listed under
  the backup as "couldn't be read".
- Special files: devices, sockets, pipes.
- Symbolic links are backed up as links; what they point to is only backed up
  if it's in the backup's folders too.

### My first backup is huge. How do I avoid hogging the connection?

Give the backup an upload speed limit and/or hours (e.g. overnight); see
[Backups](Backups#upload-speed-and-hours). Your friend can also limit how
fast they accept uploads.

### Does it back up while my laptop is asleep?

No. It catches up when the laptop wakes.

## Friends and devices

### What's the difference between Friends and Mine?

Friends have limits you set (storage, speed, hours). Your own devices
(**Mine**) don't, and are listed separately. Otherwise they work the same.
See [[Friends and Devices]].

### My friend ran out of room on my machine.

Raise their quota (**Change limits…**). Note that what they prune still
counts for a while (30 days by default); see [[Hosting for Others]].

### The invite code expired.

Make a new one. Codes last 7 days by default (`--expires-days` changes it).

## Recovery

### I lost my computer. Can I get my files back?

Yes, if you have your [[Recovery Kit]] and its passphrase. Install KinVault on
another computer, import the kit, and restore.

### I lost my computer and I don't have a recovery kit.

Then the backups can't be decrypted. The keys were only on that computer. If
you had copies of KinVault's state folder (for example in another backup of
your whole disk), restoring that folder gets you the keys back.

### Can I use the same kit on two computers at once?

No. A kit carries your instance's identity; two machines running with the
same identity confuse your hosts. Stop the old one first.

## Other

### Can several people use KinVault on one computer?

Yes. Each user account runs its own background service with its own state
folder, backups and friends.

### Where are the logs?

- Linux desktop: `journalctl --user -u kinvaultd`
- Docker: `docker logs kinvault`
- Anywhere: run `kinvaultd` in a terminal to see its output. Set
  `RUST_LOG=debug` for more.
