# Recovery Kit

Your backups are encrypted with keys that live on your computer. If the
computer is lost, the backups are useless without those keys. A **recovery
kit** is one file holding everything needed to take over your backups on a new
machine:

- this instance's identity (hosts know your backups by it),
- every backup's key,
- your backups' settings and the peers they're stored on.

The keys in it are encrypted with a passphrase you choose.

## Making one

**Settings → Recovery → Export recovery kit…**, or:

```sh
kinvault recovery export ~/kinvault-recovery.json
```

In the web interface, the kit is downloaded through your browser.

Then:

- **Store it away from this machine**: a USB stick in a drawer, a password
  manager, a printout. A kit on the disk it protects is lost with it.
- **Remember the passphrase.** Without it, the kit can't be opened.
- **Export a new kit after creating a backup.** A kit only covers the backups
  that existed when it was made.

## Restoring onto a new machine

Import the kit while the background service is **not running**, ideally
before KinVault has been used at all on the new machine.

1. Install KinVault. If the background service is running, stop it with
   `kinvault service uninstall` (you can `install` it again afterwards). On
   Windows this only stops it starting at login, so also end `kinvaultd.exe`
   in Task Manager.
2. Import the kit:
   - App: **Settings → Recovery → Import recovery kit…**
   - Command line: `kinvault recovery import ~/kinvault-recovery.json`
3. Start the background service. Your backups appear, **paused**, so nothing gets
   overwritten.
4. Restore what you need ([[Restoring Files]]).
5. Resume each backup, giving its new folders if they moved:

   ```sh
   kinvault set resume documents /home/alex/Documents
   ```

Make sure the old machine is no longer running KinVault: both would claim the
same identity.

If the new machine already has backups or peers of its own, `recovery import`
refuses, because the kit replaces the instance's identity. Use `--force` only
if you're sure; the new machine's existing backups and peers stop working.

For Docker and TrueNAS, see [[Server and NAS]].

## Scripting

Both commands read the passphrase from `KINVAULT_PASSPHRASE` if it's set,
instead of asking.
