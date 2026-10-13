# Restoring Files

You can restore from a running backup, or from one you've stopped until it's
erased (see [[Deleting Backups]]).

## In the app

1. Open **Restore** and pick the backup.
2. Pick a version (**Version from** shows when it was made and on which
   computer).
3. **Restore this version…**
4. Choose **Restore into**: a folder to put the files in.
5. Optionally, choose **Only this file or folder** to restore just part of it.
6. **Restore**.

Restores run in the background service, so you can close the app. Cancelling
keeps the files restored so far.

## On the command line

List versions:

```sh
kinvault snapshots documents
```

Restore one, by the start of its id or `latest`:

```sh
kinvault restore documents latest ~/restored
kinvault restore documents 3fa9c1 ~/restored
```

Restore only part of it:

```sh
kinvault restore documents latest ~/restored --include home/alex/Documents/taxes
```

Paths in a version are stored as they were on the original computer, without
the leading `/`: `/home/alex/Documents` is stored as `home/alex/Documents`,
and `C:\Users\alex` as `C/Users/alex`. A restore recreates these folders
inside the folder you restore into.

## Restoring somewhere new

Restoring **overwrites** files with the same name in the folder you restore
into, and leaves other files there alone. So restore into an empty folder
rather than over your existing files, check the result, then move what you
need into place.

To restore onto a different machine (because the original was lost), you first
need a [[Recovery Kit]].

## What's restored

- File contents, folders and symbolic links (as links, not what they point
  to).
- Permissions (on Linux and macOS) and modification times.
- **Not** file ownership, extended attributes or ACLs. Files are owned by
  whoever runs KinVault.
