# Getting Started

This walks through backing up a folder to a friend's computer. Backing up to an
external disk or to another of your own machines works the same way; see
[[Backups]] and [[Friends and Devices]].

## 1. Start KinVault

Install it ([[Installation]]) and open the app. Under **Settings**:

- turn on **Start at login**, so backups keep running after a restart;
- set **Name friends see**, e.g. `alex-laptop`.

On the command line:

```sh
kinvault service install
kinvault name alex-laptop
```

## 2. Connect with a friend

Your friend invites you; you accept.

**Your friend**, in the app: **Friends → Invite a friend**. They enter your
name, how much storage to give you, and tick **Ask them to keep my backups
too** if they'd like you to store theirs in return. They send you the code.

```sh
kinvault invite create --name alex --quota 500G --ask-reciprocal
```

**You**: **Friends → Join with a code**, paste it, and (if they asked) choose
how much storage to offer them back.

```sh
kinvault invite redeem kvinvite1… --offer 200G
```

Codes work once and expire after 7 days.

## 3. Create a backup

**Backups → New backup**:

1. Give it a name, e.g. `documents`.
2. Choose the folders to back up.
3. Under **Where to keep the backup**, pick your friend.
4. Leave **Old versions to keep** on **Recommended**.
5. Choose a **recovery passphrase** (at least 8 characters) and write it
   down somewhere safe.
6. **Start backing up**.

```sh
kinvault set create documents ~/Documents --peer their-name
```

The first backup starts straight away. After that, KinVault watches the
folders and backs up whatever changed about 30 seconds after you stop changing
things.

## 4. Make a recovery kit

If this computer is lost, the backups can only be decrypted with its keys.
Export a recovery kit now and keep it somewhere *other* than this computer:

**Settings → Recovery → Export recovery kit…**

```sh
kinvault recovery export ~/kinvault-recovery.json
```

See [[Recovery Kit]].

## 5. Check on it

The **Backups** page shows each backup's state (**Up to date**, **Backing
up**, **Changes waiting**, …). On the command line:

```sh
kinvault status
kinvault watch      # live activity, Ctrl+C to stop
```

Next: [[Restoring Files]].
