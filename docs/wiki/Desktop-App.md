# Desktop App

The desktop app is a window and a tray icon on top of the background service.
Everything it shows and does happens in the service, so **closing the app, or
quitting it, never stops your backups**.

The [web interface](Server-and-NAS) on servers and NAS is the same app in a
browser, with a few differences (see [below](#web-interface)).

## Tray icon

- **Click** the icon to open the window.
- **Right-click** for:
  - **Open KinVault**
  - **Back up now**: backs up every backup that isn't paused
  - **Quit (backups keep running)**: closes the app; the service carries on

Closing the window hides it to the tray.

## If the service isn't running

A banner says **The KinVault background service isn't running**, with a
**Start it** button. To have it start on its own, turn on **Settings → Start
at login**.

## Pages

### Backups

One card per backup, showing:

- its name, state (see [Backups](Backups#states)) and where it's stored;
- the folders it covers;
- while running, files scanned, bytes read and bytes sent;
- the last backup: when, how many files, how much changed and was sent, and
  any files that couldn't be read;
- the last integrity check;
- its speed limit, hours, keep rules and what it leaves out.

Buttons:

| Button | Does |
|---|---|
| **Back up now** | Backs up straight away, even outside its hours |
| **Restore…** | Opens the Restore page for this backup |
| **Check now** | Runs an integrity check |
| **Clean up old versions** | Removes versions the keep rules don't keep |
| **Pause** / **Resume** | Stops / restarts automatic backups |
| **Settings…** | Speed limit, hours, keep rules, leave-out patterns, and **Stop backing up** / **Delete permanently** |

**New backup** creates one; see [Backups](Backups#creating-a-backup).

Backups you've stopped are listed under **Stopped**, with the date they'll be
erased. Each has **Restore…** and **Delete permanently…**. See
[[Deleting Backups]].

In **Settings…** the keep rules show *latest*, *daily*, *weekly* and
*monthly*. Leave all of them empty to keep every version. Hourly and yearly
rules can only be changed on the command line (`kinvault set retention`).

### Restore

Choose a backup (stopped ones are marked *(stopped)*), then a version. Each version shows when it was made, on
which computer, how many files and how big. **Restore this version…** asks
where to restore to, and optionally a single file or folder. Progress shows
on the page; you can cancel, and files restored so far are kept. See
[[Restoring Files]].

### Mine

Your own computers and servers. Each card shows how much it stores with you
and which of your backups it keeps.

- **Find nearby devices**: pair with a device on the same network.
- **Add a device**: make a code to use on the other device.
- **Join with a code**: use a code from your other device.

See [[Friends and Devices]].

### Friends

Each friend shows how much they store with you (with a bar if they have a
quota) and whether they keep your backups. **Invites waiting to be used**
lists codes you've made that haven't been used, with when they expire.

- **Invite a friend** / **Join with a code**
- **Change limits…** / **Allow to store here…**
- **Move to Mine…**
- **Stop hosting…**

See [[Friends and Devices]] and [[Hosting for Others]].

### Settings

| Section | What's there |
|---|---|
| Background service | Whether it's running; **Start at login** |
| This computer | **Name friends see**, **Instance id** (with Copy), where friends' backups are stored, version |
| Network | Listening port, addresses in invite codes, **Change…** (see [[Networking]]) |
| Deleted data | How many days backups you stop, and data friends delete here, are kept before they're erased (default 30). See [[Deleting Backups]] and [[Hosting for Others]]. |
| Recovery | **Export recovery kit…**, **Import recovery kit…** (only while the service isn't running; see [[Recovery Kit]]) |

## Web interface

On a server or NAS, `kinvaultd` serves the same pages over HTTP. Differences:

- You sign in with a password, and **Settings** has **Sign out**.
- **Choose folder…** browses the *server's* folders. In Docker, that's only
  what's mounted into the container (e.g. under `/backup`).
- **Export recovery kit…** downloads the kit through your browser.
- There's no **Start at login** (the container or service manager handles
  that) and no **Import recovery kit…**: import kits with the command line
  before the server first starts. See [Server and NAS](Server-and-NAS#restoring-onto-a-new-nas).
