# Friends and Devices

Every KinVault installation is an **instance** with its own id (a
64-character code; see it with `kinvault id` or under **Settings**). Instances
you're connected to are **peers**, and there are two kinds:

- **Friends**: other people. You choose how much they may store with you, how
  fast, and when.
- **Mine**: your own computers and servers. They keep each other's backups
  without limits.

Being connected works both ways but isn't symmetric: a friend may store
backups with you, you may store backups with them, or both.

## Inviting a friend

**Friends → Invite a friend**, or:

```sh
kinvault invite create --name sam --quota 500G
```

| Option | App | Meaning |
|---|---|---|
| `--name` | Friend's name | What to call them |
| `--quota 500G` | Storage they may use (GB) | Leave out for unlimited |
| `--upload-limit 5M` | Upload speed limit (MB/s) | Per second |
| `--window 01:00-07:00` | Accept uploads from … to … | Only accept their uploads in these hours |
| `--ask-reciprocal` | Ask them to keep my backups too | They're asked to offer you storage back |
| `--expires-days 7` | Code valid for (days) | Default 7 |

Send them the code (starts with `kvinvite1`). Each code works once.

```sh
kinvault invite list          # codes not used yet
kinvault invite cancel <id>
```

Sizes accept `K`, `M`, `G` and `T` (binary: `1G` is 1024 MiB).

## Accepting an invite

**Friends → Join with a code**, or:

```sh
kinvault invite redeem kvinvite1… --name sam
```

Accepting lets you store backups with them. To let them store backups with you
too, tick **Let them keep their backups here too**, or:

```sh
kinvault invite redeem kvinvite1… --offer 200G
kinvault invite redeem kvinvite1… --offer-unlimited --offer-window 01:00-07:00
```

## Your own devices

Your own devices are paired the same way, or found automatically on the same
network.

### On the same network

On **both** devices: **Mine → Find nearby devices**. For three minutes each
lists the devices it finds, with a short code. Check both show the **same
code**, then choose **The codes match, add it** on both.

```sh
kinvault nearby find          # on both; lists devices as they appear
kinvault nearby pair laptop   # on both, after checking the codes match
kinvault nearby stop
```

Devices find each other with UDP broadcasts on port 47101. If that's blocked,
or the devices are on different networks, use a code instead.

### With a code

On one device, **Mine → Add a device** (`kinvault invite create --mine --name
laptop`). On the other, **Mine → Join with a code** (`kinvault invite redeem
--mine kvinvite1…`).

## Managing peers

```sh
kinvault peer list
```

| To… | App | Command line |
|---|---|---|
| Change a friend's limits | **Change limits…** | `kinvault peer allow sam --quota 1T --upload-limit 5M` |
| Let a friend store backups with you | **Allow to store here…** | `kinvault peer allow sam --quota 200G` |
| Stop accepting their backups (what they stored is kept) | **Stop hosting…** | `kinvault peer revoke sam` |
| Move a friend to Mine | **Move to Mine…** | `kinvault peer mine sam` |
| Move a device back to Friends | **Move to Friends** | `kinvault peer friend laptop` |
| Remove a peer completely | **Remove…** | `kinvault peer remove sam` |

`peer allow` replaces all of a peer's limits: options you leave out are
cleared.

Removing a peer means it can no longer store backups with you, and what it
stored with you is erased a week later. You can only remove a peer once none
of *your* backups are stored on it; delete or move those first (see
[[Deleting Backups]]).

## Where friends' backups are stored

By default in the `hosted` folder inside KinVault's state folder. The app
shows the location under **Settings → Friends' backups stored in**. On a NAS
you may want this on its own dataset; see [[Server and NAS]].

## Connecting

Instances find each other by id and connect directly, getting through home
routers by themselves and falling back to relays when they can't. No port
forwarding is needed, but it helps; see [[Networking]].
