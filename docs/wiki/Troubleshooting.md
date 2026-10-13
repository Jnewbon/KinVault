# Troubleshooting

## "kinvaultd is not running"

The command line tool and app need the background service. Start it:

- App: **Start it** on the banner, or turn on **Settings → Start at login**.
- Command line: `kinvault service install`.

If it won't stay running, start it by hand to see why:

```sh
kinvaultd
```

On Linux, its log is also in `journalctl --user -u kinvaultd`.

## A backup says "Needs attention"

The last backup failed. The app shows the error under the backup;
`kinvault status` shows it too. KinVault keeps retrying on its own (up to
every 30 minutes), so a temporary problem, such as the host being offline,
clears itself. Common causes:

- **The peer is offline.** Nothing to do; it'll back up when they're back.
- **Over quota.** Ask your friend to raise it (`kinvault peer allow <you>
  --quota …` on their side), or leave more out ([Backups](Backups#leaving-files-out)).
- **A folder was moved or unmounted.** Remount it, or `kinvault set resume
  <set> <new paths>`.
- **Permission denied** reading a file. Run KinVault as a user that can read
  it, or leave it out.

## A backup says "Problems found"

An integrity check found missing or damaged data where the backup is stored.
Run a full check to see how much:

```sh
kinvault verify <set> --full
```

Ask whoever stores it whether their disk has problems. New backups keep
working; if old versions are damaged, consider starting a new backup set to a
different place.

## Friends can't connect

KinVault usually gets through routers by itself, falling back to relays. If
connections are slow or fail:

1. Fix the port: `kinvault network port 47100`, and restart the service.
2. Forward that **UDP** port on your router.
3. Add your public IP or dynamic DNS name: `kinvault network add
   home.example.org`.
4. Make a new invite code (old ones don't contain the new address), or tell
   friends who already joined; they'll find you by id.

See [[Networking]].

## "Find nearby devices" finds nothing

- Both devices must be looking at the same time, on the same network.
- UDP port 47101 must not be blocked by a firewall.
- In Docker, the container needs host networking.
- Guest Wi-Fi and some mesh networks keep devices apart. Use **Add a device**
  with a code instead.

## Docker / TrueNAS: "Permission denied (os error 13)"

KinVault runs as user 568 and can't write to its state folder (`/data`). Give
user 568 write access to that dataset or volume, or use the `permissions`
step in the TrueNAS compose file. See [Server and NAS](Server-and-NAS#truenas-scale).

## Forgot the web interface password

It's in `/data/web-password` (or the logs from the first start). Delete the
file and restart the container to generate a new one, or set
`KINVAULT_WEB_PASSWORD`.

## Lost the recovery kit passphrase

The kit can't be opened. If the original machine still works, export a new
kit with a new passphrase now.
