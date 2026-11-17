# Server and NAS

On a machine without a screen, run the background service in Docker. It
serves the same interface as the desktop app over HTTP, with a password.

The image is published as `ghcr.io/jnewbon/kinvault`, with a tag per
release (e.g. `0.1.1`, and `0.1` for the newest 0.1.x) and `latest` for the
newest development build. Use a release tag, and change it to update. It
runs as user `568:568` (TrueNAS's `apps` user).

## Docker

```sh
docker run -d --name kinvault --restart unless-stopped --network host \
  -v kinvault-data:/data \
  -v ~/Documents:/backup/documents:ro \
  -v ~/kinvault-restore:/restore \
  ghcr.io/jnewbon/kinvault:0.1.1
docker exec kinvault cat /data/web-password   # the generated web password
```

Then open `http://<server>:8080`.

| Path in the container | What goes there |
|---|---|
| `/data` | KinVault's state: identity, keys, settings. **Must be writable and kept safe**; snapshot or back it up. |
| `/data/hosted` | Friends' backups (by default). Mount a separate volume here to keep them apart. |
| `/backup/...` | What to back up. Mount read-only; only what's mounted can be chosen. |
| `/restore` (or anywhere) | Somewhere writable to restore into. |

| Environment variable | Default | Meaning |
|---|---|---|
| `KINVAULT_WEB` | `0.0.0.0:8080` | Address of the web interface |
| `KINVAULT_WEB_PASSWORD` | generated | Web sign-in password (at least 12 characters) |
| `KINVAULT_WEB_HTTPS` | `false` | Set to `true` when only reached through an HTTPS proxy |
| `KINVAULT_WEB_HOSTS` | any | Host names the web interface answers to, comma-separated |
| `KINVAULT_LISTEN_PORT` | `47100` | UDP port for peers, used until you set one in the interface |
| `KINVAULT_STATE` | `/data` | State folder |
| `RUST_LOG` | `info,iroh=error` | Log detail |

If you don't set `KINVAULT_WEB_PASSWORD`, a password is generated on first
start and kept in `/data/web-password` (the logs say where, but not the
password): `docker exec kinvault cat /data/web-password`. Delete that file
and restart to get a new one.

The command line tool is in the image:

```sh
docker exec -it kinvault kinvault status
```

### Host networking

`--network host` (or `network_mode: host`) is recommended: KinVault sees the
server's real addresses, so devices on your network connect directly, and
**Find nearby devices** works.

Without it, publish the ports:

```sh
-p 8080:8080/tcp -p 47100:47100/udp
```

then add the server's LAN address (and any public one) under **Settings →
Network**, because inside the container KinVault only sees its container
address. Don't change the listening port in the interface in this setup: it
must match the published port. Nearby discovery won't work; pair devices with
a code instead.

## TrueNAS SCALE

TrueNAS SCALE 24.10 or later. The repository has a ready-made
[`docker-compose.yml`](https://github.com/Jnewbon/KinVault/blob/main/deploy/truenas/docker-compose.yml)
and [full instructions](https://github.com/Jnewbon/KinVault/blob/main/deploy/truenas/README.md).
In short:

1. **Create datasets**: `apps/kinvault` for KinVault's state (snapshot it),
   and optionally ones for friends' backups and for restoring into. The
   `apps` user (568) needs write access to these and read access to
   everything you back up.
2. **Install**: Apps → Discover Apps → ⋮ → **Install via YAML**, paste the
   compose file, change the paths under `volumes`, save. Its `permissions`
   step hands the writable datasets to `apps` before KinVault starts.
3. **Sign in** at `http://<nas>:8080` with the password from Apps → kinvault
   → Logs.
4. **Make it reachable**: forward UDP 47100 to the NAS and add your public
   address under Settings → Network (see [[Networking]]).

If KinVault fails with `Permission denied (os error 13)`, the `apps` user
can't write to `/data`; see [[Troubleshooting]].

### Restoring onto a new NAS

Put the [[Recovery Kit]] file in the state dataset, then, before the app first
starts (or with it stopped):

```sh
docker run --rm -it --user 568:568 -v /mnt/tank/apps/kinvault:/data \
  --entrypoint kinvault ghcr.io/jnewbon/kinvault:0.1.1 \
  recovery import /data/kinvault-recovery-kit.json
```

Start the app, restore what you need, and resume each backup.

## Security of the web interface

The web interface uses plain HTTP. Use it only on your own network, or put it
behind a reverse proxy with HTTPS (Nginx Proxy Manager, Caddy, Traefik, …) to
reach it from elsewhere, and then set `KINVAULT_WEB_HTTPS=true` so its sign-in
cookie is only ever sent over HTTPS.

- A sign-in lasts 30 days, or until it's unused for a day. At most 32 are
  kept; signing in again ends the least recently used.
- After a wrong password, that address must wait before trying again: a
  second at first, doubling with each further mistake, up to 15 minutes.
  Other addresses aren't affected.
- A `KINVAULT_WEB_PASSWORD` must be at least 12 characters.
- Set `KINVAULT_WEB_HOSTS` to the names you reach it by (e.g.
  `nas.lan,192.168.1.10`): requests for any other host name are refused,
  which stops web pages that point their own domain at your server (DNS
  rebinding) from talking to it.

## Without Docker

`kinvaultd` built with the `web` feature serves the interface itself:

```sh
cargo build --release -p kinvault-daemon --features web
kinvaultd --web 0.0.0.0:8080 --listen-port 47100 --state /var/lib/kinvault
```

Run it with your init system (e.g. a systemd service) as an unprivileged user.
