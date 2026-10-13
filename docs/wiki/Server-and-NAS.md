# Server and NAS

On a machine without a screen, run the background service in Docker. It
serves the same interface as the desktop app over HTTP, with a password.

The image is published as `ghcr.io/jnewbon/kinvault` (tags: `latest`, and one
per release). It runs as user `568:568` (TrueNAS's `apps` user).

## Docker

```sh
docker run -d --name kinvault --restart unless-stopped --network host \
  -v kinvault-data:/data \
  -v ~/Documents:/backup/documents:ro \
  -v ~/kinvault-restore:/restore \
  ghcr.io/jnewbon/kinvault:latest
docker logs kinvault        # shows the generated web password
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
| `KINVAULT_WEB_PASSWORD` | generated | Web sign-in password |
| `KINVAULT_LISTEN_PORT` | `47100` | UDP port for peers, used until you set one in the interface |
| `KINVAULT_STATE` | `/data` | State folder |
| `RUST_LOG` | `info,iroh=error` | Log detail |

If you don't set `KINVAULT_WEB_PASSWORD`, a password is generated on first
start, printed in the logs and kept in `/data/web-password`. Delete that file
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
  --entrypoint kinvault ghcr.io/jnewbon/kinvault:latest \
  recovery import /data/kinvault-recovery-kit.json
```

Start the app, restore what you need, and resume each backup.

## Security of the web interface

The web interface uses plain HTTP. Use it only on your own network, or put it
behind a reverse proxy with HTTPS (Nginx Proxy Manager, Caddy, Traefik, …) to
reach it from elsewhere. Sign-ins last 30 days.

## Without Docker

`kinvaultd` built with the `web` feature serves the interface itself:

```sh
cargo build --release -p kinvault-daemon --features web
kinvaultd --web 0.0.0.0:8080 --listen-port 47100 --state /var/lib/kinvault
```

Run it with your init system (e.g. a systemd service) as an unprivileged user.
