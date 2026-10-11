# KinVault on TrueNAS SCALE

KinVault runs as one container: `kinvaultd` (backups and hosting friends'
backups) with its web interface. Requires TrueNAS SCALE 24.10 or later
(Docker-based apps).

## 1. Create datasets

- **`apps/kinvault`**: KinVault's own state. Give the `apps` user (568)
  full control. Snapshot it: it holds the keys to your backups.
- **Optional, `kinvault-hosted`**: friends' backups, if you host any and want
  them on a separate dataset or quota. Also writable by `apps`.
- **Optional, `kinvault-restore`**: somewhere to restore files into, writable by `apps`.

The `apps` user also needs read access to every dataset you want to back up.

## 2. Install the app

Apps → Discover Apps → ⋮ → **Install via YAML**. Paste
[`docker-compose.yml`](docker-compose.yml), changing the paths under
`volumes` to your own, and save.

## 3. Sign in

Open `http://<nas-address>:8080`. Unless you set `KINVAULT_WEB_PASSWORD`, the
password is generated on first start. It's shown in the app's logs
(Apps → kinvault → Logs) and kept in `/data/web-password`.

The web interface uses plain HTTP. Use it only on your own network, or put it
behind a reverse proxy with HTTPS (for example TrueNAS's own, or Nginx Proxy
Manager) if you need to reach it from elsewhere.

## 4. Make it reachable

Friends connect to UDP port **47100** (`KINVAULT_LISTEN_PORT`). KinVault
usually gets through home routers on its own, but for reliable direct
connections:

1. Forward UDP 47100 on your router to the NAS.
2. In the web interface, Settings → Network → Change…, add your public IP or
   a dynamic DNS name (e.g. `home.example.org`). Invite codes then include it.

## Backing up the NAS itself

In the web interface, create a backup and choose folders under `/backup`.
Only datasets mounted into the container are visible. Mount them read-only,
as in the example.

## Command line

The `kinvault` CLI is in the image:

```sh
docker exec -it kinvault kinvault status
docker exec -it kinvault kinvault network show
```

## Restoring onto a new NAS with a recovery kit

Import the kit before KinVault first starts on the new NAS (or with the app
stopped). Put the kit file in the state dataset, then:

```sh
docker run --rm -it --user 568:568 -v /mnt/tank/apps/kinvault:/data \
  --entrypoint kinvault ghcr.io/jnewbon/kinvault:latest \
  recovery import /data/kinvault-recovery-kit.json
```

Start the app, restore what you need, and resume each backup set.

## Without host networking

If you can't use `network_mode: host`, publish the ports instead:

```yaml
    ports:
      - "8080:8080/tcp"
      - "47100:47100/udp"
```

Then add the NAS's LAN address (and any public address) under Settings →
Network, because inside the container KinVault only sees its container
address. Don't change the listening port in the web interface in this
setup: the published port must match.
