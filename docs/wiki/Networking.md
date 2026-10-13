# Networking

KinVault connects instances directly, getting through home routers on its own
(NAT hole-punching) and falling back to relays when it can't. For most people
nothing needs setting up.

For faster, more reliable connections, especially on a server that friends
back up to, give it a fixed port and forward it.

## Listening on a fixed port

By default KinVault listens on a random UDP port. To fix it:

```sh
kinvault network port 47123      # or "auto" for random again
```

Or **Settings → Network → Change… → Listening port (UDP)**. Restart the
background service for this to take effect.

Then forward that **UDP** port on your router to this machine.

## Adding your public address

Invite codes contain the addresses KinVault finds by itself. If friends can
reach you some other way, such as a static IP or a dynamic DNS name, add it:

```sh
kinvault network add home.example.org     # uses the listening port
kinvault network add 203.0.113.7:4433     # or a port of your choice
kinvault network remove home.example.org
kinvault network show
```

Or **Settings → Network → Change… → Extra addresses**, one per line.

Friends who redeem a code remember these addresses, and look domain names up
again on every connection, so a dynamic DNS name keeps working when your IP
changes.

## Ports used

| Port | Protocol | Used for |
|---|---|---|
| random, or the one you set | UDP | Connections from peers |
| 47101 | UDP | Finding your devices on the local network ([Friends and Devices](Friends-and-Devices#on-the-same-network)) |
| 8080 (Docker default) | TCP | Web interface ([[Server and NAS]]) |
