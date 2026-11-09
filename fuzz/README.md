# Fuzzing

Coverage-guided fuzz targets for the code that reads untrusted input.
Requires nightly Rust and `cargo install cargo-fuzz`.

| Target | Input |
|---|---|
| `net_request` | Requests and forwarding orders any peer can send a host |
| `net_response` | Responses a (possibly malicious) host sends a client |
| `net_beacon` | Nearby-device beacons from anyone on the LAN |
| `net_ticket` | Invite codes |
| `host_addr` | Host addresses and time windows |
| `core_pack` | Pack trailers, header lengths and entry bounds |
| `daemon_api` | Control API requests (desktop app, CLI socket, web UI) |

Run one target for 10 minutes with overflow checks on (`-a`). This
version uses 4 cores at low priority, so the machine stays usable:

    taskset -c 28-31 nice -n 19 cargo fuzz run -O -a net_request -- \
        -max_total_time=600 -rss_limit_mb=2048

Crashing inputs are saved to `artifacts/<target>/`; replay one with
`cargo fuzz run -O -a <target> <file>`.
