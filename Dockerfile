# KinVault server: kinvaultd with the web interface, plus the kinvault CLI.
# See deploy/truenas/README.md for running it on TrueNAS SCALE.

FROM rust:1.91-trixie AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
        -p kinvault-daemon -p kinvault-cli --features kinvault-daemon/web \
    && cp target/release/kinvaultd target/release/kinvault /usr/local/bin/

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /data && chown 568:568 /data
COPY --from=build /usr/local/bin/kinvaultd /usr/local/bin/kinvault /usr/local/bin/

# State (identity, keys, config, indexes) and, by default, friends' backups.
ENV KINVAULT_STATE=/data \
    KINVAULT_WEB=0.0.0.0:8080 \
    KINVAULT_LISTEN_PORT=47100 \
    HOME=/data \
    RUST_LOG=info,iroh=error
VOLUME /data
EXPOSE 8080/tcp 47100/udp

# TrueNAS's "apps" user; override with `user:` to match your datasets.
USER 568:568
HEALTHCHECK --interval=1m --timeout=10s --start-period=30s \
    CMD ["kinvault", "id"]
ENTRYPOINT ["tini", "--", "kinvaultd"]
