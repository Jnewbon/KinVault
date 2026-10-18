//! `kinvaultd`: runs backup sets in the background and hosts peers' backups.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use kinvault_daemon::config::Config;
use kinvault_daemon::{Daemon, DaemonOptions, default_state_dir, ipc};

#[derive(Parser)]
#[command(name = "kinvaultd", version, about = "KinVault background service")]
struct Args {
    /// Directory holding this instance's identity, configuration and keys.
    #[arg(long, env = "KINVAULT_STATE")]
    state: Option<PathBuf>,
    /// UDP port to listen on for peers when none has been configured yet
    /// (e.g. to match a container's published port).
    #[arg(long, env = "KINVAULT_LISTEN_PORT", value_parser = clap::value_parser!(u16).range(1..))]
    listen_port: Option<u16>,
    /// Serve the web interface on this address, e.g. 0.0.0.0:8080.
    #[cfg(feature = "web")]
    #[arg(long, env = "KINVAULT_WEB")]
    web: Option<std::net::SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,iroh=error".into()),
        )
        .init();
    let args = Args::parse();
    let state_dir = match args.state {
        Some(d) => d,
        None => {
            default_state_dir().context("could not determine a data directory; pass --state")?
        }
    };
    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("creating the state directory {}", state_dir.display()))?;

    let listener = ipc::Listener::bind(&ipc::listen_name(&state_dir)?)
        .await
        .with_context(|| {
            format!(
                "opening the control socket in {} (is it writable by this user?)",
                state_dir.display()
            )
        })?;
    if let Some(port) = args.listen_port {
        let path = state_dir.join("config.json");
        let mut config = Config::load(&path)?;
        if config.listen_port.is_none() {
            config.listen_port = Some(port);
            config.save(&path)?;
        }
    }
    #[cfg(feature = "web")]
    let web = match args.web {
        Some(addr) => {
            let password = kinvault_daemon::web::password(&state_dir)?;
            let tcp = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("listening for the web interface on {addr}"))?;
            Some((tcp, password))
        }
        None => None,
    };
    let daemon = Daemon::start(DaemonOptions {
        state_dir,
        endpoint: None,
        nearby: Default::default(),
        reachability: Default::default(),
    })
    .await?;
    tracing::info!(
        "kinvaultd {} running as {}",
        env!("CARGO_PKG_VERSION"),
        daemon.id()
    );

    #[cfg(feature = "web")]
    let web = async {
        match web {
            Some((tcp, password)) => {
                tracing::info!("web interface on http://{}", tcp.local_addr()?);
                kinvault_daemon::web::serve(daemon.clone(), tcp, &password).await
            }
            None => std::future::pending().await,
        }
    };
    #[cfg(not(feature = "web"))]
    let web = std::future::pending::<Result<()>>();

    let socket = listener.path().to_path_buf();
    tokio::select! {
        result = listener.serve(daemon.clone()) => result?,
        result = web => result?,
        _ = shutdown_signal() => tracing::info!("shutting down"),
    }
    daemon.shutdown().await;
    #[cfg(unix)]
    let _ = std::fs::remove_file(socket);
    #[cfg(not(unix))]
    let _ = socket;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("installing SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
