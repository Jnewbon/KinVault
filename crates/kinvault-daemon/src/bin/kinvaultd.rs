//! `kinvaultd`: runs backup sets in the background and hosts peers' backups.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use kinvault_daemon::{Daemon, DaemonOptions, default_state_dir, ipc};

#[derive(Parser)]
#[command(name = "kinvaultd", version, about = "KinVault background service")]
struct Args {
    /// Directory holding this instance's identity, configuration and keys.
    #[arg(long, env = "KINVAULT_STATE")]
    state: Option<PathBuf>,
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
    std::fs::create_dir_all(&state_dir)?;

    let listener = ipc::Listener::bind(&ipc::endpoint_name(&state_dir)).await?;
    let daemon = Daemon::start(DaemonOptions {
        state_dir,
        endpoint: None,
    })
    .await?;
    tracing::info!(
        "kinvaultd {} running as {}",
        env!("CARGO_PKG_VERSION"),
        daemon.id()
    );

    let socket = listener.path().to_path_buf();
    tokio::select! {
        result = listener.serve(daemon.clone()) => result?,
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
