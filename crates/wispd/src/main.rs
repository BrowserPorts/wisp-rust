//! `wispd` — the standalone wisp-wt server binary.
//!
//! Loads a TOML config, builds a [`wisp_core::Runtime`], and waits on
//! SIGINT/SIGTERM to drive a bounded graceful drain.

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use tokio::signal;
use tracing::info;
use wisp_core::{Runtime, RuntimeConfig};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser, Debug)]
#[command(name = "wispd", version, about = "wisp-wt over msquic")]
struct Cli {
    /// Path to the wisp-wt TOML config.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Tracing log level (overrides RUST_LOG).
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Switch the msquic execution profile to MaxThroughput and disable
    /// protocol inspection. For Wispmark runs.
    #[arg(long)]
    bench_mode: bool,
}

fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level);

    let cfg = match &cli.config {
        Some(path) => RuntimeConfig::from_toml(path)
            .with_context(|| format!("failed to load config from {}", path.display()))?,
        None => {
            info!("wispd: no --config supplied, using defaults");
            RuntimeConfig::from_options(wisp_config::WispWtServerOptions::default())
                .context("default options validate")?
        }
    }
    .with_bench_mode(cli.bench_mode)
    .with_log_level(&cli.log_level);

    info!(
        bench_mode = cfg.bench_mode,
        host = %cfg.options.host,
        port = cfg.options.port,
        endpoint = %cfg.options.base.endpoint,
        "wispd: starting"
    );

    let runtime = Runtime::start(cfg).context("runtime start")?;

    // Launch the WS-over-H2 listener first when configured: it has no
    // msquic dependency, so it can come up even if WT is disabled (the
    // Wispmark `wisp-wt-rust-ws` variant exercises this configuration).
    #[cfg(feature = "ws")]
    let ws_handle = runtime.bind_ws().context("bind ws-h2 listener")?;
    #[cfg(feature = "ws")]
    if ws_handle.is_some() {
        info!("wispd: ws-h2 listener bound");
    }

    #[cfg(feature = "quic")]
    let wt_handle = if runtime.config().options.enabled {
        let h = runtime.bind().await.context("bind wt listener")?;
        info!("wispd: wt listener bound and accepting sessions");
        Some(h)
    } else {
        None
    };

    #[cfg(all(feature = "ws", feature = "quic"))]
    if ws_handle.is_none() && wt_handle.is_none() {
        return Err(anyhow::anyhow!(
            "neither [wisp_wt] nor [wisp_websocket] is enabled — nothing to serve"
        ));
    }
    #[cfg(all(feature = "ws", not(feature = "quic")))]
    if ws_handle.is_none() {
        return Err(anyhow::anyhow!(
            "[wisp_websocket] is not enabled and this build has no QUIC support — nothing to serve"
        ));
    }
    #[cfg(all(feature = "quic", not(feature = "ws")))]
    if wt_handle.is_none() {
        return Err(anyhow::anyhow!(
            "[wisp_wt] is not enabled and this build has no WS support — nothing to serve"
        ));
    }

    wait_for_shutdown_signal().await;
    info!("wispd: shutdown signal received, draining");
    #[cfg(feature = "quic")]
    if let Some(h) = wt_handle {
        h.shutdown();
    }
    runtime.shutdown().await;
    #[cfg(feature = "ws")]
    if let Some(h) = ws_handle {
        // Cancellation in `runtime.shutdown()` already poisoned the
        // listener loop; awaiting just makes drain ordering explicit.
        let _ = h.await;
    }
    info!("wispd: drained, exiting");
    Ok(())
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use signal::unix::{signal as unix_signal, SignalKind};
    let mut sigint = unix_signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut sigterm = unix_signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = sigint.recv() => {},
        _ = sigterm.recv() => {},
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    let _ = signal::ctrl_c().await;
}
