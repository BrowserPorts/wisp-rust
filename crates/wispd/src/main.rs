//! `wispd` — the standalone wisp-wt server binary.
//!
//! Loads a TOML config, builds a [`wisp_core::Runtime`], and waits on
//! SIGINT/SIGTERM to drive a bounded graceful drain.

use std::path::PathBuf;

use anyhow::Context;
use base64::Engine;
use clap::{Parser, Subcommand};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::signal;
use tracing::info;
use wisp_core::{Runtime, RuntimeConfig};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser, Debug)]
#[command(name = "wispd", version, about = "wisp-wt over msquic")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to the wisp-wt TOML config.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Tracing log level (overrides RUST_LOG).
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Parse and validate a configuration without binding listeners.
    CheckConfig {
        #[arg(value_name = "PATH")]
        config: PathBuf,
    },
    /// Generate a bearer token and its token-file SHA-256 value.
    GenerateToken,
}

fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level);
    match &cli.command {
        Some(Command::CheckConfig { config }) => {
            let cfg = RuntimeConfig::from_toml(config)
                .with_context(|| format!("failed to load config from {}", config.display()))?;
            validate_standalone_auth(&cfg)?;
            let _runtime = Runtime::start(cfg).context("runtime validation")?;
            println!("configuration is valid");
            return Ok(());
        }
        Some(Command::GenerateToken) => {
            let mut bytes = [0_u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            println!("token={token}");
            println!("sha256={}", hex::encode(Sha256::digest(token.as_bytes())));
            return Ok(());
        }
        None => {}
    }
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all().build()?.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    let cfg = match &cli.config {
        Some(path) => RuntimeConfig::from_toml(path)
            .with_context(|| format!("failed to load config from {}", path.display()))?,
        None => {
            info!("wispd: no --config supplied, using defaults");
            RuntimeConfig::from_options(wisp_config::WispWtServerOptions::default())
                .context("default options validate")?
        }
    }
    .with_log_level(&cli.log_level);
    validate_standalone_auth(&cfg)?;

    info!(
        host = %cfg.options.host,
        port = cfg.options.port,
        endpoint = %cfg.options.base.endpoint,
        "wispd: starting"
    );

    let runtime = Runtime::start(cfg).context("runtime start")?;

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

    wait_for_shutdown_signal(&runtime).await?;
    info!("wispd: shutdown signal received, draining");
    #[cfg(feature = "quic")]
    if let Some(h) = wt_handle {
        h.shutdown();
    }
    runtime.shutdown().await;
    #[cfg(feature = "ws")]
    if let Some(h) = ws_handle {
        let _ = h.await;
    }
    info!("wispd: drained, exiting");
    Ok(())
}

fn validate_standalone_auth(cfg: &RuntimeConfig) -> anyhow::Result<()> {
    if cfg.options.base.auth.required && cfg.options.base.auth.token_file.is_none() {
        anyhow::bail!("standalone authentication requires wisp.auth.token_file");
    }
    Ok(())
}

#[cfg(unix)]
async fn wait_for_shutdown_signal(runtime: &Runtime) -> anyhow::Result<()> {
    use signal::unix::{signal as unix_signal, SignalKind};
    let mut sigint = unix_signal(SignalKind::interrupt()).context("install SIGINT handler")?;
    let mut sigterm = unix_signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut sighup = unix_signal(SignalKind::hangup()).context("install SIGHUP handler")?;
    loop {
        tokio::select! {
            _ = sigint.recv() => return Ok(()),
            _ = sigterm.recv() => return Ok(()),
            _ = sighup.recv() => {
                match runtime.reload_auth_tokens() {
                    Ok(true) => info!("wispd: reloaded authentication tokens"),
                    Ok(false) => info!("wispd: no authentication token file configured"),
                    Err(error) => tracing::error!(%error, "wispd: token reload rejected; previous tokens remain active"),
                }
            }
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal(_runtime: &Runtime) -> anyhow::Result<()> {
    signal::ctrl_c().await.context("install Ctrl-C handler")?;
    Ok(())
}
