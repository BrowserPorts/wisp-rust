//! TCP accept loop for the Wisp v2 WebSocket-over-H2 transport. Owns a
//! `tokio_rustls::TlsAcceptor` and dispatches each accepted, TLS-terminated
//! connection to [`wisp_ws_h2::accept_h2_connection`].

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use thiserror::Error;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};
use wisp_config::WispWtServerOptions;
use wisp_ws_h2::{accept_h2_connection, H2ServeContext};

use crate::tls::{build_h2_server_config, TlsError};

#[derive(Debug, Error)]
pub enum WsH2ListenerError {
    #[error("bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("tls config: {0}")]
    Tls(#[from] TlsError),
    #[error("invalid bind address {host}:{port}: {source}")]
    BadAddr {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "ws-h2 listener requires a TLS cert: set [wisp_websocket.cert_path] or [wisp_wt.cert_path]"
    )]
    MissingCert,
    #[error(
        "ws-h2 listener requires a TLS key: set [wisp_websocket.key_path] or [wisp_wt.key_path]"
    )]
    MissingKey,
}

#[derive(Debug, Clone)]
pub struct WsH2ListenerConfig {
    pub bind_addr: SocketAddr,
    pub cert_path: String,
    pub key_path: String,
}

impl WsH2ListenerConfig {
    /// Project the merged `[wisp_websocket]` + `[wisp_wt]` config into a
    /// concrete listener config. Returns `Ok(None)` if the WS transport is
    /// disabled, leaving the WT side to run alone.
    ///
    /// The cert/key paths in `[wisp_websocket]` win when present; otherwise
    /// the WT pair is reused so a single PEM identity covers both
    /// transports on the same hostname.
    pub fn try_from_wisp_wt(cfg: &WispWtServerOptions) -> Result<Option<Self>, WsH2ListenerError> {
        if !cfg.websocket.enabled || cfg.websocket.plain {
            return Ok(None);
        }
        let cert_path = cfg
            .websocket
            .cert_path
            .clone()
            .or_else(|| cfg.cert_path.clone())
            .ok_or(WsH2ListenerError::MissingCert)?;
        let key_path = cfg
            .websocket
            .key_path
            .clone()
            .or_else(|| cfg.key_path.clone())
            .ok_or(WsH2ListenerError::MissingKey)?;
        // `[wisp_websocket.bind_addr]` wins when set so a deployment can
        // configure the listener via one unified env-var-style string. We
        // resolve through `to_socket_addrs` either way so an IPv6 literal
        // like `[::]:8443` parses identically to the host+port pair.
        let (host, port, addrs_input) = if let Some(addr) = cfg.websocket.bind_addr.as_deref() {
            (addr.to_owned(), 0u16, addr.to_owned())
        } else {
            (
                cfg.websocket.host.clone(),
                cfg.websocket.port,
                format!("{}:{}", cfg.websocket.host, cfg.websocket.port),
            )
        };
        let bind_addr = addrs_input
            .as_str()
            .to_socket_addrs()
            .map_err(|source| WsH2ListenerError::BadAddr {
                host: host.clone(),
                port,
                source,
            })?
            .next()
            .ok_or_else(|| WsH2ListenerError::BadAddr {
                host: host.clone(),
                port,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "host did not resolve to any address",
                ),
            })?;
        Ok(Some(Self {
            bind_addr,
            cert_path,
            key_path,
        }))
    }
}

/// Spawns the accept loop and returns when the listener exits (the OS
/// closed the socket or an unrecoverable accept error fires). Each
/// accepted connection runs in a detached `tokio::spawn` so accept
/// continues immediately.
pub async fn serve_ws_h2_listener(
    cfg: WsH2ListenerConfig,
    ctx: Arc<H2ServeContext>,
) -> Result<(), WsH2ListenerError> {
    let server_config = build_h2_server_config(&cfg.cert_path, &cfg.key_path)?;
    let acceptor = TlsAcceptor::from(server_config);
    let listener =
        TcpListener::bind(cfg.bind_addr)
            .await
            .map_err(|source| WsH2ListenerError::Bind {
                addr: cfg.bind_addr,
                source,
            })?;
    info!(addr = %cfg.bind_addr, "wisp ws-h2 listener ready");

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                // Per the wispmark Bun reference, transient accept errors
                // are logged and the loop continues; only a hard OS error
                // that closes the listener exits the loop (the `?` on
                // `bind` above is the only fatal exit).
                warn!(error = %e, "ws-h2 accept error");
                continue;
            }
        };
        let _ = tcp.set_nodelay(true);
        let acceptor = acceptor.clone();
        let ctx = ctx.clone();
        let client_ip = peer.ip().to_string();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(e) => {
                    debug!(peer = %peer, error = %e, "ws-h2 tls handshake failed");
                    return;
                }
            };
            if let Err(e) = accept_h2_connection(tls, client_ip, ctx).await {
                debug!(peer = %peer, error = %e, "ws-h2 connection ended");
            }
        });
    }
}
