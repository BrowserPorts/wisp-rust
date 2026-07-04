//! Plain RFC 6455 `ws://` listener. No TLS, no HTTP/2, no extended CONNECT —
//! HTTP/1.1 `Upgrade: websocket` over a raw TCP stream. Used by wispmark and
//! other bench harnesses whose clients only speak plain WebSocket. Reuses
//! [`wisp_ws_h2::H2ServeContext`] for shared per-listener state.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_websockets::{Limits, Message, ServerBuilder};
use tracing::{debug, info, warn};
use wisp_config::{resolve_client_ip, WispWtServerOptions};
use wisp_dos::{global_connection_limiter, global_guard, is_connection_start_allowed};
use wisp_iphash::hash_client_ip;
use wisp_origin::{is_origin_allowed, origin_from_headers};
use wisp_wisp_server::{serve_connection, ServerContext, WispMessage};
use wisp_ws_h2::{listener::ConnectionView, H2ServeContext};

#[derive(Debug, Error)]
pub enum WsPlainListenerError {
    #[error("bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid bind address {host}:{port}: {source}")]
    BadAddr {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone)]
pub struct WsPlainListenerConfig {
    pub bind_addr: SocketAddr,
}

impl WsPlainListenerConfig {
    pub fn try_from_wisp_wt(
        cfg: &WispWtServerOptions,
    ) -> Result<Option<Self>, WsPlainListenerError> {
        if !cfg.websocket.enabled || !cfg.websocket.plain {
            return Ok(None);
        }
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
            .map_err(|source| WsPlainListenerError::BadAddr {
                host: host.clone(),
                port,
                source,
            })?
            .next()
            .ok_or_else(|| WsPlainListenerError::BadAddr {
                host: host.clone(),
                port,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "host did not resolve to any address",
                ),
            })?;
        Ok(Some(Self { bind_addr }))
    }
}

pub async fn serve_ws_plain_listener(
    cfg: WsPlainListenerConfig,
    ctx: Arc<H2ServeContext>,
) -> Result<(), WsPlainListenerError> {
    let listener =
        TcpListener::bind(cfg.bind_addr)
            .await
            .map_err(|source| WsPlainListenerError::Bind {
                addr: cfg.bind_addr,
                source,
            })?;
    info!(addr = %cfg.bind_addr, "wisp ws-plain listener ready");

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "ws-plain accept error");
                continue;
            }
        };
        let _ = tcp.set_nodelay(true);
        let ctx = ctx.clone();
        let client_ip = peer.ip().to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(tcp, client_ip, ctx).await {
                debug!(peer = %peer, error = %e, "ws-plain connection ended");
            }
        });
    }
}

async fn handle_connection(
    tcp: tokio::net::TcpStream,
    client_ip: String,
    ctx: Arc<H2ServeContext>,
) -> Result<(), tokio_websockets::Error> {
    let ws_max_payload = (ctx.server_options.max_binary_frame_bytes as usize)
        .max(ctx.server_options.max_text_frame_bytes as usize)
        .saturating_add(1024);

    let (request, ws) = ServerBuilder::new()
        .limits(Limits::default().max_payload_len(Some(ws_max_payload)))
        .accept(tcp)
        .await?;

    let path = request.uri().path();
    let Some(view) = ctx.context_for_path(path).await else {
        debug!(%path, expected = %ctx.options.endpoint, "ws-plain: path mismatch");
        return Ok(());
    };

    // Origin gate — the plain listener previously skipped this, so any web
    // page could open a cross-origin WebSocket to the proxy. Enforce it here
    // exactly as the H2 path does.
    let origin = origin_from_headers(request.headers()).map(|s| s.to_owned());
    if !is_origin_allowed(origin.as_deref(), &view.options) {
        debug!(?origin, "ws-plain: rejecting websocket: origin policy");
        return Ok(());
    }

    // Resolve the real client IP (honoring trusted X-Forwarded-For), then gate
    // on the connection-start rate and the live-connection concurrency caps
    // before doing any per-connection work.
    let xff = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    let client_ip = resolve_client_ip(&client_ip, xff, &view.options);
    let store = global_guard();
    if !is_connection_start_allowed(&client_ip, &view.options, &store) {
        debug!(client_ip = %client_ip, "ws-plain: rejecting: connection-start rate");
        return Ok(());
    }
    let _conn_guard = match global_connection_limiter().try_acquire(
        &client_ip,
        view.options.max_connections,
        view.options.max_connections_per_ip,
    ) {
        Some(g) => g,
        None => {
            debug!(client_ip = %client_ip, "ws-plain: rejecting: connection concurrency cap");
            return Ok(());
        }
    };

    let client_advertises_v2 = request
        .headers()
        .get_all("sec-websocket-protocol")
        .iter()
        .any(|v| {
            v.to_str()
                .map(|s| {
                    s.split(',')
                        .any(|p| p.trim().eq_ignore_ascii_case("wisp-v2"))
                })
                .unwrap_or(false)
        });

    let server_ctx = build_server_ctx(client_ip, &ctx, &view, client_advertises_v2);
    let (sink, stream) = ws.split();

    let outgoing = sink.with(|msg: WispMessage| async move {
        let m = match msg {
            WispMessage::Binary(b) => Message::binary(b),
            WispMessage::Text(s) => Message::text(s),
        };
        Ok::<Message, tokio_websockets::Error>(m)
    });
    let incoming = stream.filter_map(|res| async move {
        match res {
            Ok(msg) if msg.is_binary() => {
                let bytes: Bytes = msg.into_payload().into();
                Some(Ok::<WispMessage, tokio_websockets::Error>(
                    WispMessage::Binary(bytes),
                ))
            }
            Ok(msg) if msg.is_text() => msg.as_text().map(|s| Ok(WispMessage::Text(s.to_owned()))),
            Ok(msg) if msg.is_close() => None,
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        }
    });
    let outgoing = Box::pin(outgoing);
    futures::pin_mut!(incoming);
    if let Err(e) = serve_connection(outgoing, incoming, server_ctx).await {
        debug!(error = %e, "wisp-ws-plain connection ended with error");
    }
    Ok(())
}

fn build_server_ctx(
    client_ip: String,
    ctx: &H2ServeContext,
    view: &ConnectionView,
    client_advertises_v2: bool,
) -> ServerContext {
    let client_hash = hash_client_ip(Some(&client_ip), None);
    let proxy_controller = ctx
        .proxy_template
        .as_ref()
        .map(|t| {
            t.spawn(
                view.server_options.proxy_control_limits(),
                view.auth_policy.allowed_proxy_providers.clone(),
            )
        });
    ServerContext::new(
        client_ip,
        client_hash,
        view.options.clone(),
        view.server_options.clone(),
        proxy_controller,
        client_advertises_v2,
    )
}
