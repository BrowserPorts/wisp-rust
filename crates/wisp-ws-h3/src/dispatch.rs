//! Dispatch a resolved H3 extended-CONNECT `:protocol = websocket` request.
//!
//! `wisp-server` performs protocol detection (it owns the `Request<()>`
//! from the resolver) and hands over the `RequestStream` post-resolve.
//! Dispatch then:
//!   1. sends the 200 response on the stream (RFC 9220 §3 — extended
//!      CONNECT over HTTP/3 responds with 200, not a 101 upgrade)
//!   2. splits the bidi into independent send/recv halves
//!   3. spawns a reader task: pulls h3 chunks, decodes WS frames, emits
//!      `WispMessage` over `incoming_tx`; auto-replies to ping with pong
//!      and forwards close requests via `ctrl_tx`
//!   4. spawns a writer task: `select!`s between `wisp_rx` (server→client
//!      WispMessages) and `ctrl_rx` (Pong/Close), encodes and writes
//!   5. hands the inbound stream + a sink (forwarding into `wisp_tx`) to
//!      [`wisp_wisp_server::serve_connection`] — the same entry point the
//!      HTTP/2 listener uses, so wire semantics are identical across
//!      transports.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use futures::Stream;
use h3::error::StreamError;
use h3::quic::BidiStream as H3BidiStream;
use h3::server::RequestStream;
use http::{Response, StatusCode};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::{CancellationToken, PollSender};
use tracing::{debug, warn};
use wisp_config::{
    endpoint_matches, endpoint_path_token, WispAuthRegistry, WispAuthTokenPolicy,
    WispServerOptions, WispWtServerOptions, WISP_BASE_LIMIT_PROFILE,
};
use wisp_dos::{ConnectionLimiter, DosGuard};
use wisp_quic_msquic::adapter::MsQuicConnection;
use wisp_wisp_server::{
    serve_connection, ProxyControllerTemplate, ServerContext, ServerError, ServerOptions,
    WispMessage,
};

use crate::frame::{
    encode_close, encode_data, encode_pong, Decoder, FrameError, InboundFrame, OP_BINARY, OP_TEXT,
};

const CLOSE_NORMAL: u16 = 1000;
const CLOSE_PROTOCOL_ERROR: u16 = 1002;
const CLOSE_MESSAGE_TOO_BIG: u16 = 1009;

/// Per-listener shared state. Mirrors `wisp_ws_h2::H2ServeContext` so
/// both transports project the same `ServerContext` into the wisp layer.
#[derive(Clone)]
pub struct H3WsContext {
    pub options: Arc<WispServerOptions>,
    pub server_options: Arc<ServerOptions>,
    pub proxy_control_enabled: bool,
    pub auth_registry: WispAuthRegistry,
    /// Shared provider-registry template. Each accepted H3 WS connection
    /// calls `template.spawn()` to mint a fresh per-connection controller —
    /// per-tenant state isolation is enforced by construction (audit-2 #55).
    pub proxy_template: Option<Arc<ProxyControllerTemplate>>,
    pub dos: Arc<DosGuard>,
    pub connection_limiter: Arc<ConnectionLimiter>,
    pub shutdown: CancellationToken,
}

impl H3WsContext {
    pub fn with_template_and_auth(
        options: Arc<WispServerOptions>,
        proxy_control_enabled: bool,
        proxy_template: Option<Arc<ProxyControllerTemplate>>,
        auth_registry: WispAuthRegistry,
        dos: Arc<DosGuard>,
        connection_limiter: Arc<ConnectionLimiter>,
    ) -> Self {
        let server_options = Arc::new(ServerOptions::from_wisp(&options, proxy_control_enabled));
        Self {
            options,
            server_options,
            proxy_control_enabled,
            auth_registry,
            proxy_template,
            dos,
            connection_limiter,
            shutdown: CancellationToken::new(),
        }
    }

    pub fn with_shutdown_token(mut self, shutdown: CancellationToken) -> Self {
        self.shutdown = shutdown;
        self
    }

    /// Build a context from the merged wisp config. The WS sub-section's
    /// endpoint, when present, overrides the WT endpoint in the projected
    /// `WispServerOptions` so the WS dispatcher matches the right path.
    pub fn from_wisp_wt_with_template_and_auth(
        cfg: &WispWtServerOptions,
        proxy_template: Option<Arc<ProxyControllerTemplate>>,
        auth_registry: WispAuthRegistry,
        dos: Arc<DosGuard>,
        connection_limiter: Arc<ConnectionLimiter>,
    ) -> Self {
        let mut base = cfg.base.clone();
        if let Some(ep) = &cfg.websocket.endpoint {
            base.endpoint = ep.clone();
        }
        let proxy_control_enabled = cfg
            .websocket
            .proxy_control_enabled
            .unwrap_or(cfg.proxy_control_enabled);
        Self::with_template_and_auth(
            Arc::new(base),
            proxy_control_enabled,
            proxy_template,
            auth_registry,
            dos,
            connection_limiter,
        )
    }

    pub async fn context_for_path(&self, path: &str) -> Option<H3WsConnectionView> {
        let (options, auth_policy) =
            if let Some(token) = endpoint_path_token(path, &self.options.endpoint) {
                if !self.options.auth.token_path {
                    return None;
                }
                let resolved = tokio::time::timeout(
                    std::time::Duration::from_millis(self.options.auth.resolver_timeout_ms),
                    self.auth_registry.resolve(token.to_owned(), &self.options),
                )
                .await
                .ok()??;
                (Arc::new(resolved.options), resolved.policy)
            } else if endpoint_matches(path, &self.options.endpoint) {
                if self.options.auth.required {
                    return None;
                }
                let base = self
                    .auth_registry
                    .profile(WISP_BASE_LIMIT_PROFILE)
                    .map(Arc::new)
                    .unwrap_or_else(|| self.options.clone());
                (base, WispAuthTokenPolicy::default())
            } else {
                return None;
            };
        let server_options = if Arc::ptr_eq(&options, &self.options) {
            self.server_options.clone()
        } else {
            Arc::new(ServerOptions::from_wisp(
                &options,
                self.proxy_control_enabled,
            ))
        };
        Some(H3WsConnectionView {
            options,
            server_options,
            auth_policy,
        })
    }

    pub fn path_is_endpoint_scope(&self, path: &str) -> bool {
        endpoint_matches(path, &self.options.endpoint)
            || endpoint_path_token(path, &self.options.endpoint).is_some()
    }
}

#[derive(Clone)]
pub struct H3WsConnectionView {
    pub options: Arc<WispServerOptions>,
    pub server_options: Arc<ServerOptions>,
    pub auth_policy: WispAuthTokenPolicy,
}

#[derive(Debug, Error)]
pub enum H3WsError {
    #[error("send 200 response failed")]
    SendResponse(#[source] StreamError),
    #[error("wisp serve_connection error")]
    Wisp(#[from] ServerError),
}

/// Concrete type alias for the bidi stream we get from h3 over msquic.
pub type MsQuicBidi = <MsQuicConnection as h3::quic::OpenStreams<Bytes>>::BidiStream;

/// Send 200, set up the WS pumps, and drive [`serve_connection`] until
/// either side closes. Spawned reader and writer tasks are aborted on
/// return; the underlying stream is finished by the writer task.
pub async fn serve_h3_websocket(
    mut request_stream: RequestStream<MsQuicBidi, Bytes>,
    client_ip: String,
    ctx: H3WsContext,
    view: H3WsConnectionView,
    client_advertises_v2: bool,
) -> Result<(), H3WsError> {
    let mut response = Response::builder().status(StatusCode::OK);
    if client_advertises_v2
        && !matches!(
            view.server_options.wisp_version,
            wisp_config::WispVersion::V1
        )
    {
        response = response.header("sec-websocket-protocol", "wisp-v2");
    }
    let resp = response.body(()).expect("static 200 response");
    request_stream
        .send_response(resp)
        .await
        .map_err(H3WsError::SendResponse)?;

    let (send_half, recv_half) = request_stream.split();

    let (incoming_tx, incoming_rx) = mpsc::channel::<Result<WispMessage, RecvErr>>(64);
    let (wisp_tx, wisp_rx) = mpsc::channel::<WispMessage>(64);
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<ControlFrame>(8);

    let reader_ctrl = ctrl_tx.clone();
    let max_frame_payload = usize::try_from(
        view.server_options
            .max_binary_frame_bytes
            .max(view.server_options.max_text_frame_bytes),
    )
    .unwrap_or(usize::MAX);
    let reader_handle = tokio::spawn(async move {
        run_reader(recv_half, incoming_tx, reader_ctrl, max_frame_payload).await;
    });

    let writer_handle = tokio::spawn(async move {
        run_writer(send_half, wisp_rx, ctrl_rx).await;
    });

    let server_ctx = build_server_ctx(client_ip, &ctx, &view, client_advertises_v2);
    let sink = PollSender::new(wisp_tx);
    let stream = WispMessageStream { rx: incoming_rx };

    let result = serve_connection(sink, stream, server_ctx).await;

    let _ = ctrl_tx
        .send(ControlFrame::Close {
            code: CLOSE_NORMAL,
            reason: Bytes::new(),
        })
        .await;
    drop(ctrl_tx);
    let _ = writer_handle.await;
    reader_handle.abort();

    result.map_err(H3WsError::Wisp)
}

fn build_server_ctx(
    client_ip: String,
    ctx: &H3WsContext,
    view: &H3WsConnectionView,
    client_advertises_v2: bool,
) -> ServerContext {
    let client_hash = wisp_iphash::hash_client_ip(Some(&client_ip), None);
    let proxy_controller = ctx.proxy_template.as_ref().map(|t| {
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
        ctx.dos.clone(),
    )
    .with_cancel(ctx.shutdown.child_token())
}

/// Error carried on the inbound stream. [`serve_connection`]'s `RxErr`
/// bound only requires `Display`; this keeps the h3 error type from
/// crossing the crate boundary while still surfacing a reason in logs.
#[derive(Debug)]
pub struct RecvErr(String);

impl std::fmt::Display for RecvErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

async fn run_reader(
    mut recv: RequestStream<<MsQuicBidi as H3BidiStream<Bytes>>::RecvStream, Bytes>,
    incoming_tx: mpsc::Sender<Result<WispMessage, RecvErr>>,
    ctrl_tx: mpsc::Sender<ControlFrame>,
    max_frame_payload: usize,
) {
    let mut decoder = Decoder::with_max_payload(max_frame_payload);
    loop {
        let chunk = match recv.recv_data().await {
            Ok(Some(buf)) => {
                let mut bm = BytesMut::with_capacity(buf.remaining());
                bm.extend_from_slice(buf.chunk());
                bm.freeze()
            }
            Ok(None) => {
                debug!("h3 ws: peer half-closed recv stream");
                let _ = incoming_tx.send(Err(RecvErr("client closed".into()))).await;
                return;
            }
            Err(e) => {
                debug!(error = ?e, "h3 ws: recv_data error");
                let _ = incoming_tx.send(Err(RecvErr(format!("recv: {e:?}")))).await;
                return;
            }
        };
        decoder.push(&chunk);
        loop {
            match decoder.next_frame() {
                Ok(Some(InboundFrame::Binary(b))) => {
                    if incoming_tx.send(Ok(WispMessage::Binary(b))).await.is_err() {
                        return;
                    }
                }
                Ok(Some(InboundFrame::Text(s))) => {
                    if incoming_tx.send(Ok(WispMessage::Text(s))).await.is_err() {
                        return;
                    }
                }
                Ok(Some(InboundFrame::Ping(p))) => {
                    if ctrl_tx
                        .send(ControlFrame::Pong { payload: p })
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Ok(Some(InboundFrame::Pong)) => {}
                Ok(Some(InboundFrame::Close { payload })) => {
                    let (code, reason) = if payload.len() >= 2 {
                        (
                            u16::from_be_bytes([payload[0], payload[1]]),
                            payload.slice(2..),
                        )
                    } else {
                        (CLOSE_NORMAL, Bytes::new())
                    };
                    let _ = ctrl_tx.send(ControlFrame::Close { code, reason }).await;
                    let _ = incoming_tx.send(Err(RecvErr("client close".into()))).await;
                    return;
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(error = %e, "h3 ws: frame decode error");
                    let code = if matches!(e, FrameError::PayloadTooLarge(_)) {
                        CLOSE_MESSAGE_TOO_BIG
                    } else {
                        CLOSE_PROTOCOL_ERROR
                    };
                    let _ = ctrl_tx
                        .send(ControlFrame::Close {
                            code,
                            reason: Bytes::from_static(b"frame error"),
                        })
                        .await;
                    let _ = incoming_tx.send(Err(RecvErr(format!("decode: {e}")))).await;
                    return;
                }
            }
        }
    }
}

#[derive(Debug)]
enum ControlFrame {
    Pong { payload: Bytes },
    Close { code: u16, reason: Bytes },
}

async fn run_writer(
    mut send: RequestStream<<MsQuicBidi as H3BidiStream<Bytes>>::SendStream, Bytes>,
    mut wisp_rx: mpsc::Receiver<WispMessage>,
    mut ctrl_rx: mpsc::Receiver<ControlFrame>,
) {
    loop {
        tokio::select! {
            biased;
            ctrl = ctrl_rx.recv() => {
                match ctrl {
                    Some(ControlFrame::Pong { payload }) => {
                        let frame = encode_pong(&payload);
                        if send.send_data(frame).await.is_err() {
                            return;
                        }
                    }
                    Some(ControlFrame::Close { code, reason }) => {
                        let frame = encode_close(code, &reason);
                        let _ = send.send_data(frame).await;
                        let _ = send.finish().await;
                        return;
                    }
                    None => {
                        while let Some(msg) = wisp_rx.recv().await {
                            let frame = encode_message(msg);
                            if send.send_data(frame).await.is_err() {
                                break;
                            }
                        }
                        let _ = send.finish().await;
                        return;
                    }
                }
            }
            data = wisp_rx.recv() => {
                match data {
                    Some(msg) => {
                        let frame = encode_message(msg);
                        if send.send_data(frame).await.is_err() {
                            return;
                        }
                    }
                    None => {
                        let _ = send.finish().await;
                        return;
                    }
                }
            }
        }
    }
}

fn encode_message(msg: WispMessage) -> Bytes {
    match msg {
        WispMessage::Binary(b) => encode_data(OP_BINARY, &b),
        WispMessage::Text(s) => encode_data(OP_TEXT, s.as_bytes()),
    }
}

/// `Stream<Item = Result<WispMessage, RecvErr>>` over an mpsc receiver.
struct WispMessageStream {
    rx: mpsc::Receiver<Result<WispMessage, RecvErr>>,
}

impl Stream for WispMessageStream {
    type Item = Result<WispMessage, RecvErr>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}
