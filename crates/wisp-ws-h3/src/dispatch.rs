//! Dispatch a resolved H3 extended-CONNECT `:protocol = websocket` request.
//!
//! `wisp-server` does the protocol detection (it owns the `Request<()>`
//! from the resolver) and hands us the `RequestStream` post-resolve. We:
//!   1. send the 200 response on the stream (RFC 9220 §3 — H3 mirrors
//!      H2's "no 101, just 200" for extended CONNECT)
//!   2. split the bidi into independent send/recv halves
//!   3. spawn a reader task: pulls h3 chunks, decodes WS frames, emits
//!      `WispMessage` over `incoming_tx`; auto-replies to ping with pong
//!      and forwards close requests via `ctrl_tx`
//!   4. spawn a writer task: select!s between `wisp_rx` (server→client
//!      WispMessages) and `ctrl_rx` (Pong/Close), encodes and writes
//!   5. hand the inbound stream + a `WispMessageSink` (forwarding into
//!      `wisp_tx`) to [`wisp_wisp_server::serve_connection`] — same
//!      entry point the H2 listener uses, so wire semantics are
//!      identical across transports

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use futures::Stream;
use h3::quic::BidiStream as H3BidiStream;
use h3::server::RequestStream;
use http::{Response, StatusCode};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use tracing::{debug, warn};
use wisp_config::{
    endpoint_matches, endpoint_path_token, WispAuthRegistry, WispAuthTokenPolicy,
    WispServerOptions, WispWtServerOptions, WISP_BASE_LIMIT_PROFILE,
};
use wisp_quic_msquic::adapter::MsQuicConnection;
use wisp_wisp_server::{
    serve_connection, ProxyControllerTemplate, ServerContext, ServerOptions, WispMessage,
};

use crate::frame::{
    encode_close, encode_data, encode_pong, Decoder, InboundFrame, OP_BINARY, OP_TEXT,
};

const CLOSE_NORMAL: u16 = 1000;
const CLOSE_INTERNAL_ERROR: u16 = 1011;

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
}

impl H3WsContext {
    pub fn new(options: Arc<WispServerOptions>, proxy_control_enabled: bool) -> Self {
        Self::with_template(options, proxy_control_enabled, None)
    }

    pub fn with_template(
        options: Arc<WispServerOptions>,
        proxy_control_enabled: bool,
        proxy_template: Option<Arc<ProxyControllerTemplate>>,
    ) -> Self {
        Self::with_template_and_auth(
            options,
            proxy_control_enabled,
            proxy_template,
            WispAuthRegistry::default(),
        )
    }

    pub fn with_template_and_auth(
        options: Arc<WispServerOptions>,
        proxy_control_enabled: bool,
        proxy_template: Option<Arc<ProxyControllerTemplate>>,
        auth_registry: WispAuthRegistry,
    ) -> Self {
        let server_options = Arc::new(ServerOptions::from_wisp(&options, proxy_control_enabled));
        Self {
            options,
            server_options,
            proxy_control_enabled,
            auth_registry,
            proxy_template,
        }
    }

    /// Build a context from the merged wisp config. The WS sub-section's
    /// endpoint, when present, overrides the WT endpoint in the projected
    /// `WispServerOptions` so the WS dispatcher matches the right path.
    pub fn from_wisp_wt(cfg: &WispWtServerOptions) -> Self {
        Self::from_wisp_wt_with_template(cfg, None)
    }

    pub fn from_wisp_wt_with_template(
        cfg: &WispWtServerOptions,
        proxy_template: Option<Arc<ProxyControllerTemplate>>,
    ) -> Self {
        Self::from_wisp_wt_with_template_and_auth(cfg, proxy_template, WispAuthRegistry::default())
    }

    pub fn from_wisp_wt_with_template_and_auth(
        cfg: &WispWtServerOptions,
        proxy_template: Option<Arc<ProxyControllerTemplate>>,
        auth_registry: WispAuthRegistry,
    ) -> Self {
        let mut base = cfg.base.clone();
        if let Some(ep) = &cfg.websocket.endpoint {
            base.endpoint = ep.clone();
        }
        Self::with_template_and_auth(
            Arc::new(base),
            cfg.proxy_control_enabled,
            proxy_template,
            auth_registry,
        )
    }

    pub async fn context_for_path(&self, path: &str) -> Option<H3WsConnectionView> {
        let (options, auth_policy) = if let Some(token) =
            endpoint_path_token(path, &self.options.endpoint)
        {
            if !self.options.auth.token_path {
                return None;
            }
            let resolved = self
                .auth_registry
                .resolve(token.to_owned(), &self.options)
                .await?;
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
    #[error("send 200 response failed: {0}")]
    SendResponse(String),
    #[error("wisp serve_connection error: {0}")]
    Wisp(String),
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
    // 1) 200 OK — RFC 9220 §3 (and 8441 §4 for the H2 mirror).
    let resp = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .expect("static 200 response");
    request_stream
        .send_response(resp)
        .await
        .map_err(|e| H3WsError::SendResponse(format!("{e:?}")))?;

    // 2) split — independent send / recv lets us pump in parallel.
    let (send_half, recv_half) = request_stream.split();

    // Channels:
    //  - incoming: reader → serve_connection (Wisp packets the client sent)
    //  - wisp_out: serve_connection → writer (Wisp packets to send)
    //  - ctrl:     reader → writer (out-of-band WS control frames: Pong, Close)
    let (incoming_tx, incoming_rx) = mpsc::channel::<Result<WispMessage, RecvErr>>(64);
    let (wisp_tx, wisp_rx) = mpsc::channel::<WispMessage>(64);
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<ControlFrame>(8);

    let reader_ctrl = ctrl_tx.clone();
    let reader_handle = tokio::spawn(async move {
        run_reader(recv_half, incoming_tx, reader_ctrl).await;
    });

    let writer_handle = tokio::spawn(async move {
        run_writer(send_half, wisp_rx, ctrl_rx).await;
    });

    let server_ctx = build_server_ctx(client_ip, &ctx, &view, client_advertises_v2);
    let sink = PollSender::new(wisp_tx);
    let stream = WispMessageStream { rx: incoming_rx };

    let result = serve_connection(sink, stream, server_ctx).await;

    // Clean shutdown — ask writer to send a normal Close, then drop the
    // ctrl_tx so the writer's select sees both channels closed and exits.
    let _ = ctrl_tx
        .send(ControlFrame::Close {
            code: CLOSE_NORMAL,
            reason: Bytes::new(),
        })
        .await;
    drop(ctrl_tx);
    let _ = writer_handle.await;
    reader_handle.abort();

    result.map_err(|e| H3WsError::Wisp(e.to_string()))
}

fn build_server_ctx(
    client_ip: String,
    ctx: &H3WsContext,
    view: &H3WsConnectionView,
    client_advertises_v2: bool,
) -> ServerContext {
    let client_hash = wisp_iphash::hash_client_ip(Some(&client_ip), None);
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

// ---------------- reader -------------------------------------------------

/// Error placeholder for the inbound stream. `serve_connection`'s `RxErr`
/// only requires `Display`; we use a small enum so a stringly-typed error
/// shows up in logs without dragging the h3 error type across crates.
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
) {
    let mut decoder = Decoder::new();
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
                Ok(Some(InboundFrame::Pong)) => {
                    // No state to update; we never send pings.
                }
                Ok(Some(InboundFrame::Close { .. })) => {
                    let _ = ctrl_tx
                        .send(ControlFrame::Close {
                            code: CLOSE_NORMAL,
                            reason: Bytes::new(),
                        })
                        .await;
                    let _ = incoming_tx.send(Err(RecvErr("client close".into()))).await;
                    return;
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(error = %e, "h3 ws: frame decode error");
                    let _ = ctrl_tx
                        .send(ControlFrame::Close {
                            code: CLOSE_INTERNAL_ERROR,
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

// ---------------- writer -------------------------------------------------

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
        // tokio::select biases nothing — both arms are equally important.
        // Control frames take priority on tie via `biased;` so a Close
        // request is honored even if data is queued.
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
                        // ctrl channel dropped — peer-side initiated shutdown
                        // and serve_connection is winding down. Drain any
                        // residual data, finish, and exit.
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
                        // serve_connection's sink dropped. Finish the stream
                        // and exit; ctrl will still be drained by the
                        // outer drop in serve_h3_websocket.
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

// ---------------- Stream adapter -----------------------------------------

/// `Stream<Item = Result<WispMessage, RecvErr>>` over an mpsc receiver.
/// We do not use `tokio-stream::ReceiverStream` to keep the workspace
/// dep set minimal — this is a five-line impl.
struct WispMessageStream {
    rx: mpsc::Receiver<Result<WispMessage, RecvErr>>,
}

impl Stream for WispMessageStream {
    type Item = Result<WispMessage, RecvErr>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}
