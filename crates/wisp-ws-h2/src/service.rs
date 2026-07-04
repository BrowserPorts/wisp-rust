//! Per-request handler. The single hot path is extended CONNECT with
//! `:protocol = websocket`; everything else short-circuits to a status
//! response without entering the upgrade machinery.

use std::sync::Arc;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::ext::Protocol;
use hyper_util::rt::TokioIo;
use tokio_websockets::{Limits, Message, ServerBuilder};
use tracing::{debug, warn};
use wisp_config::resolve_client_ip;
use wisp_dos::{global_connection_limiter, global_guard, is_connection_start_allowed};
use wisp_origin::{is_origin_allowed, origin_from_headers, policy_headers};
use wisp_wisp_server::{serve_connection, ServerContext, WispMessage};

use crate::listener::{ConnectionView, H2ServeContext};

type Body = BoxBody<Bytes, std::convert::Infallible>;

const PROTOCOL_WEBSOCKET: &str = "websocket";

pub(crate) async fn handle_request(
    req: Request<Incoming>,
    client_ip: String,
    ctx: Arc<H2ServeContext>,
) -> Result<Response<Body>, std::convert::Infallible> {
    // 1. Path match — the configured wisp endpoint.
    let path = req.uri().path().to_owned();
    let Some(view) = ctx.context_for_path(&path).await else {
        return Ok(status(StatusCode::NOT_FOUND));
    };

    // 2. Method + :protocol pseudo header. RFC 8441 puts it in the request
    // extensions on hyper; everything else (GET, plain CONNECT) is rejected.
    if req.method() != Method::CONNECT {
        return Ok(status(StatusCode::METHOD_NOT_ALLOWED));
    }
    let proto = req.extensions().get::<Protocol>();
    let is_ws = proto
        .map(|p| p.as_str().eq_ignore_ascii_case(PROTOCOL_WEBSOCKET))
        .unwrap_or(false);
    if !is_ws {
        return Ok(status(StatusCode::BAD_REQUEST));
    }

    // 3. Origin policy. The bun server's WebTransport-Bun build skipped
    // this; the H2 path always enforces it because hyper hands us the
    // header verbatim.
    let origin = origin_from_headers(req.headers()).map(|s| s.to_owned());
    if !is_origin_allowed(origin.as_deref(), &view.options) {
        debug!(?origin, "rejecting websocket: origin policy");
        return Ok(origin_denied_response(origin.as_deref(), &view));
    }

    // Resolve the real client IP (trusted X-Forwarded-For), then gate on the
    // connection-start rate and live-connection concurrency caps before the
    // upgrade / per-connection work.
    let xff = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    let client_ip = resolve_client_ip(&client_ip, xff, &view.options);
    let store = global_guard();
    if !is_connection_start_allowed(&client_ip, &view.options, &store) {
        debug!(client_ip = %client_ip, "ws-h2: rejecting: connection-start rate");
        return Ok(status(StatusCode::TOO_MANY_REQUESTS));
    }
    let conn_guard = match global_connection_limiter().try_acquire(
        &client_ip,
        view.options.max_connections,
        view.options.max_connections_per_ip,
    ) {
        Some(g) => g,
        None => {
            debug!(client_ip = %client_ip, "ws-h2: rejecting: connection concurrency cap");
            return Ok(status(StatusCode::TOO_MANY_REQUESTS));
        }
    };

    let client_advertises_v2 = req
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

    // 4. Extract upgrade future BEFORE we hand off the response — once
    // we return the 200, hyper will drive the upgrade.
    let on_upgrade = hyper::upgrade::on(req);
    let server_ctx = build_server_ctx(client_ip, &ctx, &view, client_advertises_v2);
    // Bind tokio-websockets' max payload to the configured wisp binary
    // frame cap so a malicious client can't burn 64 MiB (the WS default)
    // per frame just to be rejected by the in-band wisp cap. The +1024 is
    // a small wisp-frame-header headroom.
    let ws_max_payload = (view.server_options.max_binary_frame_bytes as usize)
        .max(view.server_options.max_text_frame_bytes as usize)
        .saturating_add(1024);

    tokio::spawn(async move {
        // Hold the connection slot for the whole session; drops on task exit.
        let _conn_guard = conn_guard;
        let upgraded = match on_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                warn!(error = %e, "ws-h2 upgrade failed");
                return;
            }
        };
        // tokio-websockets needs tokio::io::AsyncRead+Write; TokioIo wraps
        // the hyper::rt:: traits exposed by `Upgraded`.
        let io = TokioIo::new(upgraded);
        let ws = ServerBuilder::new()
            .limits(Limits::default().max_payload_len(Some(ws_max_payload)))
            .serve(io);
        let (sink, stream) = ws.split();

        // WispMessage <-> Message adapters. Binary frames carry the Wisp v2
        // codec; text frames carry STELLITE_PROXY_CONTROL JSON. Anything
        // else (pings, close) is handled by tokio-websockets internally or
        // dropped silently.
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
                Ok(msg) if msg.is_text() => {
                    msg.as_text().map(|s| Ok(WispMessage::Text(s.to_owned())))
                }
                Ok(msg) if msg.is_close() => None,
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            }
        });
        // serve_connection moves `outgoing` into a dedicated writer task
        // (so a slow peer's back-pressure can't block the ingress loop), so
        // the sink must be `'static + Send`. Box::pin gives us a heap-pinned
        // owned sink that satisfies both bounds, where pin_mut! would not.
        let outgoing = Box::pin(outgoing);
        futures::pin_mut!(incoming);
        if let Err(e) = serve_connection(outgoing, incoming, server_ctx).await {
            debug!(error = %e, "wisp-ws connection ended with error");
        }
    });

    // 5. 200 response — extended CONNECT in HTTP/2 uses 200, not 101.
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .expect("static response builder"))
}

fn build_server_ctx(
    client_ip: String,
    ctx: &H2ServeContext,
    view: &ConnectionView,
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

fn status(code: StatusCode) -> Response<Body> {
    Response::builder()
        .status(code)
        .body(empty_body())
        .expect("static status response")
}

fn origin_denied_response(origin: Option<&str>, view: &ConnectionView) -> Response<Body> {
    let mut resp = Response::builder().status(StatusCode::FORBIDDEN);
    // policy_headers returns (Vary, ACAO). On a denied origin ACAO is None
    // (we don't want to advertise origin reflection on a 403); we always
    // emit Vary: Origin so caches don't poison.
    let (vary, acao) = policy_headers(origin, &view.options);
    resp = resp.header("Vary", HeaderValue::from_static(vary));
    if let Some(value) = acao {
        if let Ok(val) = HeaderValue::from_str(&value) {
            resp = resp.header("Access-Control-Allow-Origin", val);
        }
    }
    resp.body(text_body("origin not allowed"))
        .expect("static forbidden response")
}

fn empty_body() -> Body {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn text_body(text: &'static str) -> Body {
    Full::new(Bytes::from_static(text.as_bytes()))
        .map_err(|never| match never {})
        .boxed()
}
