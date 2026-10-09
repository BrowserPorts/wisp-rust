//! Per-request handler. The single hot path is extended CONNECT with
//! `:protocol = websocket`; everything else short-circuits to a status
//! response without entering the upgrade machinery.

use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::ext::Protocol;
use hyper_util::rt::TokioIo;
use tokio_websockets::{Config, Limits, ServerBuilder};
use tracing::{debug, warn};
use wisp_config::is_client_ip_allowed;
use wisp_dos::is_connection_start_allowed;
use wisp_origin::{is_origin_allowed, origin_from_headers, origin_headers_valid, policy_headers};
use wisp_reports::{emit_report, ConnectionContext, ReportErrorType, ReportInput, Transport};
use wisp_wisp_server::ServerContext;

use crate::listener::{ConnectionView, H2ServeContext};
use crate::websocket::serve_websocket;

type Body = BoxBody<Bytes, std::convert::Infallible>;

const PROTOCOL_WEBSOCKET: &str = "websocket";
const WS_FLUSH_THRESHOLD: usize = 1024 * 1024;

pub(crate) async fn handle_request(
    req: Request<Incoming>,
    client_ip: String,
    ctx: Arc<H2ServeContext>,
) -> Result<Response<Body>, std::convert::Infallible> {
    let path = req.uri().path().to_owned();
    let Some(view) = ctx.context_for_path(&path).await else {
        return Ok(status(StatusCode::NOT_FOUND));
    };

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

    if !origin_headers_valid(req.headers()) {
        emit_report(
            ReportErrorType::OriginBlocked,
            ReportInput {
                context: Some(ConnectionContext {
                    client_ip: Some(client_ip.clone()),
                    transport: Some(Transport::Ws),
                    ..Default::default()
                }),
                transport_close_code: Some(403),
                ..Default::default()
            },
        );
        return Ok(status(StatusCode::FORBIDDEN));
    }
    let origin = origin_from_headers(req.headers()).map(|s| s.to_owned());
    if !is_origin_allowed(origin.as_deref(), &view.options) {
        debug!(?origin, "rejecting websocket: origin policy");
        emit_report(
            ReportErrorType::OriginBlocked,
            ReportInput {
                context: Some(ConnectionContext {
                    client_ip: Some(client_ip.clone()),
                    transport: Some(Transport::Ws),
                    origin: origin.clone(),
                    ..Default::default()
                }),
                origin: origin.clone(),
                transport_close_code: Some(403),
                ..Default::default()
            },
        );
        return Ok(origin_denied_response(origin.as_deref(), &view));
    }

    if !is_client_ip_allowed(&client_ip, &view.options) {
        debug!(client_ip = %client_ip, "ws-h2: rejecting: client IP policy");
        emit_report(
            ReportErrorType::ClientBlocked,
            ReportInput {
                context: Some(ConnectionContext {
                    client_ip: Some(client_ip.clone()),
                    transport: Some(Transport::Ws),
                    origin: origin.clone(),
                    ..Default::default()
                }),
                transport_close_code: Some(403),
                ..Default::default()
            },
        );
        return Ok(status(StatusCode::FORBIDDEN));
    }
    let store = ctx.dos.clone();
    if !is_connection_start_allowed(&client_ip, &view.options, &store) {
        debug!(client_ip = %client_ip, "ws-h2: rejecting: connection-start rate");
        emit_report(
            ReportErrorType::ConnectionRateLimited,
            ReportInput {
                context: Some(ConnectionContext {
                    client_ip: Some(client_ip.clone()),
                    transport: Some(Transport::Ws),
                    origin: origin.clone(),
                    ..Default::default()
                }),
                transport_close_code: Some(429),
                limit_type: Some("connection_start".to_owned()),
                ..Default::default()
            },
        );
        return Ok(status(StatusCode::TOO_MANY_REQUESTS));
    }
    let conn_guard = match ctx.connection_limiter.try_acquire(
        &client_ip,
        view.options.max_connections,
        view.options.max_connections_per_ip,
    ) {
        Some(g) => g,
        None => {
            debug!(client_ip = %client_ip, "ws-h2: rejecting: connection concurrency cap");
            emit_report(
                ReportErrorType::ConnectionLimit,
                ReportInput {
                    context: Some(ConnectionContext {
                        client_ip: Some(client_ip.clone()),
                        transport: Some(Transport::Ws),
                        origin: origin.clone(),
                        ..Default::default()
                    }),
                    transport_close_code: Some(429),
                    limit_type: Some("max_connections".to_owned()),
                    ..Default::default()
                },
            );
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

    let on_upgrade = hyper::upgrade::on(req);
    let server_ctx = build_server_ctx(client_ip, &ctx, &view, client_advertises_v2);
    let ws_max_payload = (view.server_options.max_binary_frame_bytes as usize)
        .max(view.server_options.max_text_frame_bytes as usize)
        .saturating_add(1024);

    tokio::spawn(async move {
        let _conn_guard = conn_guard;
        let upgraded = match on_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                warn!(error = %e, "ws-h2 upgrade failed");
                return;
            }
        };
        let io = TokioIo::new(upgraded);
        let ws = ServerBuilder::new()
            .config(Config::default().flush_threshold(WS_FLUSH_THRESHOLD))
            .limits(Limits::default().max_payload_len(Some(ws_max_payload)))
            .serve(io);
        if let Err(e) = serve_websocket(ws, server_ctx).await {
            debug!(error = %e, "wisp-ws connection ended with error");
        }
    });

    let mut response = Response::builder().status(StatusCode::OK);
    if client_advertises_v2
        && !matches!(
            view.server_options.wisp_version,
            wisp_config::WispVersion::V1
        )
    {
        response = response.header("sec-websocket-protocol", "wisp-v2");
    }
    Ok(response
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

fn status(code: StatusCode) -> Response<Body> {
    Response::builder()
        .status(code)
        .body(empty_body())
        .expect("static status response")
}

fn origin_denied_response(origin: Option<&str>, view: &ConnectionView) -> Response<Body> {
    let mut resp = Response::builder().status(StatusCode::FORBIDDEN);
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
