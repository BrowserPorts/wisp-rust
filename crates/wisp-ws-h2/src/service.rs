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
use wisp_config::{is_client_ip_allowed, WispServerOptions};
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
    if !ctx.path_is_endpoint_scope(&path) {
        return Ok(status(StatusCode::NOT_FOUND));
    }

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

    // Everything that does not depend on a token runs before one is resolved,
    // so a banned, foreign-origin or flooding client never reaches the token
    // resolver (which may call out to the host's handler).
    let base = ctx.base_options();
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
    if !is_origin_allowed(origin.as_deref(), &base) {
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
        return Ok(origin_denied_response(origin.as_deref(), &base));
    }

    if !is_client_ip_allowed(&client_ip, &base) {
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
    let client_hash = wisp_iphash::hash_client_ip_keyed(Some(&client_ip));
    if ctx.ip_bans.is_banned(client_hash.as_deref()) {
        debug!(client_ip = %client_ip, "ws-h2: rejecting: banned IP hash");
        emit_report(
            ReportErrorType::IpHashBanned,
            ReportInput {
                context: Some(ConnectionContext {
                    client_ip: Some(client_ip.clone()),
                    client_ip_hash: client_hash,
                    transport: Some(Transport::Ws),
                    origin: origin.clone(),
                }),
                transport_close_code: Some(403),
                ..Default::default()
            },
        );
        return Ok(status(StatusCode::FORBIDDEN));
    }
    if !ctx.token_attempt_allowed(&client_ip, &path, &base) {
        debug!(client_ip = %client_ip, "ws-h2: rejecting: token attempt rate");
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
                limit_type: Some("token_attempt".to_owned()),
                ..Default::default()
            },
        );
        return Ok(status(StatusCode::TOO_MANY_REQUESTS));
    }
    let Some(view) = ctx.view_for_path(&path, Some(base.clone())).await else {
        return Ok(status(StatusCode::NOT_FOUND));
    };
    // A token's limit profile is a full option set and may carry its own
    // origin or client lists.
    if !Arc::ptr_eq(&view.options, &base)
        && (!is_origin_allowed(origin.as_deref(), &view.options)
            || !is_client_ip_allowed(&client_ip, &view.options))
    {
        debug!(client_ip = %client_ip, "ws-h2: rejecting: token profile origin or client policy");
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
    let server_ctx = build_server_ctx(client_ip, client_hash, &ctx, &view, client_advertises_v2);
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
    client_hash: Option<String>,
    ctx: &H2ServeContext,
    view: &ConnectionView,
    client_advertises_v2: bool,
) -> ServerContext {
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
    .with_tunnels(ctx.tunnels.clone())
    .with_principal(view.principal.clone())
}

fn status(code: StatusCode) -> Response<Body> {
    Response::builder()
        .status(code)
        .body(empty_body())
        .expect("static status response")
}

fn origin_denied_response(origin: Option<&str>, options: &WispServerOptions) -> Response<Body> {
    let mut resp = Response::builder().status(StatusCode::FORBIDDEN);
    let (vary, acao) = policy_headers(origin, options);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accept_h2_connection;
    use hyper_util::rt::TokioExecutor;
    use wisp_config::WispServerOptions;
    use wisp_dos::{ConnectionLimiter, DosGuard};
    use wisp_iphash::{hash_client_ip_keyed, IpHashBans};
    use wisp_reports::{set_report_hook, Report};

    type Client = hyper::client::conn::http2::SendRequest<Empty<Bytes>>;

    fn context(ip_bans: Arc<IpHashBans>) -> Arc<H2ServeContext> {
        let mut options = WispServerOptions {
            block_blank_origins: false,
            ..WispServerOptions::default()
        };
        options.auth.required = false;
        Arc::new(
            H2ServeContext::with_template_and_auth(
                Arc::new(options),
                false,
                None,
                wisp_config::WispAuthRegistry::default(),
                Arc::new(DosGuard::new()),
                Arc::new(ConnectionLimiter::new()),
            )
            .with_ip_bans(ip_bans),
        )
    }

    /// An in-process HTTP/2 client wired straight into the server's
    /// per-connection driver, as the post-TLS stream the listener would hand it.
    async fn connect(ctx: Arc<H2ServeContext>) -> Client {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(accept_h2_connection(server_io, "127.0.0.1".to_owned(), ctx));
        let (client, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(client_io))
            .await
            .expect("h2 client handshake");
        tokio::spawn(connection);
        client
    }

    /// Send the extended CONNECT a browser sends and return the status. The
    /// server's SETTINGS may not have arrived yet, so retry while the client
    /// still refuses to send `:protocol`.
    async fn extended_connect(client: &mut Client) -> StatusCode {
        for _ in 0..50 {
            let request = Request::builder()
                .method(Method::CONNECT)
                .uri("https://localhost/wisp")
                .extension(Protocol::from_static("websocket"))
                .body(Empty::<Bytes>::new())
                .expect("build extended CONNECT");
            match client.send_request(request).await {
                Ok(response) => return response.status(),
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
            }
        }
        panic!("extended CONNECT never reached the server");
    }

    #[tokio::test]
    async fn refuses_banned_client_with_403_and_reports_it() {
        let (report_tx, mut report_rx) = tokio::sync::mpsc::unbounded_channel();
        set_report_hook(Some(Arc::new(move |report: &Report| {
            if report.error_type == ReportErrorType::IpHashBanned {
                let _ = report_tx.send(report.ip_hash.clone());
            }
        })));

        let bans = Arc::new(IpHashBans::new());
        let ctx = context(bans.clone());

        let mut client = connect(ctx.clone()).await;
        assert_eq!(extended_connect(&mut client).await, StatusCode::OK);

        let banned = hash_client_ip_keyed(Some("127.0.0.1")).unwrap();
        bans.replace([banned.clone()]);
        let mut client = connect(ctx.clone()).await;
        assert_eq!(extended_connect(&mut client).await, StatusCode::FORBIDDEN);
        assert_eq!(report_rx.recv().await, Some(Some(banned)));

        bans.replace(Vec::<String>::new());
        let mut client = connect(ctx).await;
        assert_eq!(extended_connect(&mut client).await, StatusCode::OK);
        set_report_hook(None);
    }
}
