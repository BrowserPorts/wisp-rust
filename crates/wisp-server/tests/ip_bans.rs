//! Ban checks for the QUIC paths, driven without a live QUIC connection.
//!
//! `serve::handle_connection` refuses a connection by running
//! [`PreUpgradePolicy::check`] on the extended CONNECT request and dropping the
//! stream when it returns an error. These tests build the same requests the h3
//! resolver hands it (`:method CONNECT`, `:protocol websocket` or
//! `webtransport`, an `Origin`, the endpoint path) and build the policy the same
//! way each branch does, so the refusal, the `WISP_IP_HASH_BANNED` report and
//! the acceptance after clearing are the real code paths. The msquic
//! listener itself is not started here.

use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use tokio::sync::{mpsc, Mutex};
use wisp_config::{WispAuthRegistry, WispWtServerOptions};
use wisp_dos::{ConnectionLimiter, DosGuard};
use wisp_iphash::{hash_client_ip_keyed, IpHashBans};
use wisp_reports::{set_report_hook, Report, ReportErrorType};
use wisp_server::{H3WsContext, PreUpgradePolicy, ServeExtras};

const WS_PATH: &str = "/wisp-ws";
const WT_PATH: &str = "/wisp-wt";
const CLIENT_IP: &str = "127.0.0.1";

/// The report hook is process-wide, so the tests take turns.
static SERIAL: Mutex<()> = Mutex::const_new(());

fn options() -> Arc<WispWtServerOptions> {
    let mut options = WispWtServerOptions::default();
    options.base.block_blank_origins = false;
    options.base.auth.required = false;
    options.websocket.enabled = true;
    options.websocket.endpoint = Some(WS_PATH.to_owned());
    Arc::new(options)
}

/// The request as the h3 resolver surfaces it to `handle_connection`.
fn extended_connect(path: &str, protocol: h3::ext::Protocol) -> Request<()> {
    Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://localhost{path}"))
        .header(header::ORIGIN, "https://app.example")
        .extension(protocol)
        .body(())
        .unwrap()
}

fn report_channel() -> mpsc::UnboundedReceiver<Option<String>> {
    let (tx, rx) = mpsc::unbounded_channel();
    set_report_hook(Some(Arc::new(move |report: &Report| {
        if report.error_type == ReportErrorType::IpHashBanned {
            let _ = tx.send(report.ip_hash.clone());
        }
    })));
    rx
}

fn loopback_hash() -> String {
    hash_client_ip_keyed(Some(CLIENT_IP)).expect("loopback hashes")
}

#[tokio::test]
async fn ws_over_h3_branch_refuses_banned_client_and_accepts_after_clearing() {
    let _turn = SERIAL.lock().await;
    let mut reports = report_channel();
    let options = options();
    let bans = Arc::new(IpHashBans::new());
    let ctx = H3WsContext::from_wisp_wt_with_template_and_auth(
        &options,
        None,
        WispAuthRegistry::default(),
        Arc::new(DosGuard::new()),
        Arc::new(ConnectionLimiter::new()),
    )
    .with_ip_bans(bans.clone());
    let request = extended_connect(WS_PATH, h3::ext::Protocol::WEBSOCKET);

    // Same sequence as the WS branch of `handle_connection`.
    let check = |request: &Request<()>| {
        let view = futures::executor::block_on(ctx.context_for_path(request.uri().path()))
            .expect("the WS endpoint resolves");
        PreUpgradePolicy::new(view.options.clone(), ctx.dos.clone())
            .with_ip_bans(ctx.ip_bans.clone())
            .check(request.headers(), CLIENT_IP)
    };

    assert!(check(&request).is_ok());

    bans.replace([loopback_hash()]);
    let refused = check(&request).unwrap_err();
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.reason, "banned IP hash");
    assert_eq!(reports.recv().await, Some(Some(loopback_hash())));

    bans.replace(Vec::<String>::new());
    assert!(check(&request).is_ok());
    set_report_hook(None);
}

#[tokio::test]
async fn webtransport_branch_refuses_banned_client_and_accepts_after_clearing() {
    let _turn = SERIAL.lock().await;
    let mut reports = report_channel();
    let options = options();
    let extras = ServeExtras::default();
    let dos = Arc::new(DosGuard::new());
    let request = extended_connect(WT_PATH, h3::ext::Protocol::WEB_TRANSPORT);

    // Same construction as the WebTransport branch of `handle_connection`:
    // the base options for the endpoint, the ban set from `ServeExtras`.
    let check = || {
        PreUpgradePolicy::new(Arc::new(options.base.clone()), dos.clone())
            .with_ip_bans(extras.ip_bans.clone())
            .check(request.headers(), CLIENT_IP)
    };

    assert!(check().is_ok());

    extras.ip_bans.replace([loopback_hash()]);
    let refused = check().unwrap_err();
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.reason, "banned IP hash");
    assert_eq!(reports.recv().await, Some(Some(loopback_hash())));

    extras.ip_bans.replace(Vec::<String>::new());
    assert!(check().is_ok());
    set_report_hook(None);
}

#[tokio::test]
async fn banning_one_client_leaves_others_admitted() {
    let _turn = SERIAL.lock().await;
    let options = options();
    let bans = Arc::new(IpHashBans::new());
    bans.replace([loopback_hash()]);
    let policy = PreUpgradePolicy::new(Arc::new(options.base.clone()), Arc::new(DosGuard::new()))
        .with_ip_bans(bans);
    let request = extended_connect(WT_PATH, h3::ext::Protocol::WEB_TRANSPORT);
    assert!(policy.check(request.headers(), CLIENT_IP).is_err());
    assert!(policy.check(request.headers(), "127.0.0.2").is_ok());
}
