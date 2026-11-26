//! WISP_PROXY_CONTROL (extension 0x03) and the egress extension point.
//!
//! wisp-rust dials every upstream TCP stream itself unless an [`EgressPlugin`]
//! is installed. A plugin decides, per destination, whether a stream leaves
//! directly or through a proxy, answers the proxy-control text channel, and
//! takes the operator's admin calls. Which proxies exist and which
//! destinations may use them is entirely the plugin's business: nothing here
//! knows any provider.
//!
//! The runtime wraps the plugin in one [`ProxyControllerTemplate`] at startup,
//! and each accepted client gets its own [`ProxyController`] from
//! [`ProxyControllerTemplate::spawn`]. Whatever route the plugin picks, the
//! destination is checked and resolved through [`HostPolicy`] first, so a
//! proxy only ever receives an address that passed the policy.

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use tokio::net::TcpStream;
use tracing::warn;

use wisp_dos::{is_ip_budget_allowed, DosGuard};
use wisp_proxy::HostPolicy;

use crate::stream::{connect_checked_tcp, ConnectError};

/// Limits the control channel holds each client to. They come from the
/// `[wisp.limits]` and `[wisp.rate_limit]` proxy-control keys, and the plugin
/// enforces them on the requests it answers.
#[derive(Debug, Clone, Copy)]
pub struct ProxyControlLimits {
    pub max_rules: usize,
    pub max_reply_bytes: usize,
    pub max_field_bytes: usize,
    pub upstream_ops_per_second: NonZeroU32,
    pub upstream_burst: NonZeroU32,
    pub mutation_ops_per_second: NonZeroU32,
    pub mutation_burst: NonZeroU32,
}

impl Default for ProxyControlLimits {
    fn default() -> Self {
        Self {
            max_rules: 256,
            max_reply_bytes: 64 * 1024,
            max_field_bytes: 256,
            upstream_ops_per_second: NonZeroU32::new(8).expect("nonzero"),
            upstream_burst: NonZeroU32::new(16).expect("nonzero"),
            mutation_ops_per_second: NonZeroU32::new(64).expect("nonzero"),
            mutation_burst: NonZeroU32::new(320).expect("nonzero"),
        }
    }
}

/// One operation of a class against the client's process-wide bucket:
/// `(class, burst, window_ms)`, `true` when it is allowed. Shared across the
/// client's connections, so opening more of them does not multiply a budget.
pub type EgressIpBudget = Arc<dyn Fn(&str, u64, u64) -> bool + Send + Sync>;

/// What a plugin reports about a client's proxy use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressReportKind {
    /// The client moved to another proxy.
    Switch,
    /// A switch was refused by a hop limit.
    HopLimitExceeded,
}

#[derive(Debug, Clone)]
pub struct EgressReport {
    pub kind: EgressReportKind,
    pub client_ip: Option<String>,
    /// The control request that caused it, such as `proxy_set`.
    pub request_type: String,
    /// The plugin's name for the proxy involved.
    pub proxy: String,
    /// For a refusal, which limit refused it.
    pub limit_type: Option<String>,
    pub amount: Option<i64>,
}

/// Everything a plugin learns about a client when its session starts.
pub struct EgressSessionInit {
    pub limits: ProxyControlLimits,
    /// The proxies the client's token was granted, by the plugin's names, or
    /// `None` for a client without such a grant.
    pub allowed_proxies: Option<Vec<String>>,
    /// Where the session sends its reports.
    pub report: Arc<dyn Fn(EgressReport) + Send + Sync>,
}

/// Opens TCP connections to checked addresses through one proxy.
#[async_trait]
pub trait EgressDialer: Send + Sync + 'static {
    /// Connect to `addr`, an address the host policy already allowed. The
    /// address goes to the proxy as an IP literal, so nothing resolves a name
    /// on either side of the check.
    async fn dial(&self, addr: SocketAddr) -> std::io::Result<TcpStream>;

    /// Every address of a destination failed through this dialer, so the
    /// plugin can let go of the proxy it chose.
    fn failed(&self) {}
}

/// How one upstream TCP stream leaves the server.
#[derive(Clone)]
pub enum EgressRoute {
    /// From this server's own address.
    Direct,
    /// Through a proxy. `label` names it in logs.
    Proxy {
        label: String,
        dialer: Arc<dyn EgressDialer>,
    },
}

impl std::fmt::Debug for EgressRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EgressRoute::Direct => f.write_str("Direct"),
            EgressRoute::Proxy { label, .. } => {
                f.debug_struct("Proxy").field("label", label).finish()
            }
        }
    }
}

/// One client's view of the plugin.
#[async_trait]
pub trait EgressSession: Send + Sync + 'static {
    /// Who is on the other end, for per-client and per-token limits.
    /// `token_key` is any stable per-token identifier.
    fn bind_client(&self, client_ip: &str, token_key: Option<&str>);

    /// The client's process-wide rate budget.
    fn bind_ip_budget(&self, budget: EgressIpBudget);

    /// Answer one proxy-control text frame, or `None` to drop it.
    async fn control(&self, text: &str) -> Option<String>;

    /// How a TCP stream to `host:port` is dialed. An `Err` refuses the
    /// stream with that reason.
    async fn route(&self, host: &str, port: u16) -> Result<EgressRoute, String>;

    /// `true` when a TCP stream to `host` would leave through a proxy. UDP
    /// cannot be proxied, so such a destination gets no direct UDP flow that
    /// would show the server's own address.
    fn proxies(&self, host: &str) -> bool;
}

/// The process-wide side of an egress plugin.
#[async_trait]
pub trait EgressPlugin: Send + Sync + 'static {
    fn session(&self, init: EgressSessionInit) -> Arc<dyn EgressSession>;

    /// An operator call from the embedding runtime, by name. The plugin
    /// defines the names and their arguments.
    async fn admin(&self, op: &str, args: Value) -> Result<Value, String>;

    /// A short summary for the runtime's status.
    fn status(&self) -> Value {
        Value::Null
    }
}

#[derive(Debug, Error)]
pub enum ProxyConnectError {
    #[error("egress refused the stream: {0}")]
    Refused(String),
    #[error("proxy {label} failed: {source}")]
    Tunnel {
        label: String,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Connect(#[from] ConnectError),
}

/// The process-lifetime holder of the installed plugin. Cheap to clone.
pub struct ProxyControllerTemplate {
    plugin: Arc<dyn EgressPlugin>,
}

impl ProxyControllerTemplate {
    pub fn new(plugin: Arc<dyn EgressPlugin>) -> Self {
        Self { plugin }
    }

    pub fn plugin(&self) -> &Arc<dyn EgressPlugin> {
        &self.plugin
    }

    /// A fresh controller for one accepted client.
    pub fn spawn(
        &self,
        limits: ProxyControlLimits,
        allowed_proxy_providers: Option<Vec<String>>,
    ) -> Arc<ProxyController> {
        let session = self.plugin.session(EgressSessionInit {
            limits,
            allowed_proxies: allowed_proxy_providers,
            report: Arc::new(emit_egress_report),
        });
        Arc::new(ProxyController { session, limits })
    }
}

fn emit_egress_report(report: EgressReport) {
    let kind = match report.kind {
        EgressReportKind::Switch => wisp_reports::ReportErrorType::ProxyControlSwitch,
        EgressReportKind::HopLimitExceeded => wisp_reports::ReportErrorType::ProxyHopLimitExceeded,
    };
    wisp_reports::emit_report(
        kind,
        wisp_reports::ReportInput {
            context: Some(wisp_reports::ConnectionContext {
                client_ip: report.client_ip,
                ..Default::default()
            }),
            proxy_request_type: Some(report.request_type),
            provider: Some(report.proxy),
            limit_type: report.limit_type,
            amount: report.amount,
            ..Default::default()
        },
    );
}

/// Per-connection controller: the plugin's session for one client.
pub struct ProxyController {
    session: Arc<dyn EgressSession>,
    limits: ProxyControlLimits,
}

/// Addresses of one name tried through a proxy at most.
const MAX_PROXIED_DIAL_ADDRS: usize = 4;

impl ProxyController {
    pub fn session(&self) -> &Arc<dyn EgressSession> {
        &self.session
    }

    /// Tell the plugin who is on the other end so its limits can be kept per
    /// client IP and per token.
    pub fn bind_client(&self, client_ip: &str, token_key: Option<&str>) {
        self.session.bind_client(client_ip, token_key);
    }

    /// Charge the plugin's rate budgets to `client_ip` in the shared limiter
    /// as well, so opening more connections does not multiply them.
    pub fn bind_ip_budget(&self, client_ip: String, store: Arc<DosGuard>) {
        self.session
            .bind_ip_budget(Arc::new(move |class: &str, burst: u64, window_ms: u64| {
                is_ip_budget_allowed(&client_ip, class, burst, window_ms, &store)
            }));
    }

    /// Open an upstream TCP connection for `host:port` the way the plugin
    /// routes it. The host is checked and resolved through `policy` on every
    /// route, so each address is checked against [`HostPolicy`] (IP lists,
    /// private, loopback and this host's own addresses) whether or not a
    /// proxy carries the stream, and a proxy only ever receives a checked IP
    /// address. With a plugin installed the plugin alone decides the route;
    /// `force_proxy` only refuses streams where no plugin is installed. The
    /// second value names the proxy that carries the stream.
    pub async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
        _force_proxy: bool,
        policy: &HostPolicy,
    ) -> Result<(TcpStream, Option<String>), ProxyConnectError> {
        match self
            .session
            .route(host, port)
            .await
            .map_err(ProxyConnectError::Refused)?
        {
            EgressRoute::Direct => Ok((connect_checked_tcp(host, port, policy).await?, None)),
            EgressRoute::Proxy { label, dialer } => {
                let addrs = policy
                    .resolve(host, port)
                    .await
                    .map_err(|e| ProxyConnectError::Connect(ConnectError::Policy(e)))?;
                let mut last = None;
                for addr in addrs.into_iter().take(MAX_PROXIED_DIAL_ADDRS) {
                    match dialer.dial(addr).await {
                        Ok(stream) => return Ok((stream, Some(label))),
                        Err(e) => last = Some(e),
                    }
                }
                dialer.failed();
                Err(ProxyConnectError::Tunnel {
                    label,
                    source: last.unwrap_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::NotFound, "no address to dial")
                    }),
                })
            }
        }
    }

    /// `true` when a TCP stream to `host` would leave through a proxy.
    pub fn routes_through_proxy(&self, host: &str) -> bool {
        self.session.proxies(host)
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename = "proxy_control_error")]
struct ProxyControlErrorReply {
    ok: bool,
    error: String,
}

impl ProxyControlErrorReply {
    fn new(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: error.into(),
        }
    }
}

/// Serialize a normalized `proxy_control_error` text-frame reply
/// (`{type:"proxy_control_error", ok:false, error:"..."}`).
pub(crate) fn proxy_control_error_frame(error: &str) -> String {
    serde_json::to_string(&ProxyControlErrorReply::new(error))
        .unwrap_or_else(|_| String::from(r#"{"type":"proxy_control_error","ok":false,"error":""}"#))
}

/// Hand one text frame to the plugin and return its reply, or `None` when
/// the plugin drops the frame. A reply over the configured size is replaced
/// with an error reply.
pub async fn handle_proxy_control_text(
    controller: &Arc<ProxyController>,
    text: &str,
) -> Option<String> {
    let reply = controller.session.control(text).await?;
    if reply.len() > controller.limits.max_reply_bytes {
        warn!(
            len = reply.len(),
            "proxy_control: reply too large, replacing with error"
        );
        return Some(proxy_control_error_frame("reply too large"));
    }
    Some(reply)
}

/// A plugin for tests that routes everything direct and answers every
/// control frame with an empty provider list.
#[cfg(test)]
pub(crate) fn test_plugin() -> Arc<dyn EgressPlugin> {
    struct ListPlugin;
    struct ListSession;

    #[async_trait]
    impl EgressSession for ListSession {
        fn bind_client(&self, _client_ip: &str, _token_key: Option<&str>) {}
        fn bind_ip_budget(&self, _budget: EgressIpBudget) {}
        async fn control(&self, _text: &str) -> Option<String> {
            Some(r#"{"type":"proxy_list","providers":[]}"#.to_owned())
        }
        async fn route(&self, _host: &str, _port: u16) -> Result<EgressRoute, String> {
            Ok(EgressRoute::Direct)
        }
        fn proxies(&self, _host: &str) -> bool {
            false
        }
    }

    #[async_trait]
    impl EgressPlugin for ListPlugin {
        fn session(&self, _init: EgressSessionInit) -> Arc<dyn EgressSession> {
            Arc::new(ListSession)
        }
        async fn admin(&self, _op: &str, _args: Value) -> Result<Value, String> {
            Ok(Value::Null)
        }
    }

    Arc::new(ListPlugin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    /// Routes `proxied.example` through a dialer that connects straight to
    /// the checked address, and everything else direct.
    struct TestPlugin;

    struct TestSession {
        failures: Arc<Mutex<u32>>,
    }

    struct LoopDialer {
        failures: Arc<Mutex<u32>>,
        refuse: bool,
    }

    #[async_trait]
    impl EgressDialer for LoopDialer {
        async fn dial(&self, addr: SocketAddr) -> std::io::Result<TcpStream> {
            if self.refuse {
                return Err(std::io::Error::other("refused"));
            }
            TcpStream::connect(addr).await
        }
        fn failed(&self) {
            *self.failures.lock() += 1;
        }
    }

    #[async_trait]
    impl EgressSession for TestSession {
        fn bind_client(&self, _client_ip: &str, _token_key: Option<&str>) {}
        fn bind_ip_budget(&self, _budget: EgressIpBudget) {}
        async fn control(&self, text: &str) -> Option<String> {
            (text == "ping").then(|| "x".repeat(100))
        }
        async fn route(&self, host: &str, port: u16) -> Result<EgressRoute, String> {
            match host {
                "refused.example" => Err("not allowed".to_owned()),
                "127.0.0.1" | "dead.example" => Ok(EgressRoute::Proxy {
                    label: "test".to_owned(),
                    dialer: Arc::new(LoopDialer {
                        failures: self.failures.clone(),
                        refuse: port == 1,
                    }),
                }),
                _ => Ok(EgressRoute::Direct),
            }
        }
        fn proxies(&self, host: &str) -> bool {
            host == "127.0.0.1"
        }
    }

    #[async_trait]
    impl EgressPlugin for TestPlugin {
        fn session(&self, _init: EgressSessionInit) -> Arc<dyn EgressSession> {
            Arc::new(TestSession {
                failures: Arc::new(Mutex::new(0)),
            })
        }
        async fn admin(&self, _op: &str, _args: Value) -> Result<Value, String> {
            Ok(Value::Null)
        }
    }

    fn controller(limits: ProxyControlLimits) -> Arc<ProxyController> {
        ProxyControllerTemplate::new(Arc::new(TestPlugin)).spawn(limits, None)
    }

    fn open_policy(blacklist: Option<Vec<String>>) -> HostPolicy {
        HostPolicy::from_options(&wisp_config::WispServerOptions {
            allow_direct_ip: true,
            allow_private_ips: true,
            allow_loopback_ips: true,
            port_whitelist: None,
            ip_blacklist: blacklist,
            ..wisp_config::WispServerOptions::default()
        })
    }

    #[tokio::test]
    async fn proxied_streams_get_the_address_policy() {
        let controller = controller(ProxyControlLimits::default());
        assert!(controller.routes_through_proxy("127.0.0.1"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let err = controller
            .connect_tcp(
                "127.0.0.1",
                port,
                false,
                &open_policy(Some(vec!["127.0.0.0/8".to_owned()])),
            )
            .await
            .expect_err("ip_blacklist applies to proxied streams");
        assert!(matches!(
            err,
            ProxyConnectError::Connect(ConnectError::Policy(wisp_proxy::ProxyError::HostBlocked(
                _
            )))
        ));
        let (stream, label) = controller
            .connect_tcp("127.0.0.1", port, false, &open_policy(None))
            .await
            .expect("an allowed address goes through the proxy");
        assert_eq!(label.as_deref(), Some("test"));
        assert_eq!(stream.peer_addr().unwrap().port(), port);
    }

    #[tokio::test]
    async fn refusals_and_failed_dials_reach_the_caller() {
        let controller = controller(ProxyControlLimits::default());
        let err = controller
            .connect_tcp("refused.example", 80, false, &open_policy(None))
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyConnectError::Refused(ref why) if why == "not allowed"));
        let err = controller
            .connect_tcp("127.0.0.1", 1, false, &open_policy(None))
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyConnectError::Tunnel { .. }), "{err}");
    }

    #[tokio::test]
    async fn direct_route_still_rejects_loopback_by_policy() {
        let controller = controller(ProxyControlLimits::default());
        let policy = HostPolicy::from_options(&wisp_config::WispServerOptions {
            allow_direct_ip: true,
            port_whitelist: None,
            ..wisp_config::WispServerOptions::default()
        });
        let err = controller
            .connect_tcp("localhost", 80, false, &policy)
            .await
            .expect_err("loopback direct connect must be blocked by policy");
        assert!(matches!(err, ProxyConnectError::Connect(_)), "{err:?}");
    }

    #[tokio::test]
    async fn oversized_replies_become_an_error_frame() {
        let controller = controller(ProxyControlLimits {
            max_reply_bytes: 10,
            ..ProxyControlLimits::default()
        });
        assert!(handle_proxy_control_text(&controller, "other")
            .await
            .is_none());
        let reply = handle_proxy_control_text(&controller, "ping")
            .await
            .unwrap();
        let value: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(value["type"], "proxy_control_error");
        assert_eq!(value["error"], "reply too large");
    }

    #[test]
    fn proxy_control_error_reply_is_normalized() {
        let value: Value = serde_json::from_str(&proxy_control_error_frame("boom")).unwrap();
        assert_eq!(value["type"], "proxy_control_error");
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"], "boom");
    }
}
