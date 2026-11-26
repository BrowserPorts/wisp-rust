//! The egress plugin of a build with the `proxy-providers` feature: the
//! private router, which owns every provider and the allowlist of
//! destinations that may use one, behind wisp-rust's [`EgressPlugin`].
//! Nothing here decides a route; it only carries calls across.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::net::TcpStream;
use wisp_proxy_providers::base::{
    open_proxy_tcp_socket_addr, ActiveProxy, ControlLimits, ProxyRouter, ProxySession, Route,
    RouterReportKind, SessionInit,
};
use wisp_wisp_server::{
    EgressDialer, EgressIpBudget, EgressPlugin, EgressReport, EgressReportKind, EgressRoute,
    EgressSession, EgressSessionInit,
};

pub(crate) fn plugin_from_config(config: &Value) -> Result<Arc<dyn EgressPlugin>, String> {
    let router = wisp_proxy_providers::router_from_config(config)?;
    Ok(Arc::new(Router(router)))
}

struct Router(ProxyRouter);

struct Session(Arc<ProxySession>);

struct Dialer {
    session: Arc<ProxySession>,
    proxy: ActiveProxy,
}

#[async_trait]
impl EgressPlugin for Router {
    fn session(&self, init: EgressSessionInit) -> Arc<dyn EgressSession> {
        let limits = init.limits;
        let report = init.report;
        let session = self.0.session(SessionInit {
            limits: ControlLimits {
                max_rules: limits.max_rules,
                max_reply_bytes: limits.max_reply_bytes,
                max_field_bytes: limits.max_field_bytes,
                upstream_ops_per_second: limits.upstream_ops_per_second,
                upstream_burst: limits.upstream_burst,
                mutation_ops_per_second: limits.mutation_ops_per_second,
                mutation_burst: limits.mutation_burst,
            },
            allowed_providers: init.allowed_proxies,
            report: Arc::new(move |event| {
                report(EgressReport {
                    kind: match event.kind {
                        RouterReportKind::Switch => EgressReportKind::Switch,
                        RouterReportKind::HopLimitExceeded => EgressReportKind::HopLimitExceeded,
                    },
                    client_ip: event.client_ip,
                    request_type: event.request_type,
                    proxy: event.provider,
                    limit_type: event.limit_type,
                    amount: event.amount,
                })
            }),
        });
        Arc::new(Session(session))
    }

    async fn admin(&self, op: &str, args: Value) -> Result<Value, String> {
        self.0.admin(op, args).await
    }

    fn status(&self) -> Value {
        json!({
            "providers": self.0.providers().iter().map(|p| p.id().to_owned()).collect::<Vec<_>>(),
            "allowlist": self.0.allowlist(),
        })
    }
}

#[async_trait]
impl EgressSession for Session {
    fn bind_client(&self, client_ip: &str, token_key: Option<&str>) {
        self.0.bind_client(client_ip, token_key);
    }

    fn bind_ip_budget(&self, budget: EgressIpBudget) {
        self.0.bind_ip_budget(budget);
    }

    async fn control(&self, text: &str) -> Option<String> {
        self.0.control(text).await
    }

    async fn route(&self, host: &str, _port: u16) -> Result<EgressRoute, String> {
        match self.0.route(host).await.map_err(|e| e.to_string())? {
            Route::Direct => Ok(EgressRoute::Direct),
            Route::Proxy(proxy) => Ok(EgressRoute::Proxy {
                label: proxy.provider_id().to_owned(),
                dialer: Arc::new(Dialer {
                    session: self.0.clone(),
                    proxy,
                }),
            }),
        }
    }

    fn proxies(&self, host: &str) -> bool {
        self.0.proxies(host)
    }
}

#[async_trait]
impl EgressDialer for Dialer {
    async fn dial(&self, addr: SocketAddr) -> std::io::Result<TcpStream> {
        open_proxy_tcp_socket_addr(&self.proxy, addr)
            .await
            .map_err(std::io::Error::other)
    }

    fn failed(&self) {
        self.session.forget(&self.proxy);
    }
}
