//! Outbound WebTransport sessions used by the wisp-wt proxy extension.
//!
//! Name resolution goes through the same destination policy as TCP and UDP.
//! The selected address is passed directly to Quinn while the original host
//! remains the TLS server name, preventing a second, unchecked DNS lookup.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use dashmap::DashMap;
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use url::Url;
use web_transport_quinn::quinn::{self, crypto::rustls::QuicClientConfig};
use web_transport_quinn::{Session, ALPN};
use wisp_config::WispServerOptions;
use wisp_proxy::DestinationResolver;

#[derive(Debug, Error)]
pub enum WtProxyError {
    #[error("invalid upstream URL: {0}")]
    InvalidUrl(String),
    #[error("destination policy: {0}")]
    Destination(String),
    #[error("TLS configuration: {0}")]
    Tls(String),
    #[error("no trusted platform certificates are available")]
    NoTrustRoots,
    #[error("upstream session limit reached")]
    SessionLimit,
    #[error("upstream connection timed out")]
    Timeout,
    #[error("upstream connection failed: {0}")]
    Connect(String),
    #[error("session id space exhausted")]
    SessionIdsExhausted,
}

/// Validated URL fields retained separately so logs never need the full path,
/// which can contain a Wisp path token.
#[derive(Debug, Clone)]
pub struct ValidatedWtUrl {
    pub url: Url,
    pub host: String,
    pub port: u16,
}

pub fn validate_upstream_url(
    raw: &str,
    max_host_bytes: u64,
) -> Result<ValidatedWtUrl, WtProxyError> {
    let url = Url::parse(raw).map_err(|e| WtProxyError::InvalidUrl(e.to_string()))?;
    if url.scheme() != "https" {
        return Err(WtProxyError::InvalidUrl(
            "WebTransport upstreams require https".to_owned(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(WtProxyError::InvalidUrl(
            "URL user information is not allowed".to_owned(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(WtProxyError::InvalidUrl(
            "URL query strings and fragments are not allowed".to_owned(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| WtProxyError::InvalidUrl("URL host is required".to_owned()))?
        .to_owned();
    if host.len() as u64 > max_host_bytes {
        return Err(WtProxyError::InvalidUrl(
            "URL host exceeds the configured host limit".to_owned(),
        ));
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| WtProxyError::InvalidUrl("URL port is required".to_owned()))?;
    Ok(ValidatedWtUrl { url, host, port })
}

pub struct WtProxyConnector {
    destination: DestinationResolver,
    client_config: quinn::ClientConfig,
    connect_timeout: Duration,
    max_host_bytes: u64,
}

impl WtProxyConnector {
    pub fn from_options(options: &WispServerOptions) -> Result<Self, WtProxyError> {
        let destination = DestinationResolver::from_options(options)
            .map_err(|e| WtProxyError::Destination(e.to_string()))?;
        let client_config = client_config()?;
        Ok(Self {
            destination,
            client_config,
            connect_timeout: Duration::from_millis(
                options.connect_timeout_ms.unwrap_or(10_000).max(1),
            ),
            max_host_bytes: options.max_host_bytes,
        })
    }

    pub async fn connect(&self, raw_url: &str) -> Result<ConnectedWtProxy, WtProxyError> {
        let target = validate_upstream_url(raw_url, self.max_host_bytes)?;
        let addresses = self
            .destination
            .resolve(&target.host, target.port)
            .await
            .map_err(|e| WtProxyError::Destination(e.to_string()))?;

        let mut last_error = None;
        for remote in addresses {
            match tokio::time::timeout(
                self.connect_timeout,
                connect_one(remote, &target, self.client_config.clone()),
            )
            .await
            {
                Ok(Ok(connected)) => return Ok(connected),
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => last_error = Some(WtProxyError::Timeout),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            WtProxyError::Connect("resolver returned no permitted addresses".to_owned())
        }))
    }
}

fn client_config() -> Result<quinn::ClientConfig, WtProxyError> {
    static CLIENT_CONFIG: OnceLock<quinn::ClientConfig> = OnceLock::new();
    if let Some(config) = CLIENT_CONFIG.get() {
        return Ok(config.clone());
    }
    let native = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    for certificate in native.certs {
        if let Err(error) = roots.add(certificate) {
            tracing::warn!(%error, "skipping invalid platform trust certificate");
        }
    }
    if roots.is_empty() {
        return Err(WtProxyError::NoTrustRoots);
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| WtProxyError::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.as_bytes().to_vec()];
    tls.enable_early_data = false;

    let crypto = QuicClientConfig::try_from(tls).map_err(|e| WtProxyError::Tls(e.to_string()))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    config.transport_config(Arc::new(transport));
    let _ = CLIENT_CONFIG.set(config.clone());
    Ok(CLIENT_CONFIG.get().cloned().unwrap_or(config))
}

async fn connect_one(
    remote: SocketAddr,
    target: &ValidatedWtUrl,
    config: quinn::ClientConfig,
) -> Result<ConnectedWtProxy, WtProxyError> {
    let bind = match remote.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let endpoint = quinn::Endpoint::client(bind)
        .map_err(|e| WtProxyError::Connect(format!("local UDP endpoint: {e}")))?;
    let connection = endpoint
        .connect_with(config, remote, &target.host)
        .map_err(|e| WtProxyError::Connect(e.to_string()))?
        .await
        .map_err(|e| WtProxyError::Connect(e.to_string()))?;
    let session = Session::connect(connection, target.url.clone())
        .await
        .map_err(|e| WtProxyError::Connect(e.to_string()))?;
    Ok(ConnectedWtProxy { endpoint, session })
}

pub struct ConnectedWtProxy {
    endpoint: quinn::Endpoint,
    pub session: Session,
}

pub struct WtProxySession {
    pub id: u32,
    endpoint: quinn::Endpoint,
    pub session: Session,
    pub stream_slots: Arc<Semaphore>,
    pub cancel: CancellationToken,
    _session_slot: OwnedSemaphorePermit,
}

impl WtProxySession {
    fn new(
        id: u32,
        connected: ConnectedWtProxy,
        max_streams: u32,
        session_slot: OwnedSemaphorePermit,
        parent_cancel: &CancellationToken,
    ) -> Self {
        Self {
            id,
            endpoint: connected.endpoint,
            session: connected.session,
            stream_slots: Arc::new(Semaphore::new(max_streams as usize)),
            cancel: parent_cancel.child_token(),
            _session_slot: session_slot,
        }
    }

    pub fn close(&self, code: u32, reason: &[u8]) {
        self.cancel.cancel();
        self.session.close(code, reason);
    }
}

impl Drop for WtProxySession {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.session.close(0, b"downstream session ended");
        self.endpoint
            .close(0u32.into(), b"downstream session ended");
    }
}

pub struct WtProxyRegistry {
    connector: Arc<WtProxyConnector>,
    sessions: DashMap<u32, Arc<WtProxySession>>,
    session_slots: Arc<Semaphore>,
    max_streams: u32,
    next_id: AtomicU32,
    cancel: CancellationToken,
}

impl WtProxyRegistry {
    pub fn new(
        options: &WispServerOptions,
        max_sessions: u32,
        max_streams: u32,
        cancel: CancellationToken,
    ) -> Result<Self, WtProxyError> {
        Ok(Self {
            connector: Arc::new(WtProxyConnector::from_options(options)?),
            sessions: DashMap::new(),
            session_slots: Arc::new(Semaphore::new(max_sessions as usize)),
            max_streams,
            next_id: AtomicU32::new(1),
            cancel,
        })
    }

    pub async fn open(&self, url: &str) -> Result<Arc<WtProxySession>, WtProxyError> {
        let session_slot = self
            .session_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| WtProxyError::SessionLimit)?;
        let connected = tokio::select! {
            _ = self.cancel.cancelled() => {
                return Err(WtProxyError::Connect("downstream session closed".to_owned()));
            }
            result = self.connector.connect(url) => result?,
        };
        let id = self.allocate_id()?;
        let session = Arc::new(WtProxySession::new(
            id,
            connected,
            self.max_streams,
            session_slot,
            &self.cancel,
        ));
        self.sessions.insert(id, session.clone());
        Ok(session)
    }

    pub fn get(&self, id: u32) -> Option<Arc<WtProxySession>> {
        self.sessions.get(&id).map(|entry| entry.clone())
    }

    pub fn remove(&self, id: u32, code: u32, reason: &[u8]) -> bool {
        let Some((_, session)) = self.sessions.remove(&id) else {
            return false;
        };
        session.close(code, reason);
        true
    }

    pub fn shutdown_all(&self) {
        self.cancel.cancel();
        let ids: Vec<u32> = self.sessions.iter().map(|entry| *entry.key()).collect();
        for id in ids {
            self.remove(id, 0, b"downstream session ended");
        }
    }

    fn allocate_id(&self) -> Result<u32, WtProxyError> {
        for _ in 0..u32::MAX {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed).max(1);
            if !self.sessions.contains_key(&id) {
                return Ok(id);
            }
        }
        Err(WtProxyError::SessionIdsExhausted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_secure_upstream_url() {
        let parsed = validate_upstream_url("https://proxy.example/wisp-wt/token", 255).unwrap();
        assert_eq!(parsed.host, "proxy.example");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.url.path(), "/wisp-wt/token");
    }

    #[test]
    fn rejects_unsafe_url_parts() {
        for raw in [
            "http://proxy.example/wisp-wt",
            "https://user:pass@proxy.example/wisp-wt",
            "https://proxy.example/wisp-wt?token=secret",
            "https://proxy.example/wisp-wt#fragment",
        ] {
            assert!(validate_upstream_url(raw, 255).is_err(), "accepted {raw}");
        }
    }

    #[test]
    fn rejects_oversized_host() {
        assert!(validate_upstream_url("https://proxy.example/wisp-wt", 4).is_err());
    }
}
