//! msquic engine bootstrap: registration, configuration, listener.
//!
//! Transport tuning lives here:
//! - BBR (CongestionControlAlgorithm = 1).
//! - RFC 9221 datagrams enabled.
//! - 64 MiB connection flow-control window, 6 MiB per-stream recv window.
//! - Pacing + send buffering on.
//! - MTU discovery 1248..1500.
//! - LowLatency execution profile.

use msquic::{
    BufferRef, Configuration, Credential, CredentialConfig, CredentialFlags, ExecutionProfile,
    Listener, Registration, RegistrationConfig, ServerResumptionLevel, Settings, Status,
};
use std::sync::Arc;
use thiserror::Error;

/// `QUIC_CONGESTION_CONTROL_ALGORITHM_BBR`.
const BBR_ALGO: u16 = 1;
const ALPN_H3: &str = "h3";

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("msquic registration open: {0}")]
    Registration(#[source] Status),
    #[error("msquic configuration open: {0}")]
    Configuration(#[source] Status),
    #[error("msquic credentials: {0}")]
    Credentials(#[source] Status),
    #[error("msquic listener open: {0}")]
    Listener(#[source] Status),
}

/// Caller-controlled knobs for the engine.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub registration_name: String,
    pub alpns: Vec<String>,
    pub cert_path: String,
    pub key_path: String,
    /// Peer-initiated bidi streams allowed per connection.
    pub peer_bidi_stream_count: u16,
    /// Peer-initiated uni streams allowed per connection.
    pub peer_unidi_stream_count: u16,
    /// Per-stream recv window (bytes).
    pub stream_recv_window_default: u32,
    /// Per-connection flow-control window (bytes).
    pub conn_flow_control_window: u32,
    /// Idle timeout (ms) — peer drops if no traffic for this long.
    pub idle_timeout_ms: u64,
    /// Keep-alive interval (ms) — server sends PINGs at this interval.
    pub keep_alive_interval_ms: u32,
    /// Min MTU floor for path-MTU discovery.
    pub min_mtu: u16,
    /// Max MTU ceiling for path-MTU discovery.
    pub max_mtu: u16,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            registration_name: "wisp".to_owned(),
            alpns: vec![ALPN_H3.to_owned()],
            cert_path: String::new(),
            key_path: String::new(),
            peer_bidi_stream_count: 4096,
            peer_unidi_stream_count: 1024,
            stream_recv_window_default: 6 * 1024 * 1024,
            conn_flow_control_window: 64 * 1024 * 1024,
            idle_timeout_ms: 60_000,
            keep_alive_interval_ms: 15_000,
            min_mtu: 1248,
            max_mtu: 1500,
        }
    }
}

/// Owned msquic bootstrap. Hold one per process; drop to tear down.
pub struct MsQuicEngine {
    pub registration: Arc<Registration>,
    pub configuration: Arc<Configuration>,
    pub client_configuration: Arc<Configuration>,
}

impl MsQuicEngine {
    pub fn new(cfg: &EngineConfig) -> Result<Self, EngineError> {
        let reg_cfg = RegistrationConfig::new()
            .set_app_name(cfg.registration_name.clone())
            .set_execution_profile(ExecutionProfile::LowLatency);
        let registration = Registration::new(&reg_cfg).map_err(EngineError::Registration)?;

        let settings = transport_settings(cfg);

        let alpn_refs: Vec<BufferRef> = cfg
            .alpns
            .iter()
            .map(|s| BufferRef::from(s.as_str()))
            .collect();
        let configuration = Configuration::open(&registration, &alpn_refs, Some(&settings))
            .map_err(EngineError::Configuration)?;

        let cred = CredentialConfig::new()
            .set_credential_flags(CredentialFlags::NONE)
            .set_credential(Credential::CertificateFile(msquic::CertificateFile::new(
                cfg.key_path.clone(),
                cfg.cert_path.clone(),
            )));
        configuration
            .load_credential(&cred)
            .map_err(EngineError::Credentials)?;

        let client_configuration = Configuration::open(&registration, &alpn_refs, Some(&settings))
            .map_err(EngineError::Configuration)?;
        client_configuration
            .load_credential(&CredentialConfig::new_client())
            .map_err(EngineError::Credentials)?;

        Ok(Self {
            registration: Arc::new(registration),
            configuration: Arc::new(configuration),
            client_configuration: Arc::new(client_configuration),
        })
    }

    /// Open a server listener owned by this engine. Caller wires the
    /// new-connection callback that turns each accepted msquic connection
    /// into an [`crate::adapter::MsQuicConnection`].
    pub fn open_listener<F>(&self, handler: F) -> Result<Listener, EngineError>
    where
        F: Fn(msquic::ListenerRef, msquic::ListenerEvent) -> Result<(), Status>
            + Send
            + Sync
            + 'static,
    {
        Listener::open(&self.registration, handler).map_err(EngineError::Listener)
    }
}

fn transport_settings(cfg: &EngineConfig) -> Settings {
    Settings::new()
        .set_PeerBidiStreamCount(cfg.peer_bidi_stream_count)
        .set_PeerUnidiStreamCount(cfg.peer_unidi_stream_count)
        .set_StreamRecvWindowDefault(cfg.stream_recv_window_default)
        .set_ConnFlowControlWindow(cfg.conn_flow_control_window)
        .set_IdleTimeoutMs(cfg.idle_timeout_ms)
        .set_KeepAliveIntervalMs(cfg.keep_alive_interval_ms)
        .set_DatagramReceiveEnabled()
        .set_CongestionControlAlgorithm(BBR_ALGO)
        .set_SendBufferingEnabled()
        .set_PacingEnabled()
        .set_MaxAckDelayMs(5)
        .set_DisconnectTimeoutMs(30_000)
        .set_MinimumMtu(cfg.min_mtu)
        .set_MaximumMtu(cfg.max_mtu)
        .set_ServerResumptionLevel(ServerResumptionLevel::ResumeOnly)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_apply_transport_tuning() {
        let cfg = EngineConfig::default();
        let s = transport_settings(&cfg);
        let raw = s.as_ffi_ref();
        assert_eq!(raw.PeerBidiStreamCount, 4096);
        assert_eq!(raw.PeerUnidiStreamCount, 1024);
        assert_eq!(raw.StreamRecvWindowDefault, 6 * 1024 * 1024);
        assert_eq!(raw.ConnFlowControlWindow, 64 * 1024 * 1024);
        assert_eq!(raw.IdleTimeoutMs, 60_000);
        assert_eq!(raw.KeepAliveIntervalMs, 15_000);
        assert_eq!(raw.MaxAckDelayMs, 5);
        assert_eq!(raw.DisconnectTimeoutMs, 30_000);
        assert_eq!(raw.MinimumMtu, 1248);
        assert_eq!(raw.MaximumMtu, 1500);
        assert_eq!(raw.CongestionControlAlgorithm, BBR_ALGO);
        assert_eq!(raw.ServerResumptionLevel(), 1);
    }
}
