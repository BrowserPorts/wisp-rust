//! msquic engine bootstrap: registration, configuration, listener.
//!
//! Transport tuning lives here:
//! - BBR (CongestionControlAlgorithm = 1).
//! - RFC 9221 datagrams enabled.
//! - msquic's default flow-control windows: 16 MiB per connection, 64 KiB
//!   initial per stream (msquic auto-tunes a stream's window upward).
//! - Pacing + send buffering on.
//! - MTU discovery 1248..1500.
//! - LowLatency execution profile.
//! - Stateless Retry for every new client address, no session resumption
//!   (and so no 0-RTT), and no server keep-alive.

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
    /// Peer-initiated uni streams allowed per connection. HTTP/3 needs three
    /// (control, QPACK encoder, QPACK decoder); wisp-wt clients open none of
    /// their own, so a small count bounds what an unread stream can buffer.
    pub peer_unidi_stream_count: u16,
    /// Per-stream recv window (bytes). msquic rejects any value that is not a
    /// power of two, which fails `Configuration::open` outright.
    pub stream_recv_window_default: u32,
    /// Per-connection flow-control window (bytes).
    pub conn_flow_control_window: u32,
    /// Idle timeout (ms) — peer drops if no traffic for this long. 0 disables
    /// it (msquic's meaning of 0).
    pub idle_timeout_ms: u64,
    /// Keep-alive interval (ms) — server sends PINGs at this interval. 0, the
    /// default and msquic's, sends none: server PINGs are ack-eliciting, so they would keep
    /// an abandoned connection from ever reaching the idle timeout.
    pub keep_alive_interval_ms: u32,
    /// Min MTU floor for path-MTU discovery.
    pub min_mtu: u16,
    /// Max MTU ceiling for path-MTU discovery.
    pub max_mtu: u16,
    /// Process-wide `QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT` applied when the
    /// engine starts: the share of system memory (out of 65535) that handshakes
    /// may use before msquic answers new Initials with a stateless Retry. 0
    /// sends Retry to every unvalidated address, so a spoofed source address
    /// never creates connection state or draws a reflected flight. `None` keeps
    /// msquic's default (about 0.1% of memory).
    pub retry_memory_limit: Option<u16>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            registration_name: "wisp".to_owned(),
            alpns: vec![ALPN_H3.to_owned()],
            cert_path: String::new(),
            key_path: String::new(),
            peer_bidi_stream_count: 4096,
            peer_unidi_stream_count: 16,
            // msquic's own defaults. Every byte a peer may send before a policy
            // check runs is a byte the server buffers, so the initial windows
            // stay small: msquic grows a stream's window as the reader keeps up,
            // and must be a power of two (settings.c, "Must be power of 2").
            stream_recv_window_default: 64 * 1024,
            conn_flow_control_window: 16 * 1024 * 1024,
            idle_timeout_ms: 60_000,
            keep_alive_interval_ms: 0,
            min_mtu: 1248,
            max_mtu: 1500,
            retry_memory_limit: Some(0),
        }
    }
}

/// Owned msquic bootstrap. Hold one per process; drop to tear down.
///
/// Field order is load-bearing: msquic's `RegistrationClose` blocks until every
/// configuration, listener and connection opened under it is closed, so the
/// registration has to be dropped after the configurations. Declared the other
/// way round, dropping the engine hangs forever.
pub struct MsQuicEngine {
    pub configuration: Arc<Configuration>,
    pub client_configuration: Arc<Configuration>,
    pub registration: Arc<Registration>,
}

impl MsQuicEngine {
    pub fn new(cfg: &EngineConfig) -> Result<Self, EngineError> {
        let reg_cfg = RegistrationConfig::new()
            .set_app_name(cfg.registration_name.clone())
            .set_execution_profile(ExecutionProfile::LowLatency);
        let registration = Registration::new(&reg_cfg).map_err(EngineError::Registration)?;
        // The registration has loaded the library, so global params can be set.
        if let Some(limit) = cfg.retry_memory_limit {
            set_retry_memory_limit(limit).map_err(EngineError::Registration)?;
        }

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
            configuration: Arc::new(configuration),
            client_configuration: Arc::new(client_configuration),
            registration: Arc::new(registration),
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

/// Sets `QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT`; see
/// [`EngineConfig::retry_memory_limit`].
#[allow(unsafe_code)]
fn set_retry_memory_limit(limit: u16) -> Result<(), Status> {
    // SAFETY: a global param takes a null handle, and the buffer is a live
    // `u16`, the exact type and length msquic requires for this param.
    unsafe {
        msquic::Api::set_param(
            std::ptr::null_mut(),
            msquic::PARAM_GLOBAL_RETRY_MEMORY_PERCENT,
            std::mem::size_of::<u16>() as u32,
            std::ptr::from_ref(&limit).cast(),
        )
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
        // ResumeOnly does not turn early data off in this msquic version (the
        // TLS layer still advertises max_early_data), and 0-RTT requests can
        // be replayed, so resumption is off altogether.
        .set_ServerResumptionLevel(ServerResumptionLevel::NoResume)
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
        assert_eq!(raw.PeerUnidiStreamCount, 16);
        assert_eq!(raw.StreamRecvWindowDefault, 64 * 1024);
        assert_eq!(raw.ConnFlowControlWindow, 16 * 1024 * 1024);
        assert_eq!(raw.IdleTimeoutMs, 60_000);
        assert_eq!(raw.KeepAliveIntervalMs, 0);
        assert_eq!(raw.MaxAckDelayMs, 5);
        assert_eq!(raw.DisconnectTimeoutMs, 30_000);
        assert_eq!(raw.MinimumMtu, 1248);
        assert_eq!(raw.MaximumMtu, 1500);
        assert_eq!(raw.CongestionControlAlgorithm, BBR_ALGO);
        // QUIC_SERVER_NO_RESUME.
        assert_eq!(raw.ServerResumptionLevel(), 0);
        assert_eq!(cfg.retry_memory_limit, Some(0));
    }

    #[test]
    fn engine_start_turns_retry_on_for_every_address() {
        // Opening the registration loads the library, which the param needs.
        let _registration =
            Registration::new(&RegistrationConfig::new().set_app_name("wisp-test".to_owned()))
                .expect("registration opens");
        set_retry_memory_limit(0).expect("msquic accepts a zero retry limit");
        assert_eq!(msquic::Api::get_retry_memory_percent().unwrap(), 0);
    }

    #[test]
    fn default_settings_are_accepted_by_msquic() {
        // msquic validates settings when the configuration opens, so this fails
        // with QUIC_STATUS_INVALID_PARAMETER if a window is not a power of two.
        let cfg = EngineConfig::default();
        assert!(cfg.stream_recv_window_default.is_power_of_two());
        let registration =
            Registration::new(&RegistrationConfig::new().set_app_name("wisp-test".to_owned()))
                .expect("registration opens");
        let settings = transport_settings(&cfg);
        let alpn = [BufferRef::from(ALPN_H3)];
        Configuration::open(&registration, &alpn, Some(&settings))
            .expect("msquic accepts the default transport settings");
    }
}
