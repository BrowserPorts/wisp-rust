//! Shared TLS loading helpers. The PEM cert + key paths come from the
//! `[wisp_wt]` config block; the same paths are reused for the TCP side so
//! the H2 listener and the H3 listener present the same identity.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_pki_types::pem::{Error as PemError, PemObject};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("failed to read cert at {path}: {source}")]
    ReadCert {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read key at {path}: {source}")]
    ReadKey {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid PEM in {path}: {source}")]
    InvalidPem {
        path: String,
        #[source]
        source: PemError,
    },
    #[error("no certs found in {0}")]
    NoCerts(String),
    #[error("no usable private key found in {0}")]
    NoKey(String),
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Build an H2-only `ServerConfig` from PEM files. The ALPN list is fixed
/// to `["h2"]`; the WS-over-H2 path requires HTTP/2.
pub fn build_h2_server_config(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<ServerConfig>, TlsError> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let pem = std::fs::read(path).map_err(|e| TlsError::ReadCert {
        path: path.to_owned(),
        source: e,
    })?;
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TlsError::InvalidPem {
            path: path.to_owned(),
            source,
        })?;
    if certs.is_empty() {
        return Err(TlsError::NoCerts(path.to_owned()));
    }
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    let pem = std::fs::read(path).map_err(|e| TlsError::ReadKey {
        path: path.to_owned(),
        source: e,
    })?;
    match PrivateKeyDer::from_pem_slice(&pem) {
        Ok(key) => Ok(key.clone_key()),
        Err(PemError::NoItemsFound) => Err(TlsError::NoKey(path.to_owned())),
        Err(source) => Err(TlsError::InvalidPem {
            path: path.to_owned(),
            source,
        }),
    }
}
