//! Shared TLS loading helpers. The PEM cert + key paths come from the
//! `[wisp_wt]` config block; we keep the same paths for the TCP side so
//! the H2 listener and the H3/msquic listener present the same identity.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
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
    #[error("no certs found in {0}")]
    NoCerts(String),
    #[error("no usable private key found in {0}")]
    NoKey(String),
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Build an H2-only `ServerConfig` from PEM files. The ALPN list is fixed
/// to `["h2"]` — the WS-over-H2 path requires HTTP/2.
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
    let file = File::open(path).map_err(|e| TlsError::ReadCert {
        path: path.to_owned(),
        source: e,
    })?;
    let mut reader = BufReader::new(file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .filter_map(|r| r.ok())
        .collect();
    if certs.is_empty() {
        return Err(TlsError::NoCerts(path.to_owned()));
    }
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    let file = File::open(path).map_err(|e| TlsError::ReadKey {
        path: path.to_owned(),
        source: e,
    })?;
    let mut reader = BufReader::new(file);
    // Accept any of the three PEM key forms wispmark / openssl emit.
    let mut last_err = None;
    for key in rustls_pemfile::pkcs8_private_keys(&mut reader) {
        match key {
            Ok(k) => return Ok(PrivateKeyDer::Pkcs8(k)),
            Err(e) => last_err = Some(e),
        }
    }
    // Rewind by reopening; the iterator above consumed the reader.
    let file = File::open(path).map_err(|e| TlsError::ReadKey {
        path: path.to_owned(),
        source: e,
    })?;
    let mut reader = BufReader::new(file);
    for key in rustls_pemfile::rsa_private_keys(&mut reader) {
        match key {
            Ok(k) => return Ok(PrivateKeyDer::Pkcs1(k)),
            Err(e) => last_err = Some(e),
        }
    }
    let file = File::open(path).map_err(|e| TlsError::ReadKey {
        path: path.to_owned(),
        source: e,
    })?;
    let mut reader = BufReader::new(file);
    for key in rustls_pemfile::ec_private_keys(&mut reader) {
        match key {
            Ok(k) => return Ok(PrivateKeyDer::Sec1(k)),
            Err(e) => last_err = Some(e),
        }
    }
    if let Some(e) = last_err {
        Err(TlsError::ReadKey {
            path: path.to_owned(),
            source: e,
        })
    } else {
        Err(TlsError::NoKey(path.to_owned()))
    }
}
