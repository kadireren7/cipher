//! TLS 1.3 only, ring crypto provider. TLS is transport protection; it is NOT the
//! E2EE boundary (message confidentiality does not depend on it).
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("invalid certificate or key material")]
    Material,
    #[error("tls configuration rejected")]
    Config,
}

pub fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<ServerConfig, TlsError> {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem).collect::<Result<_, _>>().map_err(|_| TlsError::Material)?;
    if certs.is_empty() {
        return Err(TlsError::Material);
    }
    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| TlsError::Material)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| TlsError::Config)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| TlsError::Material)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}
