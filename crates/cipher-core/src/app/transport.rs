//! The only network seam of the engine, shaped for a narrow FFI.
//!
//! The Android app implements `HttpTransport` with OkHttp: TLS 1.3 only, system trust anchors, the app's
//! network-security config, and (later) certificate pinning all live in the platform stack, not in Rust. Everything
//! that crosses it is already protocol ciphertext or a signed request; the transport never sees plaintext or keys.
use crate::error::{Result, SecurityError};
use crate::relay_client::{HttpRequest, HttpResponse, RelayEndpoint, RelayTransport};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct HttpOut {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum HttpError {
    #[error("network unavailable")]
    Network,
    #[error("tls failure")]
    Tls,
    #[error("timeout")]
    Timeout,
    #[error("io failure")]
    Io,
    #[error("privacy route unavailable")]
    RouteUnavailable,
}

pub trait HttpTransport: Send + Sync {
    fn execute(
        &self,
        base_url: &str,
        method: &str,
        path_and_query: &str,
        authorization: Option<&str>,
        body: &[u8],
    ) -> std::result::Result<HttpOut, HttpError>;
    fn upload_file(
        &self,
        base_url: &str,
        path_and_query: &str,
        authorization: Option<&str>,
        file_path: &str,
    ) -> std::result::Result<HttpOut, HttpError>;
    /// Writes the response body to `dest` and returns the status; must stop at `max_bytes`.
    fn download_file(
        &self,
        base_url: &str,
        path_and_query: &str,
        authorization: Option<&str>,
        dest: &str,
        max_bytes: u64,
    ) -> std::result::Result<u16, HttpError>;
    /// The platform stack MUST accept only a certificate whose SubjectPublicKeyInfo hashes to `spki_sha256` for `base_url` (instead of validating a CA
    /// chain), for every later request to that base. Required, not defaulted: a transport that cannot pin must return an error so the request is
    /// refused (fail closed) — onion relays use self-signed certificates and are authenticated only by this pin.
    fn pin_relay(&self, base_url: &str, spki_sha256: &[u8; 32]) -> std::result::Result<(), HttpError>;
}

pub struct TransportAdapter {
    pub inner: Arc<dyn HttpTransport>,
}

impl std::fmt::Debug for TransportAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransportAdapter")
    }
}

fn map(e: HttpError) -> SecurityError {
    SecurityError::Transport(match e {
        HttpError::Network => "network unavailable",
        HttpError::Tls => "tls failure",
        HttpError::Timeout => "timeout",
        HttpError::Io => "io failure",
        HttpError::RouteUnavailable => "privacy route unavailable",
    })
}

impl TransportAdapter {
    fn apply_pin(&self, endpoint: &RelayEndpoint) -> Result<()> {
        match endpoint.pin() {
            Some(pin) => self.inner.pin_relay(endpoint.base(), &pin).map_err(map),
            None => Ok(()),
        }
    }
}

impl RelayTransport for TransportAdapter {
    fn execute(&self, endpoint: &RelayEndpoint, req: HttpRequest) -> Result<HttpResponse> {
        self.apply_pin(endpoint)?;
        let o =
            self.inner.execute(endpoint.base(), req.method, &req.path_and_query, req.authorization.as_deref(), &req.body).map_err(map)?;
        Ok(HttpResponse { status: o.status, body: o.body })
    }

    fn upload_file(&self, endpoint: &RelayEndpoint, req: HttpRequest, path: &str) -> Result<HttpResponse> {
        self.apply_pin(endpoint)?;
        let o = self.inner.upload_file(endpoint.base(), &req.path_and_query, req.authorization.as_deref(), path).map_err(map)?;
        Ok(HttpResponse { status: o.status, body: o.body })
    }

    fn download_file(&self, endpoint: &RelayEndpoint, req: HttpRequest, dest: &str, max_bytes: u64) -> Result<u16> {
        self.apply_pin(endpoint)?;
        self.inner.download_file(endpoint.base(), &req.path_and_query, req.authorization.as_deref(), dest, max_bytes).map_err(map)
    }
}
