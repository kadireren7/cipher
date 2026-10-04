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

impl RelayTransport for TransportAdapter {
    fn execute(&self, endpoint: &RelayEndpoint, req: HttpRequest) -> Result<HttpResponse> {
        let o =
            self.inner.execute(endpoint.base(), req.method, &req.path_and_query, req.authorization.as_deref(), &req.body).map_err(map)?;
        Ok(HttpResponse { status: o.status, body: o.body })
    }

    fn upload_file(&self, endpoint: &RelayEndpoint, req: HttpRequest, path: &str) -> Result<HttpResponse> {
        let o = self.inner.upload_file(endpoint.base(), &req.path_and_query, req.authorization.as_deref(), path).map_err(map)?;
        Ok(HttpResponse { status: o.status, body: o.body })
    }

    fn download_file(&self, endpoint: &RelayEndpoint, req: HttpRequest, dest: &str, max_bytes: u64) -> Result<u16> {
        self.inner.download_file(endpoint.base(), &req.path_and_query, req.authorization.as_deref(), dest, max_bytes).map_err(map)
    }
}
