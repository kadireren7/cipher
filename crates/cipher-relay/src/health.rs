//! Operator health probes, served on a SEPARATE loopback-only listener (never on the public one).
//!
//! `/healthz` = the process is up. `/readyz` = the database answers. Neither takes input, touches user data or reveals state beyond
//! "ok"/"not ready". `cipher-relay healthcheck` is the container HEALTHCHECK client (the runtime image has no curl).
use crate::api::AppState;
use axum::{extract::State, http::StatusCode, routing::get, Router};
use std::net::SocketAddr;
use std::sync::Arc;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new().route("/healthz", get(|| async { "ok" })).route("/readyz", get(ready)).with_state(state)
}

async fn ready(State(st): State<Arc<AppState>>) -> (StatusCode, &'static str) {
    if st.store.ping().await {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

/// Health listeners are for the local container runtime only: refuse anything that is not loopback.
pub fn parse_listen(v: &str) -> Option<SocketAddr> {
    v.parse::<SocketAddr>().ok().filter(|a| a.ip().is_loopback())
}

/// Minimal HTTP/1.0 GET over TCP; returns true on a `200`.
pub async fn probe(addr: SocketAddr, path: &str) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let run = async {
        let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
        s.write_all(format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        s.take(1024).read_to_end(&mut buf).await.ok()?;
        Some(buf.starts_with(b"HTTP/1.0 200") || buf.starts_with(b"HTTP/1.1 200"))
    };
    tokio::time::timeout(std::time::Duration::from_secs(3), run).await.ok().flatten().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn health_listener_must_be_loopback() {
        assert!(parse_listen("127.0.0.1:8081").is_some());
        assert!(parse_listen("[::1]:8081").is_some());
        assert!(parse_listen("0.0.0.0:8081").is_none());
        assert!(parse_listen("192.0.2.5:8081").is_none());
        assert!(parse_listen("nonsense").is_none());
    }
}
