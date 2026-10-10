//! Configuration from environment. Secrets are never logged and never given defaults.
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Config {
    /// Identity of this relay, bound into every request signature (anti cross-relay replay).
    pub audience: String,
    /// SHA-256 of the registration token (account-level credential, separate from device keys).
    pub registration_token_hash: [u8; 32],
    /// PostgreSQL connection string (never logged). TLS required unless the host is loopback.
    pub database_url: String,
    pub db_ca_pem: Option<PathBuf>,
    pub db_pool_size: usize,
    /// Secret pepper hashed into rate-limit keys so IPs/device ids are not recoverable from a DB dump.
    pub pepper: [u8; 32],
    /// Global cap on concurrently processed requests; excess is rejected with 503 (load shedding).
    pub max_inflight: usize,
    /// Cap on simultaneously open client connections.
    pub max_connections: usize,
    pub request_timeout_secs: u64,
    pub listen: SocketAddr,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Plain-HTTP is only possible with an explicit flag AND a loopback listen address.
    pub insecure_dev_http: bool,
    pub max_total_blob_bytes: u64,
    /// TLS handshake deadline. 10 s suits direct clients; a Tor rendezvous handshake routinely needs longer (measured: > 10 s), so the onion profile raises it.
    pub tls_handshake_secs: u64,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config").field("audience", &self.audience).field("listen", &self.listen).finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing or invalid configuration: {0}")]
    Invalid(&'static str),
}

/// `KEY` from the environment, or the contents of the file named by `KEY_FILE` (container secrets: keeps secrets out of `docker inspect`
/// and process environments). Setting both is an error-by-ambiguity: the file wins only when the plain variable is absent.
fn env_or_file(k: &str) -> Option<String> {
    if let Some(v) = std::env::var(k).ok().filter(|v| !v.is_empty()) {
        return Some(v);
    }
    let path = std::env::var(format!("{k}_FILE")).ok().filter(|v| !v.is_empty())?;
    let raw = std::fs::read_to_string(path).ok()?;
    let v = raw.trim_end_matches(['\n', '\r']).to_owned();
    (!v.is_empty()).then_some(v)
}

impl Config {
    pub fn hash_token(token: &str) -> [u8; 32] {
        Sha256::digest(token.as_bytes()).into()
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        let get = |k: &'static str| env_or_file(k);
        let audience = get("CIPHER_RELAY_AUDIENCE").ok_or(ConfigError::Invalid("CIPHER_RELAY_AUDIENCE"))?;
        let token = get("CIPHER_RELAY_REGISTRATION_TOKEN").ok_or(ConfigError::Invalid("CIPHER_RELAY_REGISTRATION_TOKEN"))?;
        if token.len() < 32 {
            return Err(ConfigError::Invalid("CIPHER_RELAY_REGISTRATION_TOKEN must be >= 32 chars"));
        }
        let database_url = get("CIPHER_RELAY_DATABASE_URL").ok_or(ConfigError::Invalid("CIPHER_RELAY_DATABASE_URL"))?;
        let pepper_raw = get("CIPHER_RELAY_PEPPER").ok_or(ConfigError::Invalid("CIPHER_RELAY_PEPPER"))?;
        if pepper_raw.len() < 32 {
            return Err(ConfigError::Invalid("CIPHER_RELAY_PEPPER must be >= 32 chars"));
        }
        let num = |k: &'static str, d: usize| get(k).and_then(|v| v.parse().ok()).unwrap_or(d);
        let listen: SocketAddr = get("CIPHER_RELAY_LISTEN")
            .unwrap_or_else(|| "127.0.0.1:8443".to_owned())
            .parse()
            .map_err(|_| ConfigError::Invalid("CIPHER_RELAY_LISTEN"))?;
        let insecure = get("CIPHER_RELAY_INSECURE_DEV_HTTP").as_deref() == Some("1");
        let tls_cert = get("CIPHER_RELAY_TLS_CERT").map(PathBuf::from);
        let tls_key = get("CIPHER_RELAY_TLS_KEY").map(PathBuf::from);
        let cfg = Config {
            audience,
            registration_token_hash: Self::hash_token(&token),
            database_url,
            db_ca_pem: get("CIPHER_RELAY_DB_CA").map(PathBuf::from),
            db_pool_size: num("CIPHER_RELAY_DB_POOL", 16),
            pepper: Self::hash_token(&pepper_raw),
            max_inflight: num("CIPHER_RELAY_MAX_INFLIGHT", 512),
            max_connections: num("CIPHER_RELAY_MAX_CONNECTIONS", 2048),
            request_timeout_secs: num("CIPHER_RELAY_REQUEST_TIMEOUT_SECS", 30) as u64,
            listen,
            tls_cert,
            tls_key,
            insecure_dev_http: insecure,
            max_total_blob_bytes: get("CIPHER_RELAY_MAX_BLOB_BYTES")
                .and_then(|v| v.parse().ok())
                .unwrap_or(cipher_wire::limits::DEFAULT_MAX_TOTAL_BLOB_BYTES),
            tls_handshake_secs: (num("CIPHER_RELAY_TLS_HANDSHAKE_SECS", 10) as u64).clamp(1, 120),
        };
        cfg.check_transport()?;
        Ok(cfg)
    }

    /// Fail closed: TLS is mandatory unless dev-HTTP is explicitly enabled on loopback.
    pub fn check_transport(&self) -> Result<(), ConfigError> {
        let has_tls = self.tls_cert.is_some() && self.tls_key.is_some();
        if has_tls {
            return Ok(());
        }
        if self.tls_cert.is_some() != self.tls_key.is_some() {
            return Err(ConfigError::Invalid("both TLS cert and key are required"));
        }
        if self.insecure_dev_http && self.listen.ip().is_loopback() {
            return Ok(());
        }
        Err(ConfigError::Invalid(
            "TLS is required (set CIPHER_RELAY_TLS_CERT/KEY); plain HTTP only on loopback with CIPHER_RELAY_INSECURE_DEV_HTTP=1",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Config {
        Config {
            audience: "a".into(),
            registration_token_hash: [0; 32],
            database_url: String::new(),
            db_ca_pem: None,
            db_pool_size: 1,
            pepper: [0; 32],
            max_inflight: 1,
            max_connections: 1,
            request_timeout_secs: 1,
            listen: "0.0.0.0:443".parse().unwrap_or_else(|_| unreachable_addr()),
            tls_cert: None,
            tls_key: None,
            insecure_dev_http: false,
            max_total_blob_bytes: 1,
            tls_handshake_secs: 10,
        }
    }
    fn unreachable_addr() -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0], 443))
    }

    #[test]
    fn tls_is_mandatory_unless_loopback_dev() {
        let mut c = base();
        assert!(c.check_transport().is_err());
        c.insecure_dev_http = true;
        assert!(c.check_transport().is_err(), "dev http must not be allowed on a public address");
        c.listen = SocketAddr::from(([127, 0, 0, 1], 8443));
        assert!(c.check_transport().is_ok());
        c.insecure_dev_http = false;
        assert!(c.check_transport().is_err());
        c.tls_cert = Some("c".into());
        assert!(c.check_transport().is_err(), "cert without key");
        c.tls_key = Some("k".into());
        assert!(c.check_transport().is_ok());
    }
}
