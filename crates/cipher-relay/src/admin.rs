//! Relay administration (docs/RELAY_ADMIN.md): a SEPARATE, loopback-only listener, authenticated by its own long secret.
//!
//! * No account, device or invitation can reach it or becomes an administrator: the first client to register has no special power. The administrator
//!   secret is provisioned out of band (file or environment) and must differ from the registration token.
//! * It reports health, storage and queue pressure, and COARSE user-related counts (rounded; "<10" below ten). It never exposes message content, keys,
//!   account or device identifiers, contact graphs, group membership or any per-user figure, and it has no endpoint that could.
//! * Every administrative CHANGE is written to an append-only, hash-chained audit log. Failed authentication is counted, never itemised.
use crate::api::AppState;
use crate::config::{env_or_file, Config, ConfigError};
use crate::error::ApiError;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

pub const MIN_ADMIN_TOKEN_LEN: usize = 32;
const AUDIT_PAGE: i64 = 100;

/// The administrator's configuration. Present only when BOTH the secret and a loopback listen address are set; setting one without the other refuses to start.
#[derive(Clone)]
pub struct AdminConfig {
    pub token_hash: [u8; 32],
    pub listen: SocketAddr,
    pub backup_marker: Option<PathBuf>,
}

impl std::fmt::Debug for AdminConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminConfig").field("listen", &self.listen).finish_non_exhaustive()
    }
}

impl AdminConfig {
    /// `registration_hash` is the registration token's hash: the two secrets must never be the same value.
    pub fn from_env(registration_hash: &[u8; 32]) -> Result<Option<Self>, ConfigError> {
        let token = env_or_file("CIPHER_RELAY_ADMIN_TOKEN");
        let listen = env_or_file("CIPHER_RELAY_ADMIN_LISTEN");
        let (token, listen) = match (token, listen) {
            (None, None) => return Ok(None),
            (Some(t), Some(l)) => (t, l),
            _ => return Err(ConfigError::Invalid("CIPHER_RELAY_ADMIN_TOKEN and CIPHER_RELAY_ADMIN_LISTEN must be set together")),
        };
        Self::build(&token, &listen, registration_hash, env_or_file("CIPHER_RELAY_BACKUP_MARKER").map(PathBuf::from)).map(Some)
    }

    pub fn build(token: &str, listen: &str, registration_hash: &[u8; 32], backup_marker: Option<PathBuf>) -> Result<Self, ConfigError> {
        if token.len() < MIN_ADMIN_TOKEN_LEN {
            return Err(ConfigError::Invalid("CIPHER_RELAY_ADMIN_TOKEN must be >= 32 chars"));
        }
        let token_hash = Config::hash_token(token);
        if bool::from(token_hash.ct_eq(registration_hash)) {
            return Err(ConfigError::Invalid("the administrator secret must differ from the registration token"));
        }
        let listen =
            crate::health::parse_listen(listen).ok_or(ConfigError::Invalid("CIPHER_RELAY_ADMIN_LISTEN must be a loopback address"))?;
        Ok(Self { token_hash, listen, backup_marker })
    }
}

struct AdminState {
    app: Arc<AppState>,
    token_hash: [u8; 32],
    backup_marker: Option<PathBuf>,
    started: Instant,
    auth_failures: AtomicU64,
}

pub fn router(app: Arc<AppState>, cfg: &AdminConfig) -> Router {
    let st = Arc::new(AdminState {
        app,
        token_hash: cfg.token_hash,
        backup_marker: cfg.backup_marker.clone(),
        started: Instant::now(),
        auth_failures: AtomicU64::new(0),
    });
    Router::new()
        .route("/admin/v1/stats", get(stats))
        .route("/admin/v1/audit", get(audit))
        .route("/admin/v1/registration", post(set_registration))
        .layer(middleware::from_fn_with_state(st.clone(), authenticate))
        .with_state(st)
}

/// The secret in `Authorization: Bearer ...`, compared in constant time. Every failure looks the same and costs the caller a fixed delay.
async fn authenticate(State(st): State<Arc<AdminState>>, req: Request<Body>, next: Next) -> Response {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| Config::hash_token(t.trim()));
    let ok = presented.is_some_and(|h| bool::from(h.ct_eq(&st.token_hash)));
    if !ok {
        st.auth_failures.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(250)).await;
        return with_headers((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "unauthorized"}))).into_response());
    }
    with_headers(next.run(req).await)
}

fn with_headers(mut r: Response) -> Response {
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r.headers_mut().insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    r
}

/// "0", "<10", or the count rounded DOWN to tens ("~120"): enough to see growth, not enough to count people.
pub fn coarse(n: i64) -> String {
    match n {
        i64::MIN..=0 => "0".to_owned(),
        1..=9 => "<10".to_owned(),
        _ => format!("~{}", n / 10 * 10),
    }
}

#[derive(Serialize)]
struct StatsOut {
    version: &'static str,
    uptime_secs: u64,
    schema_version: i64,
    database_ready: bool,
    registration_open: bool,
    /// Wrong-secret attempts on THIS listener since start (a count, never a list).
    admin_auth_failures: u64,
    // coarse, user-related
    accounts: String,
    devices: String,
    groups: String,
    live_invitations: String,
    pending_join_requests: String,
    queued_messages: String,
    blobs: String,
    // storage and queue pressure (exact: operational, not about people)
    queued_bytes: u64,
    blob_bytes: u64,
    /// Seconds since the backup marker file was last written, if one is configured.
    backup_age_secs: Option<u64>,
}

async fn stats(State(st): State<Arc<AdminState>>) -> Result<Json<StatsOut>, ApiError> {
    let now = crate::api::Clock::now(&*st.app.clock);
    let c = st.app.store.admin_counts(now).await?;
    let open = st.app.store.setting("registration_open").await?.as_deref() != Some("0");
    let backup_age_secs = st
        .backup_marker
        .as_ref()
        .and_then(|p| std::fs::metadata(p).ok())
        .and_then(|m| m.modified().ok())
        .and_then(|t| std::time::SystemTime::now().duration_since(t).ok())
        .map(|d| d.as_secs());
    Ok(Json(StatsOut {
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: st.started.elapsed().as_secs(),
        schema_version: c.schema_version,
        database_ready: st.app.store.ping().await,
        registration_open: open,
        admin_auth_failures: st.auth_failures.load(Ordering::Relaxed),
        accounts: coarse(c.accounts),
        devices: coarse(c.devices),
        groups: coarse(c.groups),
        live_invitations: coarse(c.live_invites),
        pending_join_requests: coarse(c.pending_join_requests),
        queued_messages: coarse(c.queued_messages),
        blobs: coarse(c.blobs),
        queued_bytes: c.queued_bytes.max(0) as u64,
        blob_bytes: c.blob_bytes.max(0) as u64,
        backup_age_secs,
    }))
}

/// `?after=N` (the last sequence number already seen), parsed by hand: the relay's HTTP stack deliberately has no query-string extractor.
fn after_param(uri: &Uri) -> i64 {
    uri.query().and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("after="))).and_then(|v| v.parse::<i64>().ok()).unwrap_or(0).max(0)
}

#[derive(Serialize)]
struct AuditOut {
    chain_ok: bool,
    entries: Vec<AuditEntry>,
}

#[derive(Serialize)]
struct AuditEntry {
    seq: i64,
    at: i64,
    action: String,
    detail: String,
}

async fn audit(State(st): State<Arc<AdminState>>, uri: Uri) -> Result<Json<AuditOut>, ApiError> {
    let chain_ok = st.app.store.audit_chain_ok().await?;
    let entries = st
        .app
        .store
        .audit_list(after_param(&uri), AUDIT_PAGE)
        .await?
        .into_iter()
        .map(|(seq, at, action, detail)| AuditEntry { seq, at, action, detail })
        .collect();
    Ok(Json(AuditOut { chain_ok, entries }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationBody {
    open: bool,
}

/// Opens or closes NEW account registration. Existing accounts are untouched. The change is audited.
async fn set_registration(State(st): State<Arc<AdminState>>, Json(b): Json<RegistrationBody>) -> Result<StatusCode, ApiError> {
    let now = crate::api::Clock::now(&*st.app.clock);
    st.app.store.set_setting("registration_open", if b.open { "1" } else { "0" }).await?;
    st.app.store.audit_append(now, "registration", if b.open { "opened" } else { "closed" }).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn say(text: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stdout(), "{text}");
}

fn say_err(text: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "{text}");
}

/// `cipher-relay admin stats | audit | registration open | registration closed`: the operator's command line (the runtime image has no curl).
/// Reads the same environment as the server; talks only to the loopback listener; prints the JSON answer.
pub async fn cli(args: &[String]) -> i32 {
    let (Some(token), Some(listen)) = (env_or_file("CIPHER_RELAY_ADMIN_TOKEN"), env_or_file("CIPHER_RELAY_ADMIN_LISTEN")) else {
        say_err("administration is not configured (CIPHER_RELAY_ADMIN_TOKEN / CIPHER_RELAY_ADMIN_LISTEN)");
        return 2;
    };
    let Some(addr) = crate::health::parse_listen(&listen) else {
        say_err("CIPHER_RELAY_ADMIN_LISTEN must be a loopback address");
        return 2;
    };
    let (method, path, body) = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["stats"] => ("GET", "/admin/v1/stats", String::new()),
        ["audit"] => ("GET", "/admin/v1/audit", String::new()),
        ["registration", "open"] => ("POST", "/admin/v1/registration", r#"{"open":true}"#.to_owned()),
        ["registration", "closed"] => ("POST", "/admin/v1/registration", r#"{"open":false}"#.to_owned()),
        _ => {
            say_err("usage: cipher-relay admin stats | audit | registration open | registration closed");
            return 2;
        }
    };
    match http(addr, method, path, &token, &body).await {
        Some((status, text)) => {
            say(&text);
            i32::from(!(200..300).contains(&status))
        }
        None => {
            say_err("the administration listener did not answer");
            1
        }
    }
}

async fn http(addr: SocketAddr, method: &str, path: &str, token: &str, body: &str) -> Option<(u16, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let run = async {
        let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
        let req = format!(
            "{method} {path} HTTP/1.0\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        s.take(1 << 20).read_to_end(&mut buf).await.ok()?;
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text.split_whitespace().nth(1)?.parse().ok()?;
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_owned()).unwrap_or_default();
        Some((status, body))
    };
    tokio::time::timeout(Duration::from_secs(5), run).await.ok().flatten()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_audit_cursor_is_parsed_strictly() {
        let p = |u: &str| after_param(&u.parse::<Uri>().unwrap());
        assert_eq!(p("/admin/v1/audit"), 0);
        assert_eq!(p("/admin/v1/audit?after=7"), 7);
        assert_eq!(p("/admin/v1/audit?x=1&after=12"), 12);
        assert_eq!(p("/admin/v1/audit?after=-5"), 0);
        assert_eq!(p("/admin/v1/audit?after=abc"), 0);
    }

    #[test]
    fn counts_are_coarse() {
        assert_eq!(coarse(0), "0");
        assert_eq!(coarse(-3), "0");
        assert_eq!(coarse(1), "<10");
        assert_eq!(coarse(9), "<10");
        assert_eq!(coarse(10), "~10");
        assert_eq!(coarse(19), "~10");
        assert_eq!(coarse(123), "~120");
    }

    #[test]
    fn the_administrator_secret_is_strict() {
        let reg = Config::hash_token(&"r".repeat(40));
        let long = "a".repeat(40);
        assert!(AdminConfig::build(&long, "127.0.0.1:9444", &reg, None).is_ok());
        assert!(AdminConfig::build("short", "127.0.0.1:9444", &reg, None).is_err(), "too short");
        assert!(AdminConfig::build(&"r".repeat(40), "127.0.0.1:9444", &reg, None).is_err(), "must differ from the registration token");
        assert!(AdminConfig::build(&long, "0.0.0.0:9444", &reg, None).is_err(), "loopback only");
        assert!(AdminConfig::build(&long, "192.0.2.5:9444", &reg, None).is_err(), "loopback only");
        assert!(AdminConfig::build(&long, "nonsense", &reg, None).is_err());
    }

    #[test]
    fn the_debug_output_never_shows_the_secret() {
        let c = AdminConfig::build(&"s".repeat(40), "127.0.0.1:9444", &[0; 32], None).unwrap();
        let shown = format!("{c:?}");
        assert!(!shown.contains("token_hash") && !shown.contains(&"s".repeat(10)));
    }
}
