#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! In-process test world: real relay router + real SQLite file + real client core.
//! The `RelayTransport` implementation records every byte that crosses the "network".
pub mod engine;
use axum::body::Body;
use axum::http::Request;
use axum::Router;
use cipher_core::clock::testing::ManualClock;
use cipher_core::clock::Clock as CoreClock;
use cipher_core::error::{Result as CoreResult, SecurityError};
use cipher_core::mls::MlsClient;
use cipher_core::relay_client::*;
use cipher_relay::api::{AppState, Clock as RelayClock, Limits};
use cipher_relay::config::Config;
use cipher_relay::push::RecordingPush;
use cipher_relay::store::PgStore;
use cipher_wire::Id16;
use http_body_util::BodyExt;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use tracing_subscriber::fmt::MakeWriter;

pub const TOKEN: &str = "test-registration-token-0123456789abcdef";
pub const AUDIENCE: &str = "relay.test";

pub struct SharedClock(pub ManualClock);
impl CoreClock for SharedClock {
    fn unix_secs(&self) -> u64 {
        self.0.unix_secs()
    }
    fn monotonic_secs(&self) -> u64 {
        self.0.monotonic_secs()
    }
}
impl RelayClock for SharedClock {
    fn now(&self) -> u64 {
        self.0.unix_secs()
    }
}

#[derive(Clone, Default)]
pub struct LogBuf(pub Arc<Mutex<Vec<u8>>>);
impl std::io::Write for LogBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> LogBuf {
        self.clone()
    }
}

#[derive(Clone, Debug)]
pub struct Captured {
    pub path: String,
    pub request_body: Vec<u8>,
    pub response_body: Vec<u8>,
    pub status: u16,
}

pub struct World {
    pub rt: Arc<tokio::runtime::Runtime>,
    pub app: Router,
    pub state: Arc<AppState>,
    pub clock: Arc<SharedClock>,
    pub push: Arc<RecordingPush>,
    pub endpoint: RelayEndpoint,
    pub pool: deadpool_postgres::Pool,
    pub db_name: String,
    pub captured: Arc<Mutex<Vec<Captured>>>,
    pub logs: LogBuf,
    _guard: tracing::subscriber::DefaultGuard,
}

pub fn generous_limits() -> Limits {
    Limits {
        device_burst: 1_000_000,
        device_refill_per_sec: 1e6,
        register_burst: 1_000_000,
        register_refill_per_sec: 1e6,
        blob_bytes_burst: u32::MAX,
        blob_bytes_refill_per_sec: 1e9,
        ..Limits::default()
    }
}

impl World {
    pub fn new() -> Self {
        Self::with_limits(generous_limits())
    }

    pub fn with_limits(limits: Limits) -> Self {
        Self::build(limits, 512, 30)
    }

    pub fn build(limits: Limits, max_inflight: usize, request_timeout_secs: u64) -> Self {
        let logs = LogBuf::default();
        let sub = tracing_subscriber::fmt().with_writer(logs.clone()).with_ansi(false).with_max_level(tracing::Level::TRACE).finish();
        let guard = tracing::subscriber::set_default(sub);
        let rt = Arc::new(tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap());
        let admin_url = std::env::var("CIPHER_TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:devonly-not-a-secret@127.0.0.1:55432/postgres".to_owned());
        let db_name = format!("cipher_t_{}", rid().to_hex());
        rt.block_on(async {
            let (c, conn) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls)
                .await
                .expect("test PostgreSQL must be running (see docs/SECURITY_TESTING.md)");
            tokio::spawn(conn);
            c.batch_execute(&format!("CREATE DATABASE {db_name}")).await.unwrap();
        });
        let test_url = admin_url.rsplit_once('/').map(|(base, _)| format!("{base}/{db_name}")).unwrap();
        let pool = cipher_relay::db::build_pool(&test_url, 8, None).unwrap();
        rt.block_on(cipher_relay::migrations::run(&pool)).unwrap();
        let store = Arc::new(PgStore::new(pool.clone()));
        let cfg = Arc::new(Config {
            audience: AUDIENCE.into(),
            registration_token_hash: Config::hash_token(TOKEN),
            database_url: test_url,
            db_ca_pem: None,
            db_pool_size: 8,
            pepper: Config::hash_token("test-pepper-0123456789abcdef0123456789"),
            max_inflight,
            max_connections: 64,
            request_timeout_secs,
            listen: "127.0.0.1:0".parse().unwrap(),
            tls_cert: None,
            tls_key: None,
            insecure_dev_http: true,
            max_total_blob_bytes: 1024 * 1024 * 1024,
            tls_handshake_secs: 10,
        });
        let clock = Arc::new(SharedClock(ManualClock::new(1_800_000_000)));
        let push = Arc::new(RecordingPush::default());
        let state = Arc::new(AppState::new(store, cfg, clock.clone(), push.clone(), limits));
        let app = cipher_relay::build_app(state.clone());
        Self {
            rt,
            app,
            state,
            clock,
            push,
            endpoint: RelayEndpoint::for_tests(AUDIENCE),
            pool,
            db_name,
            captured: Arc::default(),
            logs,
            _guard: guard,
        }
    }

    /// A second relay "instance": separate process state, same PostgreSQL database.
    pub fn instance(&self, limits: Limits) -> Router {
        let store = Arc::new(PgStore::new(self.pool.clone()));
        let st = Arc::new(AppState::new(store, self.state.cfg.clone(), self.clock.clone(), self.push.clone(), limits));
        cipher_relay::build_app(st)
    }

    pub fn raw_on(&self, app: &Router, method: &str, path: &str, auth: Option<String>, body: Vec<u8>) -> u16 {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(a) = auth {
            b = b.header("authorization", a);
        }
        let req = b.body(Body::from(body)).unwrap();
        self.rt.block_on(app.clone().oneshot(req)).unwrap().status().as_u16()
    }

    pub fn api<'a>(&'a self, c: &'a MlsClient) -> RelayApi<'a> {
        RelayApi { transport: self, endpoint: &self.endpoint, client: c, clock: &*self.clock }
    }

    pub fn register(&self, c: &MlsClient) {
        self.api(c).register_account(TOKEN).unwrap();
    }

    /// Raw HTTP, bypassing the typed client (for crafting hostile requests).
    pub fn raw(&self, method: &str, path: &str, auth: Option<String>, body: Vec<u8>) -> (u16, Vec<u8>) {
        let mut b = Request::builder().method(method).uri(path).header("content-length", body.len().to_string());
        if let Some(a) = auth {
            b = b.header("authorization", a);
        }
        let req = b.body(Body::from(body.clone())).unwrap();
        let resp = self.rt.block_on(self.app.clone().oneshot(req)).unwrap();
        let status = resp.status().as_u16();
        let bytes = self.rt.block_on(resp.into_body().collect()).unwrap().to_bytes().to_vec();
        self.captured.lock().unwrap().push(Captured { path: path.to_owned(), request_body: body, response_body: bytes.clone(), status });
        (status, bytes)
    }

    /// Same as `raw` (which already sets Content-Length); kept as a separate name for the pre-authentication tests.
    pub fn raw_with_len(&self, method: &str, path: &str, auth: Option<String>, body: Vec<u8>) -> (u16, Vec<u8>) {
        self.raw(method, path, auth, body)
    }

    pub fn all_wire_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        for c in self.captured.lock().unwrap().iter() {
            v.extend_from_slice(c.path.as_bytes());
            v.extend_from_slice(&c.request_body);
            v.extend_from_slice(&c.response_body);
        }
        v
    }

    /// Run a read query returning all `bytea` values of the first column.
    pub fn query_bytes(&self, sql: &str) -> Vec<Vec<u8>> {
        self.rt.block_on(async {
            let c = self.pool.get().await.unwrap();
            c.query(sql, &[]).await.unwrap().iter().map(|r| r.get::<_, Vec<u8>>(0)).collect()
        })
    }

    pub fn exec(&self, sql: &str, params: &[&(dyn tokio_postgres::types::ToSql + Sync)]) -> u64 {
        self.rt.block_on(async {
            let c = self.pool.get().await.unwrap();
            c.execute(sql, params).await.unwrap()
        })
    }

    /// Everything stored in the database, as text (bytea columns hex-encoded) plus raw bytea values.
    /// Search with `contains_stored(needle)`.
    pub fn db_dump(&self) -> (String, Vec<u8>) {
        self.rt.block_on(async {
            let c = self.pool.get().await.unwrap();
            let tables = c.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public'", &[]).await.unwrap();
            let mut text = String::new();
            let mut raw = Vec::new();
            for t in tables {
                let name: String = t.get(0);
                let cols =
                    c.query("SELECT column_name, data_type FROM information_schema.columns WHERE table_name=$1", &[&name]).await.unwrap();
                for col in cols {
                    let (cn, ty): (String, String) = (col.get(0), col.get(1));
                    if ty == "bytea" {
                        for r in c.query(&format!("SELECT \"{cn}\" FROM \"{name}\""), &[]).await.unwrap() {
                            if let Some(b) = r.get::<_, Option<Vec<u8>>>(0) {
                                raw.extend_from_slice(&b);
                            }
                        }
                    }
                    for r in c.query(&format!("SELECT \"{cn}\"::text FROM \"{name}\""), &[]).await.unwrap() {
                        if let Some(v) = r.get::<_, Option<String>>(0) {
                            text.push_str(&v);
                            text.push('\n');
                        }
                    }
                }
            }
            (text, raw)
        })
    }

    pub fn db_bytes(&self) -> Vec<u8> {
        let (text, mut raw) = self.db_dump();
        raw.extend_from_slice(text.as_bytes());
        raw
    }

    pub fn log_text(&self) -> Vec<u8> {
        self.logs.0.lock().unwrap().clone()
    }
}

impl RelayTransport for World {
    fn execute(&self, _endpoint: &RelayEndpoint, req: HttpRequest) -> CoreResult<HttpResponse> {
        let (status, body) = self.raw(req.method, &req.path_and_query, req.authorization, req.body);
        Ok(HttpResponse { status, body })
    }
}

/// A network attacker / malicious relay that rewrites responses.
pub type Rewrite<'a> = Box<dyn Fn(&HttpRequest, HttpResponse) -> HttpResponse + 'a>;

pub struct Mitm<'a> {
    pub inner: &'a World,
    pub rewrite: Rewrite<'a>,
}
impl RelayTransport for Mitm<'_> {
    fn execute(&self, e: &RelayEndpoint, req: HttpRequest) -> CoreResult<HttpResponse> {
        let probe = HttpRequest { method: req.method, path_and_query: req.path_and_query.clone(), authorization: None, body: Vec::new() };
        let resp = self.inner.execute(e, req)?;
        Ok((self.rewrite)(&probe, resp))
    }
}

pub fn rid() -> Id16 {
    Id16(cipher_core::rng::array::<16>().unwrap())
}

pub fn new_client() -> MlsClient {
    MlsClient::generate(rid(), rid()).unwrap()
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

pub fn no_such_error<T>(r: CoreResult<T>) -> bool {
    matches!(r, Err(SecurityError::Transport(_)))
}

/// Build a correctly signed raw request header for `client`.
pub fn sign(client: &MlsClient, audience: &str, method: &str, path: &str, ts: u64, nonce: [u8; 16], body: &[u8]) -> String {
    use cipher_wire::signing::*;
    let dev = client.device_id();
    let canon =
        canonical_string(&CanonicalParts { audience, method, path_and_query: path, timestamp: ts, nonce: &nonce, body, device: &dev });
    format_auth_header(&AuthHeader { device: dev, timestamp: ts, nonce, signature: client.sign_transport(&canon), body_hash: None })
}

/// Like `sign`, but announces the body hash in the header (`bh=`), as large uploads must (FR-10: the relay authenticates BEFORE reading the body).
pub fn sign_announced(client: &MlsClient, audience: &str, method: &str, path: &str, ts: u64, nonce: [u8; 16], body: &[u8]) -> String {
    use cipher_wire::signing::*;
    use sha2::Digest as _;
    let dev = client.device_id();
    let hash: [u8; 32] = sha2::Sha256::digest(body).into();
    let canon = canonical_string_with_hash(
        &CanonicalParts { audience, method, path_and_query: path, timestamp: ts, nonce: &nonce, body: &[], device: &dev },
        &hash,
    );
    format_auth_header(&AuthHeader { device: dev, timestamp: ts, nonce, signature: client.sign_transport(&canon), body_hash: Some(hash) })
}

impl Drop for World {
    fn drop(&mut self) {
        let name = self.db_name.clone();
        let admin_url = std::env::var("CIPHER_TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:devonly-not-a-secret@127.0.0.1:55432/postgres".to_owned());
        self.pool.close();
        self.rt.block_on(async {
            if let Ok((c, conn)) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls).await {
                tokio::spawn(conn);
                let _ = c.batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)")).await;
            }
        });
    }
}
