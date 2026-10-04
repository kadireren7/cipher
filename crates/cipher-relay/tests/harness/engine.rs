#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Engine-level test rig: full application engines (vault, MLS, outbox, attachments) talking to the REAL relay router and
//! PostgreSQL through an in-process `HttpTransport` that records every byte.
use super::*;
use axum::body::Body;
use axum::http::Request;
use cipher_core::app::transport::{HttpError, HttpOut, HttpTransport};
use cipher_core::app::{Engine, EngineConfig};
use cipher_core::kdf::{KdfFloor, KdfParams};
use cipher_core::keystore::testing::InMemoryKeyStore;
use cipher_core::keystore::ProtectionLevel;
use cipher_core::vault::VaultConfig;
use std::sync::atomic::{AtomicBool, Ordering};
use tower::ServiceExt;

pub type ResponseRewrite = Box<dyn Fn(&str, &str, Vec<u8>) -> Vec<u8> + Send + Sync>;
pub type Hook = Box<dyn FnMut(&str, &str) + Send>;

/// What a link observer (or the relay) could record about one request, without seeing inside TLS.
#[derive(Clone, Debug)]
pub struct NetEvent {
    pub t_secs: u64,
    pub method: String,
    pub path: String,
    pub req_bytes: usize,
    pub resp_bytes: usize,
    pub authed: bool,
    /// The relay answered with a queued delivery (a REAL delivery, as opposed to cover or an error).
    pub queued: bool,
}

pub struct AppTransport {
    clock: Arc<SharedClock>,
    pub log: Mutex<Vec<NetEvent>>,
    /// Privacy route down: every request fails with `RouteUnavailable` (nothing is sent anywhere).
    pub route_down: AtomicBool,
    rt: Arc<tokio::runtime::Runtime>,
    app: Router,
    captured: Arc<Mutex<Vec<Captured>>>,
    pub offline: AtomicBool,
    pub rewrite: Mutex<Option<ResponseRewrite>>,
    pub hook: Mutex<Option<Hook>>,
    pub requests: Mutex<Vec<(String, String)>>,
    /// Fault injection: the NEXT request whose path ends with this string is EXECUTED by the relay, but its response is lost (client sees a network error).
    pub lose_response_on: Mutex<Option<String>>,
    /// Paths of requests that carried NO Authorization header.
    pub unauth: Mutex<Vec<String>>,
}

impl AppTransport {
    pub fn new(w: &World) -> Arc<Self> {
        Arc::new(Self {
            clock: w.clock.clone(),
            log: Mutex::new(Vec::new()),
            route_down: AtomicBool::new(false),
            rt: w.rt.clone(),
            app: w.app.clone(),
            captured: w.captured.clone(),
            offline: AtomicBool::new(false),
            rewrite: Mutex::new(None),
            hook: Mutex::new(None),
            requests: Mutex::new(Vec::new()),
            lose_response_on: Mutex::new(None),
            unauth: Mutex::new(Vec::new()),
        })
    }

    fn call(&self, method: &str, path: &str, auth: Option<&str>, body: Vec<u8>) -> Result<(u16, Vec<u8>), HttpError> {
        if self.offline.load(Ordering::SeqCst) {
            return Err(HttpError::Network);
        }
        if self.route_down.load(Ordering::SeqCst) {
            return Err(HttpError::RouteUnavailable);
        }
        self.requests.lock().unwrap().push((method.to_owned(), path.to_owned()));
        if auth.is_none() {
            self.unauth.lock().unwrap().push(path.to_owned());
        }
        // The hook may run another engine's request (race injection); take it out while it runs to avoid re-entrancy.
        let hook = self.hook.lock().unwrap().take();
        if let Some(mut h) = hook {
            h(method, path);
            let mut g = self.hook.lock().unwrap();
            if g.is_none() {
                *g = Some(h);
            }
        }
        // A real HTTP client always sends Content-Length for a fixed-size body; the relay requires it for blob uploads.
        let mut b = Request::builder().method(method).uri(path).header("content-length", body.len().to_string());
        if let Some(a) = auth {
            b = b.header("authorization", a);
        }
        let req = b.body(Body::from(body.clone())).unwrap();
        let resp = self.rt.block_on(self.app.clone().oneshot(req)).map_err(|_| HttpError::Io)?;
        let status = resp.status().as_u16();
        use http_body_util::BodyExt;
        let mut bytes = self.rt.block_on(resp.into_body().collect()).map_err(|_| HttpError::Io)?.to_bytes().to_vec();
        self.log.lock().unwrap().push(NetEvent {
            t_secs: self.clock.0.unix_secs(),
            method: method.to_owned(),
            path: path.to_owned(),
            req_bytes: body.len() + auth.map_or(0, str::len),
            resp_bytes: bytes.len(),
            authed: auth.is_some(),
            queued: bytes.windows(8).any(|w| w == b"\"queued\""),
        });
        self.captured.lock().unwrap().push(Captured { path: path.to_owned(), request_body: body, response_body: bytes.clone(), status });
        {
            let mut lose = self.lose_response_on.lock().unwrap();
            if lose.as_ref().is_some_and(|sfx| path.ends_with(sfx.as_str())) {
                *lose = None;
                return Err(HttpError::Network);
            }
        }
        if let Some(rw) = self.rewrite.lock().unwrap().as_ref() {
            bytes = rw(method, path, bytes);
        }
        Ok((status, bytes))
    }
}

impl HttpTransport for AppTransport {
    fn execute(&self, _base: &str, method: &str, path: &str, auth: Option<&str>, body: &[u8]) -> Result<HttpOut, HttpError> {
        let (status, body) = self.call(method, path, auth, body.to_vec())?;
        Ok(HttpOut { status, body })
    }
    fn upload_file(&self, _base: &str, path: &str, auth: Option<&str>, file: &str) -> Result<HttpOut, HttpError> {
        let data = std::fs::read(file).map_err(|_| HttpError::Io)?;
        let (status, body) = self.call("POST", path, auth, data)?;
        Ok(HttpOut { status, body })
    }
    fn download_file(&self, _base: &str, path: &str, auth: Option<&str>, dest: &str, max: u64) -> Result<u16, HttpError> {
        let (status, body) = self.call("GET", path, auth, Vec::new())?;
        if status == 200 {
            if body.len() as u64 > max {
                return Err(HttpError::Io);
            }
            std::fs::write(dest, body).map_err(|_| HttpError::Io)?;
        }
        Ok(status)
    }
}

pub struct TestEngine {
    pub e: Engine,
    pub ks: Arc<InMemoryKeyStore>,
    pub transport: Arc<AppTransport>,
    pub dir: tempfile::TempDir,
}

impl std::ops::Deref for TestEngine {
    type Target = Engine;
    fn deref(&self) -> &Engine {
        &self.e
    }
}
impl std::ops::DerefMut for TestEngine {
    fn deref_mut(&mut self) -> &mut Engine {
        &mut self.e
    }
}

pub fn vault_cfg() -> VaultConfig {
    VaultConfig {
        min_protection: ProtectionLevel::HardwareBacked,
        kdf: KdfParams::INSECURE_FAST_FOR_TESTS,
        kdf_floor: KdfFloor::DisabledForTests,
        inactivity_timeout_secs: 60,
        ..VaultConfig::default()
    }
}

impl World {
    /// A provisioned, unlocked engine with a registered identity.
    pub fn engine(&self) -> TestEngine {
        let mut t = self.engine_unprovisioned();
        t.e.provision_vault().unwrap();
        t.e.create_identity(TOKEN).unwrap();
        t
    }

    pub fn engine_with_timeout(&self, inactivity_secs: u64) -> TestEngine {
        let mut t = self.engine_unprovisioned_with(inactivity_secs);
        t.e.provision_vault().unwrap();
        t.e.create_identity(TOKEN).unwrap();
        t
    }

    pub fn engine_unprovisioned(&self) -> TestEngine {
        self.engine_unprovisioned_with(30 * 86_400)
    }

    pub fn engine_unprovisioned_with(&self, inactivity_secs: u64) -> TestEngine {
        let dir = tempfile::tempdir().unwrap();
        let ks = Arc::new(InMemoryKeyStore::new(ProtectionLevel::HardwareBacked));
        let transport = AppTransport::new(self);
        let e = Engine::new_for_tests(
            EngineConfig {
                data_dir: dir.path().to_path_buf(),
                relay_url: "https://relay.test".into(),
                vault: VaultConfig { inactivity_timeout_secs: inactivity_secs, ..vault_cfg() },
            },
            ks.clone(),
            transport.clone(),
            self.clock.clone(),
            AUDIENCE,
        )
        .unwrap();
        TestEngine { e, ks, transport, dir }
    }
}

pub fn png(n: usize) -> Vec<u8> {
    let mut v = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    v.extend((0..n).map(|i| (i % 251) as u8));
    v
}

pub fn write_tmp(dir: &std::path::Path, name: &str, data: &[u8]) -> String {
    let p = dir.join(name);
    std::fs::write(&p, data).unwrap();
    p.to_str().unwrap().to_owned()
}
