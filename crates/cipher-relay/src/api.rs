//! HTTP API. Handlers see only opaque ciphertext and public keys.
use crate::auth::{authenticate, verify_ed25519};
use crate::config::Config;
use crate::error::ApiError;
use crate::push::PushNotifier;
use crate::ratelimit::KeyHasher;
use crate::store::{Enqueue, GroupOutcome, PgStore};
use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{ConnectInfo, MatchedPath, Path, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use cipher_wire::limits::*;
use cipher_wire::messages::*;
use cipher_wire::Id16;
use sha2::Digest as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

#[derive(Debug, Default)]
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub device_burst: u32,
    pub device_refill_per_sec: f64,
    pub register_burst: u32,
    pub register_refill_per_sec: f64,
    pub auth_fail_burst: u32,
    pub auth_fail_refill_per_sec: f64,
    pub blob_bytes_burst: u32,
    pub blob_bytes_refill_per_sec: f64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            device_burst: 120,
            device_refill_per_sec: 20.0,
            register_burst: 5,
            register_refill_per_sec: 0.05,
            auth_fail_burst: 20,
            auth_fail_refill_per_sec: 0.2,
            blob_bytes_burst: u32::MAX,
            blob_bytes_refill_per_sec: 4.0 * 1024.0 * 1024.0,
        }
    }
}

/// At most this many blob uploads are buffered at once (8 x 101 MiB worst case ~ 808 MiB).
const MAX_CONCURRENT_UPLOADS: usize = 8;

pub struct AppState {
    pub store: Arc<PgStore>,
    pub cfg: Arc<Config>,
    pub clock: Arc<dyn Clock>,
    pub push: Arc<dyn PushNotifier>,
    pub limits: Limits,
    pub keys: KeyHasher,
    inflight: Semaphore,
    /// Large uploads that may be buffered at the same time: bounds worst-case memory to `MAX_CONCURRENT_UPLOADS * MAX_BLOB_BYTES`.
    uploads: Semaphore,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppState")
    }
}

impl AppState {
    pub fn new(store: Arc<PgStore>, cfg: Arc<Config>, clock: Arc<dyn Clock>, push: Arc<dyn PushNotifier>, limits: Limits) -> Self {
        let keys = KeyHasher::new(cfg.pepper);
        let inflight = Semaphore::new(cfg.max_inflight.max(1));
        Self { store, cfg, clock, push, limits, keys, inflight, uploads: Semaphore::new(MAX_CONCURRENT_UPLOADS) }
    }

    async fn take(&self, class: &str, id: &[u8], cost: f64, cap: f64, rate: f64) -> Result<bool, ApiError> {
        self.store.take_tokens(&self.keys.key(class, id), cost, cap, rate, self.clock.now()).await
    }
}

type S = State<Arc<AppState>>;

pub fn build_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/accounts", post(register))
        .route("/v1/devices", post(add_device))
        .route("/v1/accounts/{account}/devices", get(directory))
        .route("/v1/key-packages", put(upload_key_packages))
        .route("/v1/devices/{device}/key-package", post(consume_key_package))
        .route("/v1/messages", post(send_message).get(fetch_messages))
        .route("/v1/messages/ack", post(ack))
        .route("/v1/messages/batch", post(send_batch))
        .route("/v1/caps", post(mint_caps))
        .route("/v1/caps/revoke", post(revoke_caps))
        .route("/v1/deliver", post(anon_deliver))
        .route("/v1/intro/directory", post(intro_directory))
        .route("/v1/intro/key-package", post(intro_key_package))
        .route("/v1/groups/{tag}", get(group_state))
        .route("/v1/groups/{tag}/commit", post(group_commit))
        .route("/v1/push-token", put(set_push_token))
        .route("/v1/blobs", post(upload_blob))
        .route("/v1/blobs/by-cap", post(upload_blob_by_cap))
        .route("/v1/blobs/{id}", get(download_blob))
        .route_layer(middleware::from_fn(log_request))
        .layer(middleware::from_fn_with_state(state.clone(), shed_and_timeout))
        .layer(middleware::map_response(security_headers))
        .with_state(state)
}

/// Load shedding and request deadline: when `max_inflight` requests are already running the request is
/// rejected immediately (503) instead of queueing without bound; slow requests are cut off (408).
async fn shed_and_timeout(State(st): S, req: Request, next: Next) -> Response {
    let Ok(_permit) = st.inflight.try_acquire() else {
        return (StatusCode::SERVICE_UNAVAILABLE, [("content-type", "application/json")], "{\"error\":\"overloaded\"}").into_response();
    };
    let secs = if req.uri().path().starts_with("/v1/blobs") { st.cfg.request_timeout_secs * 4 } else { st.cfg.request_timeout_secs };
    match tokio::time::timeout(std::time::Duration::from_secs(secs.max(1)), next.run(req)).await {
        Ok(r) => r,
        Err(_) => (StatusCode::REQUEST_TIMEOUT, [("content-type", "application/json")], "{\"error\":\"timeout\"}").into_response(),
    }
}

async fn security_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    resp
}

/// Logs only the route template and status class. Never bodies, headers, query
/// strings, ids, tokens or client addresses.
async fn log_request(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let route = req.extensions().get::<MatchedPath>().map(|m| m.as_str().to_owned()).unwrap_or_default();
    let resp = next.run(req).await;
    // DEBUG, not INFO: a per-request line is a precise activity log. It is off by default (RUST_LOG=info); enabling it is a conscious operator choice.
    tracing::debug!(%method, route = %route, status = resp.status().as_u16(), "request");
    resp
}

struct Incoming {
    method: &'static str,
    path_and_query: String,
    authorization: Option<String>,
    ip: Option<IpAddr>,
    body: Bytes,
}

async fn read(req: Request<Body>, limit: usize) -> Result<Incoming, ApiError> {
    let method = match req.method().as_str() {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        _ => return Err(ApiError::BadRequest),
    };
    let path_and_query = req.uri().path_and_query().map(|p| p.as_str().to_owned()).ok_or(ApiError::BadRequest)?;
    let authorization = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let ip = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
    let body = to_bytes(req.into_body(), limit).await.map_err(|_| ApiError::TooLarge)?;
    Ok(Incoming { method, path_and_query, authorization, ip, body })
}

async fn authed(st: &AppState, inc: &Incoming) -> Result<Id16, ApiError> {
    authenticate(st, inc.method, &inc.path_and_query, inc.authorization.as_deref(), &inc.body, inc.ip).await
}

fn parse<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(b).map_err(|_| ApiError::BadRequest)
}

fn id_param(s: &str) -> Result<Id16, ApiError> {
    Id16::parse(s).map_err(|_| ApiError::BadRequest)
}

fn token_ok(st: &AppState, token: &str) -> bool {
    let h = Config::hash_token(token);
    bool::from(h.ct_eq(&st.cfg.registration_token_hash))
}

fn validate_new_device(account: &Id16, rec: &DeviceRecord) -> Result<(), ApiError> {
    rec.validate().map_err(|_| ApiError::BadRequest)?;
    if !verify_ed25519(&rec.identity_key, &binding_message(account, &rec.device_id, &rec.auth_key), &rec.binding_sig) {
        return Err(ApiError::Forbidden); // no proof of possession of the identity key
    }
    Ok(())
}

async fn register(State(st): S, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, MAX_JSON_BODY_BYTES).await?;
    let l = st.limits;
    let ipk = inc.ip.unwrap_or(IpAddr::from([0, 0, 0, 0])).to_string();
    if !st.take("register", ipk.as_bytes(), 1.0, f64::from(l.register_burst), l.register_refill_per_sec).await? {
        return Err(ApiError::RateLimited);
    }
    let r: RegisterRequest = parse(&inc.body)?;
    if !token_ok(&st, &r.registration_token) {
        return Err(ApiError::Forbidden);
    }
    validate_new_device(&r.account_id, &r.device)?;
    if r.device.endorsement.is_some() {
        return Err(ApiError::BadRequest);
    }
    st.store.create_account(&r.account_id, &r.device).await?;
    Ok(StatusCode::CREATED.into_response())
}

async fn add_device(State(st): S, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, MAX_JSON_BODY_BYTES).await?;
    let l = st.limits;
    let ipk = inc.ip.unwrap_or(IpAddr::from([0, 0, 0, 0])).to_string();
    if !st.take("register", ipk.as_bytes(), 1.0, f64::from(l.register_burst), l.register_refill_per_sec).await? {
        return Err(ApiError::RateLimited);
    }
    let r: AddDeviceRequest = parse(&inc.body)?;
    // Knowing the account credential is NOT enough: a new device must be endorsed by
    // an existing device's identity key (A8). The relay checks it; clients re-check it.
    if !token_ok(&st, &r.registration_token) {
        return Err(ApiError::Forbidden);
    }
    validate_new_device(&r.account_id, &r.device)?;
    let e = r.device.endorsement.as_ref().ok_or(ApiError::Forbidden)?;
    let (acc, endorser) = st.store.device(&e.endorser_device).await?.ok_or(ApiError::Forbidden)?;
    if acc != r.account_id {
        return Err(ApiError::Forbidden);
    }
    let msg = endorsement_message(&r.account_id, &r.device.device_id, &r.device.identity_key, &r.device.auth_key);
    if !verify_ed25519(&endorser.identity_key, &msg, &e.signature) {
        return Err(ApiError::Forbidden);
    }
    st.store.add_device(&r.account_id, &r.device).await?;
    Ok(StatusCode::CREATED.into_response())
}

async fn directory(State(st): S, Path(account): Path<String>, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, 0).await?;
    authed(&st, &inc).await?;
    let account = id_param(&account)?;
    let devices = st.store.devices_of(&account).await?;
    if devices.is_empty() {
        return Err(ApiError::NotFound);
    }
    Ok(Json(DirectoryResponse { account_id: account, devices }).into_response())
}

async fn upload_key_packages(State(st): S, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, MAX_JSON_BODY_BYTES).await?;
    let dev = authed(&st, &inc).await?;
    let up: UploadKeyPackages = parse(&inc.body)?;
    up.validate().map_err(|_| ApiError::BadRequest)?;
    st.store.put_key_packages(&dev, &up.key_packages).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn consume_key_package(State(st): S, Path(device): Path<String>, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, 0).await?;
    let me = authed(&st, &inc).await?;
    // Throttle KeyPackage draining (a malicious peer could exhaust a victim's supply).
    let l = st.limits;
    if !st.take("device", &me.0, 9.0, f64::from(l.device_burst), l.device_refill_per_sec).await? {
        return Err(ApiError::RateLimited);
    }
    let target = id_param(&device)?;
    // FR-08: per-TARGET limits. The per-requester limit above lets one account drain a victim's whole supply (100) in under a minute
    // (and the victim could then not be added by anyone for days). Every request, found or not, spends from both buckets.
    //   * all requesters together: burst 12, refill 12/hour   * one requester vs one target: burst 4, refill 4/hour
    if !st.take("kp-target", &target.0, 1.0, 12.0, 12.0 / 3600.0).await? {
        return Err(ApiError::RateLimited);
    }
    let pair = [me.0.as_slice(), target.0.as_slice()].concat();
    if !st.take("kp-pair", &pair, 1.0, 4.0, 4.0 / 3600.0).await? {
        return Err(ApiError::RateLimited);
    }
    let kp = st.store.pop_key_package(&target).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(KeyPackageResponse { key_package: kp }).into_response())
}

async fn send_message(State(st): S, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, MAX_JSON_BODY_BYTES).await?;
    let me = authed(&st, &inc).await?; // sender identity is verified; only a keyed pair hash (ST-031 share accounting) outlives the request
    let r: SendRequest = parse(&inc.body)?;
    let ttl = r.validate().map_err(|_| ApiError::BadRequest)?;
    if st.store.device(&r.recipient_device).await?.is_none() {
        return Err(ApiError::NotFound);
    }
    let now = st.clock.now();
    let status = match st
        .store
        .enqueue(&r.recipient_device, &r.message_id, &r.ciphertext, ttl, now, Some(&crate::store::Sender { device: me, keys: &st.keys }))
        .await?
    {
        Enqueue::Queued => {
            if let Some(tok) = st.store.push_token(&r.recipient_device).await? {
                st.push.wake(&tok); // content-free wake-up only
            }
            SendStatus::Queued
        }
        Enqueue::Duplicate => SendStatus::Duplicate,
    };
    Ok(Json(SendResponse { status }).into_response())
}

async fn fetch_messages(State(st): S, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, 0).await?;
    let dev = authed(&st, &inc).await?;
    let (envelopes, more) = st.store.fetch(&dev, st.clock.now()).await?;
    Ok(Json(FetchResponse { envelopes, more }).into_response())
}

async fn ack(State(st): S, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, MAX_JSON_BODY_BYTES).await?;
    let dev = authed(&st, &inc).await?;
    let a: AckRequest = parse(&inc.body)?;
    a.validate().map_err(|_| ApiError::BadRequest)?;
    st.store.ack(&dev, &a.message_ids).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn set_push_token(State(st): S, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, MAX_JSON_BODY_BYTES).await?;
    let dev = authed(&st, &inc).await?;
    let t: PushTokenRequest = parse(&inc.body)?;
    if t.token.is_empty() || t.token.len() > MAX_PUSH_TOKEN_BYTES || !t.token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ApiError::BadRequest);
    }
    st.store.set_push_token(&dev, &t.token).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn upload_blob(State(st): S, req: Request<Body>) -> Result<Response, ApiError> {
    // FR-10: AUTHENTICATE BEFORE READING THE BODY. The signature covers the body hash, so the client announces it in the header (`bh=`);
    // the relay verifies the signature against it, and only then buffers the body (bounded by the declared Content-Length, by a global
    // upload-slot semaphore, and re-hashed afterwards). Without this an unauthenticated peer could make the relay buffer up to
    // MAX_BLOB_BYTES per connection and fail only at the end.
    let declared: usize =
        req.headers().get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok()).ok_or(ApiError::BadRequest)?; // chunked/unknown length is refused
    if declared > MAX_BLOB_BYTES {
        return Err(ApiError::TooLarge);
    }
    let path_and_query = req.uri().path_and_query().map(|p| p.as_str().to_owned()).ok_or(ApiError::BadRequest)?;
    let authorization = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let ip = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
    let (dev, announced) =
        crate::auth::authenticate_body(&st, "POST", &path_and_query, authorization.as_deref(), crate::auth::BodyAuth::Announced, ip)
            .await?;
    let _slot = st.uploads.try_acquire().map_err(|_| ApiError::Overloaded)?;
    let body = to_bytes(req.into_body(), declared).await.map_err(|_| ApiError::TooLarge)?;
    let actual: [u8; 32] = sha2::Sha256::digest(&body).into();
    if !bool::from(actual.ct_eq(&announced)) {
        return Err(ApiError::BadRequest); // the body is not what the (valid) signature covered
    }
    let inc = Incoming { method: "POST", path_and_query, authorization, ip, body };
    // Sanity only: the relay cannot verify that the body is encrypted. It enforces the
    // container header and size bounds; the client is responsible for encryption.
    if inc.body.len() < 13 + 16 || inc.body.get(..4) != Some(ATTACHMENT_MAGIC.as_slice()) {
        return Err(ApiError::BadRequest);
    }
    let now = st.clock.now();
    let l = st.limits;
    if !st.take("blob", &dev.0, inc.body.len() as f64 / 1024.0, f64::from(l.blob_bytes_burst), l.blob_bytes_refill_per_sec).await? {
        return Err(ApiError::RateLimited);
    }
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| ApiError::Internal)?;
    let id = Id16(id);
    let (store, max) = (st.store.clone(), st.cfg.max_total_blob_bytes);
    let body = inc.body;
    store.put_blob(&id, &body, now, max).await?;
    Ok((StatusCode::CREATED, Json(BlobCreated { blob_id: id })).into_response())
}

/// UNAUTHENTICATED attachment upload into the mailbox of the capability holder's CONTACT (docs/MULTI_RELAY_PROTOCOL.md §10): `Authorization: Cap <32 hex>`.
/// Like the signed upload, the capability and the declared length are checked BEFORE the body is read; usage is bounded per capability (quota),
/// per source address and globally. The relay cannot tell what the bytes are (only that they carry the container header); it learns the time and the
/// padded size, never a sender.
async fn upload_blob_by_cap(State(st): S, req: Request<Body>) -> Result<Response, ApiError> {
    let declared: usize =
        req.headers().get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok()).ok_or(ApiError::BadRequest)?;
    if !(13 + 16..=MAX_BLOB_BYTES).contains(&declared) {
        return Err(ApiError::TooLarge);
    }
    let cap = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Cap "))
        .and_then(|v| Id16::parse(v).ok())
        .ok_or(ApiError::BadRequest)?;
    let ip = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip()).unwrap_or(IpAddr::from([0, 0, 0, 0])).to_string();
    let l = st.limits;
    let kib = declared as f64 / 1024.0;
    if !st.take("blob-ip", ip.as_bytes(), kib, f64::from(l.blob_bytes_burst), l.blob_bytes_refill_per_sec).await?
        || !st.take("blob-cap", &cap.0, kib, f64::from(l.blob_bytes_burst), l.blob_bytes_refill_per_sec).await?
    {
        return Err(ApiError::RateLimited);
    }
    let now = st.clock.now();
    if !st.store.cap_is_live(&cap, now).await? {
        return Err(ApiError::NotFound); // unknown, revoked, expired: one outcome, before any body is buffered
    }
    let _slot = st.uploads.try_acquire().map_err(|_| ApiError::Overloaded)?;
    let body = to_bytes(req.into_body(), declared).await.map_err(|_| ApiError::TooLarge)?;
    if body.len() != declared || body.get(..4) != Some(ATTACHMENT_MAGIC.as_slice()) {
        return Err(ApiError::BadRequest);
    }
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| ApiError::Internal)?;
    let id = Id16(id);
    st.store.put_blob_by_cap(&id, &body, &cap, now, st.cfg.max_total_blob_bytes, st.cfg.cap_blob_quota_bytes).await?;
    Ok((StatusCode::CREATED, Json(BlobCreated { blob_id: id })).into_response())
}

async fn download_blob(State(st): S, Path(id): Path<String>, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, 0).await?;
    authed(&st, &inc).await?;
    let id = id_param(&id)?;
    let (store, now) = (st.store.clone(), st.clock.now());
    let data = store.get_blob(&id, now).await?;
    let data = data.ok_or(ApiError::NotFound)?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], data).into_response())
}

async fn send_batch(State(st): S, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, 4 * MAX_JSON_BODY_BYTES).await?;
    let me = authed(&st, &inc).await?;
    let r: BatchSendRequest = parse(&inc.body)?;
    let ttl = r.validate().map_err(|_| ApiError::BadRequest)?;
    let sender = crate::store::Sender { device: me, keys: &st.keys };
    let results = st.store.enqueue_batch(&r.deliveries, ttl, st.clock.now(), Some(&sender)).await?;
    for (d, res) in r.deliveries.iter().zip(&results) {
        if res == "queued" {
            if let Some(tok) = st.store.push_token(&d.recipient_device).await? {
                st.push.wake(&tok);
            }
        }
    }
    Ok(Json(BatchSendResponse { results }).into_response())
}

async fn group_state(State(st): S, Path(tag): Path<String>, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, 0).await?;
    authed(&st, &inc).await?;
    let tag = id_param(&tag)?;
    match st.store.group_epoch(&tag).await? {
        Some((_, true)) => Err(ApiError::Gone),
        Some((epoch, false)) => Ok(Json(GroupStateResponse { epoch }).into_response()),
        None => Err(ApiError::NotFound),
    }
}

/// Deterministic commit ordering: compare-and-swap on the group epoch. The loser gets 409 with the current
/// epoch, must process the winning commit, and re-issue (rebase) its own. The relay is trusted for liveness
/// only; a malicious relay can fork or stall a group but cannot read it, and forks are detectable client-side.
async fn group_commit(State(st): S, Path(tag): Path<String>, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, 4 * MAX_JSON_BODY_BYTES).await?;
    let me = authed(&st, &inc).await?;
    let tag = id_param(&tag)?;
    let r: GroupCommitRequest = parse(&inc.body)?;
    r.validate().map_err(|_| ApiError::BadRequest)?;
    match st
        .store
        .group_commit(
            &tag,
            r.expected_epoch,
            r.new_tag.as_ref(),
            &r.deliveries,
            st.clock.now(),
            Some(&crate::store::Sender { device: me, keys: &st.keys }),
        )
        .await?
    {
        GroupOutcome::Accepted(epoch) => {
            for d in &r.deliveries {
                if let Some(tok) = st.store.push_token(&d.recipient_device).await? {
                    st.push.wake(&tok);
                }
            }
            Ok(Json(GroupCommitResponse { epoch }).into_response())
        }
        GroupOutcome::Stale(current_epoch) => {
            Ok((StatusCode::CONFLICT, Json(GroupStaleResponse { error: "stale epoch".into(), current_epoch })).into_response())
        }
        GroupOutcome::Gone => Err(ApiError::Gone),
    }
}

async fn mint_caps(State(st): S, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, MAX_JSON_BODY_BYTES).await?;
    let me = authed(&st, &inc).await?;
    let r: MintCapsRequest = parse(&inc.body)?;
    r.validate().map_err(|_| ApiError::BadRequest)?;
    if !st.take("cap-mint", &me.0, r.caps.len() as f64, 64.0, 64.0 / 3600.0).await? {
        return Err(ApiError::RateLimited);
    }
    st.store.mint_caps(&me, &r.caps, r.intro, st.clock.now()).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn revoke_caps(State(st): S, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, MAX_JSON_BODY_BYTES).await?;
    let me = authed(&st, &inc).await?;
    let r: RevokeCapsRequest = parse(&inc.body)?;
    let grace = r.validate().map_err(|_| ApiError::BadRequest)?;
    st.store.revoke_caps(&me, &r.caps, grace, st.clock.now()).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Shared front of the two unauthenticated intro calls: bounded per source address and per capability, one `NotFound` for every invalid capability.
async fn intro_gate(st: &AppState, inc: &Incoming) -> Result<(IntroRequest, Id16), ApiError> {
    let r: IntroRequest = parse(&inc.body)?;
    let ip = inc.ip.unwrap_or(IpAddr::from([0, 0, 0, 0])).to_string();
    if !st.take("intro-ip", ip.as_bytes(), 1.0, 60.0, 2.0).await? {
        return Err(ApiError::RateLimited);
    }
    if !st.take("intro-cap", &r.cap.0, 1.0, 30.0, 30.0 / 3600.0).await? {
        return Err(ApiError::RateLimited);
    }
    let dev = st.store.intro_device(&r.cap, st.clock.now()).await?;
    Ok((r, dev))
}

/// UNAUTHENTICATED. The issuer's device records, for a holder of the issuer's contact-card capability. The records are self-authenticating (binding
/// signatures under the issuer's root key, which the card pins), so this endpoint needs no trust in the relay's honesty — only its availability.
async fn intro_directory(State(st): S, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, MAX_JSON_BODY_BYTES).await?;
    let (_, dev) = intro_gate(&st, &inc).await?;
    let (account, _) = st.store.device(&dev).await?.ok_or(ApiError::NotFound)?;
    let devices = st.store.devices_of(&account).await?;
    Ok(Json(DirectoryResponse { account_id: account, devices }).into_response())
}

/// UNAUTHENTICATED. Consume one KeyPackage of a device of the capability issuer's account. Limited per capability (4/h) AND by the same per-target
/// bucket the authenticated path uses, so leaked cards cannot drain the pool faster than before.
async fn intro_key_package(State(st): S, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, MAX_JSON_BODY_BYTES).await?;
    let (r, dev) = intro_gate(&st, &inc).await?;
    let target = r.device.ok_or(ApiError::BadRequest)?;
    let (account, _) = st.store.device(&dev).await?.ok_or(ApiError::NotFound)?;
    let (tacc, _) = st.store.device(&target).await?.ok_or(ApiError::NotFound)?;
    if tacc != account {
        return Err(ApiError::NotFound); // a card opens its issuer's devices only
    }
    if !st.take("kp-target", &target.0, 1.0, 12.0, 12.0 / 3600.0).await? || !st.take("intro-kp", &r.cap.0, 1.0, 4.0, 4.0 / 3600.0).await? {
        return Err(ApiError::RateLimited);
    }
    let kp = st.store.pop_key_package(&target).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(KeyPackageResponse { key_package: kp }).into_response())
}

/// UNAUTHENTICATED capability delivery. Abuse control is per capability and per (hashed) source address; the relay never learns who the sender is,
/// only that someone holding a valid capability delivered ciphertext. Unknown/revoked/expired capabilities all answer `invalid`.
async fn anon_deliver(State(st): S, req: Request<Body>) -> Result<Response, ApiError> {
    let inc = read(req, 4 * MAX_JSON_BODY_BYTES).await?;
    let r: AnonDeliverRequest = parse(&inc.body)?;
    let ttl = r.validate().map_err(|_| ApiError::BadRequest)?;
    let ip = inc.ip.unwrap_or(IpAddr::from([0, 0, 0, 0])).to_string();
    // Source addresses behind a privacy network are shared by many users: generous, but bounded.
    if !st.take("deliver-ip", ip.as_bytes(), r.deliveries.len() as f64, 600.0, 20.0).await? {
        return Err(ApiError::RateLimited);
    }
    let now = st.clock.now();
    let mut results = Vec::with_capacity(r.deliveries.len());
    for d in &r.deliveries {
        if !st.take("cap", &d.cap.0, 1.0, 120.0, 1.0).await? {
            results.push("queue_full".to_owned());
            continue;
        }
        match st.store.enqueue_anon(&d.cap, &d.message_id, &d.ciphertext, ttl, now).await {
            Ok((dev, Enqueue::Queued)) => {
                if let Some(tok) = st.store.push_token(&dev).await? {
                    st.push.wake(&tok);
                }
                results.push("queued".to_owned());
            }
            Ok((_, Enqueue::Duplicate)) => results.push("duplicate".to_owned()),
            Err(ApiError::NotFound) => results.push("invalid".to_owned()),
            Err(ApiError::QueueFull) => results.push("queue_full".to_owned()),
            Err(e) => return Err(e),
        }
    }
    Ok(Json(AnonDeliverResponse { results }).into_response())
}
