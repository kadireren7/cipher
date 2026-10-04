//! Device request authentication.
//!
//! Account credentials (registration token) are NOT how devices authenticate to the relay. Each request carries
//! an Ed25519 signature by the device's transport-auth key over a canonical string binding method, path,
//! timestamp, single-use nonce, body hash and this relay's audience.
//!
//! Fail closed: any parse/lookup/signature/skew/replay problem is `Unauthorized`. Unknown-device and
//! bad-signature are indistinguishable to the caller. Replay protection and failed-auth throttling are shared
//! across relay instances through PostgreSQL.
use crate::api::AppState;
use crate::error::ApiError;
use cipher_wire::limits::MAX_CLOCK_SKEW_SECS;
use cipher_wire::signing::{canonical_string_with_hash, parse_auth_header, CanonicalParts};
use cipher_wire::Id16;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::Digest as _;
use std::net::IpAddr;
use subtle::ConstantTimeEq as _;

pub fn verify_ed25519(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(pk): Result<[u8; 32], _> = public.try_into() else { return false };
    let (Ok(vk), Ok(sig)) = (VerifyingKey::from_bytes(&pk), Signature::from_slice(sig)) else { return false };
    vk.verify(msg, &sig).is_ok()
}

/// What the signature's body hash is checked against.
#[derive(Clone, Copy, Debug)]
pub enum BodyAuth<'a> {
    /// The whole body is already in memory: hash it (and, if the header announced a hash, require it to match).
    Bytes(&'a [u8]),
    /// PRE-READ authentication for large uploads: trust the hash announced in the header (`bh=`) for the signature check only. The caller
    /// MUST afterwards verify that the body it reads really hashes to the returned value.
    Announced,
}

pub async fn authenticate(
    state: &AppState,
    method: &str,
    path_and_query: &str,
    authorization: Option<&str>,
    body: &[u8],
    ip: Option<IpAddr>,
) -> Result<Id16, ApiError> {
    authenticate_body(state, method, path_and_query, authorization, BodyAuth::Bytes(body), ip).await.map(|(d, _)| d)
}

pub async fn authenticate_body(
    state: &AppState,
    method: &str,
    path_and_query: &str,
    authorization: Option<&str>,
    body: BodyAuth<'_>,
    ip: Option<IpAddr>,
) -> Result<(Id16, [u8; 32]), ApiError> {
    let now = state.clock.now();
    let ip_key = state.keys.key("ip", ip.unwrap_or(IpAddr::from([0, 0, 0, 0])).to_string().as_bytes());
    let l = &state.limits;
    if !state.store.bucket_available(&ip_key, f64::from(l.auth_fail_burst), l.auth_fail_refill_per_sec, now).await? {
        return Err(ApiError::RateLimited);
    }
    let result: Result<(Id16, [u8; 32]), ApiError> = async {
        let h = parse_auth_header(authorization.ok_or(ApiError::Unauthorized)?).ok_or(ApiError::Unauthorized)?;
        if h.timestamp.abs_diff(now) > MAX_CLOCK_SKEW_SECS {
            return Err(ApiError::Unauthorized);
        }
        let (_, rec) = state.store.device(&h.device).await?.ok_or(ApiError::Unauthorized)?;
        let hash: [u8; 32] = match body {
            BodyAuth::Bytes(b) => {
                let computed: [u8; 32] = sha2::Sha256::digest(b).into();
                if h.body_hash.is_some_and(|announced| !bool::from(announced.ct_eq(&computed))) {
                    return Err(ApiError::Unauthorized);
                }
                computed
            }
            BodyAuth::Announced => h.body_hash.ok_or(ApiError::Unauthorized)?,
        };
        let canonical = canonical_string_with_hash(
            &CanonicalParts {
                audience: &state.cfg.audience,
                method,
                path_and_query,
                timestamp: h.timestamp,
                nonce: &h.nonce,
                body: &[],
                device: &h.device,
            },
            &hash,
        );
        if !verify_ed25519(&rec.auth_key, &canonical, &h.signature) {
            return Err(ApiError::Unauthorized);
        }
        // Only a *valid* signature may occupy replay-cache space.
        state.store.use_nonce(&h.device, &h.nonce, now + 2 * MAX_CLOCK_SKEW_SECS + 1).await?;
        Ok((h.device, hash))
    }
    .await;
    match result {
        Ok((d, hash)) => {
            let dk = state.keys.key("device", &d.0);
            if !state.store.take_tokens(&dk, 1.0, f64::from(l.device_burst), l.device_refill_per_sec, now).await? {
                return Err(ApiError::RateLimited);
            }
            Ok((d, hash))
        }
        Err(e) => {
            let _ = state.store.take_tokens(&ip_key, 1.0, f64::from(l.auth_fail_burst), l.auth_fail_refill_per_sec, now).await;
            Err(e)
        }
    }
}
