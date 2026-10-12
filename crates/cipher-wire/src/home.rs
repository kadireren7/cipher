//! Home-relay commit log of a cross-relay group (docs/CROSS_RELAY_GROUPS.md §7).
//!
//! The home relay orders the commits of a group whose members live on different relays. It cannot read them and never learns who the members are:
//! it knows an opaque tag and, per epoch, two PUBLIC keys. Requests are authenticated by an Ed25519 signature made with a key that only members of
//! that epoch can derive from the MLS exporter (the derivation and signing live in `cipher-core`; this crate only fixes what is signed and hashed).
//!
//! * `seq` equals the MLS epoch the commit creates (the first commit of a group creates epoch 1).
//! * A key of epoch `e` may submit the commit that creates `e + 1` (compare-and-swap on the head) and may READ entries up to `e + 1`, never beyond:
//!   a member that was offline catches up one entry at a time, each applied entry yielding the next key; a removed member can read only its own
//!   removal commit.
//! * Entries are hash-chained and the chain also covers the two public keys, so a relay cannot hand different members different histories or swap
//!   the keys of an epoch without the members noticing.
use crate::b64;
use crate::ids::Id16;
use crate::limits::MAX_MESSAGE_CIPHERTEXT_BYTES;
use crate::messages::ValidationError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The credential travels in the ordinary `Authorization` header (`Home <epoch>.<signature>`), so every transport that can already carry the
/// device-signed scheme can carry this one without change.
pub const HOME_AUTH_SCHEME: &str = "Home";
pub const MAX_HOME_COMMIT_BYTES: usize = MAX_MESSAGE_CIPHERTEXT_BYTES;
/// Entries one group may accumulate on a home relay (a group with this many membership changes should be replaced).
pub const MAX_HOME_LOG_ENTRIES: u64 = 4096;
pub const MAX_HOME_PAGE: usize = 16;

const TAG_DOMAIN: &[u8] = b"cipher-home-tag-v1\0";
const CHAIN_DOMAIN: &[u8] = b"cipher-home-log-v1\0";
const REQ_DOMAIN: &[u8] = b"cipher-home-req-v1\0";

/// The routing tag of a group's log, derived from the (secret, random) MLS group id so every member computes it and nobody else can.
pub fn home_tag(group_id: &[u8]) -> Id16 {
    let h = Sha256::new().chain_update(TAG_DOMAIN).chain_update(group_id).finalize();
    let mut t = [0u8; 16];
    for (dst, src) in t.iter_mut().zip(h.iter()) {
        *dst = *src;
    }
    Id16(t)
}

pub fn chain_genesis(tag: &Id16) -> [u8; 32] {
    Sha256::new().chain_update(CHAIN_DOMAIN).chain_update(b"genesis").chain_update(tag.0).finalize().into()
}

/// `h_i = SHA-256(domain ‖ h_{i-1} ‖ seq ‖ commit_id ‖ SHA-256(commit) ‖ commit_pub ‖ read_pub)`.
pub fn chain_next(prev: &[u8; 32], seq: u64, commit_id: &Id16, commit: &[u8], commit_pub: &[u8; 32], read_pub: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(CHAIN_DOMAIN)
        .chain_update(prev)
        .chain_update(seq.to_be_bytes())
        .chain_update(commit_id.0)
        .chain_update(Sha256::digest(commit))
        .chain_update(commit_pub)
        .chain_update(read_pub)
        .finalize()
        .into()
}

pub fn auth_value(epoch: u64, signature: &[u8]) -> String {
    format!("{HOME_AUTH_SCHEME} {epoch}.{}", b64::encode(signature))
}

/// `(epoch, signature)` from an `Authorization` value; None when the scheme or the shape is wrong.
pub fn parse_auth(value: &str) -> Option<(u64, Vec<u8>)> {
    let rest = value.strip_prefix(HOME_AUTH_SCHEME)?.strip_prefix(' ')?;
    let (epoch, sig) = rest.split_once('.')?;
    if epoch.is_empty() || epoch.len() > 20 || !epoch.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((epoch.parse().ok()?, b64::decode(sig)?))
}

/// The bytes a request signature covers: the key's epoch, the method, the exact path and query, and the body hash.
pub fn request_message(epoch: u64, method: &str, path_and_query: &str, body: &[u8]) -> Vec<u8> {
    let mut m = REQ_DOMAIN.to_vec();
    m.extend_from_slice(&epoch.to_be_bytes());
    m.push(0);
    m.extend_from_slice(method.as_bytes());
    m.push(0);
    m.extend_from_slice(path_and_query.as_bytes());
    m.push(0);
    m.extend_from_slice(&Sha256::digest(body));
    m
}

fn key32(v: &[u8], what: &'static str) -> Result<[u8; 32], ValidationError> {
    v.try_into().map_err(|_| ValidationError::Bounds(what))
}

/// `POST /v1/home/{tag}/commit`. Signed with the commit key of epoch `expected_seq` (for `expected_seq == 0`, the group's creation, with the
/// NEW commit key it announces, which proves its sender knows it).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HomeCommitRequest {
    pub expected_seq: u64,
    /// Idempotency: a retry after a lost response carries the same id and is answered as accepted.
    pub commit_id: Id16,
    #[serde(with = "b64")]
    pub commit: Vec<u8>,
    /// Public keys of the epoch this commit creates (derived from the staged commit before it is merged).
    #[serde(with = "b64")]
    pub next_commit_pub: Vec<u8>,
    #[serde(with = "b64")]
    pub next_read_pub: Vec<u8>,
}

impl HomeCommitRequest {
    pub fn validate(&self) -> Result<([u8; 32], [u8; 32]), ValidationError> {
        if self.commit.is_empty() || self.commit.len() > MAX_HOME_COMMIT_BYTES {
            return Err(ValidationError::Bounds("commit"));
        }
        if self.expected_seq >= MAX_HOME_LOG_ENTRIES {
            return Err(ValidationError::Bounds("expected_seq"));
        }
        Ok((key32(&self.next_commit_pub, "next_commit_pub")?, key32(&self.next_read_pub, "next_read_pub")?))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HomeCommitResponse {
    pub seq: u64,
    #[serde(with = "b64")]
    pub chain: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HomeStaleResponse {
    pub error: String,
    pub head_seq: u64,
    #[serde(with = "b64")]
    pub head_chain: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct HomeLogEntry {
    pub seq: u64,
    pub commit_id: Id16,
    #[serde(with = "b64")]
    pub commit: Vec<u8>,
    #[serde(with = "b64")]
    pub chain: Vec<u8>,
    #[serde(with = "b64")]
    pub commit_pub: Vec<u8>,
    #[serde(with = "b64")]
    pub read_pub: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct HomeHead {
    pub seq: u64,
    #[serde(with = "b64")]
    pub chain: Vec<u8>,
}

/// `GET /v1/home/{tag}/log?after=N`. `head` is present only when the caller's key belongs to the head epoch.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct HomeLogResponse {
    pub entries: Vec<HomeLogEntry>,
    pub head: Option<HomeHead>,
}

impl HomeLogEntry {
    pub fn keys(&self) -> Result<([u8; 32], [u8; 32]), ValidationError> {
        Ok((key32(&self.commit_pub, "commit_pub")?, key32(&self.read_pub, "read_pub")?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_chain_binds_everything_an_entry_contains() {
        let tag = home_tag(&[7; 16]);
        let g = chain_genesis(&tag);
        let (c, r) = ([1u8; 32], [2u8; 32]);
        let id = Id16([9; 16]);
        let base = chain_next(&g, 1, &id, b"commit", &c, &r);
        assert_ne!(base, chain_next(&g, 2, &id, b"commit", &c, &r), "seq");
        assert_ne!(base, chain_next(&g, 1, &Id16([8; 16]), b"commit", &c, &r), "commit id");
        assert_ne!(base, chain_next(&g, 1, &id, b"commiT", &c, &r), "commit bytes");
        assert_ne!(base, chain_next(&g, 1, &id, b"commit", &[3; 32], &r), "commit key");
        assert_ne!(base, chain_next(&g, 1, &id, b"commit", &c, &[3; 32]), "read key");
        assert_ne!(base, chain_next(&chain_genesis(&home_tag(&[8; 16])), 1, &id, b"commit", &c, &r), "history");
    }

    #[test]
    fn a_signature_message_binds_epoch_method_path_and_body() {
        let m = request_message(3, "POST", "/v1/home/ab/commit", b"{}");
        assert_ne!(m, request_message(4, "POST", "/v1/home/ab/commit", b"{}"));
        assert_ne!(m, request_message(3, "GET", "/v1/home/ab/commit", b"{}"));
        assert_ne!(m, request_message(3, "POST", "/v1/home/ac/commit", b"{}"));
        assert_ne!(m, request_message(3, "POST", "/v1/home/ab/commit", b"{ }"));
    }

    #[test]
    fn the_credential_header_round_trips_and_rejects_other_shapes() {
        let v = auth_value(7, &[1, 2, 3]);
        assert_eq!(parse_auth(&v), Some((7, vec![1, 2, 3])));
        for bad in [
            "",
            "Home",
            "Home 7",
            "Home .AAAA",
            "Home x.AAAA",
            "Home -1.AAAA",
            "home 7.AAAA",
            "Bearer 7.AAAA",
            "Home 7.!!!",
            "Home 99999999999999999999999.AAAA",
        ] {
            assert_eq!(parse_auth(bad), None, "{bad}");
        }
    }

    #[test]
    fn requests_with_wrong_sized_keys_or_oversized_commits_are_refused() {
        let ok = HomeCommitRequest {
            expected_seq: 1,
            commit_id: Id16([1; 16]),
            commit: vec![1; 10],
            next_commit_pub: vec![0; 32],
            next_read_pub: vec![0; 32],
        };
        assert!(ok.validate().is_ok());
        assert!(HomeCommitRequest { next_read_pub: vec![0; 31], ..ok.clone() }.validate().is_err());
        assert!(HomeCommitRequest { commit: vec![], ..ok.clone() }.validate().is_err());
        assert!(HomeCommitRequest { commit: vec![0; MAX_HOME_COMMIT_BYTES + 1], ..ok.clone() }.validate().is_err());
        assert!(HomeCommitRequest { expected_seq: MAX_HOME_LOG_ENTRIES, ..ok }.validate().is_err());
    }
}
