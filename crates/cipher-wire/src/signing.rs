//! Canonical string for authenticating a device's HTTP request.
//!
//! Account credentials (registration token) are separate from device identity.
//! A request is authenticated by an Ed25519 signature from the device's
//! *transport-auth key* over this canonical string. The signature covers the
//! method, path+query, timestamp, a single-use nonce, the body hash and an
//! audience string (relay identity) so a captured request cannot be replayed
//! to another relay or with a modified body.
use crate::ids::Id16;
use sha2::{Digest, Sha256};

pub const SIG_CONTEXT: &str = "cipher-req-v1";
pub const AUTH_SCHEME: &str = "CipherSig";

#[derive(Debug)]
pub struct CanonicalParts<'a> {
    pub audience: &'a str,
    pub method: &'a str,
    pub path_and_query: &'a str,
    pub timestamp: u64,
    pub nonce: &'a [u8; 16],
    pub body: &'a [u8],
    pub device: &'a Id16,
}

pub fn canonical_string(p: &CanonicalParts<'_>) -> Vec<u8> {
    canonical_string_with_hash(p, &Sha256::digest(p.body).into())
}

/// Same canonical string for a body whose SHA-256 was computed incrementally (large file uploads);
/// `p.body` is ignored.
pub fn canonical_string_with_hash(p: &CanonicalParts<'_>, body_hash: &[u8; 32]) -> Vec<u8> {
    let mut s = String::new();
    s.push_str(SIG_CONTEXT);
    for field in [
        p.audience,
        p.method,
        p.path_and_query,
        &p.timestamp.to_string(),
        &crate::b64::encode(p.nonce),
        &crate::b64::encode(body_hash),
        &p.device.to_hex(),
    ] {
        s.push('\n');
        s.push_str(field);
    }
    s.into_bytes()
}

/// Parsed `Authorization` header value.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthHeader {
    pub device: Id16,
    pub timestamp: u64,
    pub nonce: [u8; 16],
    pub signature: [u8; 64],
    /// OPTIONAL claimed SHA-256 of the request body (`bh=`). When present it is what the signature covers, which lets the server verify
    /// the signature BEFORE it reads a large body (final review FR-10: without it the relay buffered up to 101 MiB of body per
    /// connection before it could authenticate anyone). The server still checks that the body really hashes to it.
    pub body_hash: Option<[u8; 32]>,
}

pub fn format_auth_header(h: &AuthHeader) -> String {
    let base = format!(
        "{AUTH_SCHEME} v1 device={} ts={} nonce={} sig={}",
        h.device,
        h.timestamp,
        crate::b64::encode(&h.nonce),
        crate::b64::encode(&h.signature)
    );
    match &h.body_hash {
        Some(bh) => format!("{base} bh={}", crate::b64::encode(bh)),
        None => base,
    }
}

pub fn parse_auth_header(v: &str) -> Option<AuthHeader> {
    if v.len() > 512 {
        return None;
    }
    let mut it = v.split(' ');
    if it.next()? != AUTH_SCHEME || it.next()? != "v1" {
        return None;
    }
    let (mut device, mut ts, mut nonce, mut sig, mut bh) = (None, None, None, None, None);
    for kv in it {
        let (k, val) = kv.split_once('=')?;
        match k {
            "device" if device.is_none() => device = Id16::parse(val).ok(),
            "ts" if ts.is_none() => ts = val.parse::<u64>().ok(),
            "nonce" if nonce.is_none() => nonce = crate::b64::decode(val)?.try_into().ok(),
            "sig" if sig.is_none() => sig = crate::b64::decode(val)?.try_into().ok(),
            "bh" if bh.is_none() => bh = Some(crate::b64::decode(val)?.try_into().ok()?),
            _ => return None,
        }
    }
    Some(AuthHeader { device: device?, timestamp: ts?, nonce: nonce?, signature: sig?, body_hash: bh })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn header_parser_never_panics(s in ".{0,600}") {
            let _ = parse_auth_header(&s);
        }
    }

    #[test]
    fn header_roundtrip() {
        let h = AuthHeader { device: Id16([7; 16]), timestamp: 1_700_000_000, nonce: [9; 16], signature: [3; 64], body_hash: None };
        assert_eq!(parse_auth_header(&format_auth_header(&h)), Some(h));
    }

    #[test]
    fn body_hash_roundtrips_and_garbage_is_rejected() {
        let h = AuthHeader { device: Id16([7; 16]), timestamp: 1, nonce: [9; 16], signature: [3; 64], body_hash: Some([5; 32]) };
        let good = format_auth_header(&h);
        assert_eq!(parse_auth_header(&good), Some(h));
        assert!(parse_auth_header(&format!("{good} bh={}", crate::b64::encode(&[1u8; 32]))).is_none(), "duplicate bh");
        let short = good.replace(&crate::b64::encode(&[5u8; 32]), &crate::b64::encode(&[5u8; 31]));
        assert!(parse_auth_header(&short).is_none(), "wrong-length hash");
    }

    #[test]
    fn duplicate_or_unknown_fields_rejected() {
        let h = AuthHeader { device: Id16([7; 16]), timestamp: 1, nonce: [9; 16], signature: [3; 64], body_hash: None };
        let good = format_auth_header(&h);
        assert!(parse_auth_header(&format!("{good} ts=2")).is_none());
        assert!(parse_auth_header(&format!("{good} extra=1")).is_none());
    }

    #[test]
    fn canonical_binds_every_field() {
        let dev = Id16([1; 16]);
        let n = [2u8; 16];
        let base =
            CanonicalParts { audience: "a", method: "POST", path_and_query: "/v1/x", timestamp: 5, nonce: &n, body: b"b", device: &dev };
        let c0 = canonical_string(&base);
        let variants = [
            CanonicalParts {
                audience: "b",
                ..CanonicalParts {
                    audience: "a",
                    method: "POST",
                    path_and_query: "/v1/x",
                    timestamp: 5,
                    nonce: &n,
                    body: b"b",
                    device: &dev,
                }
            },
            CanonicalParts { audience: "a", method: "GET", path_and_query: "/v1/x", timestamp: 5, nonce: &n, body: b"b", device: &dev },
            CanonicalParts { audience: "a", method: "POST", path_and_query: "/v1/y", timestamp: 5, nonce: &n, body: b"b", device: &dev },
            CanonicalParts { audience: "a", method: "POST", path_and_query: "/v1/x", timestamp: 6, nonce: &n, body: b"b", device: &dev },
            CanonicalParts { audience: "a", method: "POST", path_and_query: "/v1/x", timestamp: 5, nonce: &n, body: b"c", device: &dev },
        ];
        for v in &variants {
            assert_ne!(canonical_string(v), c0);
        }
    }
}
