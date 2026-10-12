//! Contact Card v1 (docs/MULTI_RELAY_PROTOCOL.md §3): a small, versioned, signed invitation that lets a person on ANY relay start a conversation with
//! the issuer without an account on the issuer's relay.
//!
//! Layout: `"CCD1" | payload_len(u16 BE) | payload | signature(64)`, base64url for transport (QR / link). `payload` is JSON whose exact bytes are
//! signed with the issuer's ROOT identity key under the domain `"cipher-card-v1\0"`.
//!
//! What the signature gives: nobody without the root key can change the relay, the intro capability or the expiry of a card they relay.
//! What it does NOT give: if the whole card is replaced, the recipient pins a different identity — only comparing safety numbers / scanning in person detects that.
use crate::error::{Result, SecurityError};
use crate::mls::MlsClient;
use cipher_wire::{b64, Id16, RelayDescriptor};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const CARD_MAGIC: &[u8; 4] = b"CCD1";
const DOMAIN: &[u8] = b"cipher-card-v1\0";
/// A card is an invitation, not an identity document: short-lived, and never outliving the intro capability it names (relay caps live 30 days).
pub const MAX_CARD_LIFETIME_MS: u64 = 30 * 24 * 3600 * 1000;
const MAX_PAYLOAD: usize = 1024;
/// Tolerated clock skew when checking `issued`.
const SKEW_MS: u64 = 10 * 60 * 1000;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    v: u8,
    account: Id16,
    root_key: String,
    relay: RelayDescriptor,
    intro: Id16,
    issued: u64,
    expires: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactCard {
    pub account: Id16,
    pub root_key: [u8; 32],
    pub relay: RelayDescriptor,
    pub intro: Id16,
    pub issued_ms: u64,
    pub expires_ms: u64,
}

fn signed_message(payload: &[u8]) -> Vec<u8> {
    let mut m = DOMAIN.to_vec();
    m.extend_from_slice(payload);
    m
}

impl ContactCard {
    /// Issue a card. Only the account's ROOT device may issue (its identity key is the key the card names); `intro` must be an intro capability
    /// the caller minted at `relay` (that is the caller's responsibility, enforced by the engine).
    pub fn issue(mls: &MlsClient, relay: RelayDescriptor, intro: Id16, now_ms: u64, lifetime_ms: u64) -> Result<String> {
        if lifetime_ms == 0 || lifetime_ms > MAX_CARD_LIFETIME_MS {
            return Err(SecurityError::Malformed("card lifetime"));
        }
        let relay = relay.validated().map_err(|_| SecurityError::Malformed("card relay"))?;
        let p = Payload {
            v: 1,
            account: mls.account_id(),
            root_key: b64::encode(&mls.identity_public()),
            relay,
            intro,
            issued: now_ms,
            expires: now_ms.checked_add(lifetime_ms).ok_or(SecurityError::Malformed("card lifetime"))?,
        };
        let payload = serde_json::to_vec(&p).map_err(|_| SecurityError::Malformed("card"))?;
        let len = u16::try_from(payload.len()).map_err(|_| SecurityError::Malformed("card too large"))?;
        if payload.len() > MAX_PAYLOAD {
            return Err(SecurityError::Malformed("card too large"));
        }
        let sig = mls.sign_identity_raw(&signed_message(&payload))?;
        let mut out = CARD_MAGIC.to_vec();
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&payload);
        out.extend_from_slice(&sig);
        Ok(b64::encode(&out))
    }

    /// Strict parse + signature + freshness. Any deviation is an error; nothing is returned for a card that is expired, from the future,
    /// signed by a key other than the one it names, or carries a relay descriptor that is not canonical.
    pub fn parse(text: &str, now_ms: u64) -> Result<Self> {
        let bytes = b64::decode(text.trim()).ok_or(SecurityError::Malformed("card"))?;
        let (magic, rest) = bytes.split_at_checked(4).ok_or(SecurityError::Malformed("card"))?;
        if magic != CARD_MAGIC {
            return Err(SecurityError::Malformed("card"));
        }
        let (len, rest) = rest.split_at_checked(2).ok_or(SecurityError::Malformed("card"))?;
        let len = usize::from(u16::from_be_bytes(len.try_into().map_err(|_| SecurityError::Malformed("card"))?));
        if len == 0 || len > MAX_PAYLOAD || rest.len() != len + 64 {
            return Err(SecurityError::Malformed("card"));
        }
        let (payload, sig) = rest.split_at(len);
        let p: Payload = serde_json::from_slice(payload).map_err(|_| SecurityError::Malformed("card"))?;
        if p.v != 1 {
            return Err(SecurityError::Malformed("card version"));
        }
        let root_key: [u8; 32] = b64::decode(&p.root_key).and_then(|k| k.try_into().ok()).ok_or(SecurityError::Malformed("card key"))?;
        let vk = VerifyingKey::from_bytes(&root_key).map_err(|_| SecurityError::Malformed("card key"))?;
        let sig = Signature::from_slice(sig).map_err(|_| SecurityError::Malformed("card"))?;
        vk.verify(&signed_message(payload), &sig).map_err(|_| SecurityError::IdentityUntrusted("card signature invalid"))?;
        let relay = p.relay.validated().map_err(|_| SecurityError::Malformed("card relay"))?;
        if p.expires <= p.issued || p.expires - p.issued > MAX_CARD_LIFETIME_MS {
            return Err(SecurityError::Malformed("card lifetime"));
        }
        if p.issued > now_ms.saturating_add(SKEW_MS) {
            return Err(SecurityError::Malformed("card from the future"));
        }
        if now_ms >= p.expires {
            return Err(SecurityError::Malformed("card expired"));
        }
        Ok(Self { account: p.account, root_key, relay, intro: p.intro, issued_ms: p.issued, expires_ms: p.expires })
    }
}
