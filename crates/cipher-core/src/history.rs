//! Group HISTORY ACCESS layer (see `docs/HISTORY_REVOCATION.md`).
//!
//! Stored group messages are sealed under keys that depend on MLS epoch secrets, so that a member who is removed — and whose
//! compliant client therefore deletes its copy of the keys — loses Cipher-controlled access to retained history, while remaining
//! members keep theirs.
//!
//! ```text
//!   MLS epoch secrets (RFC 9420)
//!        │  exporter("cipher/history/epoch-key/v1", group_id ‖ epoch)          (only members OF THAT EPOCH can compute it)
//!        ▼
//!   epoch history key  HEK_e   (32 bytes, stored in the vault under `hk`, one per epoch the device was a member)
//!        │  HKDF-SHA256(info = "cipher/history/msg-key/v1" ‖ group ‖ epoch ‖ message_id)
//!        ▼
//!   message key MK     (derived on demand, never stored)
//!        │  XChaCha20-Poly1305, random 24-byte nonce, AAD binds group, epoch, message id, sender
//!        ▼
//!   sealed message body (stored in the vault record in place of the plaintext content)
//! ```
//!
//! * No primitive is invented: MLS exporter, HKDF-SHA256 and XChaCha20-Poly1305 are the ones Cipher already uses.
//! * There is **no permanent master key**: keys are per epoch, and every membership change advances the epoch.
//! * A device that joins at epoch `e` never has `HEK_{<e}` (no pre-join history); a device removed at epoch `r` cannot compute `HEK_{>=r}`.
//! * Revocation (`delete_all_epoch_keys`) removes every `HEK_e` of a group from the vault: all sealed bodies become permanently undecryptable
//!   on that device, without touching the (small number of) message records.
//! * The relay never sees any of this: the keys are derived from MLS secrets it does not have.
use crate::app::model::Content;
use crate::error::{Result, SecurityError};
use crate::storage::EncryptedStore;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use cipher_wire::Id16;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const EXPORTER_LABEL: &str = "cipher/history/epoch-key/v1";
const MSG_INFO: &[u8] = b"cipher/history/msg-key/v1";
const AAD_CTX: &[u8] = b"cipher/history/body/v1";
/// Vault namespace of epoch history keys: id = `<conversation hex>-<epoch as 16 hex digits>`.
pub const NS_HIST: &str = "hk";
/// Vault namespace of revocation tombstones: id = conversation hex, value = big-endian epoch at which access ended.
pub const NS_REVOKED: &str = "revoked";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBody {
    #[serde(with = "cipher_wire::b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "cipher_wire::b64")]
    pub ct: Vec<u8>,
}

fn key_id(conv: &Id16, epoch: u64) -> String {
    format!("{}-{epoch:016x}", conv.to_hex())
}

pub fn put_epoch_key(s: &mut EncryptedStore, conv: &Id16, epoch: u64, key: &[u8; 32]) -> Result<()> {
    s.put(NS_HIST, &key_id(conv, epoch), key)
}

pub fn get_epoch_key(s: &EncryptedStore, conv: &Id16, epoch: u64) -> Result<Option<Zeroizing<[u8; 32]>>> {
    match s.get(NS_HIST, &key_id(conv, epoch))? {
        None => Ok(None),
        Some(b) => {
            let k: [u8; 32] = b.as_slice().try_into().map_err(|_| SecurityError::StorageCorrupt)?;
            Ok(Some(Zeroizing::new(k)))
        }
    }
}

/// Epochs for which this device still holds a history key.
pub fn epochs_held(s: &EncryptedStore, conv: &Id16) -> Result<Vec<u64>> {
    let prefix = format!("{}-", conv.to_hex());
    let mut v: Vec<u64> =
        s.list_ids(NS_HIST)?.into_iter().filter_map(|id| id.strip_prefix(&prefix).and_then(|e| u64::from_str_radix(e, 16).ok())).collect();
    v.sort_unstable();
    Ok(v)
}

/// Cryptographic erasure of a group's history on this device. Returns how many keys were deleted. (SQLite runs with `secure_delete`; flash
/// wear-levelling means physical overwrite is not guaranteed — the guarantee is that no reference to the key remains.)
pub fn delete_all_epoch_keys(s: &mut EncryptedStore, conv: &Id16) -> Result<usize> {
    let prefix = format!("{}-", conv.to_hex());
    let ids: Vec<String> = s.list_ids(NS_HIST)?.into_iter().filter(|i| i.starts_with(&prefix)).collect();
    for id in &ids {
        s.delete(NS_HIST, id)?;
    }
    Ok(ids.len())
}

pub fn put_tombstone(s: &mut EncryptedStore, conv: &Id16, epoch: u64) -> Result<()> {
    s.put(NS_REVOKED, &conv.to_hex(), &epoch.to_be_bytes())
}

pub fn tombstone(s: &EncryptedStore, conv: &Id16) -> Result<Option<u64>> {
    match s.get(NS_REVOKED, &conv.to_hex())? {
        None => Ok(None),
        Some(b) => Ok(Some(u64::from_be_bytes(b.as_slice().try_into().map_err(|_| SecurityError::StorageCorrupt)?))),
    }
}

fn message_key(hek: &[u8; 32], conv: &Id16, epoch: u64, msg: &Id16) -> Result<Zeroizing<[u8; 32]>> {
    let mut info = Vec::with_capacity(MSG_INFO.len() + 40);
    info.extend_from_slice(MSG_INFO);
    info.extend_from_slice(&conv.0);
    info.extend_from_slice(&epoch.to_be_bytes());
    info.extend_from_slice(&msg.0);
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, hek).expand(&info, out.as_mut_slice()).map_err(|_| SecurityError::CryptoAuthFailed)?;
    Ok(out)
}

fn aad(conv: &Id16, epoch: u64, msg: &Id16, sender: &Id16) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_CTX.len() + 56);
    a.extend_from_slice(AAD_CTX);
    a.extend_from_slice(&conv.0);
    a.extend_from_slice(&epoch.to_be_bytes());
    a.extend_from_slice(&msg.0);
    a.extend_from_slice(&sender.0);
    a
}

pub fn seal(hek: &[u8; 32], conv: &Id16, epoch: u64, msg: &Id16, sender: &Id16, content: &Content) -> Result<SealedBody> {
    let pt = Zeroizing::new(serde_json::to_vec(content).map_err(|_| SecurityError::Malformed("encode content"))?);
    let mk = message_key(hek, conv, epoch, msg)?;
    let nonce = crate::rng::array::<24>()?;
    let ct = XChaCha20Poly1305::new(Key::from_slice(mk.as_slice()))
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &pt, aad: &aad(conv, epoch, msg, sender) })
        .map_err(|_| SecurityError::CryptoAuthFailed)?;
    Ok(SealedBody { nonce: nonce.to_vec(), ct })
}

pub fn unseal(hek: &[u8; 32], conv: &Id16, epoch: u64, msg: &Id16, sender: &Id16, b: &SealedBody) -> Result<Content> {
    if b.nonce.len() != 24 {
        return Err(SecurityError::StorageCorrupt);
    }
    let mk = message_key(hek, conv, epoch, msg)?;
    let pt = XChaCha20Poly1305::new(Key::from_slice(mk.as_slice()))
        .decrypt(XNonce::from_slice(&b.nonce), Payload { msg: &b.ct, aad: &aad(conv, epoch, msg, sender) })
        .map_err(|_| SecurityError::CryptoAuthFailed)?;
    let pt = Zeroizing::new(pt);
    serde_json::from_slice(&pt).map_err(|_| SecurityError::StorageCorrupt)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn id(b: u8) -> Id16 {
        Id16([b; 16])
    }

    #[test]
    fn seal_roundtrips_and_is_bound_to_group_epoch_message_and_sender() {
        let hek = [7u8; 32];
        let c = Content::Text { body: "HISTORY-CANARY".into() };
        let s = seal(&hek, &id(1), 5, &id(2), &id(3), &c).unwrap();
        assert!(!s.ct.windows(14).any(|w| w == b"HISTORY-CANARY"));
        assert_eq!(unseal(&hek, &id(1), 5, &id(2), &id(3), &s).unwrap(), c);
        for (g, e, m, snd) in [(9, 5, 2, 3), (1, 6, 2, 3), (1, 5, 9, 3), (1, 5, 2, 9)] {
            assert!(unseal(&hek, &id(g), e, &id(m), &id(snd), &s).is_err(), "context {g},{e},{m},{snd} must not unseal");
        }
        assert!(unseal(&[8u8; 32], &id(1), 5, &id(2), &id(3), &s).is_err(), "another epoch key must not unseal");
        let mut t = s.clone();
        t.ct[3] ^= 1;
        assert!(unseal(&hek, &id(1), 5, &id(2), &id(3), &t).is_err());
    }

    #[test]
    fn sealing_is_randomised() {
        let hek = [1u8; 32];
        let c = Content::Text { body: "x".into() };
        assert_ne!(seal(&hek, &id(1), 1, &id(1), &id(1), &c).unwrap().ct, seal(&hek, &id(1), 1, &id(1), &id(1), &c).unwrap().ct);
    }
}
