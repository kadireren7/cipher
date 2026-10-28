//! Invitation cryptography (docs/INVITATIONS.md §3, §4, §6).
//!
//! One 128-bit secret `s` per invitation; everything else is derived from it with HKDF-SHA-256 under distinct labels, so no derived value reveals
//! another and none reveals `s`:
//!
//! * `id`    : what the relay is asked for (the relay stores only `id_hash(id)`);
//! * `k_enc` : the AEAD key of the PREVIEW, so the relay cannot read the group name or the inviter;
//! * `k_req` : the AEAD key of a JOIN REQUEST. Producing a request that opens under it proves possession of the link, and the relay (which knows
//!   `id` but not `s`) can neither read a request nor forge one the issuer would accept. The request itself is additionally signed by the joiner's
//!   identity key (see `app::engine_invite`), so a link holder cannot add somebody else's account.
//!
//! No MLS group secret, epoch secret or private identity key is ever an input or an output here.
use crate::error::{Result, SecurityError};
use crate::rng;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use cipher_wire::invite::{SECRET_LEN, VERSION};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const SALT: &[u8] = b"cipher-inv-v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// A preview is a group name, a display name and a public identity: kilobytes would only be an attempt to hide something in it.
pub const MAX_PREVIEW_LEN: usize = 2048;
/// A join request is a signed contact card plus a short name: well under this.
pub const MAX_REQUEST_LEN: usize = 4096;

/// The invitation secret. Zeroised on drop; `Debug` is redacted.
pub struct InviteSecret(Zeroizing<[u8; SECRET_LEN]>);

impl core::fmt::Debug for InviteSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("InviteSecret(<redacted>)")
    }
}

impl InviteSecret {
    pub fn generate() -> Result<Self> {
        Ok(Self(Zeroizing::new(rng::array::<SECRET_LEN>()?)))
    }

    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }

    pub fn keys(&self) -> InviteKeys {
        let hk = Hkdf::<Sha256>::new(Some(SALT), self.0.as_slice());
        let mut id = [0u8; 16];
        let mut k_enc = Zeroizing::new([0u8; 32]);
        let mut k_req = Zeroizing::new([0u8; 32]);
        // Output lengths are far below the HKDF limit (255 * 32 bytes): these cannot fail.
        let _ = hk.expand(b"cipher-inv-v1/id", &mut id);
        let _ = hk.expand(b"cipher-inv-v1/enc", k_enc.as_mut_slice());
        let _ = hk.expand(b"cipher-inv-v1/req", k_req.as_mut_slice());
        InviteKeys { id, k_enc, k_req }
    }
}

pub struct InviteKeys {
    id: [u8; 16],
    k_enc: Zeroizing<[u8; 32]>,
    k_req: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for InviteKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("InviteKeys(<redacted>)")
    }
}

impl InviteKeys {
    /// The identifier the relay is asked for. It is not secret from the relay (it sees it on every use) and it is not `s`.
    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }

    /// `id || version || kind`: ties a blob to ONE invitation and to ONE purpose, so a preview can never be replayed as a request or vice versa.
    fn aad(&self, kind: u8) -> [u8; 18] {
        let mut a = [0u8; 18];
        a[..16].copy_from_slice(&self.id);
        a[16] = VERSION;
        a[17] = kind;
        a
    }

    fn seal(&self, key: &[u8; 32], kind: u8, plaintext: &[u8], max: usize) -> Result<Vec<u8>> {
        if plaintext.len() > max {
            return Err(SecurityError::Malformed("invitation blob too large"));
        }
        let nonce: [u8; NONCE_LEN] = rng::array()?;
        let ct = ChaCha20Poly1305::new(Key::from_slice(key))
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &self.aad(kind) })
            .map_err(|_| SecurityError::CryptoAuthFailed)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn open(&self, key: &[u8; 32], kind: u8, blob: &[u8], max: usize) -> Result<Vec<u8>> {
        if blob.len() < NONCE_LEN + TAG_LEN || blob.len() > NONCE_LEN + max + TAG_LEN {
            return Err(SecurityError::Malformed("invitation blob size"));
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        ChaCha20Poly1305::new(Key::from_slice(key))
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &self.aad(kind) })
            .map_err(|_| SecurityError::CryptoAuthFailed)
    }

    /// `nonce(12) || ChaCha20-Poly1305(k_enc, plaintext, aad = id || version || 'P')`.
    pub fn seal_preview(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.seal(&self.k_enc, b'P', plaintext, MAX_PREVIEW_LEN)
    }

    pub fn open_preview(&self, blob: &[u8]) -> Result<Vec<u8>> {
        self.open(&self.k_enc, b'P', blob, MAX_PREVIEW_LEN)
    }

    /// `nonce(12) || ChaCha20-Poly1305(k_req, plaintext, aad = id || version || 'R')`. Only a holder of the link can produce one that opens.
    pub fn seal_request(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.seal(&self.k_req, b'R', plaintext, MAX_REQUEST_LEN)
    }

    pub fn open_request(&self, blob: &[u8]) -> Result<Vec<u8>> {
        self.open(&self.k_req, b'R', blob, MAX_REQUEST_LEN)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn keys(b: u8) -> InviteKeys {
        InviteSecret::from_bytes([b; SECRET_LEN]).keys()
    }

    #[test]
    fn derivation_is_deterministic_and_every_output_differs() {
        let a = keys(1);
        let again = keys(1);
        assert_eq!(a.id(), again.id());
        assert_eq!(a.k_enc.as_slice(), again.k_enc.as_slice());
        assert_eq!(a.k_req.as_slice(), again.k_req.as_slice());
        let b = keys(2);
        assert_ne!(a.id(), b.id());
        assert_ne!(a.k_enc.as_slice(), b.k_enc.as_slice());
        assert_ne!(a.k_req.as_slice(), b.k_req.as_slice());
        // the preview key and the request key are independent, and neither is the id or the secret
        assert_ne!(a.k_enc.as_slice(), a.k_req.as_slice());
        assert_ne!(&a.k_enc[..16], a.id().as_slice());
        assert_ne!(&a.k_enc[..16], [1u8; 16].as_slice());
        assert_ne!(&a.k_req[..16], [1u8; 16].as_slice());
    }

    #[test]
    fn secrets_are_random_and_never_printed() {
        let s: HashSet<[u8; 16]> = (0..64).map(|_| *InviteSecret::generate().unwrap().as_bytes()).collect();
        assert_eq!(s.len(), 64);
        let shown = format!("{:?} {:?}", InviteSecret::from_bytes([0xCD; 16]), keys(3));
        assert!(shown.contains("redacted"));
        assert!(!shown.to_lowercase().contains("cdcd") && !shown.contains("205"));
    }

    #[test]
    fn a_preview_round_trips_and_is_not_readable_without_the_secret() {
        let k = keys(1);
        let blob = k.seal_preview(b"Friends, invited by Mira").unwrap();
        assert_eq!(k.open_preview(&blob).unwrap(), b"Friends, invited by Mira");
        assert!(!blob.windows(7).any(|w| w == b"Friends"), "plaintext must not appear in the ciphertext");
        assert!(keys(2).open_preview(&blob).is_err(), "another invitation's keys do not open it");
    }

    #[test]
    fn any_change_to_a_preview_is_detected() {
        let k = keys(1);
        let blob = k.seal_preview(b"hello").unwrap();
        for i in 0..blob.len() {
            let mut t = blob.clone();
            t[i] ^= 1;
            assert!(k.open_preview(&t).is_err(), "byte {i}");
        }
        for n in 0..blob.len() {
            assert!(k.open_preview(&blob[..n]).is_err(), "truncated to {n}");
        }
        assert!(k.open_preview(&[blob.clone(), vec![0]].concat()).is_err());
    }

    #[test]
    fn a_preview_is_bound_to_its_invitation_id() {
        // Same key material but a different id (as if a relay moved the blob to another invitation row) must not open.
        let k = keys(1);
        let blob = k.seal_preview(b"x").unwrap();
        let moved = InviteKeys { id: [9u8; 16], k_enc: Zeroizing::new(*k.k_enc), k_req: Zeroizing::new(*k.k_req) };
        assert!(moved.open_preview(&blob).is_err());
    }

    #[test]
    fn nonces_are_never_reused_and_oversize_is_refused() {
        let k = keys(1);
        let nonces: HashSet<Vec<u8>> = (0..500).map(|_| k.seal_preview(b"same").unwrap()[..NONCE_LEN].to_vec()).collect();
        assert_eq!(nonces.len(), 500);
        assert!(k.seal_preview(&vec![0u8; MAX_PREVIEW_LEN]).is_ok());
        assert!(k.seal_preview(&vec![0u8; MAX_PREVIEW_LEN + 1]).is_err());
        assert!(k.open_preview(&vec![0u8; NONCE_LEN + MAX_PREVIEW_LEN + TAG_LEN + 1]).is_err());
    }

    #[test]
    fn a_request_opens_only_for_a_holder_of_the_link() {
        let k = keys(1);
        let req = b"signed join request";
        let blob = k.seal_request(req).unwrap();
        assert_eq!(k.open_request(&blob).unwrap(), req);
        // a relay that only knows the id (not s) derives different keys: it can neither read nor forge a request the issuer would accept
        assert!(keys(2).open_request(&blob).is_err());
        assert!(k.open_request(&keys(2).seal_request(req).unwrap()).is_err());
        for i in 0..blob.len() {
            let mut t = blob.clone();
            t[i] ^= 1;
            assert!(k.open_request(&t).is_err(), "byte {i}");
        }
        for n in 0..blob.len() {
            assert!(k.open_request(&blob[..n]).is_err(), "truncated to {n}");
        }
        assert!(k.seal_request(&vec![0u8; MAX_REQUEST_LEN]).is_ok());
        assert!(k.seal_request(&vec![0u8; MAX_REQUEST_LEN + 1]).is_err());
    }

    #[test]
    fn a_preview_and_a_request_cannot_stand_in_for_each_other() {
        let k = keys(1);
        let preview = k.seal_preview(b"x").unwrap();
        let request = k.seal_request(b"x").unwrap();
        assert!(k.open_request(&preview).is_err(), "a preview is not a request");
        assert!(k.open_preview(&request).is_err(), "a request is not a preview");
        // even with the SAME key, the purpose byte in the AAD separates them
        let same_key = k.seal(&k.k_enc, b'R', b"x", MAX_REQUEST_LEN).unwrap();
        assert!(k.open_preview(&same_key).is_err());
    }
}
