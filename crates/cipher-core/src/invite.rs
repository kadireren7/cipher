//! Invitation cryptography (docs/INVITATIONS.md §3, §4, §6).
//!
//! One 128-bit secret `s` per invitation; everything else is derived from it with HKDF-SHA-256 under distinct labels, so no derived value reveals
//! another and none reveals `s`:
//!
//! * `id`    : what the relay is asked for (the relay stores only `id_hash(id)`);
//! * `k_enc` : the AEAD key of the PREVIEW, so the relay cannot read the group name or the inviter;
//! * `k_mac` : binds a join request to possession of the link, so a relay that merely knows `id` cannot forge a request the admin would accept.
//!
//! No MLS group secret, epoch secret or private identity key is ever an input or an output here.
use crate::error::{Result, SecurityError};
use crate::rng;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use cipher_wire::invite::{SECRET_LEN, VERSION};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

const SALT: &[u8] = b"cipher-inv-v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// A preview is a group name, a display name and a public identity: kilobytes would only be an attempt to hide something in it.
pub const MAX_PREVIEW_LEN: usize = 2048;

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
        let mut k_mac = Zeroizing::new([0u8; 32]);
        // Output lengths are far below the HKDF limit (255 * 32 bytes): these cannot fail.
        let _ = hk.expand(b"cipher-inv-v1/id", &mut id);
        let _ = hk.expand(b"cipher-inv-v1/enc", k_enc.as_mut_slice());
        let _ = hk.expand(b"cipher-inv-v1/mac", k_mac.as_mut_slice());
        InviteKeys { id, k_enc, k_mac }
    }
}

pub struct InviteKeys {
    id: [u8; 16],
    k_enc: Zeroizing<[u8; 32]>,
    k_mac: Zeroizing<[u8; 32]>,
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

    fn aad(&self) -> [u8; 17] {
        let mut a = [0u8; 17];
        a[..16].copy_from_slice(&self.id);
        a[16] = VERSION;
        a
    }

    /// `nonce(12) || ChaCha20-Poly1305(k_enc, plaintext, aad = id || version)`. The AAD ties the blob to ONE invitation: a preview copied to
    /// another invitation does not open.
    pub fn seal_preview(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PREVIEW_LEN {
            return Err(SecurityError::Malformed("invitation preview too large"));
        }
        let nonce: [u8; NONCE_LEN] = rng::array()?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.k_enc.as_slice()));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &self.aad() })
            .map_err(|_| SecurityError::CryptoAuthFailed)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open_preview(&self, blob: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < NONCE_LEN + TAG_LEN || blob.len() > NONCE_LEN + MAX_PREVIEW_LEN + TAG_LEN {
            return Err(SecurityError::Malformed("invitation preview size"));
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        ChaCha20Poly1305::new(Key::from_slice(self.k_enc.as_slice()))
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &self.aad() })
            .map_err(|_| SecurityError::CryptoAuthFailed)
    }

    fn mac(&self, canonical: &[u8]) -> Hmac<Sha256> {
        // HMAC accepts any key length: this cannot fail.
        let mut m =
            <Hmac<Sha256> as Mac>::new_from_slice(self.k_mac.as_slice()).unwrap_or_else(|_| unreachable!("HMAC takes any key length"));
        m.update(b"cipher-join-v1\0");
        m.update(canonical);
        m
    }

    /// `HMAC-SHA256(k_mac, "cipher-join-v1\0" || canonical_request)`: proof that the requester holds the link.
    pub fn request_tag(&self, canonical: &[u8]) -> [u8; 32] {
        self.mac(canonical).finalize().into_bytes().into()
    }

    /// Constant-time verification. A wrong length, wrong key or any change to the request fails identically.
    pub fn verify_request_tag(&self, canonical: &[u8], tag: &[u8]) -> Result<()> {
        self.mac(canonical).verify_slice(tag).map_err(|_| SecurityError::CryptoAuthFailed)
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
        assert_eq!(a.k_mac.as_slice(), again.k_mac.as_slice());
        let b = keys(2);
        assert_ne!(a.id(), b.id());
        assert_ne!(a.k_enc.as_slice(), b.k_enc.as_slice());
        assert_ne!(a.k_mac.as_slice(), b.k_mac.as_slice());
        // the preview key and the MAC key are independent, and neither is the id or the secret
        assert_ne!(a.k_enc.as_slice(), a.k_mac.as_slice());
        assert_ne!(&a.k_enc[..16], a.id().as_slice());
        assert_ne!(&a.k_enc[..16], [1u8; 16].as_slice());
        assert_ne!(&a.k_mac[..16], [1u8; 16].as_slice());
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
        let moved = InviteKeys { id: [9u8; 16], k_enc: Zeroizing::new(*k.k_enc), k_mac: Zeroizing::new(*k.k_mac) };
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
    fn a_request_tag_proves_possession_of_the_link() {
        let k = keys(1);
        let req = b"canonical request bytes";
        let tag = k.request_tag(req);
        assert!(k.verify_request_tag(req, &tag).is_ok());
        // a relay that only knows the id (not s) derives different keys and cannot produce a tag the issuer accepts
        let relay_guess = keys(2).request_tag(req);
        assert!(k.verify_request_tag(req, &relay_guess).is_err());
        // any change to the request, and any bad tag length, fail the same way
        assert!(k.verify_request_tag(b"canonical request byteS", &tag).is_err());
        assert!(k.verify_request_tag(req, &tag[..31]).is_err());
        assert!(k.verify_request_tag(req, &[0u8; 32]).is_err());
        assert!(k.verify_request_tag(req, &[]).is_err());
        let mut flipped = tag;
        flipped[0] ^= 1;
        assert!(k.verify_request_tag(req, &flipped).is_err());
    }

    #[test]
    fn the_request_tag_is_domain_separated() {
        // It is not the bare HMAC of the message under the same key: the label keeps it from being a tag for anything else, and vice versa.
        let k = keys(1);
        let mut bare = <Hmac<Sha256> as Mac>::new_from_slice(k.k_mac.as_slice()).unwrap();
        bare.update(b"m");
        assert_ne!(k.request_tag(b"m").as_slice(), bare.finalize().into_bytes().as_slice());
    }
}
