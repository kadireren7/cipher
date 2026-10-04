//! Distributed token buckets. State lives in PostgreSQL (`take_tokens`), so every relay instance shares one
//! view and a client cannot multiply its budget by spreading requests across instances.
//!
//! Keys are `SHA-256(pepper || class || 0x00 || id)[..16]`: raw IP addresses and device ids are never stored,
//! and without the pepper a database dump cannot be reversed by enumerating the IPv4 space.
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct KeyHasher {
    pepper: [u8; 32],
}

impl std::fmt::Debug for KeyHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyHasher(<redacted>)")
    }
}

impl KeyHasher {
    pub fn new(pepper: [u8; 32]) -> Self {
        Self { pepper }
    }

    pub fn key(&self, class: &str, id: &[u8]) -> [u8; 16] {
        let mut h = Sha256::new();
        h.update(self.pepper);
        h.update(class.as_bytes());
        h.update([0u8]);
        h.update(id);
        let d = h.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(d.get(..16).unwrap_or(&[0u8; 16]));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_class_and_pepper_separated() {
        let a = KeyHasher::new([1; 32]);
        let b = KeyHasher::new([2; 32]);
        assert_ne!(a.key("ip", b"1.2.3.4"), a.key("device", b"1.2.3.4"));
        assert_ne!(a.key("ip", b"1.2.3.4"), b.key("ip", b"1.2.3.4"));
        assert_eq!(a.key("ip", b"x"), a.key("ip", b"x"));
    }
}
