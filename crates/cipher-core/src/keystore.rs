//! Secure key storage abstraction (SEC-008, SEC-009).
//!
//! The OS keystore (Android Keystore: StrongBox / TEE / software) is modelled
//! as a *wrapping oracle*: it holds non-exportable keys and wraps/unwraps small
//! secrets. Raw key bytes of the keystore never cross this boundary, so the core
//! never handles them. The native modules in `mobile/` implement this contract.
//!
//! The store reports the protection level it actually achieved; the core refuses
//! to continue below the configured minimum instead of silently downgrading.
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProtectionLevel {
    /// Test doubles / no real protection. Never acceptable in production.
    Insecure = 0,
    /// OS-managed software keystore (no hardware isolation).
    OsSoftware = 1,
    /// Hardware-backed (Android TEE).
    HardwareBacked = 2,
    /// Dedicated secure element (Android StrongBox).
    SecureElement = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    Android,
    Test,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub platform: Platform,
    /// Best level this device can offer (what a new key would get).
    pub best_level: ProtectionLevel,
    pub user_auth_supported: bool,
    pub biometric_supported: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPolicy {
    /// Using the key requires fresh user authentication (biometric / device credential).
    pub require_user_auth: bool,
    /// Key becomes permanently unusable if biometric enrolment changes.
    pub invalidate_on_biometric_change: bool,
    /// Prefer StrongBox; fall back to best available (reported, not hidden).
    pub prefer_secure_element: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum KeyStoreError {
    #[error("key not found")]
    Missing,
    #[error("key permanently invalidated")]
    Invalidated,
    #[error("user authentication required")]
    AuthRequired,
    #[error("user authentication cancelled")]
    AuthCancelled,
    #[error("wrapped blob failed authentication")]
    Corrupt,
    #[error("keystore unavailable: {0}")]
    Unavailable(&'static str),
}

pub trait SecureKeyStore: Send + Sync {
    fn capabilities(&self) -> Capabilities;
    /// Create (or fail if exists) a non-exportable wrapping key. Returns the
    /// protection level actually achieved for this key.
    fn create_key(&self, alias: &str, policy: &KeyPolicy) -> Result<ProtectionLevel, KeyStoreError>;
    fn key_protection(&self, alias: &str) -> Result<ProtectionLevel, KeyStoreError>;
    /// AEAD-wrap `plaintext`, binding `aad`.
    fn wrap(&self, alias: &str, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, KeyStoreError>;
    /// May trigger a user-authentication prompt natively.
    fn unwrap(&self, alias: &str, blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyStoreError>;
    fn delete_key(&self, alias: &str) -> Result<(), KeyStoreError>;
    /// Monotonic generation counter held by the platform keystore, OUTSIDE the app's data directory (0 when none exists yet).
    /// Used for local rollback detection: restoring an older copy of the app's files cannot lower it.
    fn counter_read(&self) -> Result<u64, KeyStoreError>;
    /// Raises the counter to `to` (never lowers it).
    fn counter_advance(&self, to: u64) -> Result<(), KeyStoreError>;
}

#[cfg(any(test, feature = "insecure-test-support"))]
pub mod testing {
    //! In-memory fake. Reports `Insecure` by default so production policy rejects it.
    use super::*;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Entry {
        key: [u8; 32],
        level: Option<ProtectionLevel>,
        require_auth: bool,
        invalidated: bool,
    }

    pub struct InMemoryKeyStore {
        keys: Mutex<HashMap<String, Entry>>,
        level: Mutex<ProtectionLevel>,
        auth_ok: Mutex<bool>,
        counter: Mutex<u64>,
    }

    impl std::fmt::Debug for InMemoryKeyStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("InMemoryKeyStore(<redacted>)")
        }
    }

    impl InMemoryKeyStore {
        pub fn counter_advance_for_tests(&self, to: u64) {
            let _ = SecureKeyStore::counter_advance(self, to);
        }

        pub fn new(level: ProtectionLevel) -> Self {
            Self { keys: Mutex::default(), level: Mutex::new(level), auth_ok: Mutex::new(true), counter: Mutex::new(0) }
        }
        /// Simulate the user failing/cancelling the biometric prompt.
        pub fn set_auth_ok(&self, ok: bool) {
            *self.auth_ok.lock().unwrap_or_else(|e| e.into_inner()) = ok;
        }
        /// Simulate OS invalidation (e.g. biometric enrolment change, passcode removal).
        pub fn invalidate(&self, alias: &str) {
            if let Some(e) = self.keys.lock().unwrap_or_else(|e| e.into_inner()).get_mut(alias) {
                e.invalidated = true;
            }
        }
        /// Simulate key loss (e.g. restore to a new device).
        pub fn remove_silently(&self, alias: &str) {
            self.keys.lock().unwrap_or_else(|e| e.into_inner()).remove(alias);
        }
    }

    impl SecureKeyStore for InMemoryKeyStore {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                platform: Platform::Test,
                best_level: *self.level.lock().unwrap_or_else(|e| e.into_inner()),
                user_auth_supported: true,
                biometric_supported: true,
            }
        }
        fn create_key(&self, alias: &str, policy: &KeyPolicy) -> Result<ProtectionLevel, KeyStoreError> {
            let mut g = self.keys.lock().unwrap_or_else(|e| e.into_inner());
            if g.contains_key(alias) {
                return Err(KeyStoreError::Unavailable("alias exists"));
            }
            let mut key = [0u8; 32];
            crate::rng::fill(&mut key).map_err(|_| KeyStoreError::Unavailable("rng"))?;
            let level = *self.level.lock().unwrap_or_else(|e| e.into_inner());
            g.insert(alias.to_owned(), Entry { key, level: Some(level), require_auth: policy.require_user_auth, invalidated: false });
            Ok(level)
        }
        fn key_protection(&self, alias: &str) -> Result<ProtectionLevel, KeyStoreError> {
            let g = self.keys.lock().unwrap_or_else(|e| e.into_inner());
            let e = g.get(alias).ok_or(KeyStoreError::Missing)?;
            if e.invalidated {
                return Err(KeyStoreError::Invalidated);
            }
            e.level.ok_or(KeyStoreError::Missing)
        }
        fn wrap(&self, alias: &str, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
            let g = self.keys.lock().unwrap_or_else(|e| e.into_inner());
            let e = g.get(alias).ok_or(KeyStoreError::Missing)?;
            if e.invalidated {
                return Err(KeyStoreError::Invalidated);
            }
            let mut nonce = [0u8; 24];
            crate::rng::fill(&mut nonce).map_err(|_| KeyStoreError::Unavailable("rng"))?;
            let c = XChaCha20Poly1305::new(Key::from_slice(&e.key));
            let ct = c.encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad }).map_err(|_| KeyStoreError::Corrupt)?;
            let mut out = nonce.to_vec();
            out.extend_from_slice(&ct);
            Ok(out)
        }
        fn unwrap(&self, alias: &str, blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
            let g = self.keys.lock().unwrap_or_else(|e| e.into_inner());
            let e = g.get(alias).ok_or(KeyStoreError::Missing)?;
            if e.invalidated {
                return Err(KeyStoreError::Invalidated);
            }
            if e.require_auth && !*self.auth_ok.lock().unwrap_or_else(|e| e.into_inner()) {
                return Err(KeyStoreError::AuthCancelled);
            }
            if blob.len() < 24 + 16 {
                return Err(KeyStoreError::Corrupt);
            }
            let (nonce, ct) = blob.split_at(24);
            let c = XChaCha20Poly1305::new(Key::from_slice(&e.key));
            c.decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad }).map(Zeroizing::new).map_err(|_| KeyStoreError::Corrupt)
        }
        fn counter_read(&self) -> Result<u64, KeyStoreError> {
            Ok(*self.counter.lock().unwrap_or_else(|e| e.into_inner()))
        }
        fn counter_advance(&self, to: u64) -> Result<(), KeyStoreError> {
            let mut c = self.counter.lock().unwrap_or_else(|e| e.into_inner());
            *c = (*c).max(to);
            Ok(())
        }
        fn delete_key(&self, alias: &str) -> Result<(), KeyStoreError> {
            self.keys.lock().unwrap_or_else(|e| e.into_inner()).remove(alias);
            Ok(())
        }
    }
}
