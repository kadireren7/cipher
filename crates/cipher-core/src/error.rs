//! One explicit error type. Security failures are *errors*, never silent
//! fallbacks (fail-closed). Messages are static categories: they never embed
//! plaintext, key bytes, PINs or ciphertext.
use crate::keystore::{KeyStoreError, ProtectionLevel};

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("secure random generation failed")]
    Rng,
    #[error("authentication or decryption failed")]
    CryptoAuthFailed,
    #[error("malformed input: {0}")]
    Malformed(&'static str),
    #[error("secure key storage: {0}")]
    KeyStore(#[from] KeyStoreError),
    #[error("key protection {actual:?} is below required minimum {required:?}")]
    ProtectionBelowMinimum { required: ProtectionLevel, actual: ProtectionLevel },
    #[error("local storage is corrupted or was tampered with")]
    StorageCorrupt,
    #[error("local data is older than the last state this device recorded (restored or rolled back)")]
    StorageRolledBack,
    #[error("storage key does not match this database")]
    StorageWrongKey,
    #[error("KDF parameters are below the enforced security floor")]
    KdfParamsBelowFloor,
    #[error("application is locked")]
    Locked,
    #[error("key material was invalidated; recovery required")]
    Invalidated,
    #[error("too many attempts; retry in {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },
    #[error("wrong credential")]
    BadCredential,
    #[error("pin does not meet policy")]
    WeakPin,
    #[error("operation not valid in current state")]
    InvalidState,
    #[error("replayed or duplicate protocol message")]
    Replay,
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("peer identity is not trusted: {0}")]
    IdentityUntrusted(&'static str),
    #[error("attachment rejected: {0}")]
    Attachment(&'static str),
    #[error("commit not authorised: {0}")]
    Unauthorized(&'static str),
    #[error("message is for a future epoch and was held")]
    FutureEpoch,
    #[error("message is for an epoch that is no longer available")]
    StaleEpoch,
    #[error("not found: {0}")]
    NotFound(&'static str),
    #[error("denied: {0}")]
    Denied(&'static str),
    #[error("transport: {0}")]
    Transport(&'static str),
}

pub type Result<T> = std::result::Result<T, SecurityError>;
