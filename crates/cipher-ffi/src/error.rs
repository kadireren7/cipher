use cipher_core::error::SecurityError;

/// Errors visible to Kotlin. Messages are static categories: never plaintext, keys, ciphertext or PINs.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CipherError {
    #[error("locked")]
    Locked,
    #[error("keys invalidated")]
    Invalidated,
    #[error("wrong credential")]
    BadCredential,
    #[error("local data rolled back")]
    RolledBack,
    #[error("pin too weak")]
    WeakPin,
    #[error("rate limited: retry in {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },
    #[error("not found: {what}")]
    NotFound { what: String },
    #[error("denied: {what}")]
    Denied { what: String },
    #[error("not authorised by group policy")]
    Unauthorized,
    #[error("identity not trusted")]
    IdentityUntrusted,
    #[error("offline")]
    Offline,
    #[error("server rejected the request")]
    Server,
    #[error("local data corrupted")]
    Corrupt,
    #[error("invalid input: {what}")]
    InvalidInput { what: String },
    #[error("attachment: {what}")]
    Attachment { what: String },
    #[error("secure key storage unavailable or too weak")]
    KeyStore,
    #[error("internal error")]
    Internal,
}

impl From<SecurityError> for CipherError {
    fn from(e: SecurityError) -> Self {
        use SecurityError as S;
        match e {
            S::Locked | S::InvalidState => CipherError::Locked,
            S::Invalidated => CipherError::Invalidated,
            S::StorageRolledBack => CipherError::RolledBack,
            S::BadCredential => CipherError::BadCredential,
            S::WeakPin => CipherError::WeakPin,
            S::RateLimited { retry_after_secs } => CipherError::RateLimited { retry_after_secs },
            S::NotFound(w) => CipherError::NotFound { what: w.to_owned() },
            S::Denied(w) => CipherError::Denied { what: w.to_owned() },
            S::Unauthorized(_) => CipherError::Unauthorized,
            S::IdentityUntrusted(_) => CipherError::IdentityUntrusted,
            S::Transport(m) => match m {
                "network unavailable" | "timeout" | "tls failure" | "io failure" => CipherError::Offline,
                "unauthorized" | "rate limited" | "not found" | "conflict" | "payload too large" | "server error" | "request rejected" => {
                    CipherError::Server
                }
                _ => CipherError::Offline,
            },
            S::StorageCorrupt | S::StorageWrongKey | S::CryptoAuthFailed => CipherError::Corrupt,
            S::Malformed(w) => CipherError::InvalidInput { what: w.to_owned() },
            S::Attachment(w) => CipherError::Attachment { what: w.to_owned() },
            S::KeyStore(_) | S::ProtectionBelowMinimum { .. } | S::KdfParamsBelowFloor => CipherError::KeyStore,
            S::Replay | S::Protocol(_) | S::FutureEpoch | S::StaleEpoch | S::Rng => CipherError::Internal,
        }
    }
}
