//! cipher-ffi: the ONLY boundary between the Kotlin app and the Rust security core.
//!
//! What crosses it: display data (names, message text the UI is about to render, ids as hex strings, public keys as
//! QR payloads, safety numbers) and opaque callbacks for platform services (Android Keystore, OkHttp).
//! What never crosses it: identity/transport private keys, MLS state, the vault data key, attachment keys, hardware-key
//! material. There is no exported function that returns any of those (enforced by `tests/boundary_guards.rs`).
//!
//! Every Kotlin->Rust input is hostile: ids are strict 32-char lowercase hex, strings are length-bounded and NUL-free, source
//! paths are restricted to `/proc/self/fd/N`, and every call runs under `catch_unwind` so a bug becomes `CipherError::Internal`
//! (and locks the vault) instead of undefined behaviour or an unlocked, half-updated state.
mod callbacks;
mod engine_api;
mod error;
mod types;
#[doc(hidden)] // public only so the fuzz crate can drive the boundary validators; not exported over FFI
pub mod validate;

pub use callbacks::*;
pub use engine_api::*;
pub use error::CipherError;
pub use types::*;

uniffi::setup_scaffolding!();

/// Exact constant wake payload a push provider may carry; anything else is ignored.
#[uniffi::export]
pub fn is_valid_wake_payload(payload: String) -> bool {
    cipher_core::app::notify::is_valid_wake(&payload)
}

/// Syntactic validation of a Cipher identifier for the UI (checksum included).
#[uniffi::export]
pub fn is_valid_cipher_id(text: String) -> bool {
    validate::bounded(&text, 64, "cipher id").is_ok() && cipher_core::app::cipher_id::parse(&text).is_ok()
}

#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}
