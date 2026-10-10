//! cipher-core: client-side security core.
//!
//! Security boundaries live here; see docs/ for the threat model. No module in
//! this crate implements a cryptographic primitive.

pub mod app;
pub mod attachment;
pub mod clock;
pub mod contact_card;
pub mod error;
pub mod events;
pub mod history;
pub mod kdf;
pub mod keystore;
pub mod mls;
pub mod protocol;
pub mod relay_client;
pub mod rng;
pub mod storage;
pub mod vault;
pub mod verification;

/// EXPERIMENTAL, NOT PRODUCTION READY (see docs/KEY_TRANSPARENCY.md). Compiled only with `transparency-experimental`.
#[cfg(feature = "transparency-experimental")]
pub mod transparency;

pub use error::{Result, SecurityError};
