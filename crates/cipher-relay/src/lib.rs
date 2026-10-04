//! cipher-relay: an UNTRUSTED relay.
//!
//! Design stance: the relay is assumed to be malicious or compromised (A2/A3/A4).
//! It stores and forwards opaque ciphertext and public key material only. It has
//! no type or dependency capable of decrypting message content (SEC-001/002/003).
//!
//! TLS protects the transport but is NOT the end-to-end boundary.
#![doc = "See docs/METADATA_MODEL.md for exactly what this process can observe."]

pub mod api;
pub mod auth;
pub mod config;
pub mod conn_limit;
pub mod db;
pub mod error;
pub mod logging;
pub mod migrations;
pub mod push;
pub mod ratelimit;
pub mod store;
pub mod tls;

pub use api::{build_app, AppState};
