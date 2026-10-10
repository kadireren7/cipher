//! Wire contract between the mobile client and the relay.
//!
//! Everything the relay can ever see is defined here. Message bodies are opaque
//! `Vec<u8>` ciphertext produced by the protocol adapter in `cipher-core`; the
//! relay has no type that could hold plaintext.
//!
//! TLS is NOT the end-to-end boundary: these types are transported over TLS, but
//! confidentiality of content comes from the MLS layer inside `ciphertext`.

pub mod b64;
pub mod ids;
pub mod limits;
pub mod messages;
pub mod relay_desc;
pub mod signing;

pub use ids::{Id16, IdError};
pub use relay_desc::{RelayDescError, RelayDescriptor};
