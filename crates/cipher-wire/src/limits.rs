//! Hard limits enforced by the relay and respected by the client.
//! Bounded queues and sizes are part of the abuse-resistance boundary.

/// Max opaque ciphertext per relay message (MLS commits/welcomes can be large).
pub const MAX_MESSAGE_CIPHERTEXT_BYTES: usize = 256 * 1024;
/// Max queued envelopes per recipient device.
pub const MAX_QUEUED_ENVELOPES_PER_DEVICE: usize = 1_000;
/// Max queued ciphertext bytes per recipient device.
pub const MAX_QUEUED_BYTES_PER_DEVICE: usize = 16 * 1024 * 1024;
/// Max envelopes returned by one fetch.
pub const MAX_FETCH_BATCH: usize = 100;
/// Max ids in one acknowledgement.
pub const MAX_ACK_BATCH: usize = 100;
/// Min / max / default time-to-live for queued ciphertext.
pub const MIN_TTL_SECS: u64 = 60;
pub const MAX_TTL_SECS: u64 = 30 * 24 * 3600;
pub const DEFAULT_TTL_SECS: u64 = 7 * 24 * 3600;
/// Max KeyPackages stored per device and accepted per upload.
pub const MAX_KEY_PACKAGES_PER_DEVICE: usize = 100;
pub const MAX_KEY_PACKAGE_BYTES: usize = 8 * 1024;
/// Max encrypted attachment blob accepted by the relay (ciphertext size).
pub const MAX_BLOB_BYTES: usize = 101 * 1024 * 1024;
/// Blob retention.
pub const BLOB_TTL_SECS: u64 = 14 * 24 * 3600;
/// Max JSON request body for non-blob endpoints (base64 inflates 4/3).
pub const MAX_JSON_BODY_BYTES: usize = 512 * 1024;
/// Max devices per account.
pub const MAX_DEVICES_PER_ACCOUNT: usize = 10;
/// Request signature freshness window (seconds, either direction).
pub const MAX_CLOCK_SKEW_SECS: u64 = 60;
/// Push token (opaque) max length.
pub const MAX_PUSH_TOKEN_BYTES: usize = 512;

/// First four bytes of every encrypted attachment container (`cipher-core::attachment`).
/// The relay uses it only as a cheap sanity check; it cannot prove the body is encrypted.
pub const ATTACHMENT_MAGIC: &[u8; 4] = b"CATT";
/// Max outstanding blob bytes stored by one relay (global abuse cap; configurable).
pub const DEFAULT_MAX_TOTAL_BLOB_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Max deliveries (recipient devices) in one batch send or group commit.
pub const MAX_BATCH_DELIVERIES: usize = 256;

/// Delivery capabilities (docs/DELIVERY_CAPABILITIES.md).
/// Max live capabilities per device, and per mint request.
pub const MAX_CAPS_PER_DEVICE: usize = 256;
pub const MAX_CAPS_PER_MINT: usize = 16;
/// Live INTRO capabilities (contact cards) per device.
pub const MAX_INTRO_CAPS_PER_DEVICE: usize = 8;
/// Live attachment bytes a single delivery capability may have stored (capability uploads, docs/MULTI_RELAY_PROTOCOL.md §10).
pub const CAP_BLOB_QUOTA_BYTES: u64 = 256 * 1024 * 1024;
/// Default capability lifetime (rotated well before this) and the grace window an old capability keeps working after rotation.
pub const CAP_TTL_SECS: u64 = 30 * 24 * 3600;
pub const CAP_REVOKE_GRACE_MAX_SECS: u64 = 24 * 3600;
/// Per-capability queue allowance, and the OPEN lane (messages from senders that hold no capability) allowance, per recipient.
pub const CAP_QUOTA_ENVELOPES: usize = 250;
pub const CAP_QUOTA_BYTES: usize = 4 * 1024 * 1024;
pub const OPEN_LANE_ENVELOPES: usize = 100;
pub const OPEN_LANE_BYTES: usize = 2 * 1024 * 1024;
/// COMMIT lane (group commits and Welcomes through the sequencer) allowance per recipient: authenticated strangers can create group tags freely, so
/// this lane is bounded separately and can never crowd out the capability lane.
pub const COMMIT_LANE_ENVELOPES: usize = 200;
pub const COMMIT_LANE_BYTES: usize = 8 * 1024 * 1024;
