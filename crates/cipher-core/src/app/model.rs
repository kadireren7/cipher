//! Application data model. Everything here is persisted only inside the vault (encrypted records).
use cipher_wire::Id16;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Role {
    Owner,
    Admin,
    Member,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustState {
    /// Key seen (TOFU) but never compared out-of-band.
    Unverified,
    /// The user compared the safety number / scanned the QR code for the pinned key.
    Verified,
    /// The identity changed unexpectedly; communication with new keys is blocked until acknowledged.
    IdentityChanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConvKind {
    Dm,
    Group,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConvState {
    Active,
    /// Invited by someone who is not a contact: contents stay hidden until the user accepts.
    Requested,
    /// We left (history stays readable) or were removed (`Conversation::access_revoked`: history keys deleted); no new messages.
    Left,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryState {
    /// Encrypted and waiting in the local outbox.
    Pending,
    /// Accepted by the relay.
    Sent,
    /// Every recipient device acknowledged (end-to-end receipt).
    Delivered,
    /// Retries exhausted; the user can retry manually.
    Failed,
    /// Incoming message.
    Received,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachmentKind {
    Image,
    Video,
    Audio,
    Voice,
    Pdf,
    File,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub account_id: Id16,
    /// Local nickname only; never sent anywhere.
    pub name: String,
    pub trust: TrustState,
    /// Root identity key pinned for this account (what safety numbers / QR refer to).
    pub root_identity_key: Vec<u8>,
    /// Key the user explicitly verified, if any (so a later change is visible even after acknowledgement).
    pub verified_key: Option<Vec<u8>>,
    pub blocked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conversation {
    pub id: Id16, // == MLS group id
    pub kind: ConvKind,
    pub state: ConvState,
    pub title: String,
    pub peer: Option<Id16>, // DM peer account
    pub tag: Id16,          // current relay routing tag
    pub relay_seq: u64,     // commit sequence last observed (for compare-and-swap)
    pub unread: u32,
    pub last_activity_ms: u64,
    pub last_preview: String, // inside the vault only; never copied to notifications unless the privacy mode allows
    pub last_self_update_ms: u64,
    /// Messages sent or received since this device last refreshed its keys in this conversation.
    pub sent_since_update: u32,
    /// This device was REMOVED from the group: its history keys were deleted (docs/HISTORY_REVOCATION.md). Not set for a voluntary leave.
    #[serde(default)]
    pub access_revoked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub kind: AttachmentKind,
    pub blob_id: Id16,
    /// JSON of `attachment::AttachmentDescriptor` (contains the key; lives only in vault + E2EE message).
    pub descriptor: String,
    pub thumb_blob_id: Option<Id16>,
    pub thumb_descriptor: Option<String>,
    pub duration_ms: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum Content {
    Text {
        body: String,
    },
    Attachment {
        caption: String,
        att: AttachmentRef,
    },
    /// End-to-end delivery receipt for the listed app message ids.
    Receipt {
        ids: Vec<Id16>,
    },
    /// Member asks admins to remove them (they cannot commit their own removal).
    LeaveRequest,
    /// Control frame: the sender's current delivery capability for this conversation (docs/DELIVERY_CAPABILITIES.md). Never shown, never stored in history.
    DeliveryCap {
        cap: Id16,
    },
}

/// Wire/plaintext message frame (padded before MLS encryption; see `codec`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub v: u8,
    pub id: Id16,
    pub ts_ms: u64,
    pub reply_to: Option<Id16>,
    pub content: Content,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: Id16,
    pub conv: Id16,
    pub outgoing: bool,
    pub sender_account: Id16,
    pub ts_ms: u64,
    pub reply_to: Option<Id16>,
    pub content: Content,
    pub state: DeliveryState,
    pub read: bool,
    /// GROUP messages only: the MLS epoch the message was encrypted in. Its body is stored SEALED under that epoch's history key.
    #[serde(default)]
    pub epoch: Option<u64>,
    /// Set when loading: the body cannot be opened because this device no longer holds the epoch's history key (access revoked).
    /// `content` is then an empty placeholder — NEVER the plaintext.
    #[serde(default)]
    pub unavailable: bool,
    /// The sealed body (group messages). Persisted instead of the plaintext `content`.
    #[serde(default)]
    pub sealed: Option<crate::history::SealedBody>,
}

/// Pending outgoing ciphertext (already encrypted; survives restarts). One MLS ciphertext, many recipient devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxItem {
    pub id: Id16,
    pub conv: Id16,
    pub devices: Vec<Id16>,
    pub ciphertext: Vec<u8>,
    pub attempts: u32,
    pub next_attempt_ms: u64,
    /// Marks a leave request: once delivered, the local MLS state of the conversation can be dropped.
    pub is_leave: bool,
}

pub fn msg_sort_key(ts_ms: u64, id: &Id16) -> String {
    format!("{:020}-{}", ts_ms, id.to_hex())
}

/// Characters that must never appear in a NAME or a notification/preview line (final review FR-13): C0/C1 controls, and the Unicode
/// *format* characters that let text disguise itself — bidirectional embeddings/overrides/isolates (U+202A–202E, U+2066–2069), zero-width
/// space and word joiners (U+200B, U+2060–2064), deprecated shaping controls (U+206A–206F), the byte-order mark (U+FEFF) and the soft hyphen.
/// ZWJ/ZWNJ (U+200C/200D) and the directional MARKS (U+200E/200F, U+061C) are kept: emoji sequences and Persian/Arabic text need them.
pub fn is_disguising_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200B}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{FEFF}' | '\u{00AD}')
}

/// Filters [`is_disguising_char`] out of `s`.
pub fn strip_disguising(s: &str) -> String {
    s.chars().filter(|c| !is_disguising_char(*c)).collect()
}

#[cfg(test)]
mod spoofing_tests {
    use super::*;

    #[test]
    fn overrides_zero_width_and_controls_are_disguising_but_emoji_joiners_and_marks_are_not() {
        for c in ['\u{202E}', '\u{202D}', '\u{2066}', '\u{2069}', '\u{200B}', '\u{2060}', '\u{FEFF}', '\u{00AD}', '\u{0007}', '\u{206A}'] {
            assert!(is_disguising_char(c), "U+{:04X}", c as u32);
        }
        for c in ['a', 'ا', '日', '👨', '\u{200D}', '\u{200C}', '\u{200E}', '\u{200F}', '\u{061C}', '\u{FE0F}'] {
            assert!(!is_disguising_char(c), "U+{:04X}", c as u32);
        }
        assert_eq!(strip_disguising("Bank\u{202E}gnirts\u{200B}!"), "Bankgnirts!");
        assert_eq!(strip_disguising("👨\u{200D}👩\u{200D}👧"), "👨\u{200D}👩\u{200D}👧", "emoji sequences survive");
    }
}
