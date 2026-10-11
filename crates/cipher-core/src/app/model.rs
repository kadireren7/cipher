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
    /// Set for a contact on ANOTHER relay (added through a contact card): where their mailbox lives and the intro capability from their card.
    /// `None` = same relay as ours (directory lookups and authenticated sends work as before).
    #[serde(default)]
    pub home: Option<RemoteHome>,
}

/// A contact's relay as learned from their signed card (docs/MULTI_RELAY_PROTOCOL.md).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteHome {
    pub relay: cipher_wire::RelayDescriptor,
    pub intro: Id16,
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
    /// The peer lives on another relay: there is no sequencer for this conversation, so it performs NO MLS commits after creation
    /// (no key-update commits, no membership changes) — docs/MULTI_RELAY_PROTOCOL.md §9.
    #[serde(default)]
    pub remote: bool,
    /// Set for a group with members on different relays: its commits are ordered by the log of a HOME relay (docs/CROSS_RELAY_GROUPS.md §7).
    #[serde(default)]
    pub home: Option<HomedGroup>,
}

/// Client-side state of a cross-relay group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomedGroup {
    /// The home relay named by the group's MLS-authenticated metadata (never taken from the relay or a peer).
    pub relay: cipher_wire::RelayDescriptor,
    /// What this device has verified of the log. `None` until a joiner has anchored itself at the entry that added it.
    pub ledger: Option<crate::home::HomeLedger>,
    /// Devices known to live on OUR relay (reachable through its authenticated path). Every other device of a cross-relay group is reached ONLY
    /// through its capability and waits for it: guessing "local" would hand a ciphertext to a relay that has never heard of the device, which answers
    /// `not_found` and looks like a delivery.
    #[serde(default)]
    pub local_devices: Vec<Id16>,
    /// Membership changes are blocked: the log was tampered with or a member submitted invalid commits. Messages keep flowing; commits do not
    /// until the user replaces the group. A static category, never free text.
    #[serde(default)]
    pub frozen: Option<String>,
    /// The home relay could not be used for a while (see `HomeIssue`). Messages keep flowing; membership changes cannot be made.
    #[serde(default)]
    pub issue: Option<HomeIssue>,
    /// Hex id of the group that replaces this one (`Engine::create_successor_group`); this group stays readable.
    #[serde(default)]
    pub superseded_by: Option<String>,
}

/// Why the commit channel of a cross-relay group is not available, observed over time. Static categories only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeIssue {
    /// `"unreachable"`: the home relay did not answer (outage, network). `"unrecognized"`: it answered but does not know this group or our
    /// credentials (log purged, database lost or rolled back, or a hostile relay).
    pub kind: String,
    /// Unix seconds of the first failure in the current streak.
    pub since: u64,
    /// The user has been told (one event per streak).
    pub alerted: bool,
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
    /// Cross-relay groups: the SAME ciphertext stored once on every other member relay. `blob_id` is the copy on the sender's relay; a member
    /// reads the entry for its own relay. Empty (and not serialised) for every other conversation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub copies: Vec<BlobCopy>,
}

/// One relay's copy of an attachment (and of its thumbnail).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobCopy {
    /// Base URL of the relay that holds this copy.
    pub relay: String,
    pub blob_id: Id16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumb_blob_id: Option<Id16>,
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
        /// The relay this capability is valid at (None only in frames from before multi-relay support: then it is the sender's and our shared relay).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay: Option<cipher_wire::RelayDescriptor>,
    },
    /// Cross-relay groups: the capabilities one member knows for the OTHER members, so two members that have never been in contact can reach each other.
    /// Sent by owners/admins when they learn a new device's capability. A device's own announcement always wins over this hearsay.
    GroupCaps {
        entries: Vec<GroupCapEntry>,
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
    /// Cross-relay groups only: the sender's verified position in the home relay's log. Members compare it with their own (equivocation
    /// detection, docs/CROSS_RELAY_GROUPS.md §7.3). Absent everywhere else, so other frames are byte-identical to before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<LogHead>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogHead {
    pub seq: u64,
    #[serde(with = "cipher_wire::b64")]
    pub chain: Vec<u8>,
}

/// One member device's inbox capability as relayed by another member (cross-relay groups: introduces members to each other).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupCapEntry {
    pub device: Id16,
    pub cap: Id16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<cipher_wire::RelayDescriptor>,
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
    /// A Welcome that creates a conversation at the peer: nothing else of that conversation is sent before it has been accepted by the peer's relay
    /// (otherwise the peer could receive messages for a group it has not joined yet, and drop them).
    #[serde(default)]
    pub welcome: bool,
    /// Position in the order messages were ENCRYPTED. Items of one conversation must leave in this order: the MLS receiver only keeps keys for a few skipped
    /// generations, so a message that arrives many generations late is undecryptable and silently lost (0 = stored by an older build).
    #[serde(default)]
    pub order: u64,
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
