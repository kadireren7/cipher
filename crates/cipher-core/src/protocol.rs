//! Protocol adapter boundary. All end-to-end message cryptography sits behind
//! this trait so the implementation (currently OpenMLS, RFC 9420) can be audited,
//! replaced or run in a separate process without touching storage, transport or UI.
//!
//! 1:1 conversations are 2-member groups. See docs/CRYPTOGRAPHIC_DESIGN.md for why
//! one protocol is used for both rather than combining Signal + MLS.
use crate::error::Result;
use cipher_wire::Id16;

/// Opaque handle to a group/conversation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GroupRef(pub Vec<u8>);

/// The pinned/expected identity of a peer device, obtained from the directory and
/// checked against the client's identity pins *before* trusting a KeyPackage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedPeer {
    pub account_id: Id16,
    pub device_id: Id16,
    pub identity_key: [u8; 32],
}

#[derive(Debug)]
pub struct CommitOutput {
    /// Commit to deliver to existing members (opaque ciphertext).
    pub commit: Vec<u8>,
    /// Welcome for newly added members, if any (opaque ciphertext).
    pub welcome: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Processed {
    Application(Vec<u8>),
    Commit {
        epoch: u64,
        added: Vec<(Id16, Id16)>,
        removed: Vec<(Id16, Id16)>,
        self_removed: bool,
    },
    /// Proposal or other handshake message that is not acted on in this foundation.
    Ignored,
}

/// Application-level approval of membership changes introduced by *other* members
/// (A10: malicious current member adding a rogue device).
pub trait CommitValidator {
    fn approve_add(&self, account: &Id16, device: &Id16, identity_key: &[u8]) -> bool;
}

/// Result of processing with sender information (used by the application engine).
#[derive(Debug, PartialEq, Eq)]
pub enum ProcessedEx {
    /// `epoch` is the epoch the message was ENCRYPTED in (may be one of the retained past epochs).
    Application {
        plaintext: Vec<u8>,
        sender: (Id16, Id16),
        epoch: u64,
    },
    Commit {
        epoch: u64,
        added: Vec<(Id16, Id16)>,
        removed: Vec<(Id16, Id16)>,
        self_removed: bool,
        sender: (Id16, Id16),
    },
    Ignored,
}

/// Cleartext framing facts about an MLS message. NOTE: `group_id` and `epoch` are visible to anyone who parses MLS framing
/// (including a malicious relay); see docs/METADATA_MODEL.md.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Header {
    Welcome,
    Group { group_id: Vec<u8>, epoch: u64 },
    Other,
}

/// One membership/metadata operation in a commit. Several can be combined into a single epoch change.
#[derive(Debug, Clone)]
pub enum GroupOp {
    Add {
        key_package: Vec<u8>,
        expected: ExpectedPeer,
    },
    /// Remove every listed device (all of an account's devices when removing a member).
    Remove {
        devices: Vec<Id16>,
    },
    SetMeta(crate::app::groupmeta::GroupMeta),
    /// Refresh this device's leaf keys (post-compromise security).
    SelfUpdate,
    /// TEST ONLY: inject arbitrary (possibly invalid / non-canonical) metadata bytes to model a malicious committer.
    #[cfg(any(test, feature = "insecure-test-support"))]
    SetMetaRawForTests(Vec<u8>),
}

pub trait GroupProtocol {
    fn generate_key_packages(&mut self, n: usize) -> Result<Vec<Vec<u8>>>;
    fn create_group(&mut self) -> Result<GroupRef>;
    /// Stages an add commit. Call `merge_pending_commit` once the relay has accepted it.
    fn add_member(&mut self, group: &GroupRef, key_package: &[u8], expected: &ExpectedPeer) -> Result<CommitOutput>;
    fn remove_member(&mut self, group: &GroupRef, device: &Id16) -> Result<CommitOutput>;
    /// Refreshes this device's leaf key material (post-compromise security). Must be issued
    /// periodically by every member for PCS to take effect. Stage + `merge_pending_commit`.
    fn self_update(&mut self, group: &GroupRef) -> Result<CommitOutput>;
    fn merge_pending_commit(&mut self, group: &GroupRef) -> Result<()>;
    fn clear_pending_commit(&mut self, group: &GroupRef) -> Result<()>;
    fn join_from_welcome(&mut self, welcome: &[u8]) -> Result<GroupRef>;
    fn encrypt(&mut self, group: &GroupRef, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn process(&mut self, group: &GroupRef, ciphertext: &[u8], validator: &dyn CommitValidator) -> Result<Processed>;
    fn epoch(&self, group: &GroupRef) -> Result<u64>;
    fn members(&self, group: &GroupRef) -> Result<Vec<(Id16, Id16)>>;
    fn is_active(&self, group: &GroupRef) -> Result<bool>;
}
