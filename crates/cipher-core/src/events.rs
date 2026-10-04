//! Security events surfaced to the UI / audit sink. Payloads are deliberately
//! limited to non-secret identifiers and categories (SEC-010).
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockReason {
    Manual,
    Inactivity,
    Backgrounded,
    DeviceScreenLocked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidationReason {
    KeystoreKeyInvalidated,
    KeystoreKeyMissing,
    PasscodeRemoved,
    BiometricsChanged,
    /// The vault file is older than the generation counter held by the platform keystore (restored/rolled-back storage).
    StorageRolledBack,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityEvent {
    Locked(LockReason),
    Unlocked,
    UnlockFailed {
        consecutive_failures: u32,
    },
    UnlockRateLimited {
        retry_after_secs: u64,
    },
    VaultInvalidated(InvalidationReason),
    /// Policy explicitly allowed a weaker keystore; surfaced so it is never silent.
    ProtectionDowngradeAccepted {
        level: crate::keystore::ProtectionLevel,
    },
    /// A known account presented a different identity key than the pinned one.
    IdentityChanged {
        account_id: String,
    },
    /// A device appeared without a valid endorsement from a pinned device.
    UnendorsedDevice {
        account_id: String,
        device_id: String,
    },
    DeviceListChanged {
        account_id: String,
    },
    ReplayRejected,
    /// A group commit that violates the group's role policy was received and dropped.
    UnauthorizedGroupChange {
        conversation_id: String,
    },
    StorageCorruptionDetected,
    /// A member was removed from this group (committed and persisted): the history-access generation advanced.
    GroupMemberRemoved {
        conversation_id: String,
    },
    /// THIS device was removed from the group: its history keys were deleted and the group state dropped.
    GroupAccessRevoked {
        conversation_id: String,
    },
    /// A message was refused because its sender is no longer a member (e.g. a removed member sending into an old epoch).
    RemovedMemberMessageRejected {
        conversation_id: String,
    },
}

pub trait SecurityEventSink: Send + Sync {
    fn emit(&self, event: SecurityEvent);
}
