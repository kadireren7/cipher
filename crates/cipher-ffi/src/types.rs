//! Plain data crossing the boundary. Ids are lowercase hex strings; nothing here can carry key material.
use cipher_core::app::model::*;
use cipher_core::app::notify::{NotificationText, PrivacyMode};
use cipher_core::events::SecurityEvent;
use cipher_core::keystore::ProtectionLevel;
use cipher_core::vault::{DeviceSecurityEvent, LockState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LockStateFfi {
    Locked,
    Unlocking,
    Unlocked,
    Background,
    Invalidated,
}
impl From<LockState> for LockStateFfi {
    fn from(s: LockState) -> Self {
        match s {
            LockState::Locked => Self::Locked,
            LockState::Unlocking => Self::Unlocking,
            LockState::Unlocked => Self::Unlocked,
            LockState::Background => Self::Background,
            LockState::Invalidated => Self::Invalidated,
        }
    }
}

/// The ACTUAL protection of the vault's hardware key. Software is never reported as hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ProtectionFfi {
    Strongbox,
    Tee,
    SoftwareOrUnknown,
    Unavailable,
}
pub(crate) fn protection(p: Option<ProtectionLevel>) -> ProtectionFfi {
    match p {
        Some(ProtectionLevel::SecureElement) => ProtectionFfi::Strongbox,
        Some(ProtectionLevel::HardwareBacked) => ProtectionFfi::Tee,
        Some(ProtectionLevel::OsSoftware) | Some(ProtectionLevel::Insecure) => ProtectionFfi::SoftwareOrUnknown,
        None => ProtectionFfi::Unavailable,
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VaultStatusFfi {
    pub state: LockStateFfi,
    pub provisioned: bool,
    pub has_identity: bool,
    pub has_pin: bool,
    /// PIN-only vault: unlocking requires the PIN; there is no biometric path.
    pub pin_only: bool,
    pub pin_retry_after_secs: u64,
    pub protection: ProtectionFfi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DeviceEventFfi {
    ScreenLocked,
    PasscodeRemoved,
    BiometricEnrollmentChanged,
}
impl From<DeviceEventFfi> for DeviceSecurityEvent {
    fn from(e: DeviceEventFfi) -> Self {
        match e {
            DeviceEventFfi::ScreenLocked => Self::ScreenLocked,
            DeviceEventFfi::PasscodeRemoved => Self::PasscodeRemoved,
            DeviceEventFfi::BiometricEnrollmentChanged => Self::BiometricEnrollmentChanged,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RoleFfi {
    Owner,
    Admin,
    Member,
}
impl From<Role> for RoleFfi {
    fn from(r: Role) -> Self {
        match r {
            Role::Owner => Self::Owner,
            Role::Admin => Self::Admin,
            Role::Member => Self::Member,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TrustStateFfi {
    Unverified,
    Verified,
    IdentityChanged,
}
impl From<TrustState> for TrustStateFfi {
    fn from(t: TrustState) -> Self {
        match t {
            TrustState::Unverified => Self::Unverified,
            TrustState::Verified => Self::Verified,
            TrustState::IdentityChanged => Self::IdentityChanged,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConvKindFfi {
    Dm,
    Group,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConvStateFfi {
    Active,
    Requested,
    Left,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DeliveryStateFfi {
    Pending,
    Sent,
    Delivered,
    Failed,
    Received,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AttachmentKindFfi {
    Image,
    Video,
    Audio,
    Voice,
    Pdf,
    File,
}
impl From<AttachmentKindFfi> for AttachmentKind {
    fn from(k: AttachmentKindFfi) -> Self {
        match k {
            AttachmentKindFfi::Image => Self::Image,
            AttachmentKindFfi::Video => Self::Video,
            AttachmentKindFfi::Audio => Self::Audio,
            AttachmentKindFfi::Voice => Self::Voice,
            AttachmentKindFfi::Pdf => Self::Pdf,
            AttachmentKindFfi::File => Self::File,
        }
    }
}
impl From<AttachmentKind> for AttachmentKindFfi {
    fn from(k: AttachmentKind) -> Self {
        match k {
            AttachmentKind::Image => Self::Image,
            AttachmentKind::Video => Self::Video,
            AttachmentKind::Audio => Self::Audio,
            AttachmentKind::Voice => Self::Voice,
            AttachmentKind::Pdf => Self::Pdf,
            AttachmentKind::File => Self::File,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PrivacyModeFfi {
    NoContent,
    SenderOnly,
    ContentWhenUnlocked,
}
impl From<PrivacyModeFfi> for PrivacyMode {
    fn from(m: PrivacyModeFfi) -> Self {
        match m {
            PrivacyModeFfi::NoContent => Self::NoContent,
            PrivacyModeFfi::SenderOnly => Self::SenderOnly,
            PrivacyModeFfi::ContentWhenUnlocked => Self::ContentWhenUnlocked,
        }
    }
}
impl From<PrivacyMode> for PrivacyModeFfi {
    fn from(m: PrivacyMode) -> Self {
        match m {
            PrivacyMode::NoContent => Self::NoContent,
            PrivacyMode::SenderOnly => Self::SenderOnly,
            PrivacyMode::ContentWhenUnlocked => Self::ContentWhenUnlocked,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NetworkProfileFfi {
    Standard,
    Enhanced,
}
impl From<NetworkProfileFfi> for cipher_core::app::netprofile::NetworkProfile {
    fn from(p: NetworkProfileFfi) -> Self {
        match p {
            NetworkProfileFfi::Standard => Self::Standard,
            NetworkProfileFfi::Enhanced => Self::Enhanced,
        }
    }
}
impl From<cipher_core::app::netprofile::NetworkProfile> for NetworkProfileFfi {
    fn from(p: cipher_core::app::netprofile::NetworkProfile) -> Self {
        match p {
            cipher_core::app::netprofile::NetworkProfile::Standard => Self::Standard,
            cipher_core::app::netprofile::NetworkProfile::Enhanced => Self::Enhanced,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SettingsFfi {
    pub privacy_mode: PrivacyModeFfi,
    pub send_receipts: bool,
    pub network_profile: NetworkProfileFfi,
}

/// One foreground tick: what arrived, and how long to wait before the next one (jittered by the profile).
#[derive(Debug, Clone, uniffi::Record)]
pub struct TickFfi {
    pub report: SyncReportFfi,
    pub next_delay_ms: u64,
}

/// Recipient deliveries made in this process: through a contact's delivery capability (no authentication) vs authenticated.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DeliveryPathFfi {
    pub anonymous: u64,
    pub authenticated: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PublicIdentityFfi {
    pub cipher_id: String,
    pub account_id: String,
    pub device_id: String,
    pub qr_payload: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ContactFfi {
    pub account_id: String,
    pub cipher_id: String,
    pub name: String,
    pub trust: TrustStateFfi,
    pub blocked: bool,
}
impl From<&Contact> for ContactFfi {
    fn from(c: &Contact) -> Self {
        Self {
            account_id: c.account_id.to_hex(),
            cipher_id: cipher_core::app::cipher_id::format(&c.account_id),
            name: c.name.clone(),
            trust: c.trust.into(),
            blocked: c.blocked,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ConversationFfi {
    pub id: String,
    pub kind: ConvKindFfi,
    pub state: ConvStateFfi,
    pub title: String,
    pub peer_account: Option<String>,
    pub unread: u32,
    pub last_activity_ms: u64,
    /// Short preview for the conversation list (decrypted locally; the UI hides it when appropriate).
    pub last_preview: String,
    /// This device was removed from the group: earlier messages are no longer available here (docs/HISTORY_REVOCATION.md).
    pub access_revoked: bool,
}
impl From<&Conversation> for ConversationFfi {
    fn from(c: &Conversation) -> Self {
        Self {
            id: c.id.to_hex(),
            kind: match c.kind {
                ConvKind::Dm => ConvKindFfi::Dm,
                ConvKind::Group => ConvKindFfi::Group,
            },
            state: match c.state {
                ConvState::Active => ConvStateFfi::Active,
                ConvState::Requested => ConvStateFfi::Requested,
                ConvState::Left => ConvStateFfi::Left,
            },
            title: c.title.clone(),
            peer_account: c.peer.map(|p| p.to_hex()),
            unread: c.unread,
            last_activity_ms: c.last_activity_ms,
            last_preview: c.last_preview.clone(),
            access_revoked: c.access_revoked,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AttachmentViewFfi {
    pub kind: AttachmentKindFfi,
    pub mime: String,
    pub filename: String,
    pub size_bytes: u64,
    pub has_thumbnail: bool,
    pub duration_ms: Option<u32>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MessageFfi {
    pub id: String,
    pub conversation_id: String,
    pub outgoing: bool,
    pub sender_account: String,
    pub sender_name: String,
    pub ts_ms: u64,
    pub reply_to: Option<String>,
    /// Text body, or the caption for attachments.
    pub text: String,
    pub attachment: Option<AttachmentViewFfi>,
    pub state: DeliveryStateFfi,
    /// The body cannot be opened because group access was revoked; `text` is empty and `attachment` is None.
    pub unavailable: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct HistoryPageFfi {
    pub items: Vec<MessageFfi>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MemberFfi {
    pub account_id: String,
    pub name: String,
    pub role: RoleFfi,
    pub devices: u32,
    pub is_me: bool,
    pub trust: Option<TrustStateFfi>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceFfi {
    pub device_id: String,
    pub is_this_device: bool,
    pub endorsed_by_another_device: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct NotificationFfi {
    pub title: String,
    pub body: String,
    pub hide_on_lock_screen: bool,
}
impl From<NotificationText> for NotificationFfi {
    fn from(n: NotificationText) -> Self {
        Self { title: n.title, body: n.body, hide_on_lock_screen: n.secret_on_lock_screen }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SyncReportFfi {
    pub new_messages: u32,
    pub changed_conversations: Vec<String>,
    /// Ready-to-show notification text for the CURRENT privacy mode and vault state (None when nothing new).
    pub notification: Option<NotificationFfi>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SecurityEventKind {
    Locked,
    Unlocked,
    UnlockFailed,
    UnlockRateLimited,
    VaultInvalidated,
    ProtectionDowngradeAccepted,
    IdentityChanged,
    UnendorsedDevice,
    DeviceListChanged,
    ReplayRejected,
    UnauthorizedGroupChange,
    StorageCorruptionDetected,
    GroupMemberRemoved,
    GroupAccessRevoked,
    RemovedMemberMessageRejected,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SecurityEventFfi {
    pub kind: SecurityEventKind,
    /// Account / conversation concerned, when applicable (hex).
    pub subject: Option<String>,
}
impl From<&SecurityEvent> for SecurityEventFfi {
    fn from(e: &SecurityEvent) -> Self {
        use SecurityEvent as E;
        let (kind, subject) = match e {
            E::Locked(_) => (SecurityEventKind::Locked, None),
            E::Unlocked => (SecurityEventKind::Unlocked, None),
            E::UnlockFailed { .. } => (SecurityEventKind::UnlockFailed, None),
            E::UnlockRateLimited { .. } => (SecurityEventKind::UnlockRateLimited, None),
            E::VaultInvalidated(_) => (SecurityEventKind::VaultInvalidated, None),
            E::ProtectionDowngradeAccepted { .. } => (SecurityEventKind::ProtectionDowngradeAccepted, None),
            E::IdentityChanged { account_id } => (SecurityEventKind::IdentityChanged, Some(account_id.clone())),
            E::UnendorsedDevice { account_id, .. } => (SecurityEventKind::UnendorsedDevice, Some(account_id.clone())),
            E::DeviceListChanged { account_id } => (SecurityEventKind::DeviceListChanged, Some(account_id.clone())),
            E::ReplayRejected => (SecurityEventKind::ReplayRejected, None),
            E::UnauthorizedGroupChange { conversation_id } => (SecurityEventKind::UnauthorizedGroupChange, Some(conversation_id.clone())),
            E::StorageCorruptionDetected => (SecurityEventKind::StorageCorruptionDetected, None),
            E::GroupMemberRemoved { conversation_id } => (SecurityEventKind::GroupMemberRemoved, Some(conversation_id.clone())),
            E::GroupAccessRevoked { conversation_id } => (SecurityEventKind::GroupAccessRevoked, Some(conversation_id.clone())),
            E::RemovedMemberMessageRejected { conversation_id } => {
                (SecurityEventKind::RemovedMemberMessageRejected, Some(conversation_id.clone()))
            }
        };
        Self { kind, subject }
    }
}
