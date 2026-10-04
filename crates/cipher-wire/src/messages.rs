//! Request/response bodies. `deny_unknown_fields` everywhere: strict input
//! validation, no silently ignored attributes.
use crate::ids::Id16;
use crate::limits::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("field out of bounds: {0}")]
    Bounds(&'static str),
    #[error("batch is empty")]
    Empty,
}

/// Public material for one device. Contains no secrets.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceRecord {
    pub device_id: Id16,
    /// Ed25519 public key: long-term *cryptographic identity* (also the MLS signature key).
    #[serde(with = "crate::b64")]
    pub identity_key: Vec<u8>,
    /// Ed25519 public key: *transport authentication* key, distinct from identity.
    #[serde(with = "crate::b64")]
    pub auth_key: Vec<u8>,
    /// identity-key signature over (account_id || device_id || auth_key): binds the keys to this account and device.
    #[serde(with = "crate::b64")]
    pub binding_sig: Vec<u8>,
    /// For additional devices: endorsement by an existing device's identity key.
    pub endorsement: Option<Endorsement>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Endorsement {
    pub endorser_device: Id16,
    /// signature by the endorser's identity key over
    /// `endorsement_message(account, new_device, new_identity_key, new_auth_key)`.
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

/// v2 (final review FR-09): the ACCOUNT id is part of what the identity key signs. v1 covered only `device ‖ auth_key`, so a valid
/// public device record could be replayed under a different account id (a directory-level unknown-key-share). The MLS credential
/// check kept that from becoming impersonation, but binding the account removes the confusion at its source.
pub fn binding_message(account: &Id16, device: &Id16, auth_key: &[u8]) -> Vec<u8> {
    let mut m = b"cipher-device-binding-v2\n".to_vec();
    m.extend_from_slice(&account.0);
    m.extend_from_slice(&device.0);
    m.extend_from_slice(auth_key);
    m
}

pub fn endorsement_message(account: &Id16, new_device: &Id16, identity_key: &[u8], auth_key: &[u8]) -> Vec<u8> {
    let mut m = b"cipher-device-endorsement-v1\n".to_vec();
    m.extend_from_slice(&account.0);
    m.extend_from_slice(&new_device.0);
    m.extend_from_slice(identity_key);
    m.extend_from_slice(auth_key);
    m
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub account_id: Id16,
    /// Server-side account credential (invite/registration token). Authenticates
    /// the *account*, never grants access to message content.
    pub registration_token: String,
    pub device: DeviceRecord,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddDeviceRequest {
    pub account_id: Id16,
    pub registration_token: String,
    pub device: DeviceRecord,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryResponse {
    pub account_id: Id16,
    pub devices: Vec<DeviceRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadKeyPackages {
    #[serde(with = "vec_b64")]
    pub key_packages: Vec<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPackageResponse {
    #[serde(with = "crate::b64")]
    pub key_package: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    /// Client-chosen random id; the relay dedups on (recipient, message_id) so
    /// retries are idempotent.
    pub message_id: Id16,
    pub recipient_device: Id16,
    /// Opaque protocol ciphertext. The relay cannot and does not interpret it.
    #[serde(with = "crate::b64")]
    pub ciphertext: Vec<u8>,
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SendStatus {
    Queued,
    Duplicate,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendResponse {
    pub status: SendStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub message_id: Id16,
    /// The sender is NOT recorded or forwarded: it is authenticated inside the
    /// protocol ciphertext. The relay sees the sender only transiently, while
    /// verifying the send request, and does not persist it.
    #[serde(with = "crate::b64")]
    pub ciphertext: Vec<u8>,
    /// For group commits and welcomes: the sequencer position (the group's commit count after this commit).
    /// Lets clients track exactly which commits they have processed, valid or not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_seq: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FetchResponse {
    pub envelopes: Vec<Envelope>,
    pub more: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckRequest {
    pub message_ids: Vec<Id16>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushTokenRequest {
    /// Opaque APNs/FCM token. Used only to send content-free wake-ups.
    pub token: String,
}

/// One ciphertext addressed to one recipient device (fan-out for groups / multi-device).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub recipient_device: Id16,
    pub message_id: Id16,
    #[serde(with = "crate::b64")]
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchSendRequest {
    pub deliveries: Vec<Delivery>,
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchSendResponse {
    /// Same order as the request. `queued`, `duplicate`, or an error code (`not_found`, `queue_full`).
    pub results: Vec<String>,
}

/// Group commit with compare-and-swap on the group epoch: the relay is the *sequencer* for
/// liveness (deterministic ordering of concurrent commits), never a trusted authority for
/// membership or content.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupCommitRequest {
    pub expected_epoch: u64,
    /// Present on removal commits: the group's routing tag rotates so removed members
    /// (who know the old tag) cannot keep advancing or bricking the group's epoch.
    pub new_tag: Option<Id16>,
    pub deliveries: Vec<Delivery>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupCommitResponse {
    /// Epoch after this commit was accepted.
    pub epoch: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupStaleResponse {
    pub error: String,
    pub current_epoch: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupStateResponse {
    pub epoch: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlobCreated {
    pub blob_id: Id16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

impl SendRequest {
    pub fn validate(&self) -> Result<u64, ValidationError> {
        if self.ciphertext.is_empty() || self.ciphertext.len() > MAX_MESSAGE_CIPHERTEXT_BYTES {
            return Err(ValidationError::Bounds("ciphertext"));
        }
        let ttl = self.ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
        if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&ttl) {
            return Err(ValidationError::Bounds("ttl_secs"));
        }
        Ok(ttl)
    }
}

fn validate_deliveries(d: &[Delivery]) -> Result<(), ValidationError> {
    if d.is_empty() {
        return Err(ValidationError::Empty);
    }
    if d.len() > MAX_BATCH_DELIVERIES {
        return Err(ValidationError::Bounds("deliveries"));
    }
    let total: usize = d.iter().map(|x| x.ciphertext.len()).sum();
    if d.iter().any(|x| x.ciphertext.is_empty() || x.ciphertext.len() > MAX_MESSAGE_CIPHERTEXT_BYTES)
        || total > 4 * MAX_MESSAGE_CIPHERTEXT_BYTES
    {
        return Err(ValidationError::Bounds("ciphertext"));
    }
    Ok(())
}

impl BatchSendRequest {
    pub fn validate(&self) -> Result<u64, ValidationError> {
        validate_deliveries(&self.deliveries)?;
        let ttl = self.ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
        if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&ttl) {
            return Err(ValidationError::Bounds("ttl_secs"));
        }
        Ok(ttl)
    }
}

impl GroupCommitRequest {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_deliveries(&self.deliveries)
    }
}

impl AckRequest {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.message_ids.is_empty() {
            return Err(ValidationError::Empty);
        }
        if self.message_ids.len() > MAX_ACK_BATCH {
            return Err(ValidationError::Bounds("message_ids"));
        }
        Ok(())
    }
}

impl UploadKeyPackages {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.key_packages.is_empty() {
            return Err(ValidationError::Empty);
        }
        if self.key_packages.len() > MAX_KEY_PACKAGES_PER_DEVICE {
            return Err(ValidationError::Bounds("key_packages"));
        }
        if self.key_packages.iter().any(|k| k.is_empty() || k.len() > MAX_KEY_PACKAGE_BYTES) {
            return Err(ValidationError::Bounds("key_package"));
        }
        Ok(())
    }
}

impl DeviceRecord {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.identity_key.len() != 32 {
            return Err(ValidationError::Bounds("identity_key"));
        }
        if self.auth_key.len() != 32 {
            return Err(ValidationError::Bounds("auth_key"));
        }
        if self.binding_sig.len() != 64 {
            return Err(ValidationError::Bounds("binding_sig"));
        }
        if let Some(e) = &self.endorsement {
            if e.signature.len() != 64 {
                return Err(ValidationError::Bounds("endorsement"));
            }
        }
        Ok(())
    }
}

mod vec_b64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        v.iter().map(|b| crate::b64::encode(b)).collect::<Vec<_>>().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let v = Vec::<String>::deserialize(d)?;
        if v.len() > super::MAX_KEY_PACKAGES_PER_DEVICE {
            return Err(serde::de::Error::custom("too many items"));
        }
        v.iter().map(|s| crate::b64::decode(s).ok_or_else(|| serde::de::Error::custom("invalid base64url"))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_fields_are_rejected() {
        let j = r#"{"message_id":"00000000000000000000000000000000","recipient_device":"00000000000000000000000000000000","ciphertext":"AA","ttl_secs":null,"plaintext":"x"}"#;
        assert!(serde_json::from_str::<SendRequest>(j).is_err());
    }

    #[test]
    fn oversize_and_ttl_bounds() {
        let mut r = SendRequest { message_id: Id16([0; 16]), recipient_device: Id16([0; 16]), ciphertext: vec![1; 10], ttl_secs: None };
        assert!(r.validate().is_ok());
        r.ciphertext = vec![0; MAX_MESSAGE_CIPHERTEXT_BYTES + 1];
        assert!(r.validate().is_err());
        r.ciphertext = vec![1];
        r.ttl_secs = Some(MAX_TTL_SECS + 1);
        assert!(r.validate().is_err());
        r.ttl_secs = Some(1);
        assert!(r.validate().is_err());
    }
}

// ------------------------------------------------------------------------------------ delivery capabilities

/// Recipient asks the relay for fresh random delivery capabilities (authenticated). A capability lets whoever holds it queue ciphertext for the minting
/// device WITHOUT authenticating; it grants no decryption ability and is useless without the (separately encrypted) message.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintCapsRequest {
    /// Chosen by the CLIENT (random 128-bit values): the relay never influences them. It stores only their hashes.
    pub caps: Vec<Id16>,
}

/// Revoke capabilities minted by the calling device. `grace_secs` keeps them valid a little longer so in-flight sends do not fail on rotation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeCapsRequest {
    pub caps: Vec<Id16>,
    pub grace_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnonDelivery {
    pub cap: Id16,
    pub message_id: Id16,
    #[serde(with = "crate::b64")]
    pub ciphertext: Vec<u8>,
}

/// UNAUTHENTICATED delivery: the relay learns neither the sender nor (beyond the capability) the recipient's stable identity.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnonDeliverRequest {
    pub deliveries: Vec<AnonDelivery>,
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnonDeliverResponse {
    /// Same order as the request: `queued`, `duplicate`, `queue_full`, or `invalid` (unknown / revoked / expired capability — deliberately one code).
    pub results: Vec<String>,
}

impl MintCapsRequest {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.caps.is_empty() || self.caps.len() > MAX_CAPS_PER_MINT {
            return Err(ValidationError::Bounds("caps"));
        }
        Ok(())
    }
}

impl RevokeCapsRequest {
    pub fn validate(&self) -> Result<u64, ValidationError> {
        if self.caps.is_empty() || self.caps.len() > MAX_CAPS_PER_MINT {
            return Err(ValidationError::Bounds("caps"));
        }
        let g = self.grace_secs.unwrap_or(0);
        if g > CAP_REVOKE_GRACE_MAX_SECS {
            return Err(ValidationError::Bounds("grace_secs"));
        }
        Ok(g)
    }
}

impl AnonDeliverRequest {
    pub fn validate(&self) -> Result<u64, ValidationError> {
        if self.deliveries.is_empty() {
            return Err(ValidationError::Empty);
        }
        if self.deliveries.len() > MAX_BATCH_DELIVERIES {
            return Err(ValidationError::Bounds("deliveries"));
        }
        let total: usize = self.deliveries.iter().map(|x| x.ciphertext.len()).sum();
        if self.deliveries.iter().any(|x| x.ciphertext.is_empty() || x.ciphertext.len() > MAX_MESSAGE_CIPHERTEXT_BYTES)
            || total > 4 * MAX_MESSAGE_CIPHERTEXT_BYTES
        {
            return Err(ValidationError::Bounds("ciphertext"));
        }
        let ttl = self.ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
        if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&ttl) {
            return Err(ValidationError::Bounds("ttl_secs"));
        }
        Ok(ttl)
    }
}
