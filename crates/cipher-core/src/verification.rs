//! Key verification: safety numbers, QR payloads, identity pinning (SEC-011).
//!
//! Trust model: trust-on-first-use pin of each account's first (root) device
//! identity key, plus *device endorsements*: further devices must be signed by an
//! already-pinned device's identity key. A server that substitutes or injects a
//! key cannot forge an endorsement, so the client detects it and raises a
//! `SecurityEvent` instead of silently trusting. Users can compare safety numbers /
//! QR codes out-of-band to close the first-use gap.
//!
//! Limits: TOFU cannot detect a server that lies from the very first contact
//! unless users verify out-of-band. Key transparency (auditable logs) is a
//! SECURITY TODO (ST-006) for a later phase.
use crate::error::{Result, SecurityError};
use crate::events::SecurityEvent;
use crate::storage::EncryptedStore;
use cipher_wire::messages::{binding_message, endorsement_message, DeviceRecord};
use cipher_wire::Id16;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const NS_PINS: &str = "identity_pins";
const FP_ITERATIONS: u32 = 5200;

fn fingerprint_30(account: &Id16, identity_key: &[u8; 32]) -> [u8; 30] {
    let mut h = Sha256::new();
    h.update(b"cipher-fingerprint-v1");
    h.update(account.0);
    h.update(identity_key);
    let mut d: [u8; 32] = h.finalize().into();
    for _ in 0..FP_ITERATIONS {
        let mut h = Sha256::new();
        h.update(d);
        h.update(account.0);
        h.update(identity_key);
        d = h.finalize().into();
    }
    let mut out = [0u8; 30];
    out.copy_from_slice(&d[..30]);
    out
}

fn digits(fp: &[u8; 30]) -> String {
    // 6 groups of 5 digits per party; each group is 5 bytes mod 100000.
    let mut s = String::new();
    for chunk in fp.chunks_exact(5) {
        let mut n: u64 = 0;
        for b in chunk {
            n = (n << 8) | u64::from(*b);
        }
        s.push_str(&format!("{:05}", n % 100_000));
    }
    s
}

/// 60-digit safety number: symmetric (both parties compute the same value).
pub fn safety_number(a_account: &Id16, a_key: &[u8; 32], b_account: &Id16, b_key: &[u8; 32]) -> String {
    let a = digits(&fingerprint_30(a_account, a_key));
    let b = digits(&fingerprint_30(b_account, b_key));
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let all = format!("{first}{second}");
    all.as_bytes().chunks(5).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(" ")
}

const QR_MAGIC: &[u8; 4] = b"CQR1";

/// Payload a device shows as a QR code: its account id and identity key.
pub fn qr_payload(account: &Id16, identity_key: &[u8; 32]) -> String {
    let mut b = QR_MAGIC.to_vec();
    b.extend_from_slice(&account.0);
    b.extend_from_slice(identity_key);
    cipher_wire::b64::encode(&b)
}

/// Decode a QR payload into (account id, identity key). Strict: exact length and magic.
pub fn parse_qr(payload: &str) -> Result<(Id16, [u8; 32])> {
    let bytes = cipher_wire::b64::decode(payload.trim()).ok_or(SecurityError::Malformed("qr"))?;
    if bytes.len() != 4 + 16 + 32 || bytes.get(..4) != Some(QR_MAGIC.as_slice()) {
        return Err(SecurityError::Malformed("qr"));
    }
    let account: [u8; 16] = bytes.get(4..20).and_then(|b| b.try_into().ok()).ok_or(SecurityError::Malformed("qr"))?;
    let key: [u8; 32] = bytes.get(20..52).and_then(|b| b.try_into().ok()).ok_or(SecurityError::Malformed("qr"))?;
    Ok((Id16(account), key))
}

/// Compare a scanned QR payload to what *this client has pinned*. Mismatch means
/// the key the server gave us differs from the key the peer's device really holds.
pub fn verify_scanned_qr(scanned: &str, pinned_account: &Id16, pinned_key: &[u8; 32]) -> Result<()> {
    let bytes = cipher_wire::b64::decode(scanned).ok_or(SecurityError::Malformed("qr"))?;
    let mut expected = QR_MAGIC.to_vec();
    expected.extend_from_slice(&pinned_account.0);
    expected.extend_from_slice(pinned_key);
    if bytes.len() == expected.len() && bool::from(bytes.ct_eq(&expected)) {
        Ok(())
    } else {
        Err(SecurityError::IdentityUntrusted("scanned identity does not match pinned identity"))
    }
}

fn vk(b: &[u8]) -> Option<VerifyingKey> {
    VerifyingKey::from_bytes(b.try_into().ok()?).ok()
}

fn verify_sig(key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match (vk(key), Signature::from_slice(sig)) {
        (Some(k), Ok(s)) => k.verify(msg, &s).is_ok(),
        _ => false,
    }
}

/// Verify the identity-key signature binding a device's transport auth key to its identity.
pub fn verify_binding(account: &Id16, rec: &DeviceRecord) -> bool {
    rec.validate().is_ok() && verify_sig(&rec.identity_key, &binding_message(account, &rec.device_id, &rec.auth_key), &rec.binding_sig)
}

#[derive(Serialize, Deserialize, Clone)]
struct PinnedDevice {
    device: Id16,
    identity_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Default)]
struct AccountPin {
    devices: Vec<PinnedDevice>,
    /// Devices seen but not trusted (changed key / unendorsed), awaiting user acknowledgement.
    pending: Vec<PinnedDevice>,
}

#[derive(Debug, Default)]
pub struct DirectoryTrust {
    /// Records that are pinned or endorsed by a pinned device: safe to use.
    pub trusted: Vec<DeviceRecord>,
    /// Events the UI must surface.
    pub events: Vec<SecurityEvent>,
    pub first_contact: bool,
}

pub struct IdentityPins<'a> {
    store: &'a mut EncryptedStore,
}

impl std::fmt::Debug for IdentityPins<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdentityPins")
    }
}

impl<'a> IdentityPins<'a> {
    pub fn new(store: &'a mut EncryptedStore) -> Self {
        Self { store }
    }

    fn load(&self, account: &Id16) -> Result<Option<AccountPin>> {
        match self.store.get(NS_PINS, &account.to_hex())? {
            None => Ok(None),
            Some(b) => serde_json::from_slice(&b).map(Some).map_err(|_| SecurityError::StorageCorrupt),
        }
    }

    fn save(&mut self, account: &Id16, pin: &AccountPin) -> Result<()> {
        let b = serde_json::to_vec(pin).map_err(|_| SecurityError::StorageCorrupt)?;
        self.store.put(NS_PINS, &account.to_hex(), &b)
    }

    /// All pinned devices: account -> device -> identity key.
    pub fn pinned_devices(&self) -> Result<std::collections::BTreeMap<Id16, std::collections::BTreeMap<Id16, Vec<u8>>>> {
        let mut out = std::collections::BTreeMap::new();
        for id in self.store.list_ids(NS_PINS)? {
            let account = Id16::parse(&id).map_err(|_| SecurityError::StorageCorrupt)?;
            if let Some(pin) = self.load(&account)? {
                out.insert(account, pin.devices.iter().map(|d| (d.device, d.identity_key.clone())).collect());
            }
        }
        Ok(out)
    }

    /// Returns the pinned identity key for a device, if any.
    pub fn pinned_key(&self, account: &Id16, device: &Id16) -> Result<Option<[u8; 32]>> {
        Ok(self
            .load(account)?
            .and_then(|p| p.devices.iter().find(|d| &d.device == device).and_then(|d| d.identity_key.as_slice().try_into().ok())))
    }

    /// Evaluate a directory response from the (untrusted) relay.
    pub fn evaluate_directory(&mut self, account: &Id16, records: &[DeviceRecord]) -> Result<DirectoryTrust> {
        let mut out = DirectoryTrust::default();
        // 1. Every record must carry a valid identity->auth binding; otherwise fail closed.
        if records.iter().any(|r| !verify_binding(account, r)) {
            return Err(SecurityError::IdentityUntrusted("directory record failed binding verification"));
        }
        let existing = self.load(account)?;
        let first = existing.is_none();
        let mut pin = existing.unwrap_or_default();
        out.first_contact = first;

        if first {
            let roots: Vec<&DeviceRecord> = records.iter().filter(|r| r.endorsement.is_none()).collect();
            if roots.len() != 1 {
                return Err(SecurityError::IdentityUntrusted("cannot determine root device on first contact"));
            }
            if let Some(r) = roots.first() {
                pin.devices.push(PinnedDevice { device: r.device_id, identity_key: r.identity_key.clone() });
            }
        }

        // 2. Iterate to a fixpoint so endorsement chains resolve regardless of order.
        let mut changed = true;
        let mut accepted: Vec<Id16> = Vec::new();
        let mut rejected: Vec<&DeviceRecord> = Vec::new();
        let mut remaining: Vec<&DeviceRecord> = records.iter().collect();
        while changed {
            changed = false;
            let mut next = Vec::new();
            for r in remaining {
                let pinned = pin.devices.iter().find(|d| d.device == r.device_id).cloned();
                match pinned {
                    Some(p) if bool::from(p.identity_key.as_slice().ct_eq(&r.identity_key)) => {
                        accepted.push(r.device_id);
                        changed = true;
                    }
                    Some(_) => rejected.push(r), // same device id, different identity key
                    None => {
                        let endorsed = r.endorsement.as_ref().is_some_and(|e| {
                            pin.devices.iter().find(|d| d.device == e.endorser_device).is_some_and(|endorser| {
                                verify_sig(
                                    &endorser.identity_key,
                                    &endorsement_message(account, &r.device_id, &r.identity_key, &r.auth_key),
                                    &e.signature,
                                )
                            })
                        });
                        if endorsed {
                            pin.devices.push(PinnedDevice { device: r.device_id, identity_key: r.identity_key.clone() });
                            accepted.push(r.device_id);
                            if !first {
                                out.events.push(SecurityEvent::DeviceListChanged { account_id: account.to_hex() });
                            }
                            changed = true;
                        } else {
                            next.push(r);
                        }
                    }
                }
            }
            remaining = next;
        }

        // 3. Whatever is left is not trusted: surface and park as pending.
        for r in rejected {
            out.events.push(SecurityEvent::IdentityChanged { account_id: account.to_hex() });
            Self::park(&mut pin, r);
        }
        for r in remaining {
            out.events.push(SecurityEvent::UnendorsedDevice { account_id: account.to_hex(), device_id: r.device_id.to_hex() });
            Self::park(&mut pin, r);
        }

        out.trusted = records.iter().filter(|r| accepted.contains(&r.device_id)).cloned().collect();
        self.save(account, &pin)?;
        Ok(out)
    }

    fn park(pin: &mut AccountPin, r: &DeviceRecord) {
        pin.pending.retain(|p| p.device != r.device_id);
        pin.pending.push(PinnedDevice { device: r.device_id, identity_key: r.identity_key.clone() });
    }

    /// The user compared safety numbers / scanned a QR code and accepts this device's key.
    /// This is the ONLY way an identity change becomes trusted.
    pub fn acknowledge(&mut self, account: &Id16, device: &Id16) -> Result<()> {
        let mut pin = self.load(account)?.ok_or(SecurityError::InvalidState)?;
        let idx = pin.pending.iter().position(|p| &p.device == device).ok_or(SecurityError::InvalidState)?;
        let p = pin.pending.remove(idx);
        pin.devices.retain(|d| d.device != p.device);
        pin.devices.push(p);
        self.save(account, &pin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]
        #[test]
        fn safety_number_is_symmetric(a in any::<[u8;16]>(), b in any::<[u8;16]>(), ka in any::<[u8;32]>(), kb in any::<[u8;32]>()) {
            let (a, b) = (Id16(a), Id16(b));
            prop_assert_eq!(safety_number(&a, &ka, &b, &kb), safety_number(&b, &kb, &a, &ka));
        }

        #[test]
        fn qr_decoder_never_panics(s in ".{0,200}") {
            let _ = verify_scanned_qr(&s, &Id16([0;16]), &[0;32]);
        }
    }

    #[test]
    fn safety_number_has_sixty_digits_and_changes_with_key() {
        let a = Id16([1; 16]);
        let b = Id16([2; 16]);
        let n1 = safety_number(&a, &[3; 32], &b, &[4; 32]);
        let n2 = safety_number(&a, &[3; 32], &b, &[5; 32]);
        assert_eq!(n1.chars().filter(char::is_ascii_digit).count(), 60);
        assert_ne!(n1, n2);
    }
}
