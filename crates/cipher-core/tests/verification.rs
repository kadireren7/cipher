#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::cloned_ref_to_slice_refs)]
mod common;
use cipher_core::clock::testing::ManualClock;
use cipher_core::events::SecurityEvent;
use cipher_core::keystore::testing::InMemoryKeyStore;
use cipher_core::keystore::ProtectionLevel;
use cipher_core::mls::MlsClient;
use cipher_core::vault::{Vault, VaultConfig};
use cipher_core::verification::*;
use cipher_wire::messages::DeviceRecord;
use common::*;
use std::sync::Arc;

fn vault() -> Vault {
    let mut v = Vault::open(
        None,
        Arc::new(InMemoryKeyStore::new(ProtectionLevel::HardwareBacked)),
        Arc::new(ManualClock::new(1)),
        VaultConfig::default(),
    )
    .unwrap();
    v.provision().unwrap();
    v
}

fn linked_device(root: &MlsClient) -> MlsClient {
    let d = MlsClient::generate(root.account_id(), rid()).unwrap();
    let e = root.endorse_device(&d.device_id(), &d.identity_public(), &d.auth_public()).unwrap();
    let _ = e;
    d
}

fn endorsed_record(root: &MlsClient, new: &MlsClient) -> DeviceRecord {
    let e = root.endorse_device(&new.device_id(), &new.identity_public(), &new.auth_public()).unwrap();
    new.device_record(Some(e)).unwrap()
}

#[test]
fn first_contact_pins_root_then_stable() {
    let mut v = vault();
    let alice = new_client();
    let rec = alice.device_record(None).unwrap();
    v.with_store(|s| {
        let mut pins = IdentityPins::new(s);
        let t = pins.evaluate_directory(&alice.account_id(), &[rec.clone()])?;
        assert!(t.first_contact && t.events.is_empty() && t.trusted.len() == 1);
        let t = pins.evaluate_directory(&alice.account_id(), &[rec.clone()])?;
        assert!(!t.first_contact && t.events.is_empty() && t.trusted.len() == 1);
        assert_eq!(pins.pinned_key(&alice.account_id(), &alice.device_id())?, Some(alice.identity_public()));
        Ok(())
    })
    .unwrap();
}

#[test]
fn sec_011_server_substituting_identity_key_is_detected_and_untrusted_until_acknowledged() {
    let mut v = vault();
    let alice = new_client();
    let real = alice.device_record(None).unwrap();
    // Malicious server: same device id, attacker's identity + auth keys, validly self-bound.
    let attacker = MlsClient::generate(alice.account_id(), alice.device_id()).unwrap();
    let forged = attacker.device_record(None).unwrap();
    v.with_store(|s| {
        let mut pins = IdentityPins::new(s);
        pins.evaluate_directory(&alice.account_id(), &[real.clone()])?;
        let t = pins.evaluate_directory(&alice.account_id(), &[forged.clone()])?;
        assert!(t.trusted.is_empty(), "substituted key must not be trusted");
        assert!(t.events.iter().any(|e| matches!(e, SecurityEvent::IdentityChanged { .. })));
        // Pin is unchanged: still the real key.
        assert_eq!(pins.pinned_key(&alice.account_id(), &alice.device_id())?, Some(alice.identity_public()));
        // The original, honest record is still trusted (no silent replacement).
        assert_eq!(pins.evaluate_directory(&alice.account_id(), &[real.clone()])?.trusted.len(), 1);
        // Only explicit acknowledgement (after safety-number comparison) trusts the new key.
        pins.acknowledge(&alice.account_id(), &alice.device_id())?;
        assert_eq!(pins.evaluate_directory(&alice.account_id(), &[forged.clone()])?.trusted.len(), 1);
        Ok(())
    })
    .unwrap();
}

#[test]
fn rogue_unendorsed_device_injected_by_server_is_untrusted() {
    let mut v = vault();
    let alice = new_client();
    let rogue = MlsClient::generate(alice.account_id(), rid()).unwrap();
    v.with_store(|s| {
        let mut pins = IdentityPins::new(s);
        pins.evaluate_directory(&alice.account_id(), &[alice.device_record(None)?])?;
        let t = pins.evaluate_directory(&alice.account_id(), &[alice.device_record(None)?, rogue.device_record(None)?])?;
        assert_eq!(t.trusted.len(), 1);
        assert!(t.events.iter().any(|e| matches!(e, SecurityEvent::UnendorsedDevice { .. })));
        Ok(())
    })
    .unwrap();
}

#[test]
fn endorsed_new_device_is_accepted_with_notification_and_forged_endorsement_is_not() {
    let mut v = vault();
    let alice = new_client();
    let phone2 = linked_device(&alice);
    let evil_signer = new_client(); // not a pinned device of alice
    let forged_e = evil_signer.endorse_device(&phone2.device_id(), &phone2.identity_public(), &phone2.auth_public()).unwrap();
    let forged = phone2.device_record(Some(forged_e)).unwrap();
    v.with_store(|s| {
        let mut pins = IdentityPins::new(s);
        pins.evaluate_directory(&alice.account_id(), &[alice.device_record(None)?])?;
        let t = pins.evaluate_directory(&alice.account_id(), &[alice.device_record(None)?, forged])?;
        assert_eq!(t.trusted.len(), 1, "endorsement by a non-pinned key is not valid");
        assert!(t.events.iter().any(|e| matches!(e, SecurityEvent::UnendorsedDevice { .. })));

        let ok = endorsed_record(&alice, &phone2);
        let t = pins.evaluate_directory(&alice.account_id(), &[alice.device_record(None)?, ok])?;
        assert_eq!(t.trusted.len(), 2);
        assert!(t.events.iter().any(|e| matches!(e, SecurityEvent::DeviceListChanged { .. })), "device-change warning");
        Ok(())
    })
    .unwrap();
}

#[test]
fn endorsement_is_bound_to_the_device_and_keys_it_endorsed() {
    let mut v = vault();
    let alice = new_client();
    let phone2 = linked_device(&alice);
    let phone3 = linked_device(&alice);
    // Reuse phone2's endorsement on phone3's record: must fail.
    let e2 = alice.endorse_device(&phone2.device_id(), &phone2.identity_public(), &phone2.auth_public()).unwrap();
    let mut stolen = phone3.device_record(Some(e2)).unwrap();
    stolen.device_id = phone3.device_id();
    v.with_store(|s| {
        let mut pins = IdentityPins::new(s);
        pins.evaluate_directory(&alice.account_id(), &[alice.device_record(None)?])?;
        let t = pins.evaluate_directory(&alice.account_id(), &[alice.device_record(None)?, stolen])?;
        assert_eq!(t.trusted.len(), 1);
        Ok(())
    })
    .unwrap();
}

#[test]
fn auth_key_swapped_by_server_fails_binding_check() {
    let mut v = vault();
    let alice = new_client();
    let mut rec = alice.device_record(None).unwrap();
    rec.auth_key = new_client().auth_public().to_vec(); // server swaps transport key to enable impersonation
    assert!(!verify_binding(&alice.account_id(), &rec));
    v.with_store(|s| {
        let mut pins = IdentityPins::new(s);
        assert!(pins.evaluate_directory(&alice.account_id(), &[rec.clone()]).is_err());
        Ok(())
    })
    .unwrap();
}

#[test]
fn ambiguous_first_contact_is_refused() {
    let mut v = vault();
    let a = new_client();
    let b = MlsClient::generate(a.account_id(), rid()).unwrap();
    v.with_store(|s| {
        let mut pins = IdentityPins::new(s);
        assert!(pins.evaluate_directory(&a.account_id(), &[a.device_record(None)?, b.device_record(None)?]).is_err());
        Ok(())
    })
    .unwrap();
}

#[test]
fn safety_number_and_qr_detect_substitution() {
    let (alice, bob) = (new_client(), new_client());
    let mallory = new_client();
    let n_true = safety_number(&alice.account_id(), &alice.identity_public(), &bob.account_id(), &bob.identity_public());
    let n_seen_by_alice = safety_number(&alice.account_id(), &alice.identity_public(), &bob.account_id(), &mallory.identity_public());
    assert_ne!(n_true, n_seen_by_alice);
    // Bob shows his real QR; Alice's client has Mallory's key pinned for Bob -> mismatch.
    let qr = qr_payload(&bob.account_id(), &bob.identity_public());
    assert!(verify_scanned_qr(&qr, &bob.account_id(), &bob.identity_public()).is_ok());
    assert!(verify_scanned_qr(&qr, &bob.account_id(), &mallory.identity_public()).is_err());
    assert!(verify_scanned_qr("###", &bob.account_id(), &bob.identity_public()).is_err());
}

/// FR-09: a valid public device record must not be usable under a DIFFERENT account id (directory unknown-key-share).
#[test]
fn a_device_record_transplanted_to_another_account_fails_binding_verification() {
    let mut v = vault();
    let (alice, mallory) = (new_client(), new_client());
    let rec = alice.device_record(None).unwrap();
    assert!(verify_binding(&alice.account_id(), &rec), "control: the record is valid for its own account");
    assert!(!verify_binding(&mallory.account_id(), &rec), "the same record under another account id must not verify");
    v.with_store(|s| {
        let mut pins = IdentityPins::new(s);
        // a malicious relay answers a lookup for Mallory with Alice's (valid) record
        assert!(pins.evaluate_directory(&mallory.account_id(), &[rec.clone()]).is_err());
        assert!(pins.evaluate_directory(&alice.account_id(), &[rec.clone()]).is_ok());
        Ok(())
    })
    .unwrap();
}
