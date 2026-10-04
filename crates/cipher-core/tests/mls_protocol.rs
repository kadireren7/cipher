#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod common;
use cipher_core::error::SecurityError;
use cipher_core::mls::MlsClient;
use cipher_core::protocol::{GroupProtocol, Processed};
use common::*;

const PLAINTEXT: &[u8] = b"PLAINTEXT-FIXTURE-meet-at-dawn-7731";

#[test]
fn one_to_one_roundtrip_and_ciphertext_hides_plaintext() {
    let (mut a, mut b) = (new_client(), new_client());
    let g = build_group(&mut a, &mut [&mut b]);
    let ct = a.encrypt(&g, PLAINTEXT).unwrap();
    assert!(!ct.windows(PLAINTEXT.len()).any(|w| w == PLAINTEXT));
    assert_eq!(b.process(&g, &ct, &AllowAll).unwrap(), Processed::Application(PLAINTEXT.to_vec()));
    let back = b.encrypt(&g, b"reply").unwrap();
    assert_eq!(a.process(&g, &back, &AllowAll).unwrap(), Processed::Application(b"reply".to_vec()));
}

#[test]
fn sec_015_modified_ciphertext_is_rejected_at_every_byte_position_sample() {
    let (mut a, mut b) = (new_client(), new_client());
    let g = build_group(&mut a, &mut [&mut b]);
    let ct = a.encrypt(&g, PLAINTEXT).unwrap();
    // Flip one bit at a spread of positions; every variant must fail closed.
    let step = (ct.len() / 40).max(1);
    for i in (0..ct.len()).step_by(step) {
        let mut bad = ct.clone();
        bad[i] ^= 0x01;
        assert!(b.process(&g, &bad, &AllowAll).is_err(), "tamper at byte {i} accepted");
    }
    // The untampered original still works afterwards (failed attempts did not poison state).
    assert_eq!(b.process(&g, &ct, &AllowAll).unwrap(), Processed::Application(PLAINTEXT.to_vec()));
}

#[test]
fn malformed_and_truncated_ciphertext_rejected() {
    let (mut a, mut b) = (new_client(), new_client());
    let g = build_group(&mut a, &mut [&mut b]);
    let ct = a.encrypt(&g, PLAINTEXT).unwrap();
    for bad in [vec![], vec![0u8; 3], vec![0xff; 64], ct[..ct.len() / 2].to_vec(), [ct.clone(), vec![0]].concat()] {
        assert!(b.process(&g, &bad, &AllowAll).is_err());
    }
}

#[test]
fn wrong_keys_cannot_decrypt() {
    let (mut a, mut b) = (new_client(), new_client());
    let g = build_group(&mut a, &mut [&mut b]);
    let ct = a.encrypt(&g, PLAINTEXT).unwrap();
    // An unrelated client with its own group of the same id cannot read it.
    let (mut x, mut y) = (new_client(), new_client());
    let gx = build_group(&mut x, &mut [&mut y]);
    assert!(y.process(&gx, &ct, &AllowAll).is_err());
    // A client that was never in the group has no such group.
    let mut outsider = new_client();
    assert!(outsider.process(&g, &ct, &AllowAll).is_err());
}

#[test]
fn sec_014_replay_does_not_produce_second_valid_transition() {
    let (mut a, mut b) = (new_client(), new_client());
    let g = build_group(&mut a, &mut [&mut b]);
    let ct = a.encrypt(&g, PLAINTEXT).unwrap();
    assert!(matches!(b.process(&g, &ct, &AllowAll), Ok(Processed::Application(_))));
    let epoch = b.epoch(&g).unwrap();
    assert!(matches!(b.process(&g, &ct, &AllowAll), Err(SecurityError::Replay)));
    assert_eq!(b.epoch(&g).unwrap(), epoch);

    // Replayed commit: must not advance the epoch twice.
    let mut c = new_client();
    let kp = c.generate_key_packages(1).unwrap().remove(0);
    let out = a.add_member(&g, &kp, &expected(&c)).unwrap();
    a.merge_pending_commit(&g).unwrap();
    assert!(matches!(b.process(&g, &out.commit, &AllowAll), Ok(Processed::Commit { .. })));
    let e2 = b.epoch(&g).unwrap();
    assert!(matches!(b.process(&g, &out.commit, &AllowAll), Err(SecurityError::Replay)));
    assert_eq!(b.epoch(&g).unwrap(), e2);
}

#[test]
fn sec_014_replay_rejected_by_protocol_layer_even_without_client_cache() {
    let (mut a, mut b) = (new_client(), new_client());
    let g = build_group(&mut a, &mut [&mut b]);
    let ct = a.encrypt(&g, PLAINTEXT).unwrap();
    b.process(&g, &ct, &AllowAll).unwrap();
    b.clear_replay_cache_for_tests();
    assert!(b.process(&g, &ct, &AllowAll).is_err(), "MLS secret-tree must refuse an already-consumed message key");
}

#[test]
fn sec_006_removed_member_cannot_read_later_epochs_and_cannot_send() {
    let (mut a, mut b, mut c) = (new_client(), new_client(), new_client());
    let g = build_group(&mut a, &mut [&mut b, &mut c]);
    let before = a.encrypt(&g, b"before-removal").unwrap();
    assert!(c.process(&g, &before, &AllowAll).is_ok()); // legitimately readable before removal

    let out = a.remove_member(&g, &c.device_id()).unwrap();
    a.merge_pending_commit(&g).unwrap();
    match b.process(&g, &out.commit, &AllowAll).unwrap() {
        Processed::Commit { removed, self_removed, .. } => {
            assert_eq!(removed, vec![(c.account_id(), c.device_id())]);
            assert!(!self_removed);
        }
        other => panic!("{other:?}"),
    }
    // Carol receives the removal commit itself and learns she is out.
    match c.process(&g, &out.commit, &AllowAll).unwrap() {
        Processed::Commit { self_removed, .. } => assert!(self_removed),
        other => panic!("{other:?}"),
    }
    assert!(!c.is_active(&g).unwrap());

    // Messages in the new epoch: members read them, the removed member cannot.
    let after = a.encrypt(&g, b"after-removal-secret").unwrap();
    assert_eq!(b.process(&g, &after, &AllowAll).unwrap(), Processed::Application(b"after-removal-secret".to_vec()));
    assert!(c.process(&g, &after, &AllowAll).is_err());
    assert!(c.encrypt(&g, b"i am still here").is_err());
    assert!(!a.members(&g).unwrap().iter().any(|(_, d)| *d == c.device_id()));
}

#[test]
fn sec_006_removed_member_with_old_state_snapshot_still_cannot_read_new_epoch() {
    let (mut a, mut b, mut c) = (new_client(), new_client(), new_client());
    let g = build_group(&mut a, &mut [&mut b, &mut c]);
    // Carol's full state is exfiltrated *before* removal (worst case for the group).
    let carol_snapshot = c.snapshot().unwrap();
    let pre = a.encrypt(&g, b"pre-removal").unwrap();
    // Control: the exfiltrated state is functional for the epoch it belongs to.
    let mut control = MlsClient::restore(&carol_snapshot).unwrap();
    assert!(matches!(control.process(&g, &pre, &AllowAll), Ok(Processed::Application(_))));
    let out = a.remove_member(&g, &c.device_id()).unwrap();
    a.merge_pending_commit(&g).unwrap();
    b.process(&g, &out.commit, &AllowAll).unwrap();
    let after = a.encrypt(&g, b"new-epoch-secret").unwrap();
    let mut stolen = MlsClient::restore(&carol_snapshot).unwrap();
    assert!(stolen.process(&g, &after, &AllowAll).is_err());
}

#[test]
fn sec_007_forward_secrecy_current_state_cannot_decrypt_past_messages() {
    let (mut a, mut b) = (new_client(), new_client());
    let g = build_group(&mut a, &mut [&mut b]);
    let m1 = a.encrypt(&g, PLAINTEXT).unwrap();
    b.process(&g, &m1, &AllowAll).unwrap();
    let m2 = a.encrypt(&g, b"second").unwrap();
    b.process(&g, &m2, &AllowAll).unwrap();
    // A message Bob has NOT yet consumed: positive control that the restored state is functional.
    let m3 = a.encrypt(&g, b"third").unwrap();
    // Attacker obtains Bob's *current* complete state, with no replay cache.
    let snap = b.snapshot().unwrap();
    let mut attacker = MlsClient::restore(&snap).unwrap();
    attacker.clear_replay_cache_for_tests();
    assert!(attacker.process(&g, &m1, &AllowAll).is_err(), "consumed message keys must be gone");
    assert!(attacker.process(&g, &m2, &AllowAll).is_err());
    assert_eq!(attacker.process(&g, &m3, &AllowAll).unwrap(), Processed::Application(b"third".to_vec()), "control: restored state works");
}

#[test]
fn sec_010_malicious_member_adding_unapproved_device_is_rejected_fail_closed() {
    let (mut a, mut b) = (new_client(), new_client());
    let g = build_group(&mut a, &mut [&mut b]);
    let mut rogue = new_client();
    let kp = rogue.generate_key_packages(1).unwrap().remove(0);
    let out = a.add_member(&g, &kp, &expected(&rogue)).unwrap();
    a.merge_pending_commit(&g).unwrap();
    let epoch = b.epoch(&g).unwrap();
    assert!(matches!(b.process(&g, &out.commit, &DenyAll), Err(SecurityError::IdentityUntrusted(_))));
    assert_eq!(b.epoch(&g).unwrap(), epoch, "state must not advance on a rejected commit");
    assert_eq!(b.members(&g).unwrap().len(), 2);
}

#[test]
fn sec_011_key_package_with_substituted_identity_is_refused() {
    let (mut a, mut bob) = (new_client(), new_client());
    let g = a.create_group().unwrap();
    let mut mallory = new_client();
    // Server swaps Bob's key package for Mallory's.
    let evil_kp = mallory.generate_key_packages(1).unwrap().remove(0);
    assert!(matches!(a.add_member(&g, &evil_kp, &expected(&bob)), Err(SecurityError::IdentityUntrusted(_))));
    // Same device id but attacker's key: pinned identity key mismatch.
    let mut impostor = MlsClient::generate(bob.account_id(), bob.device_id()).unwrap();
    let evil_kp2 = impostor.generate_key_packages(1).unwrap().remove(0);
    assert!(matches!(a.add_member(&g, &evil_kp2, &expected(&bob)), Err(SecurityError::IdentityUntrusted(_))));
    // Garbage key package.
    assert!(a.add_member(&g, &[1, 2, 3], &expected(&bob)).is_err());
    let _ = bob.generate_key_packages(1);
}

#[test]
fn snapshot_roundtrip_preserves_sessions_and_rejects_corruption() {
    let (mut a, mut b) = (new_client(), new_client());
    let g = build_group(&mut a, &mut [&mut b]);
    let snap = a.snapshot().unwrap();
    let mut a2 = MlsClient::restore(&snap).unwrap();
    let ct = a2.encrypt(&g, b"after-restore").unwrap();
    assert_eq!(b.process(&g, &ct, &AllowAll).unwrap(), Processed::Application(b"after-restore".to_vec()));
    // Truncations and trailing bytes are rejected, never partially loaded.
    for n in [0usize, 3, 40, snap.len() - 1] {
        assert!(MlsClient::restore(&snap[..n]).is_err());
    }
    let mut extra = snap.to_vec();
    extra.push(0);
    assert!(MlsClient::restore(&extra).is_err());
}

#[test]
fn snapshot_does_not_leak_into_debug_output() {
    let a = new_client();
    let dbg = format!("{a:?}");
    assert!(!dbg.contains("auth_key") && !dbg.contains("sig"));
}

#[test]
fn sec_007_post_compromise_security_after_self_update_old_state_loses_access() {
    let (mut a, mut b) = (new_client(), new_client());
    let g = build_group(&mut a, &mut [&mut b]);
    // Attacker exfiltrates Bob's complete state at time T.
    let stolen_snapshot = b.snapshot().unwrap();
    let mut attacker = MlsClient::restore(&stolen_snapshot).unwrap();
    let before = a.encrypt(&g, b"pre-update").unwrap();
    assert!(matches!(attacker.process(&g, &before, &AllowAll), Ok(Processed::Application(_))), "control: stolen state is live at time T");

    // Bob heals: refreshes his leaf keys. Alice merges the commit; the attacker does NOT see it
    // (or sees it but cannot process it without Bob's new private keys).
    let out = b.self_update(&g).unwrap();
    b.merge_pending_commit(&g).unwrap();
    a.process(&g, &out.commit, &AllowAll).unwrap();
    assert!(
        !matches!(attacker.process(&g, &out.commit, &AllowAll), Ok(Processed::Commit { .. })),
        "old state must not be able to apply the healing commit"
    );
    assert_ne!(attacker.epoch(&g).unwrap(), b.epoch(&g).unwrap());

    // New epoch traffic is unreadable to the holder of the OLD state.
    let after = a.encrypt(&g, b"post-update-secret").unwrap();
    assert_eq!(b.process(&g, &after, &AllowAll).unwrap(), Processed::Application(b"post-update-secret".to_vec()));
    assert!(attacker.process(&g, &after, &AllowAll).is_err());
}
