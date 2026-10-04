#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Adversarial group tests (final review). Each test is a regression for a finding in docs/FINAL_SECURITY_REVIEW.md.
mod common;
use cipher_core::app::groupmeta::GroupMeta;
use cipher_core::protocol::{GroupOp, GroupProtocol, Processed};
use common::*;

/// FR-01 (INFORMATIONAL, hypothesis refuted): suspected that a Welcome carrying the group id of an EXISTING group could overwrite that
/// group's MLS state (the engine only noticed the collision after `into_group`). Anyone who knows a conversation id could then break or
/// hijack it. The test shows OpenMLS refuses, (already while staging; `join_welcome_ex` additionally carries an explicit pre-`into_group` check as defence in depth). Control: the
/// same Welcome with a fresh group id joins fine, so the refusal is caused by the collision and not by a broken fixture.
#[test]
fn welcome_with_the_group_id_of_an_existing_group_cannot_overwrite_it() {
    let (mut alice, mut bob, mut mallory) = (new_client(), new_client(), new_client());
    let meta = GroupMeta::new_dm(rid());
    let g = alice.create_group_with_meta(&meta).unwrap();
    let kp = bob.generate_key_packages(1).unwrap().remove(0);
    let out = alice.commit(&g, &[GroupOp::Add { key_package: kp, expected: expected(&bob) }]).unwrap();
    alice.merge_pending_commit(&g).unwrap();
    bob.join_welcome_ex(out.welcome.as_ref().unwrap()).unwrap();

    // Mallory knows the group id and invites BOB into a different group that reuses it.
    let evil_meta = GroupMeta::new_dm(rid());
    let eg = mallory.create_group_with_id_for_tests(&evil_meta, &g.0).unwrap();
    let kp2 = bob.generate_key_packages(1).unwrap().remove(0);
    let evil = mallory.commit(&eg, &[GroupOp::Add { key_package: kp2, expected: expected(&bob) }]).unwrap();

    let r = bob.join_welcome_ex(evil.welcome.as_ref().unwrap());
    assert!(r.is_err(), "colliding Welcome was accepted");

    // The real conversation still works both ways.
    let ct = alice.encrypt(&g, b"still here").unwrap();
    assert_eq!(bob.process(&g, &ct, &AllowAll).unwrap(), Processed::Application(b"still here".to_vec()));
}

#[test]
fn control_a_welcome_with_a_fresh_group_id_is_accepted() {
    let (mut bob, mut mallory) = (new_client(), new_client());
    let eg = mallory.create_group_with_id_for_tests(&GroupMeta::new_dm(rid()), &rid().0).unwrap();
    let kp = bob.generate_key_packages(1).unwrap().remove(0);
    let out = mallory.commit(&eg, &[GroupOp::Add { key_package: kp, expected: expected(&bob) }]).unwrap();
    assert!(bob.join_welcome_ex(out.welcome.as_ref().unwrap()).is_ok());
}
