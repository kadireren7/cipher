#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Feasibility of docs/CROSS_RELAY_GROUPS.md §7.1: the credentials of the NEXT epoch are computable from a staged commit, without touching real
//! state, and a member removed by that commit cannot compute them.
mod common;
use cipher_core::mls::MlsClient;
use cipher_core::protocol::{GroupOp, GroupProtocol};
use common::*;

fn add(joiner: &mut MlsClient) -> GroupOp {
    let kp = joiner.generate_key_packages(1).unwrap().remove(0);
    GroupOp::Add { key_package: kp, expected: expected(joiner) }
}

#[test]
fn next_epoch_credentials_equal_the_ones_every_member_derives_after_the_commit() {
    let (mut alice, mut bob, mut carol) = (new_client(), new_client(), new_client());
    let g = build_group(&mut alice, &mut [&mut bob]);
    let before = alice.home_keys(&g).unwrap();
    let op = add(&mut carol);
    let out = alice.commit(&g, &[op]).unwrap();
    // computed BEFORE merging, on a copy
    let predicted = alice.home_keys_after_pending_commit(&g).unwrap();
    assert_eq!(alice.home_keys(&g).unwrap().commit.as_slice(), before.commit.as_slice(), "real state untouched by the prediction");
    alice.merge_pending_commit(&g).unwrap();
    let actual = alice.home_keys(&g).unwrap();
    assert_eq!(predicted.commit.as_slice(), actual.commit.as_slice());
    assert_eq!(predicted.read.as_slice(), actual.read.as_slice());
    // the other members arrive at the same values
    bob.process_ex(&g, &out.commit, &AllowAll).unwrap();
    carol.join_welcome_ex(out.welcome.as_ref().unwrap()).unwrap();
    for c in [&bob, &carol] {
        let k = c.home_keys(&g).unwrap();
        assert_eq!(k.commit.as_slice(), actual.commit.as_slice());
        assert_eq!(k.read.as_slice(), actual.read.as_slice());
    }
    // every epoch has fresh credentials, and the two are distinct
    assert_ne!(before.commit.as_slice(), actual.commit.as_slice());
    assert_ne!(before.read.as_slice(), actual.read.as_slice());
    assert_ne!(actual.commit.as_slice(), actual.read.as_slice());
}

#[test]
fn a_removed_member_cannot_derive_the_credentials_of_the_epoch_that_removed_it() {
    let (mut alice, mut bob, mut carol) = (new_client(), new_client(), new_client());
    let g = build_group(&mut alice, &mut [&mut bob, &mut carol]);
    let old = carol.home_keys(&g).unwrap();
    let out = alice.commit(&g, &[GroupOp::Remove { devices: vec![carol.device_id()] }]).unwrap();
    let predicted = alice.home_keys_after_pending_commit(&g).unwrap();
    alice.merge_pending_commit(&g).unwrap();
    bob.process_ex(&g, &out.commit, &AllowAll).unwrap();
    assert_eq!(bob.home_keys(&g).unwrap().commit.as_slice(), predicted.commit.as_slice());
    // Carol processing the removal commit learns she is out; she keeps only the OLD epoch's credentials, which differ.
    let _ = carol.process_ex(&g, &out.commit, &AllowAll);
    assert_ne!(old.commit.as_slice(), predicted.commit.as_slice());
    assert_ne!(old.read.as_slice(), predicted.read.as_slice());
    assert!(carol.home_keys(&g).map(|k| k.commit.as_slice() != predicted.commit.as_slice()).unwrap_or(true));
}

#[test]
fn prediction_requires_a_staged_commit() {
    let (mut alice, mut bob) = (new_client(), new_client());
    let g = build_group(&mut alice, &mut [&mut bob]);
    assert!(alice.home_keys_after_pending_commit(&g).is_err());
}
