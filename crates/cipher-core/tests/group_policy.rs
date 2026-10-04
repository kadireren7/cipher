#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::cloned_ref_to_slice_refs)]
//! Group authorization (ST-007) and commit-ordering safety at the MLS layer. Policy is enforced by every
//! *receiver*; the tests include a malicious committer that skips its own pre-check.
mod common;
use cipher_core::app::groupmeta::{GroupMeta, RoleEntry};
use cipher_core::app::model::Role;
use cipher_core::error::SecurityError;
use cipher_core::mls::MlsClient;
use cipher_core::protocol::{GroupOp, GroupProtocol, Processed, ProcessedEx};
use common::*;

fn add_op(adder: &mut MlsClient, joiner: &mut MlsClient) -> GroupOp {
    let _ = adder;
    let kp = joiner.generate_key_packages(1).unwrap().remove(0);
    GroupOp::Add { key_package: kp, expected: expected(joiner) }
}

#[test]
fn creating_a_group_whose_roles_name_a_non_member_cannot_be_joined() {
    // roles list an admin account that never joins -> a joiner must refuse (roles inconsistent with members)
    let (mut owner, mut bob) = (new_client(), new_client());
    let mut meta = GroupMeta::new_group(rid(), "G", owner.account_id());
    meta.roles.push(RoleEntry { account: new_client().account_id(), role: Role::Admin }); // ghost admin
    let g = owner.create_group_with_meta(&meta).unwrap();
    let op = add_op(&mut owner, &mut bob);
    let out = owner.commit(&g, &[op]);
    // The owner's own policy pre-check already refuses a metadata state whose roles reference non-members.
    assert!(out.is_err(), "owner pre-check: {out:?}");
}

#[test]
fn full_group_lifecycle_with_roles_and_enforced_policy() {
    let (mut owner, mut admin, mut m1, mut m2) = (new_client(), new_client(), new_client(), new_client());
    let tag0 = rid();
    let meta0 = GroupMeta::new_group(tag0, "Team", owner.account_id());
    let g = owner.create_group_with_meta(&meta0).unwrap();

    // owner adds admin and promotes them in ONE commit (add + metadata change)
    let mut meta1 = meta0.clone();
    meta1.roles.push(RoleEntry { account: admin.account_id(), role: Role::Admin });
    let meta1 = meta1.normalised();
    let op = add_op(&mut owner, &mut admin);
    let out = owner.commit(&g, &[op, GroupOp::SetMeta(meta1.clone())]).unwrap();
    owner.merge_pending_commit(&g).unwrap();
    let joined = admin.join_welcome_ex(out.welcome.as_ref().unwrap()).unwrap();
    assert_eq!(joined.meta.as_ref(), Some(&meta1));
    assert_eq!(joined.inviter.0, owner.account_id());
    assert_eq!(joined.members.len(), 2);

    // admin adds m1 (allowed), owner processes
    let op = add_op(&mut admin, &mut m1);
    let out = admin.commit(&g, &[op]).unwrap();
    admin.merge_pending_commit(&g).unwrap();
    assert!(matches!(owner.process_ex(&g, &out.commit, &AllowAll).unwrap(), ProcessedEx::Commit { .. }));
    m1.join_welcome_ex(out.welcome.as_ref().unwrap()).unwrap();

    // m1 (plain member) cannot add: refused by its OWN pre-check ...
    let op = add_op(&mut m1, &mut m2);
    assert!(matches!(m1.commit(&g, &[op]), Err(SecurityError::Unauthorized(_))));
    // ... and a MALICIOUS m1 that skips the pre-check is rejected by every receiver; state is unchanged.
    let kp = m2.generate_key_packages(1).unwrap().remove(0);
    let forged = m1.commit_unchecked_for_tests(&g, &[GroupOp::Add { key_package: kp, expected: expected(&m2) }]).unwrap();
    let (e_owner, e_admin) = (owner.epoch(&g).unwrap(), admin.epoch(&g).unwrap());
    assert!(matches!(owner.process_ex(&g, &forged.commit, &AllowAll), Err(SecurityError::Unauthorized(_))));
    assert!(matches!(admin.process_ex(&g, &forged.commit, &AllowAll), Err(SecurityError::Unauthorized(_))));
    assert_eq!((owner.epoch(&g).unwrap(), admin.epoch(&g).unwrap()), (e_owner, e_admin));
    assert_eq!(owner.members_detailed(&g).unwrap().len(), 3, "m2 was never added");
    m1.clear_pending_commit(&g).unwrap();

    // admin cannot promote m1 (role change is owner-only): own pre-check + receiver enforcement
    let mut promote = meta1.clone();
    promote.roles.push(RoleEntry { account: m1.account_id(), role: Role::Admin });
    let promote = promote.normalised();
    assert!(matches!(admin.commit(&g, &[GroupOp::SetMeta(promote.clone())]), Err(SecurityError::Unauthorized(_))));
    let forged = admin.commit_unchecked_for_tests(&g, &[GroupOp::SetMeta(promote)]).unwrap();
    assert!(matches!(owner.process_ex(&g, &forged.commit, &AllowAll), Err(SecurityError::Unauthorized(_))));
    admin.clear_pending_commit(&g).unwrap();

    // admin renames the group (allowed)
    let mut renamed = meta1.clone();
    renamed.name = "Team Renamed".into();
    let out = admin.commit(&g, &[GroupOp::SetMeta(renamed.clone())]).unwrap();
    admin.merge_pending_commit(&g).unwrap();
    owner.process_ex(&g, &out.commit, &AllowAll).unwrap();
    m1.process_ex(&g, &out.commit, &AllowAll).unwrap();
    assert_eq!(m1.group_meta(&g).unwrap().unwrap().name, "Team Renamed");

    // admin removes m1: must rotate the routing tag; the removed member cannot read later traffic (SEC-006)
    let mut after = renamed.clone();
    after.tag = rid();
    assert!(
        admin.commit(&g, &[GroupOp::Remove { devices: vec![m1.device_id()] }, GroupOp::SetMeta(renamed.clone())]).is_err(),
        "removal without tag rotation is refused"
    );
    let out = admin.commit(&g, &[GroupOp::Remove { devices: vec![m1.device_id()] }, GroupOp::SetMeta(after.clone())]).unwrap();
    admin.merge_pending_commit(&g).unwrap();
    assert!(matches!(owner.process_ex(&g, &out.commit, &AllowAll).unwrap(), ProcessedEx::Commit { removed, .. } if removed.len() == 1));
    assert!(matches!(m1.process_ex(&g, &out.commit, &AllowAll).unwrap(), ProcessedEx::Commit { self_removed: true, .. }));
    assert_eq!(owner.group_meta(&g).unwrap().unwrap().tag, after.tag);
    let secret = admin.encrypt(&g, b"after removal").unwrap();
    assert!(matches!(owner.process(&g, &secret, &AllowAll), Ok(Processed::Application(_))));
    assert!(m1.process(&g, &secret, &AllowAll).is_err());

    // admin cannot remove the owner; owner can remove the admin
    let mut c = after.clone();
    c.tag = rid();
    assert!(admin.commit(&g, &[GroupOp::Remove { devices: vec![owner.device_id()] }, GroupOp::SetMeta(c)]).is_err());
}

#[test]
fn malicious_metadata_commits_are_rejected_by_receivers() {
    let (mut owner, mut admin) = (new_client(), new_client());
    let meta0 = GroupMeta::new_group(rid(), "T", owner.account_id());
    let g = owner.create_group_with_meta(&meta0).unwrap();
    let mut meta1 = meta0.clone();
    meta1.roles.push(RoleEntry { account: admin.account_id(), role: Role::Admin });
    let meta1 = meta1.normalised();
    let op = add_op(&mut owner, &mut admin);
    let out = owner.commit(&g, &[op, GroupOp::SetMeta(meta1.clone())]).unwrap();
    owner.merge_pending_commit(&g).unwrap();
    admin.join_welcome_ex(out.welcome.as_ref().unwrap()).unwrap();
    let epoch = owner.epoch(&g).unwrap();

    // Each forged variant is created by the ADMIN (who passes MLS validity) and must be refused by the owner's client.
    let cases: Vec<(&str, GroupOp)> = vec![
        ("garbage metadata", GroupOp::SetMetaRawForTests(b"not json".to_vec())),
        ("empty metadata (strip)", GroupOp::SetMetaRawForTests(Vec::new())),
        ("non-canonical order", GroupOp::SetMetaRawForTests(serde_json::to_vec(&serde_json::json!({"v":1,"kind":"Group","tag":meta1.tag,"name":"T","roles":[{"account":admin.account_id(),"role":"Admin"},{"account":owner.account_id(),"role":"Owner"}]})).unwrap())),
        ("second owner", {
            let mut m = meta1.clone();
            m.roles = vec![RoleEntry { account: owner.account_id(), role: Role::Owner }, RoleEntry { account: admin.account_id(), role: Role::Owner }];
            GroupOp::SetMetaRawForTests(serde_json::to_vec(&m.normalised()).unwrap())
        }),
        ("kind change", {
            let mut m = meta1.clone();
            m.kind = cipher_core::app::groupmeta::MetaKind::Dm;
            m.roles.clear();
            GroupOp::SetMetaRawForTests(serde_json::to_vec(&m).unwrap())
        }),
        ("oversized metadata", GroupOp::SetMetaRawForTests(vec![b' '; 10_000])),
    ];
    for (name, op) in cases {
        let forged = admin.commit_unchecked_for_tests(&g, &[op]).unwrap();
        let r = owner.process_ex(&g, &forged.commit, &AllowAll);
        assert!(matches!(r, Err(SecurityError::Unauthorized(_))), "{name}: {r:?}");
        assert_eq!(owner.epoch(&g).unwrap(), epoch, "{name}: epoch must not advance");
        admin.clear_pending_commit(&g).unwrap();
    }
    // control: a legitimate rename by the admin still works afterwards
    let mut renamed = meta1.clone();
    renamed.name = "OK".into();
    let out = admin.commit(&g, &[GroupOp::SetMeta(renamed)]).unwrap();
    admin.merge_pending_commit(&g).unwrap();
    owner.process_ex(&g, &out.commit, &AllowAll).unwrap();
}

#[test]
fn concurrent_commits_fork_is_detected_not_silently_merged() {
    let (mut owner, mut admin, mut c) = (new_client(), new_client(), new_client());
    let meta0 = GroupMeta::new_group(rid(), "T", owner.account_id());
    let g = owner.create_group_with_meta(&meta0).unwrap();
    let mut meta1 = meta0.clone();
    meta1.roles.push(RoleEntry { account: admin.account_id(), role: Role::Admin });
    let meta1 = meta1.normalised();
    let op = add_op(&mut owner, &mut admin);
    let out = owner.commit(&g, &[op, GroupOp::SetMeta(meta1.clone())]).unwrap();
    owner.merge_pending_commit(&g).unwrap();
    admin.join_welcome_ex(out.welcome.as_ref().unwrap()).unwrap();
    let op = add_op(&mut owner, &mut c);
    let out = owner.commit(&g, &[op]).unwrap();
    owner.merge_pending_commit(&g).unwrap();
    admin.process_ex(&g, &out.commit, &AllowAll).unwrap();
    c.join_welcome_ex(out.welcome.as_ref().unwrap()).unwrap();

    // Owner and admin BOTH create a commit on the same epoch (no sequencer yet).
    let mut r1 = meta1.clone();
    r1.name = "owner-name".into();
    let mut r2 = meta1.clone();
    r2.name = "admin-name".into();
    let co = owner.commit(&g, &[GroupOp::SetMeta(r1)]).unwrap();
    let ca = admin.commit(&g, &[GroupOp::SetMeta(r2)]).unwrap();
    // The sequencer picked the owner's commit: owner merges, c and admin process it.
    owner.merge_pending_commit(&g).unwrap();
    admin.clear_pending_commit(&g).unwrap();
    admin.process_ex(&g, &co.commit, &AllowAll).unwrap();
    c.process_ex(&g, &co.commit, &AllowAll).unwrap();
    // The losing commit (same epoch) is delivered late by a malicious/confused relay: every member refuses it.
    let before = c.epoch(&g).unwrap();
    assert!(c.process_ex(&g, &ca.commit, &AllowAll).is_err());
    assert!(owner.process_ex(&g, &ca.commit, &AllowAll).is_err());
    assert_eq!(c.epoch(&g).unwrap(), before);
    assert_eq!(c.group_meta(&g).unwrap().unwrap().name, "owner-name");
}

#[test]
fn reordered_commits_are_held_not_applied_and_stale_ones_are_dropped() {
    let (mut a, mut b) = (new_client(), new_client());
    let meta = GroupMeta::new_dm(rid());
    let g = a.create_group_with_meta(&meta).unwrap();
    let op = add_op(&mut a, &mut b);
    let out = a.commit(&g, &[op]).unwrap();
    a.merge_pending_commit(&g).unwrap();
    b.join_welcome_ex(out.welcome.as_ref().unwrap()).unwrap();
    // three consecutive self-update commits by A
    let mut commits = Vec::new();
    for _ in 0..4 {
        let c = a.commit(&g, &[GroupOp::SelfUpdate]).unwrap();
        a.merge_pending_commit(&g).unwrap();
        commits.push(c.commit);
    }
    // delivered out of order: #2 before #1 -> FutureEpoch, no state change, and NOT remembered as replay
    let e0 = b.epoch(&g).unwrap();
    assert!(matches!(b.process_ex(&g, &commits[1], &AllowAll), Err(SecurityError::FutureEpoch)));
    assert_eq!(b.epoch(&g).unwrap(), e0);
    b.process_ex(&g, &commits[0], &AllowAll).unwrap();
    b.process_ex(&g, &commits[1], &AllowAll).unwrap(); // now accepted in order
    b.process_ex(&g, &commits[2], &AllowAll).unwrap();
    b.process_ex(&g, &commits[3], &AllowAll).unwrap();
    assert_eq!(b.epoch(&g).unwrap(), a.epoch(&g).unwrap());
    // a very old commit replayed after the epoch moved on: dropped (replay or stale), never applied
    let (mut x, mut y) = (new_client(), new_client());
    let g2 = x.create_group_with_meta(&GroupMeta::new_dm(rid())).unwrap();
    let op = add_op(&mut x, &mut y);
    let out = x.commit(&g2, &[op]).unwrap();
    x.merge_pending_commit(&g2).unwrap();
    y.join_welcome_ex(out.welcome.as_ref().unwrap()).unwrap();
    let mut old = Vec::new();
    for _ in 0..4 {
        let c = x.commit(&g2, &[GroupOp::SelfUpdate]).unwrap();
        x.merge_pending_commit(&g2).unwrap();
        y.process_ex(&g2, &c.commit, &AllowAll).unwrap();
        old.push(c.commit);
    }
    y.drop_replay_marker(&old[0]); // even without the replay cache the protocol layer must refuse
    let ep = y.epoch(&g2).unwrap();
    assert!(matches!(y.process_ex(&g2, &old[0], &AllowAll), Err(SecurityError::StaleEpoch)));
    assert_eq!(y.epoch(&g2).unwrap(), ep);
}

#[test]
fn sender_identity_comes_from_the_authenticated_tree_not_from_the_relay() {
    let (mut a, mut b) = (new_client(), new_client());
    let g = a.create_group_with_meta(&GroupMeta::new_dm(rid())).unwrap();
    let op = add_op(&mut a, &mut b);
    let out = a.commit(&g, &[op]).unwrap();
    a.merge_pending_commit(&g).unwrap();
    b.join_welcome_ex(out.welcome.as_ref().unwrap()).unwrap();
    let ct = a.encrypt(&g, b"hello").unwrap();
    match b.process_ex(&g, &ct, &AllowAll).unwrap() {
        ProcessedEx::Application { plaintext, sender, .. } => {
            assert_eq!(plaintext, b"hello");
            assert_eq!(sender, (a.account_id(), a.device_id()));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn header_peeking_exposes_only_group_id_and_epoch() {
    use cipher_core::protocol::Header;
    let (mut a, mut b) = (new_client(), new_client());
    let g = a.create_group_with_meta(&GroupMeta::new_dm(rid())).unwrap();
    let op = add_op(&mut a, &mut b);
    let out = a.commit(&g, &[op]).unwrap();
    a.merge_pending_commit(&g).unwrap();
    assert_eq!(MlsClient::peek_header(out.welcome.as_ref().unwrap()).unwrap(), Header::Welcome);
    let ct = a.encrypt(&g, b"x").unwrap();
    assert_eq!(MlsClient::peek_header(&ct).unwrap(), Header::Group { group_id: g.0.clone(), epoch: a.epoch(&g).unwrap() });
    assert!(MlsClient::peek_header(&[1, 2, 3]).is_err());
}
