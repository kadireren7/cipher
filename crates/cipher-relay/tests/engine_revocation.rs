#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::needless_range_loop)]
//! GROUP HISTORY REVOCATION (docs/HISTORY_REVOCATION.md) through real engines, the real relay router and PostgreSQL.
//! Every test asserts CRYPTOGRAPHIC behaviour: decryption operations fail / keys are gone / vaults contain no plaintext — not what a UI shows.
//! Naming: R-nn refers to the revocation test matrix; REV-nnn to the invariants in security/invariants.json.
mod harness;
use cipher_core::app::model::*;
use cipher_core::error::SecurityError;
use cipher_core::events::SecurityEvent;
use cipher_core::protocol::GroupOp;
use cipher_wire::Id16;
use harness::engine::*;
use harness::*;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

const M1: &str = "M1-HISTORY-CANARY-alpha-4401";
const M2: &str = "M2-HISTORY-CANARY-bravo-4402";
const M3: &str = "M3-POSTREMOVAL-CANARY-charlie-4403";

struct Four {
    a: TestEngine,
    b: TestEngine,
    c: TestEngine,
    d: TestEngine,
    ids: [Id16; 4],
    g: Id16,
}

fn four(w: &World) -> Four {
    let mut e = [w.engine(), w.engine(), w.engine(), w.engine()];
    let pubs: Vec<_> = e.iter_mut().map(|x| x.public_identity().unwrap()).collect();
    for i in 0..4 {
        for j in 0..4 {
            if i != j {
                e[i].add_contact_by_id(&pubs[j].cipher_id, &format!("P{j}")).unwrap();
            }
        }
    }
    let [mut a, mut b, mut c, mut d] = e;
    let g = a.create_group("Team", &[pubs[1].account_id, pubs[2].account_id, pubs[3].account_id]).unwrap();
    for x in [&mut b, &mut c, &mut d] {
        x.sync().unwrap();
    }
    let ids = [pubs[0].account_id, pubs[1].account_id, pubs[2].account_id, pubs[3].account_id];
    Four { a, b, c, d, ids, g }
}

/// Readable (available) text bodies, oldest first.
fn readable(e: &mut TestEngine, g: &Id16) -> Vec<String> {
    let mut v: Vec<String> = e
        .history(g, None, 200)
        .unwrap()
        .items
        .into_iter()
        .filter(|m| !m.unavailable)
        .filter_map(|m| if let Content::Text { body } = m.content { Some(body) } else { None })
        .collect();
    v.reverse();
    v
}

fn unavailable(e: &mut TestEngine, g: &Id16) -> usize {
    e.history(g, None, 200).unwrap().items.iter().filter(|m| m.unavailable).count()
}

fn msg_id(e: &mut TestEngine, g: &Id16, text: &str) -> Id16 {
    e.history(g, None, 200)
        .unwrap()
        .items
        .into_iter()
        .find(|m| matches!(&m.content, Content::Text { body } if body == text))
        .unwrap_or_else(|| panic!("message {text} not found"))
        .id
}

fn sync_all(es: &mut [&mut TestEngine]) {
    for e in es.iter_mut() {
        e.sync().unwrap();
    }
}

fn say(w: &World, e: &mut TestEngine, g: &Id16, t: &str) -> Id16 {
    w.clock.0.advance(2);
    e.send_text(g, t, None).unwrap().id
}

fn rows_for(w: &World, dev: &Id16) -> Vec<(Vec<u8>, Option<i64>)> {
    let dev = dev.0.to_vec();
    w.rt.block_on(async {
        let c = w.pool.get().await.unwrap();
        c.query("SELECT ct, group_seq FROM queue WHERE recipient=$1 ORDER BY seq", &[&dev])
            .await
            .unwrap()
            .iter()
            .map(|r| (r.get::<_, Vec<u8>>(0), r.get::<_, Option<i64>>(1)))
            .collect()
    })
}

fn fix_counters(w: &World) {
    w.exec(
        "UPDATE devices d SET queued_count = (SELECT count(*) FROM queue q WHERE q.recipient = d.device_id), queued_bytes = (SELECT COALESCE(sum(octet_length(q.ct)),0) FROM queue q WHERE q.recipient = d.device_id)",
        &[],
    );
}

fn restart(w: &World, t: TestEngine) -> TestEngine {
    let TestEngine { e, ks, transport, dir } = t;
    drop(e);
    let mut e = cipher_core::app::Engine::new_for_tests(
        cipher_core::app::EngineConfig { data_dir: dir.path().to_path_buf(), relay_url: "https://relay.test".into(), vault: vault_cfg() },
        ks.clone(),
        transport.clone(),
        w.clock.clone(),
        AUDIENCE,
    )
    .unwrap();
    e.unlock_with_device_auth().unwrap();
    TestEngine { e, ks, transport, dir }
}

/// R-01, R-05, R-06, R-07 / REV-001, REV-002, REV-003, REV-006: normal member removed by the owner.
#[test]
fn removal_splits_history_access_cryptographically() {
    let w = World::new();
    let mut f = four(&w);
    let g = f.g;
    say(&w, &mut f.a, &g, M1);
    say(&w, &mut f.b, &g, M2);
    sync_all(&mut [&mut f.a, &mut f.b, &mut f.c, &mut f.d]);
    let (m1, d_dev) = (msg_id(&mut f.d, &g, M1), f.d.clone_public_for_tests().device_id);

    // CONTROL: before removal D can read M1 AND the retained ciphertext opens with D's keys.
    assert_eq!(readable(&mut f.d, &g), [M1, M2]);
    let (epoch, sender, sealed) = f.d.sealed_body_for_tests(&g, &m1).unwrap().expect("group messages are stored sealed");
    assert!(
        f.d.open_sealed_for_tests(&g, epoch, &m1, &sender, &sealed).is_ok(),
        "control: the retained ciphertext opens before revocation"
    );
    assert!(!f.d.history_epochs_for_tests(&g).unwrap().is_empty());
    let epoch_a_before = f.a.conversation_epoch(&g).unwrap();

    f.a.remove_group_member(&g, &f.ids[3]).unwrap();
    assert!(f.a.conversation_epoch(&g).unwrap() > epoch_a_before, "REV-006: removal advances the epoch (new history-access generation)");
    f.d.sync().unwrap();

    // REV-002: the DECRYPTION OPERATION fails for the revoked client — not "the UI hides it".
    assert!(
        matches!(f.d.open_sealed_for_tests(&g, epoch, &m1, &sender, &sealed), Err(SecurityError::Denied(_))),
        "retained ciphertext must not open"
    );
    assert!(f.d.history_epochs_for_tests(&g).unwrap().is_empty(), "every history key of the group is gone");
    assert!(f.d.conversation(&g).unwrap().access_revoked);
    assert_eq!(unavailable(&mut f.d, &g), 2);
    assert!(readable(&mut f.d, &g).is_empty());
    for canary in [M1, M2] {
        assert_eq!(f.d.vault_plaintext_hits_for_tests(canary.as_bytes()).unwrap(), 0, "no plaintext of {canary} left in D's vault");
    }
    assert!(f.d.take_events().iter().any(|e| matches!(e, SecurityEvent::GroupAccessRevoked { .. })));

    // REV-003: remaining members keep their authorised history.
    assert_eq!(readable(&mut f.a, &g), [M1, M2]);
    f.b.sync().unwrap();
    f.c.sync().unwrap();
    assert_eq!(readable(&mut f.b, &g), [M1, M2]);
    assert_eq!(readable(&mut f.c, &g), [M1, M2]);

    // REV-001: new messages are readable by A/B/C and NOT by D (even if the relay misroutes them to D).
    say(&w, &mut f.a, &g, M3);
    let a_dev = f.a.clone_public_for_tests().device_id;
    let _ = a_dev;
    let b_dev = f.b.clone_public_for_tests().device_id;
    let kept = rows_for(&w, &b_dev);
    for (i, (ct, _)) in kept.iter().enumerate() {
        let mut mid = [0u8; 16];
        mid[0] = 0xAB;
        mid[1] = i as u8;
        w.exec(
            "INSERT INTO queue (recipient, message_id, ct, expires_at) VALUES ($1,$2,$3,9999999999)",
            &[&d_dev.0.to_vec(), &mid.to_vec(), ct],
        );
    }
    fix_counters(&w);
    f.d.sync().unwrap();
    for (ct, _) in &kept {
        assert!(
            f.d.process_raw_for_tests(&g, ct).is_err(),
            "REV-001: D has no MLS state for the group: post-removal ciphertext cannot be decrypted"
        );
    }
    sync_all(&mut [&mut f.b, &mut f.c]);
    assert_eq!(readable(&mut f.b, &g), [M1, M2, M3]);
    assert_eq!(readable(&mut f.c, &g), [M1, M2, M3]);
    assert_eq!(f.d.vault_plaintext_hits_for_tests(M3.as_bytes()).unwrap(), 0);
    assert_eq!(unavailable(&mut f.d, &g), 2);
    // D cannot send either (REV-001 / R-07, compliant client).
    assert!(matches!(f.d.send_text(&g, "let me in", None), Err(SecurityError::Denied(_))));
}

/// R-02, R-03 / REV-001/002: an ADMIN removes a member; the OWNER removes an ADMIN.
#[test]
fn admin_and_owner_removals_revoke_the_removed_member() {
    let w = World::new();
    let mut f = four(&w);
    let g = f.g;
    say(&w, &mut f.a, &g, M1);
    sync_all(&mut [&mut f.b, &mut f.c, &mut f.d]);
    f.a.promote_admin(&g, &f.ids[1]).unwrap();
    sync_all(&mut [&mut f.b, &mut f.c, &mut f.d]);
    // admin B removes member D
    f.b.remove_group_member(&g, &f.ids[3]).unwrap();
    f.d.sync().unwrap();
    assert!(f.d.conversation(&g).unwrap().access_revoked && f.d.history_epochs_for_tests(&g).unwrap().is_empty());
    sync_all(&mut [&mut f.a, &mut f.c]);
    assert_eq!(readable(&mut f.c, &g), [M1]);
    // owner A removes admin B
    f.a.remove_group_member(&g, &f.ids[1]).unwrap();
    f.b.sync().unwrap();
    assert!(f.b.conversation(&g).unwrap().access_revoked && f.b.history_epochs_for_tests(&g).unwrap().is_empty());
    assert_eq!(unavailable(&mut f.b, &g), 1);
    f.c.sync().unwrap();
    assert_eq!(readable(&mut f.a, &g), [M1]);
    assert_eq!(readable(&mut f.c, &g), [M1]);
}

/// R-04: unauthorised removal attempts do nothing: the group state and everybody's history keys are untouched.
#[test]
fn unauthorised_removal_attempts_change_nothing() {
    let w = World::new();
    let mut f = four(&w);
    let g = f.g;
    say(&w, &mut f.a, &g, M1);
    sync_all(&mut [&mut f.b, &mut f.c, &mut f.d]);
    let epoch = f.a.conversation_epoch(&g).unwrap();
    let keys_d = f.d.history_epochs_for_tests(&g).unwrap();
    // a plain MEMBER refuses locally ...
    assert!(matches!(f.c.remove_group_member(&g, &f.ids[3]), Err(SecurityError::Unauthorized(_))));
    // ... and a MALICIOUS member that skips its own pre-check is rejected by every receiver.
    let d_dev = f.d.clone_public_for_tests().device_id;
    f.c.inject_forged_commit_for_tests(&g, &[GroupOp::Remove { devices: vec![d_dev] }]).unwrap();
    sync_all(&mut [&mut f.a, &mut f.b, &mut f.d]);
    assert_eq!(f.a.conversation_epoch(&g).unwrap(), epoch, "epoch must not move");
    assert_eq!(f.d.conversation_epoch(&g).unwrap(), epoch);
    assert_eq!(f.d.history_epochs_for_tests(&g).unwrap(), keys_d, "no history key was added or removed anywhere");
    assert!(!f.d.conversation(&g).unwrap().access_revoked);
    assert_eq!(readable(&mut f.d, &g), [M1]);
    assert!(f.a.take_events().iter().any(|e| matches!(e, SecurityEvent::UnauthorizedGroupChange { .. })));
    assert!(!f.a.take_events().iter().any(|e| matches!(e, SecurityEvent::GroupMemberRemoved { .. })));
}

/// R-07, R-08, R-09 / REV-001, REV-004: D is OFFLINE during removal, then tries everything with its stale state.
#[test]
fn an_offline_removed_member_cannot_send_receive_or_force_a_rollback() {
    let w = World::new();
    let mut f = four(&w);
    let g = f.g;
    say(&w, &mut f.a, &g, M1);
    sync_all(&mut [&mut f.b, &mut f.c, &mut f.d]);
    f.d.transport.offline.store(true, Ordering::SeqCst); // D loses connectivity (stale state at epoch e)
    f.a.remove_group_member(&g, &f.ids[3]).unwrap();
    say(&w, &mut f.a, &g, M3);
    sync_all(&mut [&mut f.b, &mut f.c]);
    let epoch_now = f.a.conversation_epoch(&g).unwrap();

    // D reconnects but has NOT yet seen the removal (stale MLS state, believes it is a member): it sends a message into its old epoch.
    f.d.transport.offline.store(false, Ordering::SeqCst);
    let ghost = {
        w.clock.0.advance(2);
        f.d.send_text(&g, "GHOST-from-removed-member", None).unwrap().id
    };
    let _ = ghost;
    // ... and tries to force a rollback with a commit of its own.
    assert!(f.d.refresh_keys(&g).is_err(), "a stale/removed member's commit must be refused (retired routing tag)");
    sync_all(&mut [&mut f.a, &mut f.b, &mut f.c]);
    for e in [&mut f.a, &mut f.b, &mut f.c] {
        assert!(!readable(e, &g).iter().any(|t| t.contains("GHOST")), "a message from a removed member must not be accepted");
        assert_eq!(e.conversation_epoch(&g).unwrap(), epoch_now, "no rollback, no epoch change");
    }
    let evs: Vec<_> = [&mut f.a, &mut f.b, &mut f.c].into_iter().flat_map(|e| e.take_events()).collect();
    assert!(evs.iter().any(|e| matches!(e, SecurityEvent::RemovedMemberMessageRejected { .. })));

    // D finally processes its queue: pending pre-removal items, then the removal. It ends with NO access and never sees M3.
    f.d.sync().unwrap();
    assert!(f.d.conversation(&g).unwrap().access_revoked);
    assert!(f.d.history_epochs_for_tests(&g).unwrap().is_empty());
    assert_eq!(f.d.vault_plaintext_hits_for_tests(M3.as_bytes()).unwrap(), 0);
    assert!(readable(&mut f.d, &g).is_empty());
    assert!(matches!(f.d.send_text(&g, "again", None), Err(SecurityError::Denied(_))));
}

/// R-10 / REV-004: restoring an OLD vault snapshot (from before the removal) cannot restore access: the rollback is detected at unlock.
#[test]
fn an_old_vault_snapshot_cannot_restore_access() {
    let w = World::new();
    let mut f = four(&w);
    let g = f.g;
    say(&w, &mut f.a, &g, M1);
    sync_all(&mut [&mut f.b, &mut f.c, &mut f.d]);
    f.d.lock();
    let snapshot = std::fs::read(f.d.dir.path().join("vault.db")).unwrap(); // the attacker copies the files while D still has access
    f.d.unlock_with_device_auth().unwrap();
    assert_eq!(readable(&mut f.d, &g), [M1]);
    f.a.remove_group_member(&g, &f.ids[3]).unwrap();
    f.d.sync().unwrap();
    assert!(f.d.conversation(&g).unwrap().access_revoked);
    f.d.lock();
    // restore the pre-removal vault
    let path = f.d.dir.path().join("vault.db");
    let TestEngine { e, ks, transport, dir } = f.d;
    drop(e);
    std::fs::write(&path, &snapshot).unwrap();
    let mut e = cipher_core::app::Engine::new_for_tests(
        cipher_core::app::EngineConfig { data_dir: dir.path().to_path_buf(), relay_url: "https://relay.test".into(), vault: vault_cfg() },
        ks,
        transport,
        w.clock.clone(),
        AUDIENCE,
    )
    .unwrap();
    assert!(matches!(e.unlock_with_device_auth(), Err(SecurityError::StorageRolledBack)), "the stale snapshot must be refused");
    assert!(e.list_conversations().is_err(), "and nothing is readable afterwards");
}

/// R-11, R-17 / REV-004, REV-005: a relay that replays an old Welcome (or old commits) cannot restore access; re-adding gives only NEW history.
#[test]
fn replayed_welcome_and_a_legitimate_readd_restore_only_new_history() {
    let w = World::new();
    let (mut a, mut b, mut c, mut d) = (w.engine(), w.engine(), w.engine(), w.engine());
    let pubs: Vec<_> = [&mut a, &mut b, &mut c, &mut d].iter_mut().map(|x| x.public_identity().unwrap()).collect();
    let (es, ids) = ([&mut a, &mut b, &mut c, &mut d], pubs.iter().map(|p| p.account_id).collect::<Vec<_>>());
    for i in 0..4 {
        for j in 0..4 {
            if i != j {
                es[i].add_contact_by_id(&pubs[j].cipher_id, "P").unwrap();
            }
        }
    }
    let g = a.create_group("Team", &[ids[1], ids[2], ids[3]]).unwrap();
    let d_dev = d.clone_public_for_tests().device_id;
    let old_welcome = rows_for(&w, &d_dev); // the Welcome D will consume
    sync_all(&mut [&mut b, &mut c, &mut d]);
    say(&w, &mut a, &g, M1);
    sync_all(&mut [&mut b, &mut c, &mut d]);
    a.remove_group_member(&g, &ids[3]).unwrap();
    d.sync().unwrap();
    assert!(d.conversation(&g).unwrap().access_revoked);
    say(&w, &mut a, &g, M3);

    // The relay replays D's OLD Welcome and every old commit it still has.
    for (i, (ct, seq)) in old_welcome.iter().enumerate() {
        let mut mid = [0u8; 16];
        mid[0] = 0xCD;
        mid[1] = i as u8;
        w.exec(
            "INSERT INTO queue (recipient, message_id, ct, expires_at, group_seq) VALUES ($1,$2,$3,9999999999,$4)",
            &[&d_dev.0.to_vec(), &mid.to_vec(), ct, seq],
        );
    }
    fix_counters(&w);
    d.sync().unwrap();
    assert!(d.conversation(&g).unwrap().access_revoked, "REV-004: a replayed Welcome must not restore access");
    assert!(d.history_epochs_for_tests(&g).unwrap().is_empty());
    assert!(readable(&mut d, &g).is_empty());

    // A LEGITIMATE re-add (new Welcome, newer epoch): D gets the NEW membership era only.
    a.add_group_members(&g, &[ids[3]]).unwrap();
    say(&w, &mut a, &g, "M4-AFTER-READD-CANARY-9912");
    sync_all(&mut [&mut b, &mut c]);
    d.sync().unwrap();
    assert!(!d.conversation(&g).unwrap().access_revoked, "re-added: access in the new era");
    assert_eq!(readable(&mut d, &g), ["M4-AFTER-READD-CANARY-9912"], "only post-re-add history");
    assert_eq!(unavailable(&mut d, &g), 1, "the old era stays unavailable (the M1 stub)");
    assert_eq!(d.vault_plaintext_hits_for_tests(M1.as_bytes()).unwrap(), 0);
    assert_eq!(d.vault_plaintext_hits_for_tests(M3.as_bytes()).unwrap(), 0);
}

/// R-12 / REV-005: a relay that WITHHOLDS the removal commit from D cannot give D anything new — but it cannot make D's compliant client
/// forget what it already holds either (documented limitation, asserted explicitly). When the commit finally arrives, access ends.
#[test]
fn withheld_removal_blocks_new_content_and_ends_old_access_when_it_arrives() {
    let w = World::new();
    let mut f = four(&w);
    let g = f.g;
    say(&w, &mut f.a, &g, M1);
    sync_all(&mut [&mut f.b, &mut f.c, &mut f.d]);
    let d_dev = f.d.clone_public_for_tests().device_id;
    f.a.remove_group_member(&g, &f.ids[3]).unwrap();
    let stash: Vec<_> = rows_for(&w, &d_dev);
    w.exec("DELETE FROM queue WHERE recipient=$1", &[&d_dev.0.to_vec()]);
    fix_counters(&w);
    say(&w, &mut f.a, &g, M3);
    f.d.sync().unwrap(); // nothing arrives
    assert_eq!(f.d.vault_plaintext_hits_for_tests(M3.as_bytes()).unwrap(), 0);
    assert!(!readable(&mut f.d, &g).iter().any(|t| t == M3), "new content is unreachable without the new epoch's key");
    // DOCUMENTED LIMITATION: D has not OBSERVED its removal, so its compliant client still holds the OLD keys it was legitimately given.
    assert_eq!(
        readable(&mut f.d, &g),
        [M1],
        "limitation: revocation on D requires D to observe the removal (see docs/HISTORY_REVOCATION.md)"
    );
    // The relay finally delivers the commit.
    for (i, (ct, seq)) in stash.iter().enumerate() {
        let mut mid = [0u8; 16];
        mid[0] = 0xEF;
        mid[1] = i as u8;
        w.exec(
            "INSERT INTO queue (recipient, message_id, ct, expires_at, group_seq) VALUES ($1,$2,$3,9999999999,$4)",
            &[&d_dev.0.to_vec(), &mid.to_vec(), ct, seq],
        );
    }
    fix_counters(&w);
    f.d.sync().unwrap();
    assert!(f.d.conversation(&g).unwrap().access_revoked && readable(&mut f.d, &g).is_empty());
}

/// R-13: the relay REORDERS the removal commit after a later message: the member holds the message and resolves it once the commit arrives.
#[test]
fn a_reordered_removal_is_resolved_without_losing_history() {
    let w = World::new();
    let mut f = four(&w);
    let g = f.g;
    say(&w, &mut f.a, &g, M1);
    sync_all(&mut [&mut f.b, &mut f.c, &mut f.d]);
    let b_dev = f.b.clone_public_for_tests().device_id;
    f.a.remove_group_member(&g, &f.ids[3]).unwrap();
    let commit_rows: Vec<_> = rows_for(&w, &b_dev).into_iter().filter(|(_, s)| s.is_some()).collect();
    w.exec("DELETE FROM queue WHERE recipient=$1 AND group_seq IS NOT NULL", &[&b_dev.0.to_vec()]);
    fix_counters(&w);
    say(&w, &mut f.a, &g, M3); // new epoch message reaches B BEFORE the commit
    f.b.sync().unwrap();
    assert_eq!(readable(&mut f.b, &g), [M1], "held, not misapplied");
    for (i, (ct, seq)) in commit_rows.iter().enumerate() {
        let mut mid = [0u8; 16];
        mid[0] = 0xF1;
        mid[1] = i as u8;
        w.exec(
            "INSERT INTO queue (recipient, message_id, ct, expires_at, group_seq) VALUES ($1,$2,$3,9999999999,$4)",
            &[&b_dev.0.to_vec(), &mid.to_vec(), ct, seq],
        );
    }
    fix_counters(&w);
    f.b.sync().unwrap();
    assert_eq!(readable(&mut f.b, &g), [M1, M3]);
    assert_eq!(f.b.history_epochs_for_tests(&g).unwrap().len(), 2, "B holds the keys of both epochs it lived through");
}

/// R-14 / REV-003: a member sends WHILE the owner commits the removal. The message (old epoch) is readable by the remaining members.
#[test]
fn a_message_sent_during_the_removal_is_kept_by_remaining_members_and_revoked_for_the_removed() {
    let w = World::new();
    let mut f = four(&w);
    let g = f.g;
    say(&w, &mut f.a, &g, M1);
    sync_all(&mut [&mut f.b, &mut f.c, &mut f.d]);
    let b = Arc::new(Mutex::new(f.b));
    let hook_b = b.clone();
    let mut fired = false;
    *f.a.transport.hook.lock().unwrap() = Some(Box::new(move |_m, p| {
        if p.ends_with("/commit") && !fired {
            fired = true;
            hook_b.lock().unwrap().send_text(&g, "CONCURRENT-SEND-CANARY-7731", None).unwrap();
        }
    }));
    f.a.remove_group_member(&g, &f.ids[3]).unwrap();
    *f.a.transport.hook.lock().unwrap() = None;
    let mut b = Arc::try_unwrap(b).ok().unwrap().into_inner().unwrap();
    sync_all(&mut [&mut f.a, &mut f.c, &mut b, &mut f.d]);
    for e in [&mut f.a, &mut f.c, &mut b] {
        assert!(readable(e, &g).iter().any(|t| t == "CONCURRENT-SEND-CANARY-7731"), "remaining members read the concurrent message");
    }
    assert!(f.d.conversation(&g).unwrap().access_revoked);
    assert_eq!(
        f.d.vault_plaintext_hits_for_tests(b"CONCURRENT-SEND-CANARY-7731").unwrap(),
        0,
        "D read it transiently, then lost it with the revocation"
    );
    assert!(readable(&mut f.d, &g).is_empty());
}

/// R-15: an ATTACHMENT sent while the removal commits: remaining members open it; the removed member cannot (keys gone).
#[test]
fn an_attachment_sent_during_the_removal_is_unavailable_to_the_removed_member() {
    let w = World::new();
    let mut f = four(&w);
    let g = f.g;
    say(&w, &mut f.a, &g, M1);
    sync_all(&mut [&mut f.b, &mut f.c, &mut f.d]);
    let file = png(5_000);
    let b = Arc::new(Mutex::new(f.b));
    let hook_b = b.clone();
    let mut fired = false;
    let fb = file.clone();
    *f.a.transport.hook.lock().unwrap() = Some(Box::new(move |_m, p| {
        if p.ends_with("/commit") && !fired {
            fired = true;
            hook_b
                .lock()
                .unwrap()
                .send_attachment_bytes(&g, &fb, "image/png", "pic.png", AttachmentKind::Image, None, None, &mut |_, _| true)
                .unwrap();
        }
    }));
    f.a.remove_group_member(&g, &f.ids[3]).unwrap();
    *f.a.transport.hook.lock().unwrap() = None;
    let mut b = Arc::try_unwrap(b).ok().unwrap().into_inner().unwrap();
    sync_all(&mut [&mut f.a, &mut f.c, &mut b, &mut f.d]);
    let att = |e: &mut TestEngine| {
        e.history(&g, None, 50).unwrap().items.into_iter().find(|m| matches!(m.content, Content::Attachment { .. }) || m.unavailable)
    };
    let m_a = att(&mut f.a).unwrap();
    assert!(!m_a.unavailable);
    let bytes = f.a.open_attachment(&g, &m_a.id, false, &mut |_, _| true).unwrap();
    assert_eq!(bytes.as_slice(), file.as_slice(), "remaining members open the attachment");
    let m_d = f.d.history(&g, None, 50).unwrap().items.into_iter().find(|m| m.id == m_a.id).unwrap();
    assert!(m_d.unavailable, "the attachment descriptor (and its key) is sealed and gone on D");
    assert!(matches!(f.d.open_attachment(&g, &m_a.id, false, &mut |_, _| true), Err(SecurityError::Denied(_))));
}

/// R-16: several rapid removals: every epoch gets its own key; remaining members keep ALL their history; each removed member loses all of it.
#[test]
fn rapid_successive_removals_keep_history_for_the_remaining_and_revoke_each_removed() {
    let w = World::new();
    let mut f = four(&w);
    let g = f.g;
    say(&w, &mut f.a, &g, M1);
    say(&w, &mut f.b, &g, M2);
    sync_all(&mut [&mut f.a, &mut f.b, &mut f.c, &mut f.d]);
    let epochs_before = f.a.history_epochs_for_tests(&g).unwrap().len();
    f.a.remove_group_member(&g, &f.ids[2]).unwrap();
    f.a.remove_group_member(&g, &f.ids[3]).unwrap();
    assert_eq!(f.a.history_epochs_for_tests(&g).unwrap().len(), epochs_before + 2);
    say(&w, &mut f.a, &g, M3);
    sync_all(&mut [&mut f.b, &mut f.c, &mut f.d]);
    assert_eq!(readable(&mut f.a, &g), [M1, M2, M3]);
    assert_eq!(readable(&mut f.b, &g), [M1, M2, M3]);
    for e in [&mut f.c, &mut f.d] {
        assert!(e.conversation(&g).unwrap().access_revoked);
        assert!(e.history_epochs_for_tests(&g).unwrap().is_empty());
        assert!(readable(e, &g).is_empty());
        assert_eq!(e.vault_plaintext_hits_for_tests(M3.as_bytes()).unwrap(), 0);
    }
}

/// R-19: app restart after removal — remaining members keep history across restarts, the removed member stays revoked.
#[test]
fn restart_after_removal_keeps_access_for_members_and_revocation_for_the_removed() {
    let w = World::new();
    let mut f = four(&w);
    let g = f.g;
    say(&w, &mut f.a, &g, M1);
    sync_all(&mut [&mut f.b, &mut f.c, &mut f.d]);
    f.a.remove_group_member(&g, &f.ids[3]).unwrap();
    f.d.sync().unwrap();
    say(&w, &mut f.a, &g, M3);
    let mut a = restart(&w, f.a);
    let mut d = restart(&w, f.d);
    assert_eq!(readable(&mut a, &g), [M1, M3], "history keys survive a restart");
    assert!(d.conversation(&g).unwrap().access_revoked);
    assert!(d.history_epochs_for_tests(&g).unwrap().is_empty());
    d.sync().unwrap();
    assert!(readable(&mut d, &g).is_empty() && unavailable(&mut d, &g) == 1);
}

/// R-20 (removed side): the process dies after the revocation committed but BEFORE the relay acknowledgement. On restart the removal envelope is redelivered:
/// it must not resurrect anything and must not crash.
#[test]
fn process_death_around_the_removed_members_revocation_is_safe() {
    let w = World::new();
    let mut f = four(&w);
    let g = f.g;
    say(&w, &mut f.a, &g, M1);
    sync_all(&mut [&mut f.b, &mut f.c, &mut f.d]);
    f.a.remove_group_member(&g, &f.ids[3]).unwrap();
    *f.d.transport.lose_response_on.lock().unwrap() = Some("/messages/ack".into()); // the ack never reaches the relay ("process dies")
    let _ = f.d.sync();
    assert!(f.d.conversation(&g).unwrap().access_revoked, "the revocation was committed locally before the ack");
    let mut d = restart(&w, f.d);
    d.sync().unwrap(); // the relay redelivers the removal commit
    assert!(d.conversation(&g).unwrap().access_revoked);
    assert!(d.history_epochs_for_tests(&g).unwrap().is_empty());
    assert_eq!(d.vault_plaintext_hits_for_tests(M1.as_bytes()).unwrap(), 0);
    assert!(readable(&mut d, &g).is_empty());
}

/// R-20 (committer side) / REV-006: the relay ACCEPTS the removal commit but the response is lost (process death / network). The committer must not
/// diverge: after a restart it re-sends the identical request, the relay answers idempotently, and the removal completes everywhere.
#[test]
fn a_lost_response_after_the_relay_accepted_the_removal_does_not_diverge_the_committer() {
    for restart_first in [false, true] {
        let w = World::new();
        let mut f = four(&w);
        let g = f.g;
        say(&w, &mut f.a, &g, M1);
        sync_all(&mut [&mut f.b, &mut f.c, &mut f.d]);
        let epoch0 = f.a.conversation_epoch(&g).unwrap();
        *f.a.transport.lose_response_on.lock().unwrap() = Some("/commit".into());
        // The relay EXECUTES the commit; only the response is lost (harness fault injection).
        assert!(f.a.remove_group_member(&g, &f.ids[3]).is_err(), "outcome unknown is reported as a failure, never as success");
        assert_eq!(f.a.conversation_epoch(&g).unwrap(), epoch0, "nothing merged before the relay answered");
        let mut a = if restart_first { restart(&w, f.a) } else { f.a };
        a.sync().unwrap(); // resolves the pending commit: re-sends, relay says Accepted (or, if never executed, accepts now)
        assert!(a.conversation_epoch(&g).unwrap() > epoch0, "committer reached the new epoch");
        f.d.sync().unwrap();
        assert!(f.d.conversation(&g).unwrap().access_revoked);
        say(&w, &mut a, &g, M3);
        sync_all(&mut [&mut f.b, &mut f.c]);
        assert_eq!(readable(&mut f.b, &g), [M1, M3]);
        assert_eq!(readable(&mut f.c, &g), [M1, M3]);
        assert_eq!(readable(&mut a, &g), [M1, M3]);
    }
}
