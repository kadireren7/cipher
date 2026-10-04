#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Groups through the real engine, relay and PostgreSQL: roles, enforced authorization, no pre-join history,
//! removal, leave requests, commit races, forged commits, withheld commits, and PCS scheduling.
mod harness;
use cipher_core::app::model::*;
use cipher_core::clock::Clock as _;
use cipher_core::error::SecurityError;
use cipher_core::events::SecurityEvent;
use cipher_core::protocol::GroupOp;
use cipher_wire::Id16;
use harness::engine::*;
use harness::*;

const PT: &str = "PLAINTEXT-FIXTURE-group-secret-5521";

struct Crew {
    a: TestEngine,
    b: TestEngine,
    c: TestEngine,
    ia: cipher_core::app::PublicIdentity,
    ib: cipher_core::app::PublicIdentity,
    ic: cipher_core::app::PublicIdentity,
}

fn crew(w: &World) -> Crew {
    let (mut a, mut b, mut c) = (w.engine(), w.engine(), w.engine());
    let (ia, ib, ic) = (a.public_identity().unwrap(), b.public_identity().unwrap(), c.public_identity().unwrap());
    for (e, others) in
        [(&mut a, [(&ib, "Bob"), (&ic, "Carol")]), (&mut b, [(&ia, "Alice"), (&ic, "Carol")]), (&mut c, [(&ia, "Alice"), (&ib, "Bob")])]
    {
        for (id, name) in others {
            e.add_contact_by_id(&id.cipher_id, name).unwrap();
        }
    }
    Crew { a, b, c, ia, ib, ic }
}

fn texts(e: &mut TestEngine, conv: &Id16) -> Vec<String> {
    let mut v: Vec<String> = e
        .history(conv, None, 200)
        .unwrap()
        .items
        .into_iter()
        .filter_map(|m| if let Content::Text { body } = m.content { Some(body) } else { None })
        .collect();
    v.reverse();
    v
}

fn group_of(e: &mut TestEngine) -> Id16 {
    e.list_conversations().unwrap().into_iter().find(|c| c.kind == ConvKind::Group).unwrap().id
}

fn set_up(w: &World) -> (Crew, Id16) {
    let mut k = crew(w);
    let g = k.a.create_group("Team", &[k.ib.account_id, k.ic.account_id]).unwrap();
    k.b.sync().unwrap();
    k.c.sync().unwrap();
    assert_eq!(group_of(&mut k.b), g);
    assert_eq!(group_of(&mut k.c), g);
    (k, g)
}

#[test]
fn group_messaging_roles_and_enforced_authorization() {
    let w = World::new();
    let (mut k, g) = set_up(&w);
    assert_eq!(k.b.conversation(&g).unwrap().title, "Team");
    assert_eq!(k.a.my_role(&g).unwrap(), Role::Owner);
    assert_eq!(k.b.my_role(&g).unwrap(), Role::Member);

    // Everybody can talk; everybody sees everything.
    w.clock.0.advance(1);
    k.a.send_text(&g, PT, None).unwrap();
    w.clock.0.advance(1);
    k.b.send_text(&g, "from-bob", None).unwrap();
    k.a.sync().unwrap();
    k.b.sync().unwrap();
    k.c.sync().unwrap();
    for e in [&mut k.a, &mut k.b, &mut k.c] {
        assert_eq!(texts(e, &g), [PT, "from-bob"]);
    }
    let members = k.a.members(&g).unwrap();
    assert_eq!(members.len(), 3);
    assert_eq!(members[0].role, Role::Owner);

    // A plain member cannot add, rename, promote, or remove: refused by the engine's own policy check.
    let d = w.engine();
    let id_d = d.e.clone_public_for_tests();
    k.b.add_contact_by_id(&cipher_core::app::cipher_id::format(&id_d.account_id), "Dave").unwrap();
    assert!(matches!(k.b.add_group_members(&g, &[id_d.account_id]), Err(SecurityError::Unauthorized(_))));
    assert!(matches!(k.b.rename_group(&g, "Hijacked"), Err(SecurityError::Unauthorized(_))));
    assert!(matches!(k.b.promote_admin(&g, &k.ib.account_id), Err(SecurityError::Unauthorized(_))));
    assert!(matches!(k.b.remove_group_member(&g, &k.ic.account_id), Err(SecurityError::Unauthorized(_))));
    assert!(matches!(k.a.leave_group(&g), Err(SecurityError::Denied(_))), "owner must transfer first");

    // Owner promotes Bob; Bob can now add Dave and rename, but cannot promote or remove the owner.
    k.a.promote_admin(&g, &k.ib.account_id).unwrap();
    k.b.sync().unwrap();
    assert_eq!(k.b.my_role(&g).unwrap(), Role::Admin);
    k.b.rename_group(&g, "Team Renamed").unwrap();
    assert!(matches!(k.b.promote_admin(&g, &k.ic.account_id), Err(SecurityError::Unauthorized(_))));
    assert!(matches!(k.b.remove_group_member(&g, &k.ia.account_id), Err(SecurityError::Unauthorized(_))));
    k.a.sync().unwrap();
    assert_eq!(k.a.conversation(&g).unwrap().title, "Team Renamed");

    // NEW MEMBERS DO NOT RECEIVE PRE-JOIN HISTORY.
    w.clock.0.advance(1);
    k.a.send_text(&g, "before-dave-joined", None).unwrap();
    k.b.add_group_members(&g, &[id_d.account_id]).unwrap();
    let mut d = d;
    d.add_contact_by_id(&k.ib.cipher_id, "Bob").unwrap(); // Bob is a contact, so the invite is Active
    w.clock.0.advance(1);
    k.a.sync().unwrap();
    k.a.send_text(&g, "after-dave-joined", None).unwrap();
    d.sync().unwrap();
    let dg = group_of(&mut d);
    assert_eq!(texts(&mut d, &dg), ["after-dave-joined"], "Dave must not see anything sent before he joined");
    assert!(!texts(&mut d, &dg).iter().any(|t| t.contains("before-dave") || t == PT));

    // No plaintext anywhere outside the vaults.
    for (n, hay) in [("wire", w.all_wire_bytes()), ("db", w.db_bytes()), ("logs", w.log_text())] {
        assert!(!contains(&hay, b"PLAINTEXT-FIXTURE") && !contains(&hay, b"before-dave") && !contains(&hay, b"from-bob"), "leak in {n}");
    }
}

#[test]
fn removal_rotates_the_tag_and_the_removed_member_cannot_read_even_if_the_relay_misroutes() {
    let w = World::new();
    let (mut k, g) = set_up(&w);
    k.a.send_text(&g, "pre-removal", None).unwrap();
    k.c.sync().unwrap();
    assert_eq!(texts(&mut k.c, &g), ["pre-removal"]);
    let old_tag = k.a.conversation(&g).unwrap().tag;

    k.a.remove_group_member(&g, &k.ic.account_id).unwrap();
    let new_tag = k.a.conversation(&g).unwrap().tag;
    assert_ne!(old_tag, new_tag, "routing tag rotates on removal");
    // The old tag is retired at the relay.
    let gone = w.rt.block_on(async {
        w.pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT retired FROM groups WHERE tag=$1", &[&old_tag.0.as_slice()])
            .await
            .unwrap()
            .get::<_, bool>(0)
    });
    assert!(gone);
    k.b.sync().unwrap();
    assert!(k.b.members(&g).unwrap().iter().all(|m| m.account != k.ic.account_id));
    k.c.sync().unwrap();
    assert_eq!(k.c.conversation(&g).unwrap().state, ConvState::Left);
    assert!(k.c.conversation(&g).unwrap().access_revoked, "removal revokes Cipher-controlled history access");
    // Carol's retained history is now unavailable: the sealed body cannot be opened because her epoch keys were deleted (docs/HISTORY_REVOCATION.md).
    let hist = k.c.history(&g, None, 10).unwrap().items;
    assert!(hist.len() == 1 && hist[0].unavailable && texts(&mut k.c, &g).iter().all(|t| t.is_empty()));

    // A post-removal message. A hostile relay copies it into Carol's queue anyway.
    w.clock.0.advance(1);
    k.a.send_text(&g, "post-removal-secret-4471", None).unwrap();
    let cdev = k.c.clone_public_for_tests().device_id;
    let bdev = k.b.clone_public_for_tests().device_id;
    w.exec(
        "INSERT INTO queue (recipient, message_id, ct, expires_at) SELECT $1, decode(md5(random()::text),'hex'), ct, expires_at FROM queue WHERE recipient=$2",
        &[&cdev.0.as_slice(), &bdev.0.as_slice()],
    );
    w.exec("UPDATE devices SET queued_count = (SELECT count(*) FROM queue WHERE recipient=$1), queued_bytes = (SELECT COALESCE(sum(octet_length(ct)),0) FROM queue WHERE recipient=$1) WHERE device_id=$1", &[&cdev.0.as_slice()]);
    k.c.sync().unwrap();
    let hist = k.c.history(&g, None, 10).unwrap().items;
    assert!(hist.iter().all(|m| m.unavailable), "removed member can open NOTHING: neither old history nor later epochs");
    assert!(!texts(&mut k.c, &g).iter().any(|t| t.contains("post-removal") || t == "pre-removal"));
    // Carol cannot send either, and the removed member's old tag cannot brick the group.
    assert!(matches!(k.c.send_text(&g, "still here?", None), Err(SecurityError::Denied(_))));
    k.b.sync().unwrap();
    assert_eq!(texts(&mut k.b, &g), ["pre-removal", "post-removal-secret-4471"]);
}

#[test]
fn leave_request_is_honoured_by_an_admin_and_the_owner_can_transfer() {
    let w = World::new();
    let (mut k, g) = set_up(&w);
    k.a.promote_admin(&g, &k.ib.account_id).unwrap();
    k.b.sync().unwrap();
    // Carol leaves: she cannot commit her own removal, so an admin does it on sync.
    k.c.leave_group(&g).unwrap();
    assert_eq!(k.c.conversation(&g).unwrap().state, ConvState::Left);
    k.a.sync().unwrap();
    k.b.sync().unwrap();
    k.a.sync().unwrap();
    for e in [&mut k.a, &mut k.b] {
        let m = e.members(&g).unwrap();
        assert!(m.iter().all(|x| x.account != k.ic.account_id), "Carol is gone for everyone");
    }
    // Owner transfer then leave.
    k.a.transfer_ownership(&g, &k.ib.account_id).unwrap();
    k.b.sync().unwrap();
    assert_eq!(k.b.my_role(&g).unwrap(), Role::Owner);
    assert_eq!(k.a.my_role(&g).unwrap(), Role::Admin);
    k.a.leave_group(&g).unwrap();
    k.b.sync().unwrap();
    assert_eq!(k.b.members(&g).unwrap().len(), 1);
}

#[test]
fn concurrent_commits_are_ordered_deterministically_and_the_loser_rebases() {
    let w = World::new();
    let (mut k, g) = set_up(&w);
    k.a.promote_admin(&g, &k.ib.account_id).unwrap();
    k.b.sync().unwrap();
    k.c.sync().unwrap();
    let before = k.a.conversation_epoch(&g).unwrap();

    // Bob renames the group. At the instant Bob's commit reaches the relay, Alice's rename wins the race (injected).
    use std::sync::{Arc, Mutex};
    let alice = Arc::new(Mutex::new(k.a));
    let hook_alice = alice.clone();
    let mut fired = false;
    *k.b.transport.hook.lock().unwrap() = Some(Box::new(move |_m, p| {
        if p.ends_with("/commit") && !fired {
            fired = true;
            hook_alice.lock().unwrap().rename_group(&g, "alice-won").unwrap();
        }
    }));
    k.b.rename_group(&g, "bob-rebased").unwrap();
    *k.b.transport.hook.lock().unwrap() = None;
    let mut a = Arc::try_unwrap(alice).ok().unwrap().into_inner().unwrap();
    // Exactly two commits happened, in a deterministic order: Alice first, then Bob rebased on top.
    a.sync().unwrap();
    k.c.sync().unwrap();
    for e in [&mut a, &mut k.b, &mut k.c] {
        assert_eq!(e.conversation(&g).unwrap().title, "bob-rebased", "all members converge on the last commit");
        assert_eq!(e.conversation_epoch(&g).unwrap(), before + 2);
    }
    let seq: i64 = w.rt.block_on(async {
        w.pool.get().await.unwrap().query_one("SELECT epoch FROM groups WHERE retired=false", &[]).await.unwrap().get(0)
    });
    assert_eq!(seq as u64, a.conversation(&g).unwrap().relay_seq);
}

#[test]
fn a_forged_commit_from_a_member_is_rejected_by_everyone_and_does_not_brick_the_group() {
    let w = World::new();
    let (mut k, g) = set_up(&w);
    let epoch = k.a.conversation_epoch(&g).unwrap();
    // Malicious member Bob (plain MEMBER) tries to make himself admin.
    let mut meta = cipher_core::app::groupmeta::GroupMeta::new_group(k.a.conversation(&g).unwrap().tag, "Team", k.ia.account_id);
    meta.roles.push(cipher_core::app::groupmeta::RoleEntry { account: k.ib.account_id, role: Role::Admin });
    k.b.inject_forged_commit_for_tests(&g, &[GroupOp::SetMeta(meta.normalised())]).unwrap();

    k.a.sync().unwrap();
    k.c.sync().unwrap();
    assert!(k.a.take_events().iter().any(|e| matches!(e, SecurityEvent::UnauthorizedGroupChange { .. })));
    assert!(k.c.take_events().iter().any(|e| matches!(e, SecurityEvent::UnauthorizedGroupChange { .. })));
    for e in [&mut k.a, &mut k.c] {
        assert_eq!(e.conversation_epoch(&g).unwrap(), epoch, "epoch must not advance");
        assert!(
            e.my_role(&g).unwrap() != Role::Admin
                || e.members(&g).unwrap().iter().all(|m| m.role != Role::Admin || m.account != k.ib.account_id)
        );
    }
    assert_eq!(k.a.members(&g).unwrap().iter().filter(|m| m.role == Role::Admin).count(), 0, "Bob was not promoted");
    // Liveness: the relay's commit counter advanced for the rejected commit; Alice still commits successfully (she tracks it).
    k.a.rename_group(&g, "still-works").unwrap();
    k.c.sync().unwrap();
    assert_eq!(k.c.conversation(&g).unwrap().title, "still-works");
    k.a.send_text(&g, "alive", None).unwrap();
    k.c.sync().unwrap();
    assert_eq!(texts(&mut k.c, &g), ["alive"]);
}

#[test]
fn a_commit_withheld_by_the_relay_holds_later_messages_until_it_arrives() {
    let w = World::new();
    let (mut k, g) = set_up(&w);
    k.a.rename_group(&g, "epoch-two").unwrap();
    w.clock.0.advance(1);
    k.a.send_text(&g, "needs-new-epoch", None).unwrap();
    let cdev = k.c.clone_public_for_tests().device_id;
    // The relay withholds the commit from Carol (takes it out of her queue) but delivers the message.
    let commit_row: (Vec<u8>, Vec<u8>, i64, Option<i64>) = w.rt.block_on(async {
        let c = w.pool.get().await.unwrap();
        let r = c.query_one("SELECT message_id, ct, expires_at, group_seq FROM queue WHERE recipient=$1 AND group_seq IS NOT NULL ORDER BY seq DESC LIMIT 1", &[&cdev.0.as_slice()]).await.unwrap();
        (r.get(0), r.get(1), r.get(2), r.get(3))
    });
    w.exec("DELETE FROM queue WHERE recipient=$1 AND message_id=$2", &[&cdev.0.as_slice(), &commit_row.0]);
    w.exec("UPDATE devices SET queued_count = (SELECT count(*) FROM queue WHERE recipient=$1), queued_bytes = (SELECT COALESCE(sum(octet_length(ct)),0) FROM queue WHERE recipient=$1) WHERE device_id=$1", &[&cdev.0.as_slice()]);
    k.c.sync().unwrap();
    assert!(texts(&mut k.c, &g).is_empty(), "cannot decrypt a future-epoch message yet");
    // The relay finally delivers the commit: Carol catches up and the held message appears.
    w.exec(
        "INSERT INTO queue (recipient, message_id, ct, expires_at, group_seq) VALUES ($1,$2,$3,$4,$5)",
        &[&cdev.0.as_slice(), &commit_row.0, &commit_row.1, &commit_row.2, &commit_row.3],
    );
    w.exec("UPDATE devices SET queued_count = (SELECT count(*) FROM queue WHERE recipient=$1), queued_bytes = (SELECT COALESCE(sum(octet_length(ct)),0) FROM queue WHERE recipient=$1) WHERE device_id=$1", &[&cdev.0.as_slice()]);
    k.c.sync().unwrap();
    assert_eq!(texts(&mut k.c, &g), ["needs-new-epoch"]);
    assert_eq!(k.c.conversation(&g).unwrap().title, "epoch-two");
}

#[test]
fn scheduled_key_refresh_advances_the_epoch_and_keeps_the_group_working() {
    let w = World::new();
    let (mut k, g) = set_up(&w);
    k.a.send_text(&g, "activity", None).unwrap();
    let e0 = k.a.conversation_epoch(&g).unwrap();
    w.clock.0.advance(2 * 3600);
    k.a.maintenance().unwrap();
    assert_eq!(k.a.conversation_epoch(&g).unwrap(), e0, "not due yet (< 24 h)");
    w.clock.0.advance(24 * 3600);
    k.a.maintenance().unwrap();
    let e1 = k.a.conversation_epoch(&g).unwrap();
    assert_eq!(e1, e0 + 1, "self-update commit issued after 24 h of use");
    // Everyone else is also 24 h into the epoch and refreshes their own keys when they next sync; all converge.
    for _ in 0..2 {
        k.b.sync().unwrap();
        k.c.sync().unwrap();
        k.a.sync().unwrap();
    }
    let (ea, eb, ec) = (k.a.conversation_epoch(&g).unwrap(), k.b.conversation_epoch(&g).unwrap(), k.c.conversation_epoch(&g).unwrap());
    assert!(ea == eb && eb == ec && ea >= e1, "members converge: {ea} {eb} {ec} (>= {e1})");
    w.clock.0.advance(10);
    k.b.send_text(&g, "after refresh", None).unwrap();
    k.a.sync().unwrap();
    assert!(texts(&mut k.a, &g).contains(&"after refresh".to_owned()));
    // Event-driven: an explicit refresh is always possible (spacing rules apply only to the scheduler).
    let before = k.c.conversation_epoch(&g).unwrap();
    k.c.refresh_keys(&g).unwrap();
    k.a.sync().unwrap();
    assert_eq!(k.a.conversation_epoch(&g).unwrap(), before + 1);
    let _ = w.clock.unix_secs();
}

#[test]
fn group_creation_requires_trusted_contacts_and_sane_input() {
    let w = World::new();
    let mut k = crew(&w);
    assert!(k.a.create_group("", &[k.ib.account_id]).is_err());
    assert!(k.a.create_group("x", &[]).is_err());
    let stranger = w.engine().e.clone_public_for_tests();
    assert!(k.a.create_group("x", &[stranger.account_id]).is_err(), "not a contact");
    k.a.set_blocked(&k.ib.account_id, true).unwrap();
    assert!(matches!(k.a.create_group("x", &[k.ib.account_id]), Err(SecurityError::Denied(_))));
    assert!(k.a.list_conversations().unwrap().is_empty());
}
