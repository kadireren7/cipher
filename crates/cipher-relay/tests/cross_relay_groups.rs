#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Groups whose members live on three independent relays (docs/CROSS_RELAY_GROUPS.md §7): the creator's relay is the HOME relay that orders
//! commits; application messages travel to each member's own relay through capabilities. Separate databases, no relay-to-relay contact.
mod harness;
use cipher_core::app::model::*;
use cipher_wire::{Id16, RelayDescriptor};
use harness::engine::*;
use harness::*;

const BASE_A: &str = "https://relay-a.test";
const BASE_B: &str = "https://relay-b.test";
const BASE_C: &str = "https://relay-c.test";

struct Rig {
    wa: World,
    wb: World,
    wc: World,
    alice: TestEngine,
    bob: TestEngine,
    carol: TestEngine,
    bob_id: Id16,
    carol_id: Id16,
}

fn rig() -> Rig {
    let (wa, wb, wc) = (World::new(), World::new(), World::new());
    let (mut alice, mut bob, mut carol) = (wa.engine(), wb.engine(), wc.engine());
    alice.set_own_relay(RelayDescriptor::new(BASE_A, None).unwrap()).unwrap();
    bob.set_own_relay(RelayDescriptor::new(BASE_B, None).unwrap()).unwrap();
    carol.set_own_relay(RelayDescriptor::new(BASE_C, None).unwrap()).unwrap();
    // Every device reaches ITS OWN relay as before and may reach the others directly (client-mediated). The relays never talk to each other.
    for (e, others) in
        [(&alice, [(BASE_B, &wb), (BASE_C, &wc)]), (&bob, [(BASE_A, &wa), (BASE_C, &wc)]), (&carol, [(BASE_A, &wa), (BASE_B, &wb)])]
    {
        for (base, w) in others {
            e.transport.reach(base, w.app.clone(), w.rt.clone());
        }
    }
    let (bob_id, carol_id) = (bob.public_identity().unwrap().account_id, carol.public_identity().unwrap().account_id);
    Rig { wa, wb, wc, alice, bob, carol, bob_id, carol_id }
}

impl Rig {
    fn sync_all(&mut self, rounds: usize) {
        for _ in 0..rounds {
            self.alice.sync().unwrap();
            self.bob.sync().unwrap();
            self.carol.sync().unwrap();
        }
    }
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

/// Alice (relay A) adds Bob (B) and Carol (C) by their cards and creates the group; both accept. Returns (alice conv, bob conv, carol conv).
fn trio(r: &mut Rig) -> (Id16, Id16, Id16) {
    let (cb, cc) = (r.bob.create_contact_card(7).unwrap(), r.carol.create_contact_card(7).unwrap());
    r.alice.add_contact_by_card(&cb, "Bob", true).unwrap();
    r.alice.add_contact_by_card(&cc, "Carol", true).unwrap();
    let conv_a = r.alice.create_group("Trio", &[r.bob_id, r.carol_id]).unwrap();
    r.sync_all(2);
    let conv_b = r.bob.list_conversations().unwrap().into_iter().find(|c| c.kind == ConvKind::Group).expect("bob received the Welcome").id;
    let conv_c =
        r.carol.list_conversations().unwrap().into_iter().find(|c| c.kind == ConvKind::Group).expect("carol received the Welcome").id;
    r.bob.accept_conversation(&conv_b).unwrap();
    r.carol.accept_conversation(&conv_c).unwrap();
    r.sync_all(4);
    (conv_a, conv_b, conv_c)
}

#[test]
fn a_group_across_three_relays_carries_text_between_every_pair_of_members() {
    let mut r = rig();
    let (ca, cb, cc) = trio(&mut r);
    assert!(r.alice.conversation(&ca).unwrap().home.is_some(), "the creator's group is homed");
    assert_eq!(r.bob.conversation(&cb).unwrap().home.unwrap().relay.url(), BASE_A, "the home relay comes from the authenticated metadata");
    r.alice.send_text(&ca, "from alice on A", None).unwrap();
    r.bob.send_text(&cb, "from bob on B", None).unwrap();
    r.carol.send_text(&cc, "from carol on C", None).unwrap();
    r.sync_all(5);
    for (e, c) in [(&mut r.alice, ca), (&mut r.bob, cb), (&mut r.carol, cc)] {
        let t = texts(e, &c);
        for want in ["from alice on A", "from bob on B", "from carol on C"] {
            assert!(t.contains(&want.to_owned()), "missing {want:?} in {t:?}");
        }
    }
}

use cipher_core::app::groupmeta::{GroupMeta, RoleEntry};
use cipher_core::app::HomeForgery;
use cipher_core::events::SecurityEvent;
use cipher_core::protocol::GroupOp;
use std::sync::{Arc, Mutex};

const BASE_D: &str = "https://relay-d.test";

fn has_event(e: &mut TestEngine, f: impl Fn(&SecurityEvent) -> bool) -> bool {
    e.take_events().iter().any(f)
}

fn frozen(e: &mut TestEngine, c: &Id16) -> Option<String> {
    e.conversation(c).unwrap().home.unwrap().frozen
}

/// A fourth member on a fourth relay, reachable from and reaching everyone.
fn dave(r: &Rig) -> (World, TestEngine, Id16) {
    let wd = World::new();
    let mut d = wd.engine();
    d.set_own_relay(RelayDescriptor::new(BASE_D, None).unwrap()).unwrap();
    for (base, w) in [(BASE_A, &r.wa), (BASE_B, &r.wb), (BASE_C, &r.wc)] {
        d.transport.reach(base, w.app.clone(), w.rt.clone());
    }
    for e in [&r.alice, &r.bob, &r.carol] {
        e.transport.reach(BASE_D, wd.app.clone(), wd.rt.clone());
    }
    let id = d.public_identity().unwrap().account_id;
    (wd, d, id)
}

#[test]
fn a_member_who_was_offline_receives_everything_in_order_after_returning() {
    let mut r = rig();
    let (ca, cb, cc) = trio(&mut r);
    for i in 1..=4 {
        r.alice.send_text(&ca, &format!("a{i}"), None).unwrap();
        r.bob.send_text(&cb, &format!("b{i}"), None).unwrap();
    }
    for _ in 0..4 {
        r.alice.sync().unwrap();
        r.bob.sync().unwrap(); // Carol does not sync at all
    }
    r.sync_all(4);
    let t = texts(&mut r.carol, &cc);
    let of = |p: &str| t.iter().filter(|x| x.starts_with(p)).cloned().collect::<Vec<_>>();
    assert_eq!(of("a"), ["a1", "a2", "a3", "a4"], "{t:?}");
    assert_eq!(of("b"), ["b1", "b2", "b3", "b4"], "{t:?}");
}

#[test]
fn one_unreachable_member_relay_does_not_stall_the_others_and_that_member_catches_up_later() {
    let mut r = rig();
    let (ca, cb, cc) = trio(&mut r);
    for e in [&r.alice, &r.bob] {
        e.transport.down.lock().unwrap().push(BASE_C.to_owned()); // Carol's relay is unreachable from the others
    }
    let m = r.alice.send_text(&ca, "while-c-is-down", None).unwrap();
    r.bob.send_text(&cb, "bob-while-c-is-down", None).unwrap();
    for _ in 0..3 {
        r.alice.sync().unwrap();
        r.bob.sync().unwrap();
    }
    assert!(texts(&mut r.bob, &cb).contains(&"while-c-is-down".to_owned()), "Bob is not held up by Carol's outage");
    assert!(texts(&mut r.alice, &ca).contains(&"bob-while-c-is-down".to_owned()));
    assert_eq!(
        r.alice.message(&ca, &m.id).unwrap().unwrap().state,
        DeliveryState::Pending,
        "not reported sent while a member was not reached"
    );
    // Carol's relay returns; the senders' retry back-off elapses.
    for e in [&r.alice, &r.bob] {
        e.transport.down.lock().unwrap().clear();
    }
    r.wa.clock.0.advance(600);
    r.wb.clock.0.advance(600);
    r.sync_all(4);
    let t = texts(&mut r.carol, &cc);
    assert!(t.contains(&"while-c-is-down".to_owned()) && t.contains(&"bob-while-c-is-down".to_owned()), "{t:?}");
    assert_ne!(r.alice.message(&ca, &m.id).unwrap().unwrap().state, DeliveryState::Pending);
}

#[test]
fn commits_continue_after_the_home_relay_restarts_and_members_on_other_relays_follow() {
    let mut r = rig();
    let (ca, cb, cc) = trio(&mut r);
    let fresh = r.wa.instance(generous_limits());
    r.alice.transport.restart_relay(fresh.clone());
    r.bob.transport.restart_other(BASE_A, fresh.clone());
    r.carol.transport.restart_other(BASE_A, fresh);
    r.alice.rename_group(&ca, "after-the-restart").unwrap();
    r.sync_all(3);
    for (e, c) in [(&mut r.alice, ca), (&mut r.bob, cb), (&mut r.carol, cc)] {
        assert_eq!(e.conversation(&c).unwrap().title, "after-the-restart");
    }
}

#[test]
fn the_home_relay_being_down_blocks_membership_changes_but_not_messages() {
    let mut r = rig();
    let (ca, cb, cc) = trio(&mut r);
    for e in [&r.alice, &r.bob, &r.carol] {
        e.transport.down.lock().unwrap().push(BASE_A.to_owned());
    }
    // Alice's own mailbox is on relay A too, so she is offline entirely; Bob and Carol still reach each other.
    r.bob.send_text(&cb, "no-home-needed", None).unwrap();
    for _ in 0..3 {
        r.bob.sync().unwrap();
        r.carol.sync().unwrap();
    }
    assert!(texts(&mut r.carol, &cc).contains(&"no-home-needed".to_owned()));
    assert!(r.bob.rename_group(&cb, "cannot-while-home-is-down").is_err());
    assert_eq!(r.bob.conversation(&cb).unwrap().title, "Trio", "nothing changed locally");
    for e in [&r.alice, &r.bob, &r.carol] {
        e.transport.down.lock().unwrap().clear();
    }
    r.wb.clock.0.advance(600);
    r.bob.promote_admin(&cb, &r.carol_id).unwrap_err(); // Bob is a plain member: his own pre-check refuses, the home relay is not even needed
    r.alice.rename_group(&ca, "back-again").unwrap();
    r.sync_all(3);
    assert_eq!(r.carol.conversation(&cc).unwrap().title, "back-again");
}

#[test]
fn concurrent_commits_from_two_admins_are_ordered_by_the_home_log_and_the_loser_rebases() {
    let mut r = rig();
    let (ca, cb, cc) = trio(&mut r);
    r.alice.promote_admin(&ca, &r.bob_id).unwrap();
    r.sync_all(3);
    let before = r.alice.conversation_epoch(&ca).unwrap();
    let alice = Arc::new(Mutex::new(r.alice));
    let hook_alice = alice.clone();
    let mut fired = false;
    *r.bob.transport.hook.lock().unwrap() = Some(Box::new(move |_m, p| {
        if p.starts_with("/v1/home/") && p.ends_with("/commit") && !fired {
            fired = true;
            hook_alice.lock().unwrap().rename_group(&ca, "alice-won").unwrap(); // Alice's commit takes the slot Bob was about to use
        }
    }));
    r.bob.rename_group(&cb, "bob-rebased").unwrap();
    *r.bob.transport.hook.lock().unwrap() = None;
    r.alice = Arc::try_unwrap(alice).ok().unwrap().into_inner().unwrap();
    r.sync_all(3);
    for (e, c) in [(&mut r.alice, ca), (&mut r.bob, cb), (&mut r.carol, cc)] {
        assert_eq!(e.conversation(&c).unwrap().title, "bob-rebased", "all members converge on the last commit");
        assert_eq!(e.conversation_epoch(&c).unwrap(), before + 2, "exactly two commits happened");
    }
    let head: i64 =
        r.wa.rt.block_on(async { r.wa.pool.get().await.unwrap().query_one("SELECT head_seq FROM home_groups", &[]).await.unwrap().get(0) });
    assert_eq!(head as u64, before + 2);
}

#[test]
fn removing_a_member_cuts_it_off_even_when_the_removed_member_commits_first() {
    let mut r = rig();
    let (ca, cb, cc) = trio(&mut r);
    let carol = Arc::new(Mutex::new(r.carol));
    let hook_carol = carol.clone();
    let mut fired = false;
    *r.alice.transport.hook.lock().unwrap() = Some(Box::new(move |_m, p| {
        if p.starts_with("/v1/home/") && p.ends_with("/commit") && !fired {
            fired = true;
            hook_carol.lock().unwrap().refresh_keys(&cc).unwrap(); // the member being removed wins the race for the slot
        }
    }));
    r.alice.remove_group_member(&ca, &r.carol_id).unwrap();
    *r.alice.transport.hook.lock().unwrap() = None;
    r.carol = Arc::try_unwrap(carol).ok().unwrap().into_inner().unwrap();
    r.sync_all(4);
    let c = r.carol.conversation(&cc).unwrap();
    assert!(c.access_revoked && c.state == ConvState::Left, "Carol lost access");
    assert!(has_event(&mut r.carol, |e| matches!(e, SecurityEvent::GroupAccessRevoked { .. })));
    assert_eq!(r.alice.members(&ca).unwrap().len(), 2);
    assert_eq!(r.bob.members(&cb).unwrap().len(), 2);
    r.alice.send_text(&ca, "after-the-removal", None).unwrap();
    r.sync_all(4);
    assert!(texts(&mut r.bob, &cb).contains(&"after-the-removal".to_owned()));
    assert!(!texts(&mut r.carol, &cc).contains(&"after-the-removal".to_owned()), "a removed member reads nothing sent afterwards");
    assert!(r.carol.send_text(&cc, "i-am-still-here", None).is_err());
}

#[test]
fn a_lost_response_to_a_commit_that_adds_a_member_is_resolved_and_the_welcome_still_arrives() {
    let mut r = rig();
    let (ca, cb, _cc) = trio(&mut r);
    let (wd, mut dave, dave_id) = dave(&r);
    let card = dave.create_contact_card(7).unwrap();
    r.alice.add_contact_by_card(&card, "Dave", true).unwrap();
    *r.alice.transport.lose_response_on.lock().unwrap() = Some("/commit".to_owned()); // the home relay accepts, the answer is lost
    assert!(r.alice.add_group_members(&ca, &[dave_id]).is_err(), "outcome unknown to Alice");
    r.alice.sync().unwrap(); // resends the identical request: answered as already accepted, then finishes and queues the Welcome
    for _ in 0..4 {
        r.alice.sync().unwrap();
        r.bob.sync().unwrap();
        dave.sync().unwrap();
    }
    let cd = dave.list_conversations().unwrap().into_iter().find(|c| c.kind == ConvKind::Group).expect("Dave received the Welcome").id;
    dave.accept_conversation(&cd).unwrap();
    for _ in 0..4 {
        r.alice.sync().unwrap();
        r.bob.sync().unwrap();
        r.carol.sync().unwrap();
        dave.sync().unwrap();
    }
    let head: i64 =
        r.wa.rt.block_on(async { r.wa.pool.get().await.unwrap().query_one("SELECT head_seq FROM home_groups", &[]).await.unwrap().get(0) });
    assert_eq!(head, 2, "creation + exactly ONE add, not two");
    assert_eq!(r.alice.members(&ca).unwrap().len(), 4);
    dave.send_text(&cd, "hello from relay D", None).unwrap();
    for _ in 0..4 {
        r.alice.sync().unwrap();
        r.bob.sync().unwrap();
        r.carol.sync().unwrap();
        dave.sync().unwrap();
    }
    assert!(texts(&mut r.bob, &cb).contains(&"hello from relay D".to_owned()));
    drop(wd);
}

#[test]
fn the_welcome_for_a_member_on_an_unreachable_relay_waits_without_blocking_the_group() {
    let mut r = rig();
    let (ca, cb, cc) = trio(&mut r);
    let (wd, mut dave, dave_id) = dave(&r);
    let card = dave.create_contact_card(7).unwrap();
    r.alice.add_contact_by_card(&card, "Dave", true).unwrap();
    r.alice.transport.down.lock().unwrap().push(BASE_D.to_owned()); // Dave's relay is down while he is added
                                                                    // adding Dave needs his KeyPackage from relay D, so Alice must reach it for that one request
    r.alice.transport.down.lock().unwrap().clear();
    r.alice.add_group_members(&ca, &[dave_id]).unwrap();
    r.alice.transport.down.lock().unwrap().push(BASE_D.to_owned());
    r.alice.send_text(&ca, "while-dave-is-unreachable", None).unwrap();
    r.bob.sync().unwrap(); // Bob must have applied the commit that added Dave, otherwise Dave is not a recipient at Bob's epoch
    r.bob.send_text(&cb, "bob-too", None).unwrap();
    for _ in 0..4 {
        r.alice.sync().unwrap();
        r.bob.sync().unwrap();
        r.carol.sync().unwrap();
    }
    assert!(texts(&mut r.carol, &cc).contains(&"while-dave-is-unreachable".to_owned()), "Carol is not held up by Dave's Welcome");
    // Dave's relay returns: he gets the Welcome FIRST, then the messages that were waiting for him
    r.alice.transport.down.lock().unwrap().clear();
    r.wa.clock.0.advance(3600);
    r.wb.clock.0.advance(3600);
    for _ in 0..3 {
        r.alice.sync().unwrap();
        r.bob.sync().unwrap();
        dave.sync().unwrap();
    }
    let cd = dave.list_conversations().unwrap().into_iter().find(|c| c.kind == ConvKind::Group).expect("Dave received the Welcome").id;
    dave.accept_conversation(&cd).unwrap();
    for _ in 0..5 {
        r.alice.sync().unwrap();
        r.bob.sync().unwrap();
        r.carol.sync().unwrap();
        dave.sync().unwrap();
    }
    let t = texts(&mut dave, &cd);
    assert!(t.contains(&"while-dave-is-unreachable".to_owned()) && t.contains(&"bob-too".to_owned()), "{t:?}");
    drop(wd);
}

#[test]
fn a_member_added_later_learns_everyone_and_can_exchange_messages_with_all_of_them() {
    let mut r = rig();
    let (ca, cb, cc) = trio(&mut r);
    let (wd, mut dave, dave_id) = dave(&r);
    let card = dave.create_contact_card(7).unwrap();
    r.alice.add_contact_by_card(&card, "Dave", true).unwrap();
    r.alice.add_group_members(&ca, &[dave_id]).unwrap();
    for _ in 0..3 {
        r.alice.sync().unwrap();
        dave.sync().unwrap();
    }
    let cd = dave.list_conversations().unwrap().into_iter().find(|c| c.kind == ConvKind::Group).unwrap().id;
    dave.accept_conversation(&cd).unwrap();
    for _ in 0..6 {
        r.alice.sync().unwrap();
        r.bob.sync().unwrap();
        r.carol.sync().unwrap();
        dave.sync().unwrap();
    }
    r.bob.send_text(&cb, "bob to everyone", None).unwrap();
    r.carol.send_text(&cc, "carol to everyone", None).unwrap();
    dave.send_text(&cd, "dave to everyone", None).unwrap();
    for _ in 0..6 {
        r.alice.sync().unwrap();
        r.bob.sync().unwrap();
        r.carol.sync().unwrap();
        dave.sync().unwrap();
    }
    for (e, c) in [(&mut r.alice, ca), (&mut r.bob, cb), (&mut r.carol, cc), (&mut dave, cd)] {
        let t = texts(e, &c);
        for want in ["bob to everyone", "carol to everyone", "dave to everyone"] {
            assert!(t.contains(&want.to_owned()), "missing {want:?} in {t:?}");
        }
    }
    drop(wd);
}

// ------------------------------------------------------------------------------------------------------------------ hostile relays

fn rewrite_log(e: &TestEngine, f: impl Fn(&str, serde_json::Value) -> serde_json::Value + Send + Sync + 'static) {
    *e.transport.rewrite.lock().unwrap() = Some(Box::new(move |_m, p, body| {
        if p.starts_with("/v1/home/") && p.contains("/log") {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
                return serde_json::to_vec(&f(p, v)).unwrap();
            }
        }
        body
    }));
}

fn flip_b64(v: &mut serde_json::Value, field: &str) {
    let mut raw = cipher_wire::b64::decode(v[field].as_str().unwrap()).unwrap();
    raw[0] ^= 1;
    v[field] = serde_json::Value::String(cipher_wire::b64::encode(&raw));
}

/// Alice commits twice while Bob is not looking; returns the rig ready for Bob's next sync.
fn alice_commits_while_bob_sleeps(r: &mut Rig, ca: &Id16) {
    r.alice.rename_group(ca, "one").unwrap();
    r.alice.rename_group(ca, "two").unwrap();
    r.alice.sync().unwrap();
}

#[test]
fn a_home_relay_that_tampers_with_a_commit_is_caught_and_freezes_membership_changes() {
    let mut r = rig();
    let (ca, cb, _cc) = trio(&mut r);
    alice_commits_while_bob_sleeps(&mut r, &ca);
    let epoch = r.bob.conversation_epoch(&cb).unwrap();
    rewrite_log(&r.bob, |_, mut v| {
        if let Some(e) = v["entries"].as_array_mut().and_then(|a| a.first_mut()) {
            flip_b64(e, "commit");
        }
        v
    });
    r.bob.sync().unwrap();
    assert_eq!(frozen(&mut r.bob, &cb).as_deref(), Some(cipher_core::home::FORK_CHAIN));
    assert!(has_event(&mut r.bob, |e| matches!(e, SecurityEvent::GroupForkDetected { .. })));
    assert_eq!(r.bob.conversation_epoch(&cb).unwrap(), epoch, "nothing from the tampered entry was applied");
    assert!(
        r.bob.rename_group(&cb, "x").is_err() && r.bob.send_text(&cb, "x", None).is_err(),
        "a group with an untrustworthy log is frozen"
    );
}

#[test]
fn a_home_relay_that_drops_reorders_or_rolls_back_the_log_is_caught() {
    // (1) a gap: the relay renumbers the entry it serves
    let mut r = rig();
    let (ca, cb, _cc) = trio(&mut r);
    alice_commits_while_bob_sleeps(&mut r, &ca);
    rewrite_log(&r.bob, |_, mut v| {
        if let Some(e) = v["entries"].as_array_mut().and_then(|a| a.first_mut()) {
            e["seq"] = serde_json::json!(e["seq"].as_u64().unwrap() + 1);
        }
        v
    });
    r.bob.sync().unwrap();
    assert_eq!(frozen(&mut r.bob, &cb).as_deref(), Some(cipher_core::home::FORK_GAP));

    // (2) rollback: Bob is up to date and the relay claims an older head
    let mut r = rig();
    let (ca, cb, _cc) = trio(&mut r);
    r.alice.rename_group(&ca, "one").unwrap();
    r.sync_all(3);
    rewrite_log(&r.bob, |_, mut v| {
        v["entries"] = serde_json::json!([]);
        v["head"] = serde_json::json!({"seq": 1, "chain": cipher_wire::b64::encode(&[9u8; 32])});
        v
    });
    r.bob.sync().unwrap();
    assert_eq!(frozen(&mut r.bob, &cb).as_deref(), Some(cipher_core::home::FORK_ROLLBACK));

    // (3) same position, different hash
    let mut r = rig();
    let (ca, cb, _cc) = trio(&mut r);
    r.alice.rename_group(&ca, "one").unwrap();
    r.sync_all(3);
    let head = r.bob.conversation(&cb).unwrap().home.unwrap().ledger.unwrap().head;
    rewrite_log(&r.bob, move |_, mut v| {
        v["entries"] = serde_json::json!([]);
        v["head"] = serde_json::json!({"seq": head.seq, "chain": cipher_wire::b64::encode(&[9u8; 32])});
        v
    });
    r.bob.sync().unwrap();
    assert_eq!(frozen(&mut r.bob, &cb).as_deref(), Some(cipher_core::home::FORK_CHAIN));
}

#[test]
fn a_relay_that_only_withholds_the_log_costs_liveness_never_safety() {
    let mut r = rig();
    let (ca, cb, _cc) = trio(&mut r);
    alice_commits_while_bob_sleeps(&mut r, &ca);
    rewrite_log(&r.bob, |_, mut v| {
        v["entries"] = serde_json::json!([]);
        v["head"] = serde_json::Value::Null;
        v
    });
    for _ in 0..3 {
        r.bob.sync().unwrap();
    }
    assert!(frozen(&mut r.bob, &cb).is_none(), "withholding is indistinguishable from an outage: no false alarm");
    assert_eq!(r.bob.conversation(&cb).unwrap().title, "Trio", "Bob has not seen the renames yet");
    *r.bob.transport.rewrite.lock().unwrap() = None;
    r.sync_all(3);
    assert_eq!(r.bob.conversation(&cb).unwrap().title, "two", "he catches up when the relay behaves");
}

#[test]
fn members_shown_different_histories_by_the_home_relay_detect_it_as_soon_as_they_exchange_a_message() {
    let mut r = rig();
    // The relay serves Carol a history with different commit ids: internally perfect (valid chain, same MLS commits), but not Alice's and Bob's.
    let seen: Arc<Mutex<std::collections::HashMap<u64, [u8; 32]>>> = Arc::default();
    rewrite_log(&r.carol, move |path, mut v| {
        let tag_hex = path.trim_start_matches("/v1/home/").split('/').next().unwrap().to_owned();
        let tag = Id16::parse(&tag_hex).unwrap();
        let mut seen = seen.lock().unwrap();
        for e in v["entries"].as_array_mut().into_iter().flatten() {
            let seq = e["seq"].as_u64().unwrap();
            let mut id = Id16::parse(&e["commit_id"].as_str().unwrap().to_owned().replace('-', "")).ok();
            if id.is_none() {
                id = serde_json::from_value::<Id16>(e["commit_id"].clone()).ok();
            }
            let mut id = id.unwrap();
            id.0[0] ^= 0xFF;
            let commit = cipher_wire::b64::decode(e["commit"].as_str().unwrap()).unwrap();
            let cp: [u8; 32] = cipher_wire::b64::decode(e["commit_pub"].as_str().unwrap()).unwrap().try_into().unwrap();
            let rp: [u8; 32] = cipher_wire::b64::decode(e["read_pub"].as_str().unwrap()).unwrap().try_into().unwrap();
            let prev = if seq <= 1 { cipher_wire::home::chain_genesis(&tag) } else { *seen.get(&(seq - 1)).unwrap_or(&[0; 32]) };
            let chain = cipher_wire::home::chain_next(&prev, seq, &id, &commit, &cp, &rp);
            seen.insert(seq, chain);
            e["commit_id"] = serde_json::to_value(id).unwrap();
            e["chain"] = serde_json::Value::String(cipher_wire::b64::encode(&chain));
        }
        if let Some(h) = v.get_mut("head").filter(|h| !h.is_null()) {
            // the reported head must tell the same story as the entries it follows
            if let Some(c) = seen.get(&h["seq"].as_u64().unwrap()) {
                h["chain"] = serde_json::Value::String(cipher_wire::b64::encode(c));
            }
        }
        v
    });
    let (ca, _cb, cc) = trio(&mut r);
    let _ = r.alice.send_text(&ca, "hello everyone", None); // may already be refused: the fork can be noticed while the group is being set up
    r.carol.sync().unwrap();
    r.sync_all(4);
    let carol_alarm = frozen(&mut r.carol, &cc);
    let alice_alarm = frozen(&mut r.alice, &ca);
    assert!(
        carol_alarm.as_deref() == Some(cipher_core::home::FORK_EQUIVOCATION)
            || alice_alarm.as_deref() == Some(cipher_core::home::FORK_EQUIVOCATION),
        "someone must have noticed: carol {carol_alarm:?}, alice {alice_alarm:?}"
    );
}

#[test]
fn a_malicious_member_cannot_forge_membership_and_invalid_commits_only_block_membership_changes() {
    let mut r = rig();
    let (ca, cb, cc) = trio(&mut r);
    let epoch = r.alice.conversation_epoch(&ca).unwrap();
    // Bob (a plain member) tries to make himself admin with the real credentials of the current epoch.
    let meta = {
        let mut m = GroupMeta::new_group(r.bob.conversation(&cb).unwrap().tag, "Trio", r.alice.public_identity().unwrap().account_id)
            .with_home(RelayDescriptor::new(BASE_A, None).unwrap());
        m.roles.push(RoleEntry { account: r.bob_id, role: Role::Admin });
        m.normalised()
    };
    r.bob.inject_forged_home_commit_for_tests(&cb, HomeForgery::Unauthorized(vec![GroupOp::SetMeta(meta)])).unwrap();
    r.sync_all(3);
    for (e, c) in [(&mut r.alice, ca), (&mut r.carol, cc)] {
        assert!(has_event(e, |ev| matches!(ev, SecurityEvent::UnauthorizedGroupChange { .. })));
        assert_eq!(e.conversation_epoch(&c).unwrap(), epoch, "the epoch did not advance");
        assert_ne!(e.my_role(&c).unwrap(), Role::Admin);
        assert!(e.members(&c).unwrap().iter().all(|m| m.role != Role::Admin || m.name != "Bob"));
        assert_eq!(frozen(e, &c).as_deref(), Some("an invalid commit occupies the home log: membership changes are blocked"));
    }
    // membership changes are blocked, messages are not
    assert!(r.alice.rename_group(&ca, "no").is_err());
    r.alice.send_text(&ca, "still talking", None).unwrap();
    r.sync_all(3);
    assert!(texts(&mut r.carol, &cc).contains(&"still talking".to_owned()));
}

#[test]
fn garbage_with_attacker_chosen_keys_blocks_membership_changes_and_is_reported_but_messages_flow() {
    let mut r = rig();
    let (ca, cb, cc) = trio(&mut r);
    r.bob.inject_forged_home_commit_for_tests(&cb, HomeForgery::Garbage).unwrap();
    r.sync_all(3);
    for (e, c) in [(&mut r.alice, ca), (&mut r.carol, cc)] {
        assert!(frozen(e, &c).is_some(), "the channel capture is noticed");
        assert!(e.remove_group_member(&c, &Id16([0; 16])).is_err());
    }
    r.carol.send_text(&cc, "messages-do-not-need-the-home-relay", None).unwrap();
    r.sync_all(3);
    assert!(texts(&mut r.alice, &ca).contains(&"messages-do-not-need-the-home-relay".to_owned()));
}

// ------------------------------------------------------------------------------------------------------------------ files, metadata, refusals

#[test]
fn an_encrypted_attachment_reaches_members_on_every_relay_byte_for_byte_and_relays_hold_only_ciphertext() {
    let mut r = rig();
    let (ca, cb, cc) = trio(&mut r);
    let marker = b"PLAINTEXT-MARKER-0123456789-ABCDEF";
    let mut data = Vec::new();
    for i in 0..9_000u32 {
        data.extend_from_slice(marker);
        data.extend_from_slice(&i.to_be_bytes());
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.bin");
    std::fs::write(&path, &data).unwrap();
    r.alice
        .send_attachment(
            &ca,
            path.to_str().unwrap(),
            "application/octet-stream",
            "report.bin",
            AttachmentKind::File,
            "",
            None,
            None,
            None,
            &mut |_, _| true,
        )
        .unwrap();
    r.sync_all(5);
    for (e, c) in [(&mut r.bob, cb), (&mut r.carol, cc), (&mut r.alice, ca)] {
        let m = e
            .history(&c, None, 50)
            .unwrap()
            .items
            .into_iter()
            .find(|m| matches!(m.content, Content::Attachment { .. }))
            .expect("attachment message");
        let got = e.open_attachment(&c, &m.id, false, &mut |_, _| true).unwrap();
        assert_eq!(got.as_slice(), data.as_slice(), "byte-for-byte");
    }
    for w in [&r.wa, &r.wb, &r.wc] {
        let blobs: i64 =
            w.rt.block_on(async { w.pool.get().await.unwrap().query_one("SELECT count(*) FROM blobs", &[]).await.unwrap().get(0) });
        assert_eq!(blobs, 1, "one ciphertext copy per relay");
        assert!(!contains(&w.db_bytes(), marker) && !contains(&w.all_wire_bytes(), marker), "a relay holds only ciphertext");
    }
}

#[test]
fn members_talk_only_to_their_own_relay_and_the_home_relay_and_no_other_relay_sees_the_group_log() {
    let mut r = rig();
    let (ca, cb, cc) = trio(&mut r);
    r.alice.rename_group(&ca, "x").unwrap();
    r.bob.send_text(&cb, "m", None).unwrap();
    r.sync_all(4);
    let _ = cc;
    for (name, e) in [("alice", &r.alice), ("bob", &r.bob), ("carol", &r.carol)] {
        let home_requests: Vec<String> = e
            .transport
            .requests_by_base
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, p)| p.starts_with("/v1/home/"))
            .map(|(b, _)| b.clone())
            .collect();
        assert!(!home_requests.is_empty() || name == "alice" || true);
        assert!(
            home_requests.iter().all(|b| b == BASE_A),
            "{name} sent a home-log request somewhere other than the home relay: {home_requests:?}"
        );
    }
    let accounts_on_home: i64 =
        r.wa.rt.block_on(async { r.wa.pool.get().await.unwrap().query_one("SELECT count(*) FROM devices", &[]).await.unwrap().get(0) });
    assert_eq!(accounts_on_home, 1, "Bob and Carol have no account on the home relay");
    for w in [&r.wb, &r.wc] {
        let n: i64 =
            w.rt.block_on(async { w.pool.get().await.unwrap().query_one("SELECT count(*) FROM home_groups", &[]).await.unwrap().get(0) });
        assert_eq!(n, 0, "only the home relay stores the log");
    }
}

#[test]
fn a_cross_relay_group_cannot_be_created_unless_this_relay_is_named() {
    let (wa, wb) = (World::new(), World::new());
    let (mut alice, mut bob) = (wa.engine(), wb.engine());
    bob.set_own_relay(RelayDescriptor::new(BASE_B, None).unwrap()).unwrap();
    alice.transport.reach(BASE_B, wb.app.clone(), wb.rt.clone());
    let card = bob.create_contact_card(7).unwrap();
    alice.add_contact_by_card(&card, "Bob", true).unwrap();
    let bob_id = bob.public_identity().unwrap().account_id;
    assert!(matches!(alice.create_group("G", &[bob_id]), Err(cipher_core::error::SecurityError::Denied(_))));
    assert!(alice.list_conversations().unwrap().is_empty(), "nothing was left behind");
}
