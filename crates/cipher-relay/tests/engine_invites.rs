#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Private invitations end to end (docs/INVITATIONS.md): two real relays with separate PostgreSQL databases, real engines, real MLS Add/Welcome.
//! What a link holder can and cannot do, what an admin must approve, and what a hostile joiner or relay cannot get.
mod harness;
use cipher_core::app::model::*;
use cipher_core::clock::Clock as _;
use cipher_core::error::SecurityError;
use cipher_core::invite::InviteSecret;
use cipher_wire::invite::{InviteLink, InvitePolicy, JoinMode};
use cipher_wire::{b64, Id16, RelayDescriptor};
use ed25519_dalek::{Signer, SigningKey};
use harness::engine::*;
use harness::*;

const BASE_A: &str = "https://relay-a.test";
const BASE_B: &str = "https://relay-b.test";
const DAY_MS: u64 = 24 * 3_600_000;

struct Rig {
    wa: World,
    wb: World,
    alice: TestEngine, // owner of the group, relay A
    dave: TestEngine,  // existing member, relay A
    erin: TestEngine,  // joiner on relay A
    bob: TestEngine,   // joiner on relay B
    group: Id16,
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

fn group_of(e: &mut TestEngine) -> Option<Id16> {
    e.list_conversations().unwrap().into_iter().find(|c| c.kind == ConvKind::Group).map(|c| c.id)
}

fn policy(max_uses: u32, mode: JoinMode) -> InvitePolicy {
    InvitePolicy { lifetime_ms: DAY_MS, max_uses, mode }
}

/// Alice (relay A) owns "Team" with Dave (relay A). Erin (A) and Bob (B) are strangers who will be handed a link.
fn rig() -> Rig {
    let (wa, wb) = (World::new(), World::new());
    let (mut alice, mut dave, mut erin, mut bob) = (wa.engine(), wa.engine(), wa.engine(), wb.engine());
    alice.set_own_relay(RelayDescriptor::new(BASE_A, None).unwrap()).unwrap();
    erin.set_own_relay(RelayDescriptor::new(BASE_A, None).unwrap()).unwrap();
    bob.set_own_relay(RelayDescriptor::new(BASE_B, None).unwrap()).unwrap();
    // Everyone who opens a link or a card may reach the relay it names (client-mediated); relays never talk to each other.
    for e in [&erin, &bob, &dave] {
        e.transport.reach(BASE_A, wa.app.clone(), wa.rt.clone());
    }
    alice.transport.reach(BASE_B, wb.app.clone(), wb.rt.clone());
    erin.transport.reach(BASE_B, wb.app.clone(), wb.rt.clone());
    bob.transport.reach(BASE_B, wb.app.clone(), wb.rt.clone());
    let dave_id = dave.public_identity().unwrap();
    alice.add_contact_by_id(&dave_id.cipher_id, "Dave").unwrap();
    let group = alice.create_group("Team", &[dave_id.account_id]).unwrap();
    dave.sync().unwrap();
    Rig { wa, wb, alice, dave, erin, bob, group }
}

fn settle(r: &mut Rig) {
    for _ in 0..3 {
        r.alice.sync().unwrap();
        r.dave.sync().unwrap();
        r.erin.sync().unwrap();
        r.bob.sync().unwrap();
    }
}

#[test]
fn a_link_holder_on_the_same_relay_joins_after_approval_and_sees_no_earlier_history() {
    let mut r = rig();
    r.alice.send_text(&r.group, "before-admission secret", None).unwrap();
    let created = r.alice.create_invite(&r.group, policy(2, JoinMode::Approval)).unwrap();
    assert!(created.link.starts_with("cipher-invite:v1:"));

    // The link holder can read the preview, which the relay cannot.
    let preview = r.erin.preview_invite(&created.link).unwrap();
    assert_eq!(preview.group_name, "Team");
    assert!(!preview.auto_admission);
    r.erin.request_to_join(&created.link, "Erin").unwrap();

    // Nothing happens without the admin: Erin is not a member and the group did not change.
    settle(&mut r);
    assert!(group_of(&mut r.erin).is_none());
    assert_eq!(r.alice.members(&r.group).unwrap().len(), 2);

    let pending = r.alice.poll_join_requests().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].account, r.erin.public_identity().unwrap().account_id);
    assert_eq!(pending[0].name, "Erin");
    assert!(!pending[0].safety_number.is_empty());
    r.alice.resolve_join_request(&pending[0].request_id, true).unwrap();
    assert_eq!(r.alice.members(&r.group).unwrap().len(), 3);
    assert!(r.alice.poll_join_requests().unwrap().is_empty(), "the decided request is no longer pending");
    assert_eq!(r.alice.list_invites(&r.group).unwrap()[0].admitted, 1);

    settle(&mut r);
    let conv = group_of(&mut r.erin).expect("Erin received the Welcome");
    if r.erin.conversation(&conv).unwrap().state == ConvState::Requested {
        r.erin.accept_conversation(&conv).unwrap();
    }
    r.alice.send_text(&r.group, "after-admission hello", None).unwrap();
    settle(&mut r);
    assert_eq!(texts(&mut r.erin, &conv), vec!["after-admission hello".to_owned()], "no message from before the admission is readable");
    assert_eq!(texts(&mut r.dave, &r.group).len(), 2);
}

#[test]
fn a_link_holder_on_another_relay_cannot_join_a_group_that_has_no_home_relay() {
    let mut r = rig();
    let created = r.alice.create_invite(&r.group, policy(1, JoinMode::Approval)).unwrap();
    let preview = r.bob.preview_invite(&created.link).unwrap();
    assert!(!preview.accepts_other_relays, "the preview says so up front");
    r.bob.request_to_join(&created.link, "Bob").unwrap();
    let pending = r.alice.poll_join_requests().unwrap();
    assert_eq!(pending.len(), 1);
    let before = r.alice.members(&r.group).unwrap().len();
    let err = r.alice.resolve_join_request(&pending[0].request_id, true).unwrap_err();
    assert!(matches!(err, SecurityError::Denied(_)), "{err:?}");
    assert_eq!(r.alice.members(&r.group).unwrap().len(), before, "nothing changed");
    assert!(r.alice.contact(&r.bob.public_identity().unwrap().account_id).unwrap().is_none(), "not even a contact was stored");
    r.alice.resolve_join_request(&pending[0].request_id, false).unwrap();
}

#[test]
fn a_link_holder_on_another_relay_joins_a_group_that_has_a_home_relay() {
    let mut r = rig();
    // A group created with a member on another relay is ordered by a home relay (CROSS_RELAY_GROUPS.md): it can take members from either relay.
    let mut carl = r.wb.engine();
    carl.set_own_relay(RelayDescriptor::new(BASE_B, None).unwrap()).unwrap();
    carl.transport.reach(BASE_A, r.wa.app.clone(), r.wa.rt.clone());
    r.alice.transport.reach(BASE_B, r.wb.app.clone(), r.wb.rt.clone());
    let card = carl.create_contact_card(7).unwrap();
    let carl_c = r.alice.add_contact_by_card(&card, "Carl", true).unwrap();
    let homed = r.alice.create_group("Open team", &[carl_c.account_id]).unwrap();
    carl.sync().unwrap();
    assert!(r.alice.conversation(&homed).unwrap().home.is_some());

    let created = r.alice.create_invite(&homed, policy(1, JoinMode::Approval)).unwrap();
    assert!(r.bob.preview_invite(&created.link).unwrap().accepts_other_relays);
    r.bob.request_to_join(&created.link, "Bob").unwrap();
    let pending = r.alice.poll_join_requests().unwrap();
    r.alice.resolve_join_request(&pending[0].request_id, true).unwrap();
    assert_eq!(r.alice.members(&homed).unwrap().len(), 3);

    for _ in 0..4 {
        r.alice.sync().unwrap();
        r.bob.sync().unwrap();
        carl.sync().unwrap();
    }
    let conv = group_of(&mut r.bob).expect("Bob, on relay B, received the Welcome");
    if r.bob.conversation(&conv).unwrap().state == ConvState::Requested {
        r.bob.accept_conversation(&conv).unwrap();
    }
    r.alice.send_text(&homed, "welcome across relays", None).unwrap();
    for _ in 0..4 {
        r.alice.sync().unwrap();
        r.bob.sync().unwrap();
        carl.sync().unwrap();
    }
    assert_eq!(texts(&mut r.bob, &conv), vec!["welcome across relays".to_owned()]);
}

#[test]
fn a_rejection_returns_the_slot_and_the_requester_is_not_added() {
    let mut r = rig();
    let created = r.alice.create_invite(&r.group, policy(1, JoinMode::Approval)).unwrap();
    r.erin.request_to_join(&created.link, "Erin").unwrap();
    let pending = r.alice.poll_join_requests().unwrap();
    r.alice.resolve_join_request(&pending[0].request_id, false).unwrap();
    assert!(r.alice.poll_join_requests().unwrap().is_empty());
    settle(&mut r);
    assert!(group_of(&mut r.erin).is_none());
    assert_eq!(r.alice.members(&r.group).unwrap().len(), 2);
    // the single use is available again (the account that was refused cannot ask twice, but anyone else can)
    assert!(r.erin.request_to_join(&created.link, "Erin again").is_ok());
    assert!(r.alice.poll_join_requests().unwrap().is_empty(), "the same account is refused a second time (one request per account)");
    r.bob.request_to_join(&created.link, "Bob").unwrap();
    assert_eq!(r.alice.poll_join_requests().unwrap().len(), 1);
}

#[test]
fn a_used_up_invitation_admits_nobody_else() {
    let mut r = rig();
    let created = r.alice.create_invite(&r.group, policy(1, JoinMode::Approval)).unwrap();
    r.erin.request_to_join(&created.link, "Erin").unwrap();
    let pending = r.alice.poll_join_requests().unwrap();
    r.alice.resolve_join_request(&pending[0].request_id, true).unwrap();
    assert!(r.bob.preview_invite(&created.link).is_err(), "a used-up link no longer even previews");
    assert!(r.bob.request_to_join(&created.link, "Bob").is_err());
}

#[test]
fn a_revoked_or_expired_invitation_cannot_admit_even_a_request_already_waiting() {
    let mut r = rig();
    let revoked = r.alice.create_invite(&r.group, policy(3, JoinMode::Approval)).unwrap();
    r.erin.request_to_join(&revoked.link, "Erin").unwrap();
    let pending = r.alice.poll_join_requests().unwrap();
    assert_eq!(pending.len(), 1);
    r.alice.revoke_invite(&revoked.id).unwrap();
    assert!(r.alice.list_invites(&r.group).unwrap()[0].revoked);
    let err = r.alice.resolve_join_request(&pending[0].request_id, true).unwrap_err();
    assert!(matches!(err, SecurityError::Denied(_)), "{err:?}");
    assert_eq!(r.alice.members(&r.group).unwrap().len(), 2);
    assert!(r.bob.request_to_join(&revoked.link, "Bob").is_err());

    // expiry: nothing is admitted after the invitation's lifetime, whatever the relay says
    let short =
        r.alice.create_invite(&r.group, InvitePolicy { lifetime_ms: 2 * 3_600_000, max_uses: 3, mode: JoinMode::Approval }).unwrap();
    r.bob.request_to_join(&short.link, "Bob").unwrap();
    let waiting = r.alice.poll_join_requests().unwrap();
    assert_eq!(waiting.len(), 1);
    r.wa.clock.0.advance(3 * 3600);
    r.wb.clock.0.advance(3 * 3600);
    let err = r.alice.resolve_join_request(&waiting[0].request_id, true).unwrap_err();
    assert!(matches!(err, SecurityError::Denied(_)), "{err:?}");
    assert_eq!(r.alice.members(&r.group).unwrap().len(), 2);
}

#[test]
fn only_an_owner_or_admin_can_create_an_invitation_or_decide_a_request() {
    let mut r = rig();
    let err = r.dave.create_invite(&r.group, policy(1, JoinMode::Approval)).unwrap_err();
    assert!(matches!(err, SecurityError::Denied(_)), "{err:?}");
    // a one-to-one conversation has no invitation links
    let dave = r.dave.public_identity().unwrap();
    let dm = r.alice.start_dm(&dave.account_id).unwrap();
    assert!(r.alice.create_invite(&dm, policy(1, JoinMode::Approval)).is_err());
    // automatic admission is capped
    assert!(r.alice.create_invite(&r.group, InvitePolicy { lifetime_ms: DAY_MS, max_uses: 11, mode: JoinMode::Auto }).is_err());
    assert!(r.alice.create_invite(&r.group, InvitePolicy { lifetime_ms: DAY_MS + 1, max_uses: 1, mode: JoinMode::Auto }).is_err());
}

#[test]
fn automatic_admission_admits_within_its_caps_and_only_the_first_requester_for_a_single_use() {
    let mut r = rig();
    let created = r.alice.create_invite(&r.group, policy(1, JoinMode::Auto)).unwrap();
    r.erin.request_to_join(&created.link, "Erin").unwrap();
    assert!(r.alice.poll_join_requests().unwrap().is_empty(), "admitted at once: nothing is left waiting for a person");
    assert_eq!(r.alice.members(&r.group).unwrap().len(), 3);
    assert!(r.bob.request_to_join(&created.link, "Bob").is_err(), "the single use is gone");
}

#[test]
fn an_account_that_is_already_a_member_cannot_be_admitted_again() {
    let mut r = rig();
    let created = r.alice.create_invite(&r.group, policy(2, JoinMode::Approval)).unwrap();
    r.dave.transport.reach(BASE_B, r.wb.app.clone(), r.wb.rt.clone());
    r.dave.set_own_relay(RelayDescriptor::new(BASE_A, None).unwrap()).unwrap();
    r.dave.request_to_join(&created.link, "Dave").unwrap();
    let pending = r.alice.poll_join_requests().unwrap();
    assert_eq!(pending.len(), 1);
    let err = r.alice.resolve_join_request(&pending[0].request_id, true).unwrap_err();
    assert!(matches!(err, SecurityError::Denied(_)), "{err:?}");
    assert_eq!(r.alice.members(&r.group).unwrap().len(), 2);
}

// ------------------------------------------------------------------------------------------------------------------ hostile requests

/// Seals `envelope` as a join request for `link` (what a malicious client or relay that holds the link could do) and posts it to the relay.
fn inject(world: &World, link: &str, envelope: serde_json::Value) -> u16 {
    let parsed = InviteLink::parse(link).unwrap();
    let keys = InviteSecret::from_bytes(*parsed.secret()).keys();
    let sealed = keys.seal_request(&serde_json::to_vec(&envelope).unwrap()).unwrap();
    let body = serde_json::to_vec(&cipher_wire::invite::InviteSubmitRequest { id: Id16(*keys.id()), body: sealed }).unwrap();
    world.raw("POST", "/v1/invites/request", None, body).0
}

fn request_body(link: &str, card: &str, nonce: [u8; 16], ts: u64) -> String {
    let id = Id16(*InviteSecret::from_bytes(*InviteLink::parse(link).unwrap().secret()).keys().id());
    serde_json::to_string(&serde_json::json!({"v":1,"id":id.to_hex(),"nonce":b64::encode(&nonce),"ts":ts,"name":"Mallory","card":card}))
        .unwrap()
}

#[test]
fn a_link_holder_cannot_get_somebody_elses_account_added_with_their_public_card() {
    let mut r = rig();
    let created = r.alice.create_invite(&r.group, policy(2, JoinMode::Approval)).unwrap();
    // Mallory holds the link and Erin's public contact card, but not Erin's identity key.
    let erin_card = r.erin.create_contact_card(7).unwrap();
    let ts = r.wa.clock.0.unix_secs() * 1000;
    let rbody = request_body(&created.link, &erin_card, [9u8; 16], ts);
    let mallory = SigningKey::from_bytes(&[5u8; 32]);
    let mut signed = b"cipher-join-v1\0".to_vec();
    signed.extend_from_slice(rbody.as_bytes());
    let sig = mallory.sign(&signed);
    assert_eq!(inject(&r.wa, &created.link, serde_json::json!({"r": rbody, "s": b64::encode(&sig.to_bytes())})), 200);
    assert!(r.alice.poll_join_requests().unwrap().is_empty(), "the card's owner did not sign this request");
    assert_eq!(r.alice.members(&r.group).unwrap().len(), 2);
    // the slot went back: a real request still fits
    r.bob.request_to_join(&created.link, "Bob").unwrap();
    assert_eq!(r.alice.poll_join_requests().unwrap().len(), 1);
}

#[test]
fn a_request_sealed_under_a_different_link_is_dropped() {
    let mut r = rig();
    let created = r.alice.create_invite(&r.group, policy(1, JoinMode::Approval)).unwrap();
    // A relay (or anybody) that knows the identifier but not the secret cannot produce a request that opens.
    let id = Id16(*InviteSecret::from_bytes(*InviteLink::parse(&created.link).unwrap().secret()).keys().id());
    let other = InviteSecret::generate().unwrap().keys();
    let sealed = other.seal_request(b"{\"r\":\"x\",\"s\":\"y\"}").unwrap();
    let body = serde_json::to_vec(&cipher_wire::invite::InviteSubmitRequest { id, body: sealed }).unwrap();
    assert_eq!(r.wa.raw("POST", "/v1/invites/request", None, body).0, 200, "the relay cannot tell");
    assert!(r.alice.poll_join_requests().unwrap().is_empty());
    r.erin.request_to_join(&created.link, "Erin").unwrap();
    assert_eq!(r.alice.poll_join_requests().unwrap().len(), 1, "the dropped request returned its slot");
}

#[test]
fn replaying_a_captured_request_does_not_admit_twice_or_take_a_second_place() {
    let mut r = rig();
    let created = r.alice.create_invite(&r.group, policy(3, JoinMode::Approval)).unwrap();
    r.erin.request_to_join(&created.link, "Erin").unwrap();
    // a hostile relay replays the exact sealed request it stored
    let sealed = {
        let cap = r.wa.captured.lock().unwrap();
        let submit = cap.iter().rev().find(|c| c.path == "/v1/invites/request").unwrap();
        submit.request_body.clone()
    };
    assert_eq!(r.wa.raw("POST", "/v1/invites/request", None, sealed.clone()).0, 200);
    assert_eq!(r.wa.raw("POST", "/v1/invites/request", None, sealed).0, 200);
    let pending = r.alice.poll_join_requests().unwrap();
    assert_eq!(pending.len(), 1, "the replays carry the same nonce and account: refused");
    r.alice.resolve_join_request(&pending[0].request_id, true).unwrap();
    assert_eq!(r.alice.members(&r.group).unwrap().len(), 3);
    assert_eq!(r.alice.list_invites(&r.group).unwrap()[0].admitted, 1);
}

#[test]
fn the_link_text_is_never_stored_on_either_device_and_the_relay_never_logs_it() {
    let mut r = rig();
    let created = r.alice.create_invite(&r.group, policy(1, JoinMode::Approval)).unwrap();
    r.erin.request_to_join(&created.link, "Erin").unwrap();
    let parsed = InviteLink::parse(&created.link).unwrap();
    let secret_b64 = b64::encode(parsed.secret());
    // Neither the issuer's nor the joiner's vault holds the link text or its base64 secret (the issuer keeps the secret only as a vault record).
    for needle in [created.link.as_bytes(), secret_b64.as_bytes()] {
        assert_eq!(r.alice.vault_plaintext_hits_for_tests(needle).unwrap(), 0, "issuer vault");
        assert_eq!(r.erin.vault_plaintext_hits_for_tests(needle).unwrap(), 0, "joiner vault");
    }
    // The relay's logs hold neither the link nor its secret.
    let logs = r.wa.logs.0.lock().unwrap().clone();
    for (what, needle) in [("link", created.link.clone().into_bytes()), ("secret", secret_b64.into_bytes())] {
        assert!(!contains(&logs, &needle), "the {what} must not be in the relay's logs");
    }
    // The identifier the relay was asked for is not the secret.
    let id = Id16(*InviteSecret::from_bytes(*parsed.secret()).keys().id());
    assert_ne!(id.0, *parsed.secret());
}

#[test]
fn the_app_polls_only_while_there_is_something_to_poll_for() {
    let mut r = rig();
    assert!(!r.alice.has_live_invites().unwrap(), "someone who never invited anyone never polls");
    let created = r.alice.create_invite(&r.group, policy(1, JoinMode::Approval)).unwrap();
    assert!(r.alice.has_live_invites().unwrap());
    r.alice.revoke_invite(&created.id).unwrap();
    assert!(!r.alice.has_live_invites().unwrap(), "a revoked invitation needs no more polling");
    let short =
        r.alice.create_invite(&r.group, InvitePolicy { lifetime_ms: 2 * 3_600_000, max_uses: 1, mode: JoinMode::Approval }).unwrap();
    assert!(r.alice.has_live_invites().unwrap());
    r.wa.clock.0.advance(3 * 3600);
    assert!(!r.alice.has_live_invites().unwrap(), "nor does an expired one ({:?})", short.id);
}
