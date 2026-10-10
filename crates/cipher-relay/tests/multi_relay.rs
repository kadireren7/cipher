#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Phase 3 exit gate: Alice on relay A and Bob on relay B — two independent relay instances with SEPARATE PostgreSQL databases, no server-to-server
//! contact — exchange messages, including while one of them is offline. docs/MULTI_RELAY_PROTOCOL.md.
mod harness;
use cipher_core::app::model::*;
use cipher_core::error::SecurityError;
use cipher_wire::{Id16, RelayDescriptor};
use harness::engine::*;
use harness::*;

const BASE_A: &str = "https://relay-a.test";
const BASE_B: &str = "https://relay-b.test";

struct Rig {
    wa: World,
    wb: World,
    alice: TestEngine,
    bob: TestEngine,
    bob_id: Id16,
}

fn rig() -> Rig {
    let (wa, wb) = (World::new(), World::new());
    let (mut alice, mut bob) = (wa.engine(), wb.engine());
    alice.set_own_relay(RelayDescriptor::new(BASE_A, None).unwrap()).unwrap();
    bob.set_own_relay(RelayDescriptor::new(BASE_B, None).unwrap()).unwrap();
    // Each device reaches ITS OWN relay as before, and may reach the other relay directly (client-mediated). The relays never talk to each other.
    alice.transport.reach(BASE_B, wb.app.clone(), wb.rt.clone());
    bob.transport.reach(BASE_A, wa.app.clone(), wa.rt.clone());
    let bob_id = bob.public_identity().unwrap().account_id;
    Rig { wa, wb, alice, bob, bob_id }
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

/// Alice scans Bob's card, starts a DM and sends the first message; Bob syncs, accepts. Returns (alice conv, bob conv).
fn connect(r: &mut Rig) -> (Id16, Id16) {
    let card = r.bob.create_contact_card(7).unwrap();
    let c = r.alice.add_contact_by_card(&card, "Bob", true).unwrap();
    assert_eq!(c.trust, TrustState::Verified);
    assert_eq!(c.home.as_ref().unwrap().relay.url(), BASE_B);
    let conv_a = r.alice.start_dm(&r.bob_id).unwrap();
    r.alice.send_text(&conv_a, "hello bob, from relay A", None).unwrap();
    r.alice.sync().unwrap();
    r.bob.sync().unwrap();
    let convs = r.bob.list_conversations().unwrap();
    assert_eq!(convs.len(), 1);
    assert_eq!(convs[0].state, ConvState::Requested, "an unknown inviter is a message request, exactly as on one relay");
    assert!(convs[0].remote);
    r.bob.accept_conversation(&convs[0].id).unwrap();
    (conv_a, convs[0].id)
}

#[test]
fn alice_on_relay_a_and_bob_on_relay_b_exchange_messages_both_ways_with_end_to_end_receipts() {
    let mut r = rig();
    let (conv_a, conv_b) = connect(&mut r);
    assert_eq!(texts(&mut r.bob, &conv_b), vec!["hello bob, from relay A".to_owned()]);

    // Bob's capability for Alice only exists once Alice's DeliveryCap (which names relay A) arrived; sync until both directions are wired.
    for _ in 0..3 {
        r.bob.sync().unwrap();
        r.alice.sync().unwrap();
    }
    let alice_dev = r.alice.public_identity().unwrap().device_id;
    assert_eq!(
        r.bob.peer_relay_for_tests(&conv_b, &alice_dev).as_deref(),
        Some(BASE_A),
        "Bob learned Alice's relay from an MLS-authenticated frame"
    );
    let bob_dev = r.bob.public_identity().unwrap().device_id;
    assert_eq!(r.alice.peer_relay_for_tests(&conv_a, &bob_dev).as_deref(), Some(BASE_B));

    let reply = r.bob.send_text(&conv_b, "hi alice, from relay B", None).unwrap();
    r.bob.sync().unwrap();
    r.alice.sync().unwrap();
    assert!(texts(&mut r.alice, &conv_a).contains(&"hi alice, from relay B".to_owned()));
    // Alice's first message is Delivered only because Bob's device sent an end-to-end receipt (not because a relay said "queued").
    r.bob.sync().unwrap();
    r.alice.sync().unwrap();
    let first = r.alice.history(&conv_a, None, 10).unwrap().items.into_iter().find(|m| m.outgoing).unwrap();
    assert_eq!(first.state, DeliveryState::Delivered);
    r.bob.sync().unwrap();
    r.alice.sync().unwrap();
    assert_eq!(r.bob.message(&conv_b, &reply.id).unwrap().unwrap().state, DeliveryState::Delivered);
}

#[test]
fn a_participant_who_is_offline_receives_everything_in_order_when_back() {
    let mut r = rig();
    let (conv_a, conv_b) = connect(&mut r);
    for _ in 0..3 {
        r.bob.sync().unwrap();
        r.alice.sync().unwrap();
    }
    // Bob goes offline (stops syncing); Alice keeps writing.
    for i in 1..=5 {
        r.alice.send_text(&conv_a, &format!("while-bob-offline-{i}"), None).unwrap();
    }
    r.alice.sync().unwrap();
    // Alice goes offline; Bob (back) reads and answers three times.
    r.bob.sync().unwrap();
    let got: Vec<String> = texts(&mut r.bob, &conv_b).into_iter().filter(|t| t.starts_with("while-bob-offline")).collect();
    let expected: Vec<String> = (1..=5).map(|i| format!("while-bob-offline-{i}")).collect();
    assert_eq!(got, expected, "all five, in order");
    for i in 1..=3 {
        r.bob.send_text(&conv_b, &format!("while-alice-offline-{i}"), None).unwrap();
    }
    r.bob.sync().unwrap();
    r.alice.sync().unwrap();
    // Order is per sender (each device stamps strictly increasing timestamps; the two relays have independent clocks here).
    let got: Vec<String> = texts(&mut r.alice, &conv_a).into_iter().filter(|t| t.starts_with("while-alice-offline")).collect();
    assert_eq!(got, ["while-alice-offline-1", "while-alice-offline-2", "while-alice-offline-3"]);
}

#[test]
fn when_the_peers_relay_is_down_messages_stay_pending_and_are_delivered_after_it_returns() {
    let mut r = rig();
    let (conv_a, conv_b) = connect(&mut r);
    for _ in 0..3 {
        r.bob.sync().unwrap();
        r.alice.sync().unwrap();
    }
    r.alice.transport.down.lock().unwrap().push(BASE_B.to_owned());
    let m = r.alice.send_text(&conv_a, "relay-b-is-down", None).unwrap();
    assert_eq!(m.state, DeliveryState::Pending, "never reported as sent while nothing left the device");
    for _ in 0..3 {
        r.alice.sync().unwrap();
    }
    assert_eq!(r.alice.message(&conv_a, &m.id).unwrap().unwrap().state, DeliveryState::Pending);
    r.alice.transport.down.lock().unwrap().clear();
    r.wa.clock.0.advance(3600); // past the retry back-off
    r.wb.clock.0.advance(3600);
    r.alice.sync().unwrap();
    r.bob.sync().unwrap();
    assert!(texts(&mut r.bob, &conv_b).contains(&"relay-b-is-down".to_owned()));
}

#[test]
fn a_peer_on_another_relay_is_never_reached_through_the_authenticated_path() {
    let mut r = rig();
    let (conv_a, conv_b) = connect(&mut r);
    for _ in 0..3 {
        r.alice.sync().unwrap();
        r.bob.sync().unwrap();
    }
    r.alice.send_text(&conv_a, "x", None).unwrap();
    r.bob.send_text(&conv_b, "y", None).unwrap();
    r.alice.sync().unwrap();
    r.bob.sync().unwrap();
    // On the wire: everything Alice ever sent to relay B was unauthenticated and one of exactly three endpoints.
    let unauth_b: Vec<String> =
        r.alice.transport.requests_by_base.lock().unwrap().iter().filter(|(b, _)| b == BASE_B).map(|(_, p)| p.clone()).collect();
    assert!(!unauth_b.is_empty());
    for p in &unauth_b {
        assert!(
            ["/v1/intro/directory", "/v1/intro/key-package", "/v1/deliver"].contains(&p.as_str()),
            "unexpected request to the peer's relay: {p}"
        );
    }
    // In the databases: neither relay has any record of the other relay's user.
    let devices_a: i64 =
        r.wa.rt.block_on(async { r.wa.pool.get().await.unwrap().query_one("SELECT count(*) FROM devices", &[]).await.unwrap().get(0) });
    let devices_b: i64 =
        r.wb.rt.block_on(async { r.wb.pool.get().await.unwrap().query_one("SELECT count(*) FROM devices", &[]).await.unwrap().get(0) });
    assert_eq!((devices_a, devices_b), (1, 1), "each relay knows only its own user");
    let alice_dev = r.alice.public_identity().unwrap().device_id;
    let hits: i64 = r.wb.rt.block_on(async {
        r.wb.pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT count(*) FROM devices WHERE device_id=$1", &[&alice_dev.0.as_slice()])
            .await
            .unwrap()
            .get(0)
    });
    assert_eq!(hits, 0);
    // No sender is stored with anything queued at relay B.
    let senders: i64 = r.wb.rt.block_on(async {
        r.wb.pool.get().await.unwrap().query_one("SELECT count(*) FROM queue WHERE sender_h IS NOT NULL", &[]).await.unwrap().get(0)
    });
    assert_eq!(senders, 0);
}

#[test]
fn a_hostile_relay_cannot_substitute_the_contacts_keys_in_the_directory_answer() {
    let mut r = rig();
    let card = r.bob.create_contact_card(7).unwrap();
    // Relay B (or anyone on the path) alters the identity key in the device record it returns.
    *r.alice.transport.rewrite.lock().unwrap() = Some(Box::new(|_m, path, body| {
        if path == "/v1/intro/directory" {
            let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let k = v["devices"][0]["identity_key"].as_str().unwrap().to_owned();
            let mut forged = k.into_bytes();
            forged[0] = if forged[0] == b'A' { b'B' } else { b'A' };
            v["devices"][0]["identity_key"] = serde_json::Value::String(String::from_utf8(forged).unwrap());
            serde_json::to_vec(&v).unwrap()
        } else {
            body
        }
    }));
    let err = r.alice.add_contact_by_card(&card, "Bob", true).unwrap_err();
    assert!(matches!(err, SecurityError::IdentityUntrusted(_)), "{err:?}");
    assert!(r.alice.contact(&r.bob_id).unwrap().is_none(), "nothing was pinned or stored");
}

#[test]
fn a_card_that_changes_hands_with_a_different_identity_is_never_merged_into_an_existing_contact() {
    let mut r = rig();
    let card = r.bob.create_contact_card(7).unwrap();
    r.alice.add_contact_by_card(&card, "Bob", false).unwrap();
    // Mallory (also on relay B) issues her own, valid card — she cannot make it name Bob's account with a different key.
    let mut mallory = r.wb.engine();
    mallory.set_own_relay(RelayDescriptor::new(BASE_B, None).unwrap()).unwrap();
    let mcard = mallory.create_contact_card(7).unwrap();
    let c = r.alice.add_contact_by_card(&mcard, "Mallory", false).unwrap();
    assert_ne!(c.account_id, r.bob_id, "a different account is a different contact");
    let bobs = r.alice.contact(&r.bob_id).unwrap().unwrap();
    assert_eq!(bobs.home.unwrap().relay.url(), BASE_B, "Bob's contact is untouched by Mallory's card");
}

#[test]
fn groups_and_commits_with_a_peer_on_another_relay_are_refused_not_improvised() {
    let mut r = rig();
    let (conv_a, _) = connect(&mut r);
    assert!(matches!(r.alice.create_group("g", &[r.bob_id]), Err(SecurityError::Denied(_))));
    assert!(matches!(r.alice.refresh_keys(&conv_a), Err(SecurityError::Denied(_))), "no sequencer, so no commits");
}

#[test]
fn an_expired_card_cannot_start_a_conversation() {
    let mut r = rig();
    let card = r.bob.create_contact_card(1).unwrap();
    r.wa.clock.0.advance(2 * 24 * 3600);
    r.wb.clock.0.advance(2 * 24 * 3600);
    assert!(r.alice.add_contact_by_card(&card, "Bob", false).is_err(), "expired");
}

// ------------------------------------------------------------------------------------------------ Phase 4: attachments across relays

const NAME: &str = "SECRET-FIXTURE-quarterly-report.pdf";
const BODY: &[u8] = b"PLAINTEXT-FIXTURE-attachment-contents-9917";

fn pdf(n: usize) -> Vec<u8> {
    let mut v = b"%PDF-1.7\n".to_vec();
    v.extend_from_slice(BODY);
    v.extend((0..n).map(|i| (i % 253) as u8));
    v
}
fn mp4(n: usize) -> Vec<u8> {
    let mut v = vec![0, 0, 0, 0x18];
    v.extend_from_slice(b"ftypmp42");
    v.extend((0..n).map(|i| (i % 249) as u8));
    v
}
fn aac(n: usize) -> Vec<u8> {
    let mut v = vec![0xFF, 0xF1, 0x50, 0x80];
    v.extend((0..n).map(|i| (i % 241) as u8));
    v
}

fn wired(r: &mut Rig) -> (Id16, Id16) {
    let (a, b) = connect(r);
    for _ in 0..3 {
        r.bob.sync().unwrap();
        r.alice.sync().unwrap();
    }
    (a, b)
}

fn send(
    e: &mut TestEngine,
    conv: &Id16,
    kind: AttachmentKind,
    mime: &str,
    name: &str,
    data: &[u8],
    thumb: Option<&[u8]>,
) -> Result<StoredMessage, SecurityError> {
    let path = write_tmp(e.dir.path(), "src.bin", data);
    let r = e.send_attachment(
        conv,
        &path,
        mime,
        name,
        kind,
        "cap",
        thumb,
        if kind == AttachmentKind::Voice { Some(1500) } else { None },
        None,
        &mut |_, _| true,
    );
    std::fs::remove_file(&path).unwrap();
    r
}

fn blobs(w: &World) -> Vec<Vec<u8>> {
    w.query_bytes("SELECT data FROM blobs")
}

#[test]
fn text_image_pdf_video_voice_and_arbitrary_files_cross_relays_and_each_relay_stores_only_ciphertext() {
    let mut r = rig();
    let (conv_a, _conv_b) = wired(&mut r);
    let cases: Vec<(AttachmentKind, &str, &str, Vec<u8>)> = vec![
        (AttachmentKind::Image, "image/png", "photo.png", png(300_000)),
        (AttachmentKind::Pdf, "application/pdf", NAME, pdf(150_000)),
        (AttachmentKind::Video, "video/mp4", "clip.mp4", mp4(900_000)),
        (AttachmentKind::Voice, "audio/aac", "voice.aac", aac(40_000)),
        (AttachmentKind::File, "application/octet-stream", "data.bin", (0..70_000u32).map(|i| (i % 255) as u8).collect()),
    ];
    let thumb = vec![0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3, 4];
    let mut sent = Vec::new();
    for (kind, mime, name, data) in &cases {
        let t = (*kind == AttachmentKind::Image).then_some(thumb.as_slice());
        let m = send(&mut r.alice, &conv_a, *kind, mime, name, data, t).unwrap();
        sent.push((m.id, data.clone(), *kind));
    }
    r.alice.sync().unwrap();
    r.bob.sync().unwrap();
    let conv_b = r.bob.list_conversations().unwrap()[0].id;
    for (id, data, kind) in &sent {
        // The recipient downloads from the relay he already uses (relay B), never from relay A.
        assert_eq!(r.bob.open_attachment(&conv_b, id, false, &mut |_, _| true).unwrap().as_slice(), data.as_slice(), "bob {kind:?}");
        // The sender can still open what she sent: her copy lives on HER relay.
        assert_eq!(r.alice.open_attachment(&conv_a, id, false, &mut |_, _| true).unwrap().as_slice(), data.as_slice(), "alice {kind:?}");
    }
    assert_eq!(r.bob.open_attachment(&conv_b, &sent[0].0, true, &mut |_, _| true).unwrap().as_slice(), thumb.as_slice());
    let requests = r.bob.transport.requests_by_base.lock().unwrap().clone();
    assert!(requests.iter().all(|(b, p)| !p.starts_with("/v1/blobs") || !b.contains("relay-a")), "Bob never touched relay A for a blob");

    for (label, w) in [("relay A", &r.wa), ("relay B", &r.wb)] {
        let bl = blobs(w);
        assert_eq!(bl.len(), 6, "{label}: 5 files + 1 thumbnail");
        for b in &bl {
            assert!(
                !contains(b, b"PLAINTEXT-FIXTURE")
                    && !contains(b, b"SECRET-FIXTURE")
                    && !contains(b, b"application/pdf")
                    && !contains(b, b"%PDF"),
                "{label}"
            );
            assert_eq!(&b[..4], b"CATT", "{label}");
        }
        let (text, raw) = w.db_dump();
        assert!(!text.contains("quarterly") && !contains(&raw, b"quarterly") && !contains(&raw, b"PLAINTEXT-FIXTURE"), "{label}");
        assert!(!contains(&w.all_wire_bytes(), b"PLAINTEXT-FIXTURE") && !contains(&w.all_wire_bytes(), b"quarterly"), "{label}");
        assert!(!contains(&w.log_text(), b"quarterly"), "{label}");
    }
}

#[test]
fn tampered_truncated_swapped_and_missing_blobs_at_the_recipients_relay_fail_closed() {
    let mut r = rig();
    let (conv_a, _) = wired(&mut r);
    let data = pdf(120_000);
    let m = send(&mut r.alice, &conv_a, AttachmentKind::Pdf, "application/pdf", "a.pdf", &data, None).unwrap();
    let m2 = send(&mut r.alice, &conv_a, AttachmentKind::File, "application/octet-stream", "b.bin", &[7u8; 5000], None).unwrap();
    r.alice.sync().unwrap();
    r.bob.sync().unwrap();
    let conv_b = r.bob.list_conversations().unwrap()[0].id;
    assert!(r.bob.open_attachment(&conv_b, &m.id, false, &mut |_, _| true).is_ok());
    // flip one byte in the middle, in place
    r.wb.exec("UPDATE blobs SET data = set_byte(data, 5000, get_byte(data, 5000) # 1) WHERE size_bytes > 100000", &[]);
    assert!(r.bob.open_attachment(&conv_b, &m.id, false, &mut |_, _| true).is_err(), "tampered chunk");
    // truncate
    r.wb.exec("UPDATE blobs SET data = substring(data from 1 for 60000), size_bytes = 60000 WHERE size_bytes > 100000", &[]);
    assert!(r.bob.open_attachment(&conv_b, &m.id, false, &mut |_, _| true).is_err(), "truncated");
    // swap two blobs' contents
    r.wb.exec(
        "UPDATE blobs b SET data = o.data FROM (SELECT blob_id, data FROM blobs) o WHERE b.blob_id <> o.blob_id AND b.size_bytes < 10000",
        &[],
    );
    assert!(r.bob.open_attachment(&conv_b, &m2.id, false, &mut |_, _| true).is_err(), "swapped contents");
    // gone
    r.wb.exec("DELETE FROM blobs", &[]);
    assert!(r.bob.open_attachment(&conv_b, &m.id, false, &mut |_, _| true).is_err(), "missing");
    // and the sender's own copy on relay A is unaffected by anything done to relay B
    assert_eq!(r.alice.open_attachment(&conv_a, &m.id, false, &mut |_, _| true).unwrap().as_slice(), data.as_slice());
    // no temp file is left behind on either device
    for e in [&r.alice, &r.bob] {
        let leftovers = std::fs::read_dir(e.dir.path().join("tmp")).map(|d| d.flatten().count()).unwrap_or(0);
        assert!(leftovers <= 2, "temp dirs only, no files: {leftovers}");
    }
}

#[test]
fn uploads_to_a_foreign_relay_need_a_live_capability_and_respect_quota() {
    let (wa, wb) = (World::new(), World::with_blob_limits(300_000, 10 * 1024 * 1024));
    let (mut alice, mut bob) = (wa.engine(), wb.engine());
    alice.set_own_relay(RelayDescriptor::new(BASE_A, None).unwrap()).unwrap();
    bob.set_own_relay(RelayDescriptor::new(BASE_B, None).unwrap()).unwrap();
    alice.transport.reach(BASE_B, wb.app.clone(), wb.rt.clone());
    bob.transport.reach(BASE_A, wa.app.clone(), wa.rt.clone());
    let bob_id = bob.public_identity().unwrap().account_id;
    let card = bob.create_contact_card(7).unwrap();
    alice.add_contact_by_card(&card, "Bob", true).unwrap();
    let conv_a = alice.start_dm(&bob_id).unwrap();
    for _ in 0..3 {
        alice.sync().unwrap();
        bob.sync().unwrap();
        if let Some(c) = bob.list_conversations().unwrap().first() {
            bob.accept_conversation(&c.id).unwrap();
        }
    }
    // per-capability quota (300 kB on this relay): the third ~120 kB padded blob does not fit
    let mut ok = 0;
    let mut last_err = None;
    for i in 0..4 {
        match send(&mut alice, &conv_a, AttachmentKind::File, "application/octet-stream", "f.bin", &vec![i as u8; 100_000], None) {
            Ok(_) => ok += 1,
            Err(e) => last_err = Some(e),
        }
    }
    assert!((1..4).contains(&ok), "quota must stop the uploads, {ok} accepted");
    assert!(matches!(last_err, Some(SecurityError::Transport(_))), "{last_err:?}");

    // raw requests: nothing without a live capability, nothing with a revoked one, nothing without a declared length
    let body = {
        let mut b = b"CATT".to_vec();
        b.extend(vec![0u8; 60]);
        b
    };
    let up = |auth: Option<&str>| wb.raw_with_len("POST", "/v1/blobs/by-cap", auth.map(str::to_owned), body.clone()).0;
    assert_eq!(up(None), 400);
    assert_eq!(up(Some("Bearer x")), 400);
    assert_eq!(up(Some(&format!("Cap {}", rid()))), 404, "a guessed capability");
    assert_eq!(up(Some("Cap zz")), 400);
    let cap = rid();
    assert_eq!(wb.raw_with_len("POST", "/v1/blobs/by-cap", Some(format!("Cap {cap}")), b"NOPE".repeat(20)).0, 404);
}

#[test]
fn a_transfer_interrupted_by_the_network_creates_no_message_leaves_no_files_and_can_be_retried() {
    let mut r = rig();
    let (conv_a, _) = wired(&mut r);
    let data = pdf(200_000);
    // the recipient's relay accepts the upload but the response is lost
    *r.alice.transport.lose_response_on.lock().unwrap() = Some("/v1/blobs/by-cap".to_owned());
    assert!(send(&mut r.alice, &conv_a, AttachmentKind::Pdf, "application/pdf", "a.pdf", &data, None).is_err());
    // the recipient's relay is unreachable
    r.alice.transport.down.lock().unwrap().push(BASE_B.to_owned());
    assert!(send(&mut r.alice, &conv_a, AttachmentKind::Pdf, "application/pdf", "a.pdf", &data, None).is_err());
    r.alice.transport.down.lock().unwrap().clear();
    let before =
        r.alice.history(&conv_a, None, 50).unwrap().items.iter().filter(|m| matches!(m.content, Content::Attachment { .. })).count();
    assert_eq!(before, 0, "a failed transfer never produces a message");
    let leftovers = std::fs::read_dir(r.alice.dir.path().join("tmp").join("up")).map(|d| d.flatten().count()).unwrap_or(0);
    assert_eq!(leftovers, 0, "ciphertext temp files are removed even when the transfer fails");
    // retry works and Bob gets exactly one file
    let m = send(&mut r.alice, &conv_a, AttachmentKind::Pdf, "application/pdf", "a.pdf", &data, None).unwrap();
    r.alice.sync().unwrap();
    r.bob.sync().unwrap();
    let conv_b = r.bob.list_conversations().unwrap()[0].id;
    assert_eq!(r.bob.open_attachment(&conv_b, &m.id, false, &mut |_, _| true).unwrap().as_slice(), data.as_slice());
    let attachments =
        r.bob.history(&conv_b, None, 50).unwrap().items.iter().filter(|m| matches!(m.content, Content::Attachment { .. })).count();
    assert_eq!(attachments, 1);
}
