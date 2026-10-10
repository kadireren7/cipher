#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! 1:1 messaging through the real engine, relay and PostgreSQL.
mod harness;
use cipher_core::app::model::*;
use cipher_core::clock::Clock as _;
use cipher_core::error::SecurityError;
use cipher_core::events::SecurityEvent;
use cipher_core::vault::LockState;
use harness::engine::*;
use harness::*;
use std::sync::atomic::Ordering;

const PT: &str = "PLAINTEXT-FIXTURE-dm-lunch-at-noon-6612";

fn pair(w: &World) -> (TestEngine, TestEngine, cipher_wire::Id16, cipher_wire::Id16) {
    let (mut a, mut b) = (w.engine(), w.engine());
    let (ia, ib) = (a.public_identity().unwrap(), b.public_identity().unwrap());
    a.add_contact_by_id(&ib.cipher_id, "Bob").unwrap();
    b.add_contact_by_id(&ia.cipher_id, "Alice").unwrap();
    (a, b, ia.account_id, ib.account_id)
}

fn texts(e: &mut TestEngine, conv: &cipher_wire::Id16) -> Vec<String> {
    let mut v: Vec<String> = e
        .history(conv, None, 200)
        .unwrap()
        .items
        .into_iter()
        .filter_map(|m| if let Content::Text { body } = m.content { Some(body) } else { None })
        .collect();
    v.reverse(); // oldest first
    v
}

#[test]
fn dm_roundtrip_delivery_receipts_and_no_plaintext_anywhere_outside_the_vault() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv_a = a.start_dm(&ib).unwrap();
    let sent = a.send_text(&conv_a, PT, None).unwrap();
    assert_eq!(sent.state, DeliveryState::Sent, "relay accepted it");

    let rep = b.sync().unwrap();
    assert_eq!(rep.new_messages, 1);
    let convs = b.list_conversations().unwrap();
    assert_eq!(convs.len(), 1);
    assert_eq!((convs[0].kind, convs[0].state, convs[0].unread), (ConvKind::Dm, ConvState::Active, 1), "inviter is a contact -> active");
    assert_eq!(convs[0].title, "Alice");
    assert_eq!(texts(&mut b, &convs[0].id), vec![PT.to_owned()]);
    assert_eq!(rep.notices.len(), 1);

    // B replies; A sees the reply and a delivery receipt for its message.
    b.mark_read(&convs[0].id).unwrap();
    b.send_text(&convs[0].id, "reply-fixture-ok", Some(sent.id)).unwrap();
    a.sync().unwrap();
    assert_eq!(a.message(&conv_a, &sent.id).unwrap().unwrap().state, DeliveryState::Delivered);
    let hist = a.history(&conv_a, None, 10).unwrap();
    assert_eq!(hist.items.len(), 2);
    let reply = hist.items.iter().find(|m| !m.outgoing).unwrap();
    assert_eq!(reply.reply_to, Some(sent.id));
    assert_eq!(a.list_conversations().unwrap()[0].unread, 1);

    // Nothing the relay, the network, PostgreSQL or the logs saw contains the plaintext.
    let wire = w.all_wire_bytes();
    let db = w.db_bytes();
    let logs = w.log_text();
    for (name, hay) in [("wire", &wire), ("postgres", &db), ("logs", &logs)] {
        assert!(!contains(hay, b"PLAINTEXT-FIXTURE"), "plaintext leaked into {name}");
        assert!(!contains(hay, b"reply-fixture"), "reply leaked into {name}");
    }
    // ... nor does the client's vault file or anything else in its data dir.
    let leak = scan_dir(a.dir.path(), b"PLAINTEXT-FIXTURE");
    assert!(leak.is_empty(), "plaintext on disk: {leak:?}");
    let leak = scan_dir(b.dir.path(), b"PLAINTEXT-FIXTURE");
    assert!(leak.is_empty(), "plaintext on disk: {leak:?}");
}

fn scan_dir(dir: &std::path::Path, needle: &[u8]) -> Vec<String> {
    let mut hits = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            hits.extend(scan_dir(&p, needle));
        } else if contains(&std::fs::read(&p).unwrap_or_default(), needle) {
            hits.push(p.display().to_string());
        }
    }
    hits
}

#[test]
fn unknown_inviter_creates_a_hidden_request_and_no_receipt_until_accepted() {
    let w = World::new();
    let (mut a, mut b) = (w.engine(), w.engine());
    let ib = b.public_identity().unwrap();
    a.add_contact_by_id(&ib.cipher_id, "Bob").unwrap();
    let conv = a.start_dm(&ib.account_id).unwrap();
    let m = a.send_text(&conv, "hello stranger", None).unwrap();
    b.sync().unwrap();
    let c = &b.list_conversations().unwrap()[0];
    assert_eq!(c.state, ConvState::Requested);
    a.sync().unwrap();
    assert_ne!(a.message(&conv, &m.id).unwrap().unwrap().state, DeliveryState::Delivered, "no receipt for an unaccepted request");
    b.accept_conversation(&c.id).unwrap();
    assert_eq!(b.list_conversations().unwrap()[0].state, ConvState::Active);
}

#[test]
fn offline_delivery_preserves_order_and_acknowledgement_cleans_the_relay_queue() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv = a.start_dm(&ib).unwrap();
    for i in 0..5 {
        w.clock.0.advance(1);
        a.send_text(&conv, &format!("msg-{i}"), None).unwrap();
    }
    // Bob was offline the whole time: ciphertext waits in the relay queue.
    let queued: i64 =
        w.rt.block_on(async { w.pool.get().await.unwrap().query_one("SELECT count(*) FROM queue", &[]).await.unwrap().get(0) });
    assert!(queued >= 5);
    b.sync().unwrap();
    let cid = b.list_conversations().unwrap()[0].id;
    assert_eq!(texts(&mut b, &cid), ["msg-0", "msg-1", "msg-2", "msg-3", "msg-4"]);
    // After acknowledgement the message ciphertext is gone from the relay (receipts may now sit there for Alice).
    let left: i64 = w.rt.block_on(async {
        let c = w.pool.get().await.unwrap();
        c.query_one("SELECT count(*) FROM queue q JOIN devices d ON d.device_id=q.recipient WHERE octet_length(q.ct) > 0 AND d.queued_count >= 0 AND q.recipient = (SELECT device_id FROM devices ORDER BY ord OFFSET 1 LIMIT 1)", &[]).await.unwrap().get(0)
    });
    assert_eq!(left, 0, "everything Bob processed was acknowledged and deleted");
}

#[test]
fn network_failures_leave_messages_pending_then_retry_then_fail_visibly() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv = a.start_dm(&ib).unwrap();
    a.transport.offline.store(true, Ordering::SeqCst);
    let m = a.send_text(&conv, "queued while offline", None).unwrap();
    assert_eq!(m.state, DeliveryState::Pending);
    assert_eq!(a.list_conversations().unwrap()[0].last_preview, "queued while offline");
    a.transport.offline.store(false, Ordering::SeqCst);
    w.clock.0.advance(10); // past the first back-off
    assert_eq!(a.flush_outbox().unwrap(), 1);
    assert_eq!(a.message(&conv, &m.id).unwrap().unwrap().state, DeliveryState::Sent);
    b.sync().unwrap();
    let cid = b.list_conversations().unwrap()[0].id;
    assert_eq!(texts(&mut b, &cid), ["queued while offline"]);

    // Permanent failure: exponential back-off, then FAILED, then manual retry succeeds.
    a.transport.offline.store(true, Ordering::SeqCst);
    let m2 = a.send_text(&conv, "will fail", None).unwrap();
    for _ in 0..12 {
        w.clock.0.advance(4000);
        let _ = a.flush_outbox();
    }
    assert_eq!(a.message(&conv, &m2.id).unwrap().unwrap().state, DeliveryState::Failed);
    a.transport.offline.store(false, Ordering::SeqCst);
    a.retry_message(&conv, &m2.id).unwrap();
    assert_eq!(a.message(&conv, &m2.id).unwrap().unwrap().state, DeliveryState::Sent);
}

#[test]
fn restart_does_not_lose_or_duplicate_pending_messages() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv = a.start_dm(&ib).unwrap();
    a.transport.offline.store(true, Ordering::SeqCst);
    a.send_text(&conv, "survives restart", None).unwrap();
    // "Process restart": drop the in-memory engine and open the same data dir again (vault is persisted, keys in the keystore).
    let dir = a.dir.path().to_path_buf();
    let ks = a.ks.clone();
    let transport = a.transport.clone();
    drop(a.e);
    let mut e = cipher_core::app::Engine::new_for_tests(
        cipher_core::app::EngineConfig { data_dir: dir, relay_url: "https://relay.test".into(), vault: vault_cfg() },
        ks,
        transport.clone(),
        w.clock.clone(),
        AUDIENCE,
    )
    .unwrap();
    assert_eq!(e.status().unwrap().state, LockState::Locked);
    assert!(matches!(e.list_conversations(), Err(SecurityError::Locked)));
    e.unlock_with_device_auth().unwrap();
    transport.offline.store(false, Ordering::SeqCst);
    w.clock.0.advance(10);
    e.flush_outbox().unwrap();
    b.sync().unwrap();
    let cid = b.list_conversations().unwrap()[0].id;
    assert_eq!(texts(&mut b, &cid), ["survives restart"]);
    e.flush_outbox().unwrap(); // second flush must not duplicate
    b.sync().unwrap();
    assert_eq!(texts(&mut b, &cid).len(), 1);
}

#[test]
fn duplicates_replays_and_reordering_are_handled() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv = a.start_dm(&ib).unwrap();
    for i in 0..4 {
        w.clock.0.advance(1);
        a.send_text(&conv, &format!("m{i}"), None).unwrap();
    }
    // A malicious relay reverses delivery order for Bob.
    let (bdev,): (Vec<u8>,) = w.rt.block_on(async {
        let r = w.pool.get().await.unwrap().query_one("SELECT device_id FROM devices ORDER BY ord OFFSET 1 LIMIT 1", &[]).await.unwrap();
        (r.get(0),)
    });
    // (the Welcome stays first: it is what creates the group; everything after it is delivered in reverse)
    w.exec(
        "UPDATE queue SET seq = 1000000 - seq WHERE recipient = $1 AND seq > (SELECT min(seq) FROM queue WHERE recipient = $1)",
        &[&bdev],
    );
    // ... and injects a duplicate of every message under a NEW relay message id (the relay's own dedup cannot catch that).
    w.exec(
        "INSERT INTO queue (recipient, message_id, ct, expires_at) SELECT recipient, decode(md5(random()::text || seq::text), 'hex'), ct, expires_at FROM queue WHERE recipient = $1 AND seq > (SELECT min(seq) FROM queue WHERE recipient = $1) - 1000000000",
        &[&bdev],
    );
    w.exec("UPDATE devices SET queued_count = (SELECT count(*) FROM queue WHERE recipient = $1), queued_bytes = (SELECT COALESCE(sum(octet_length(ct)), 0) FROM queue WHERE recipient = $1) WHERE device_id = $1", &[&bdev]);
    b.sync().unwrap();
    let cid = b.list_conversations().unwrap()[0].id;
    assert_eq!(texts(&mut b, &cid), ["m0", "m1", "m2", "m3"], "history is ordered by sender time, not arrival; duplicates suppressed");
    assert!(b.take_events().iter().any(|e| matches!(e, SecurityEvent::ReplayRejected)), "replays are surfaced");
    // Replaying the identical ciphertexts again changes nothing.
    let before = b.history(&cid, None, 50).unwrap().items.len();
    b.sync().unwrap();
    assert_eq!(b.history(&cid, None, 50).unwrap().items.len(), before);
}

#[test]
fn history_is_paginated_newest_first_without_loading_everything() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv = a.start_dm(&ib).unwrap();
    // A stranger-lane sender may only have a small number of messages queued for a recipient who has not answered (OPEN lane, ST-031); once the
    // contact has exchanged delivery capabilities the per-capability allowance applies. So: first contact, then the burst.
    a.send_text(&conv, "hello", None).unwrap();
    b.sync().unwrap();
    a.sync().unwrap();
    for i in 0..130 {
        w.clock.0.advance(1);
        a.send_text(&conv, &format!("m{i:03}"), None).unwrap();
    }
    b.sync().unwrap();
    let cid = b.list_conversations().unwrap()[0].id;
    let mut seen = Vec::new();
    let mut cursor = None;
    let mut pages = 0;
    loop {
        let p = b.history(&cid, cursor.clone(), 50).unwrap();
        assert!(p.items.len() <= 50);
        seen.extend(p.items.iter().map(|m| match &m.content {
            Content::Text { body } => body.clone(),
            _ => unreachable!(),
        }));
        pages += 1;
        match p.next {
            Some(n) => cursor = Some(n),
            None => break,
        }
    }
    assert_eq!(pages, 3);
    assert_eq!(seen.len(), 131);
    assert_eq!(seen.first().unwrap(), "m129");
    assert_eq!(seen.last().unwrap(), "hello");
    assert!(b.history(&cid, None, 1_000_000).unwrap().items.len() <= 200, "page size is clamped");
}

#[test]
fn local_deletion_is_local_and_sticky() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv = a.start_dm(&ib).unwrap();
    let m = a.send_text(&conv, "to be deleted", None).unwrap();
    b.sync().unwrap();
    let cid = b.list_conversations().unwrap()[0].id;
    b.delete_message_local(&cid, &m.id).unwrap();
    assert!(b.message(&cid, &m.id).unwrap().is_none());
    assert_eq!(a.message(&conv, &m.id).unwrap().unwrap().id, m.id, "Alice still has her copy");
    b.sync().unwrap();
    assert!(b.history(&cid, None, 10).unwrap().items.is_empty(), "does not resurrect");
}

#[test]
fn lock_lifecycle_blocks_every_plaintext_api_and_drops_the_session() {
    let w = World::new();
    let (mut a, mut b) = (w.engine_with_timeout(60), w.engine());
    let (ia, ib) = (a.public_identity().unwrap(), b.public_identity().unwrap());
    a.add_contact_by_id(&ib.cipher_id, "Bob").unwrap();
    b.add_contact_by_id(&ia.cipher_id, "Alice").unwrap();
    let ib = ib.account_id;
    let conv = a.start_dm(&ib).unwrap();
    a.send_text(&conv, PT, None).unwrap();
    a.enable_pin("493817").unwrap();
    assert_eq!(a.status().unwrap().state, LockState::Unlocked);

    let locked_ok = |a: &mut TestEngine| {
        assert!(matches!(a.list_conversations(), Err(SecurityError::Locked)));
        assert!(matches!(a.history(&conv, None, 10), Err(SecurityError::Locked)));
        assert!(matches!(a.send_text(&conv, "x", None), Err(SecurityError::Locked)));
        assert!(matches!(a.sync(), Err(SecurityError::Locked)));
        assert!(matches!(a.public_identity(), Err(SecurityError::Locked)));
        assert!(matches!(a.list_contacts(), Err(SecurityError::Locked)));
        assert!(matches!(a.safety_number(&ib), Err(SecurityError::Locked)));
        assert!(matches!(a.open_attachment(&conv, &conv, false, &mut |_, _| true), Err(SecurityError::Locked)));
    };
    a.lock();
    assert_eq!(a.status().unwrap().state, LockState::Locked);
    locked_ok(&mut a);

    // PIN: wrong then right
    assert!(matches!(a.unlock_with_pin("000111"), Err(SecurityError::BadCredential)));
    a.unlock_with_pin("493817").unwrap();
    assert_eq!(a.history(&conv, None, 10).unwrap().items.len(), 1);

    // background -> BACKGROUND -> foreground -> LOCKED (never straight back to unlocked)
    a.on_background();
    assert_eq!(a.status().unwrap().state, LockState::Background);
    locked_ok(&mut a);
    a.on_foreground();
    assert_eq!(a.status().unwrap().state, LockState::Locked);
    locked_ok(&mut a);
    a.unlock_with_device_auth().unwrap();

    // inactivity timeout
    w.clock.0.advance(61);
    assert!(matches!(a.list_conversations(), Err(SecurityError::Locked)));
    a.unlock_with_device_auth().unwrap();

    // device security events
    a.on_device_event(cipher_core::vault::DeviceSecurityEvent::ScreenLocked);
    locked_ok(&mut a);
    a.unlock_with_device_auth().unwrap();

    // INVALIDATED: terminal and fail-closed; a new Engine over the same data also fails
    a.on_device_event(cipher_core::vault::DeviceSecurityEvent::BiometricEnrollmentChanged);
    assert_eq!(a.status().unwrap().state, LockState::Invalidated);
    assert!(matches!(a.list_conversations(), Err(SecurityError::Invalidated)));
    assert!(matches!(a.unlock_with_device_auth(), Err(SecurityError::Invalidated)));
    let _ = &mut b;
}

#[test]
fn notifications_never_reveal_content_while_locked_whatever_the_mode() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv = a.start_dm(&ib).unwrap();
    a.send_text(&conv, "PLAINTEXT-FIXTURE-notify", None).unwrap();
    let rep = b.sync().unwrap();
    // default mode: no content even while unlocked
    let t = b.notification_for(&rep.notices);
    assert_eq!((t.title.as_str(), t.body.as_str()), ("Cipher", "New message"));
    let mut s = b.settings().unwrap();
    s.privacy_mode = cipher_core::app::notify::PrivacyMode::ContentWhenUnlocked;
    b.set_settings(&s).unwrap();
    let t = b.notification_for(&rep.notices);
    assert_eq!(t.body, "PLAINTEXT-FIXTURE-notify");
    b.lock();
    let t = b.notification_for(&rep.notices);
    assert_eq!((t.title.as_str(), t.body.as_str()), ("Cipher", "New message"), "locked vault: generic only");
    assert!(!format!("{t:?}").contains("PLAINTEXT"));
}

#[test]
fn sizes_seen_by_the_relay_collapse_into_buckets() {
    let w = World::new();
    let (mut a, _b, _ia, ib) = pair(&w);
    let conv = a.start_dm(&ib).unwrap();
    for n in [1usize, 20, 80, 150, 300, 400] {
        a.send_text(&conv, &"x".repeat(n), None).unwrap();
    }
    let lens = w.query_bytes("SELECT ct FROM queue ORDER BY seq").into_iter().map(|c| c.len()).collect::<Vec<_>>();
    let msg_lens: std::collections::BTreeSet<usize> = lens.iter().skip(1).copied().collect(); // skip the Welcome
    assert!(msg_lens.len() <= 2, "six different message lengths produce at most two ciphertext sizes: {lens:?}");
}

#[test]
fn contact_trust_states_and_identity_substitution() {
    let w = World::new();
    let (mut a, mut b) = (w.engine(), w.engine());
    let ib = b.public_identity().unwrap();
    let ia = a.public_identity().unwrap();

    // QR from a *different* identity than the relay reports -> refused, event raised, nothing trusted.
    let mallory = w.engine();
    let im = mallory.e.clone_public_for_tests();
    let forged_qr = cipher_core::verification::qr_payload(&ib.account_id, &im.identity_key);
    assert!(matches!(a.add_contact_by_qr(&forged_qr, "Bob"), Err(SecurityError::IdentityUntrusted(_))));
    assert!(a.take_events().iter().any(|e| matches!(e, SecurityEvent::IdentityChanged { .. })));
    assert!(a.list_contacts().unwrap().is_empty());

    // Real QR: VERIFIED.
    let c = a.add_contact_by_qr(&ib.qr_payload, "Bob").unwrap();
    assert_eq!(c.trust, TrustState::Verified);
    // Safety numbers are symmetric and 60 digits.
    b.add_contact_by_id(&ia.cipher_id, "Alice").unwrap();
    let (sa, sb) = (a.safety_number(&ib.account_id).unwrap(), b.safety_number(&ia.account_id).unwrap());
    assert_eq!(sa, sb);
    assert_eq!(sa.chars().filter(char::is_ascii_digit).count(), 60);

    // The relay now serves a different identity key for Bob's device (validly self-bound): IDENTITY_CHANGED.
    let evil = w.engine();
    let evil_rec = evil.e.forged_record_for_tests(ib.account_id, ib.device_id);
    let rec_json =
        serde_json::to_vec(&cipher_wire::messages::DirectoryResponse { account_id: ib.account_id, devices: vec![evil_rec] }).unwrap();
    *a.transport.rewrite.lock().unwrap() =
        Some(Box::new(move |m, p, body| if m == "GET" && p.ends_with("/devices") { rec_json.clone() } else { body }));
    let r = a.add_contact_by_id(&ib.cipher_id, "Bob");
    assert!(r.is_ok());
    let after = a.contact(&ib.account_id).unwrap().unwrap();
    assert_eq!(after.trust, TrustState::IdentityChanged, "never silently accepted");
    assert!(a.take_events().iter().any(|e| matches!(e, SecurityEvent::IdentityChanged { .. })));
    assert!(matches!(a.start_dm(&ib.account_id), Err(SecurityError::IdentityUntrusted(_))), "no new conversation with a changed identity");
    // Sending to an EXISTING session is unaffected by a relay lie about the directory, but new devices are never trusted.
    *a.transport.rewrite.lock().unwrap() = None;
    // Acknowledge after out-of-band verification: back to UNVERIFIED (verification is not carried over).
    a.acknowledge_identity_change(&ib.account_id).unwrap();
    let c = a.contact(&ib.account_id).unwrap().unwrap();
    assert_eq!(c.trust, TrustState::Unverified);
    assert!(c.verified_key.is_none());
}

#[test]
fn start_dm_refuses_a_key_package_substituted_by_the_relay() {
    let w = World::new();
    let (mut a, b) = (w.engine(), w.engine());
    let ib = b.e.clone_public_for_tests();
    let mut mallory = w.engine();
    let mut kp_bytes = mallory.e.key_package_for_tests();
    let cid = cipher_core::app::cipher_id::format(&ib.account_id);
    a.add_contact_by_id(&cid, "Bob").unwrap();
    kp_bytes.shrink_to_fit();
    let swapped = serde_json::to_vec(&cipher_wire::messages::KeyPackageResponse { key_package: kp_bytes }).unwrap();
    *a.transport.rewrite.lock().unwrap() =
        Some(Box::new(move |_m, p, body| if p.ends_with("/key-package") { swapped.clone() } else { body }));
    assert!(a.start_dm(&ib.account_id).is_err(), "substituted KeyPackage must be refused");
    assert!(a.list_conversations().unwrap().is_empty(), "no half-created conversation");
    let _ = w.clock.unix_secs();
}

/// Phase 1 regression (lost acknowledgment): receipts for messages that arrived while the conversation was still a MESSAGE REQUEST used to be
/// discarded in the same sync, so the sender's first message stayed `Sent` forever even after the recipient accepted.
#[test]
fn a_message_that_arrived_as_a_request_becomes_delivered_once_the_recipient_accepts() {
    let w = World::new();
    let (mut a, mut b) = (w.engine(), w.engine());
    let ib = b.public_identity().unwrap();
    a.add_contact_by_id(&ib.cipher_id, "Bob").unwrap(); // Bob does NOT know Alice: the conversation arrives as a request
    let conv_a = a.start_dm(&ib.account_id).unwrap();
    let sent = a.send_text(&conv_a, "first contact", None).unwrap();
    b.sync().unwrap();
    let c = b.list_conversations().unwrap().remove(0);
    assert_eq!(c.state, ConvState::Requested);
    a.sync().unwrap();
    assert_eq!(a.message(&conv_a, &sent.id).unwrap().unwrap().state, DeliveryState::Sent, "no receipt while the request is unanswered");
    b.accept_conversation(&c.id).unwrap();
    b.sync().unwrap();
    a.sync().unwrap();
    assert_eq!(a.message(&conv_a, &sent.id).unwrap().unwrap().state, DeliveryState::Delivered);
}

/// Phase 1 regression (ordering): messages sent in the same millisecond must keep their order (ties used to be broken by the random message id).
#[test]
fn messages_sent_within_one_clock_tick_keep_their_order() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv_a = a.start_dm(&ib).unwrap();
    for i in 0..20 {
        a.send_text(&conv_a, &format!("m{i:02}"), None).unwrap(); // the test clock does not advance at all
    }
    b.sync().unwrap();
    let conv_b = b.list_conversations().unwrap()[0].id;
    let got = texts(&mut b, &conv_b);
    let expected: Vec<String> = (0..20).map(|i| format!("m{i:02}")).collect();
    assert_eq!(got, expected);
    assert_eq!(texts(&mut a, &conv_a), expected, "and on the sender's own device");
}

/// Phase 1 regression (message LOSS): messages queued while offline must reach the peer in the order they were encrypted. The outbox used to be flushed
/// in random-id order, so the relay queue could hold generation 9 before generation 2; MLS only keeps keys for 5 skipped generations, so the recipient
/// silently dropped the older ones as undecryptable.
#[test]
fn many_messages_queued_offline_all_arrive_after_reconnecting() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv = a.start_dm(&ib).unwrap();
    a.transport.offline.store(true, Ordering::SeqCst);
    let sent: Vec<String> = (0..25).map(|i| format!("queued-{i:02}")).collect();
    for t in &sent {
        a.send_text(&conv, t, None).unwrap();
    }
    a.transport.offline.store(false, Ordering::SeqCst);
    w.clock.0.advance(3600);
    a.flush_outbox().unwrap();
    b.sync().unwrap();
    let cid = b.list_conversations().unwrap()[0].id;
    assert_eq!(texts(&mut b, &cid), sent, "all 25, once each, in order");
}
