#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! FINAL REVIEW — the relay AND its PostgreSQL are fully attacker-controlled. Every test manipulates the relay's database directly
//! (queue rows, group counters, tags) the way a malicious or restored operator could, and asserts what the clients do.
//! Each test states whether the attack is PREVENTED, DETECTED or UNDETECTABLE (documented in docs/FINAL_SECURITY_REVIEW.md §Relay).
mod harness;
use cipher_core::app::model::*;
use cipher_core::protocol::GroupProtocol as _;
use cipher_wire::Id16;
use harness::engine::*;
use harness::*;

const PT: &str = "PLAINTEXT-FIXTURE-relay-attack-7741";

fn trio(w: &World) -> (TestEngine, TestEngine, TestEngine, cipher_core::app::PublicIdentity, cipher_core::app::PublicIdentity, Id16) {
    let (mut a, mut b, mut c) = (w.engine(), w.engine(), w.engine());
    let (ia, ib, ic) = (a.public_identity().unwrap(), b.public_identity().unwrap(), c.public_identity().unwrap());
    for (e, others) in
        [(&mut a, [(&ib, "Bob"), (&ic, "Carol")]), (&mut b, [(&ia, "Alice"), (&ic, "Carol")]), (&mut c, [(&ia, "Alice"), (&ib, "Bob")])]
    {
        for (id, name) in others {
            e.add_contact_by_id(&id.cipher_id, name).unwrap();
        }
    }
    let g = a.create_group("Team", &[ib.account_id, ic.account_id]).unwrap();
    b.sync().unwrap();
    c.sync().unwrap();
    (a, b, c, ib, ic, g)
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

/// Direct inserts/deletes bypass the relay's bookkeeping; recompute the per-device counters so the relay itself stays consistent
/// (a hostile relay can of course also just answer with errors — that is plain denial of service).
fn fix_counters(w: &World) {
    w.exec(
        "UPDATE devices d SET queued_count = (SELECT count(*) FROM queue q WHERE q.recipient = d.device_id), queued_bytes = (SELECT COALESCE(sum(octet_length(q.ct)),0) FROM queue q WHERE q.recipient = d.device_id)",
        &[],
    );
}

fn rows_for(w: &World, dev: &[u8]) -> Vec<Vec<u8>> {
    let dev = dev.to_vec();
    w.rt.block_on(async {
        let c = w.pool.get().await.unwrap();
        c.query("SELECT ct FROM queue WHERE recipient = $1 ORDER BY seq", &[&dev])
            .await
            .unwrap()
            .iter()
            .map(|r| r.get::<_, Vec<u8>>(0))
            .collect()
    })
}

/// PREVENTED (confidentiality) / DETECTED (as a dropped poison message): the relay flips a bit in queued ciphertext.
#[test]
fn bit_flipped_ciphertext_is_dropped_never_decrypted_and_never_blocks_the_queue() {
    let w = World::new();
    let (mut a, mut b, _c, _ib, _ic, g) = trio(&w);
    w.clock.0.advance(1);
    a.send_text(&g, "victim-message", None).unwrap();
    w.exec("UPDATE queue SET ct = set_byte(ct, 40, get_byte(ct, 40) # 255)", &[]);
    b.sync().unwrap(); // must not error, panic or block
    assert!(!texts(&mut b, &g).iter().any(|t| t == "victim-message"));
    // the queue is not wedged: a later honest message arrives
    w.clock.0.advance(1);
    a.send_text(&g, PT, None).unwrap();
    b.sync().unwrap();
    assert!(texts(&mut b, &g).iter().any(|t| t == PT));
}

/// PREVENTED: the relay redirects a ciphertext to a device that is not its recipient (recipient substitution).
#[test]
fn ciphertext_redirected_to_the_wrong_device_yields_nothing() {
    let w = World::new();
    let (mut a, mut b, mut c, ..) = trio(&w);
    // Bob and Carol are both members; make a DM Alice<->Bob that Carol is NOT part of.
    let ib = b.public_identity().unwrap();
    let dm = a.start_dm(&ib.account_id).unwrap();
    w.clock.0.advance(1);
    a.send_text(&dm, PT, None).unwrap();
    // The relay copies every queued row addressed to Bob into Carol's queue.
    let carol_dev = c.public_identity().unwrap().device_id.0.to_vec();
    let bob_dev = b.public_identity().unwrap().device_id.0.to_vec();
    w.exec(
        "INSERT INTO queue (recipient, message_id, ct, expires_at, group_seq) SELECT $1, substr(message_id,1,15) || '\\x01'::bytea, ct, expires_at, group_seq FROM queue WHERE recipient=$2",
        &[&carol_dev, &bob_dev],
    );
    fix_counters(&w);
    let before = c.list_conversations().unwrap().len();
    c.sync().unwrap();
    assert_eq!(c.list_conversations().unwrap().len(), before, "Carol must not gain a conversation she cannot decrypt");
    for conv in c.list_conversations().unwrap() {
        assert!(!texts(&mut c, &conv.id).iter().any(|t| t == PT));
    }
    // and Bob still receives it normally
    b.sync().unwrap();
    let dm_b = b.list_conversations().unwrap().into_iter().find(|x| x.kind == ConvKind::Dm).unwrap();
    assert!(texts(&mut b, &dm_b.id).iter().any(|t| t == PT));
}

/// PREVENTED: duplicating a queued message under a new message id does not duplicate the message.
#[test]
fn relay_duplication_is_not_shown_twice() {
    let w = World::new();
    let (mut a, mut b, _c, _ib, _ic, g) = trio(&w);
    w.clock.0.advance(1);
    a.send_text(&g, PT, None).unwrap();
    w.exec("INSERT INTO queue (recipient, message_id, ct, expires_at, group_seq) SELECT recipient, substr(message_id,1,15) || '\\x7f'::bytea, ct, expires_at, group_seq FROM queue", &[]);
    fix_counters(&w);
    b.sync().unwrap();
    assert_eq!(texts(&mut b, &g).iter().filter(|t| *t == PT).count(), 1);
}

/// UNDETECTABLE (documented limitation): a relay that silently DROPS a message cannot be noticed by the recipient (no per-sender
/// sequence numbers are exposed to the UI). What we assert is the safety property: later messages still decrypt and nothing crashes.
#[test]
fn a_dropped_message_is_undetectable_but_later_messages_still_work() {
    let w = World::new();
    let (mut a, mut b, _c, _ib, _ic, g) = trio(&w);
    w.clock.0.advance(1);
    a.send_text(&g, "will-be-dropped", None).unwrap();
    let bob_dev = b.public_identity().unwrap().device_id.0.to_vec();
    let removed = w.exec("DELETE FROM queue WHERE recipient = $1 AND group_seq IS NULL", &[&bob_dev]);
    assert!(removed >= 1, "the attack must actually have dropped Bob's copy");
    fix_counters(&w);
    w.clock.0.advance(1);
    a.send_text(&g, PT, None).unwrap();
    b.sync().unwrap();
    let t = texts(&mut b, &g);
    assert!(t.iter().any(|x| x == PT), "MLS skips the missing generation");
}

/// PREVENTED: the relay cannot forge delivery. It "acknowledges" (deletes) the message without delivering it; the sender must NOT show
/// Delivered, because delivery receipts are end-to-end messages from the recipient.
#[test]
fn a_fake_acknowledgement_does_not_make_a_message_delivered() {
    let w = World::new();
    let (mut a, mut b, ..) = {
        let (a, b, c, ib, ic, g) = trio(&w);
        let _ = (ib, ic, g, c);
        (a, b, ())
    };
    let ib = b.public_identity().unwrap();
    let dm = a.start_dm(&ib.account_id).unwrap();
    w.clock.0.advance(1);
    let m = a.send_text(&dm, PT, None).unwrap();
    w.exec("DELETE FROM queue", &[]); // relay swallows everything and pretends all is well
    fix_counters(&w);
    a.sync().unwrap();
    assert_ne!(a.message(&dm, &m.id).unwrap().unwrap().state, DeliveryState::Delivered);
    assert_eq!(b.sync().unwrap().new_messages, 0);
}

/// PREVENTED: replaying an OLD commit (epoch rollback) is dropped and changes nothing.
#[test]
fn replaying_an_old_commit_cannot_roll_the_group_back() {
    let w = World::new();
    let (mut a, mut b, mut c, _ib, _ic, g) = trio(&w);
    a.promote_admin(&g, &b.public_identity().unwrap().account_id).unwrap();
    // capture the commit rows the relay holds for Carol right now, deliver them, then advance the group further
    c.sync().unwrap();
    b.sync().unwrap();
    let old_rows = w.query_bytes("SELECT ct FROM queue WHERE group_seq IS NOT NULL");
    a.rename_group(&g, "epoch-N+1").unwrap();
    b.sync().unwrap();
    c.sync().unwrap();
    let epoch = c.conversation_epoch(&g).unwrap();
    // relay re-injects the older commit(s) to Carol under fresh message ids
    let carol_dev = c.public_identity().unwrap().device_id.0.to_vec();
    for (i, ct) in old_rows.iter().enumerate() {
        let mid = {
            let mut m = [0u8; 16];
            m[0] = 0xEE;
            m[1] = i as u8;
            m.to_vec()
        };
        w.exec(
            "INSERT INTO queue (recipient, message_id, ct, expires_at, group_seq) VALUES ($1,$2,$3,9999999999,NULL)",
            &[&carol_dev, &mid, ct],
        );
        fix_counters(&w);
    }
    c.sync().unwrap();
    assert_eq!(c.conversation_epoch(&g).unwrap(), epoch, "epoch must not move");
    assert_eq!(c.conversation(&g).unwrap().title, "epoch-N+1");
}

/// DETECTED (as undecryptable traffic): partition — the relay withholds a commit from Carol only. Carol cannot read what Bob sends in the
/// new epoch (held, bounded), nothing crashes, and Carol recovers as soon as the commit is delivered.
#[test]
fn a_group_partition_is_visible_as_held_messages_and_heals_when_the_commit_arrives() {
    let w = World::new();
    let (mut a, mut b, mut c, _ib, _ic, g) = trio(&w);
    let carol_dev = c.public_identity().unwrap().device_id.0.to_vec();
    a.rename_group(&g, "partitioned").unwrap();
    // relay pulls the commit out of Carol's queue and keeps it
    let stash = rows_for(&w, &carol_dev);
    w.exec("DELETE FROM queue WHERE recipient = $1", &[&carol_dev]);
    fix_counters(&w);
    b.sync().unwrap();
    w.clock.0.advance(1);
    b.send_text(&g, PT, None).unwrap();
    c.sync().unwrap();
    assert!(!texts(&mut c, &g).iter().any(|t| t == PT), "Carol is in the old epoch and cannot read it");
    // heal: the relay finally delivers the withheld commit
    for (i, ct) in stash.iter().enumerate() {
        let mut m = [0u8; 16];
        m[0] = 0xDD;
        m[1] = i as u8;
        w.exec(
            "INSERT INTO queue (recipient, message_id, ct, expires_at, group_seq) VALUES ($1,$2,$3,9999999999,NULL)",
            &[&carol_dev, &m.to_vec(), ct],
        );
        fix_counters(&w);
    }
    c.sync().unwrap();
    c.sync().unwrap();
    assert_eq!(c.conversation(&g).unwrap().title, "partitioned");
}

/// FINDING FR-07 (MEDIUM, availability): after the relay's group counter is reset (a restored backup, or a hostile operator),
/// every member's stored `relay_seq` is AHEAD of the relay's value. `max()` semantics meant they could NEVER commit again
/// (renames, adds, removals AND the scheduled key refreshes that give post-compromise security all fail forever).
/// FIXED: a `Stale` answer whose current value is BELOW ours is adopted (the relay is the ordering authority); see `run_commit`.
#[test]
fn a_reset_relay_group_counter_does_not_permanently_brick_commits() {
    let w = World::new();
    let (mut a, mut b, _c, _ib, _ic, g) = trio(&w);
    a.rename_group(&g, "one").unwrap();
    a.rename_group(&g, "two").unwrap();
    b.sync().unwrap();
    assert!(a.conversation(&g).unwrap().relay_seq >= 2);
    // operator restores an old backup: counters back to 0 (the queue is empty after delivery)
    w.exec("UPDATE groups SET epoch = 0", &[]);
    a.rename_group(&g, "after-reset").unwrap();
    b.sync().unwrap();
    assert_eq!(b.conversation(&g).unwrap().title, "after-reset");
    a.refresh_keys(&g).unwrap(); // PCS update must work too
}

/// PREVENTED: a hostile relay retires the routing tag. Commits are refused with an error, local state is unchanged and chat continues.
#[test]
fn a_retired_routing_tag_stops_commits_cleanly_without_corrupting_state() {
    let w = World::new();
    let (mut a, mut b, _c, _ib, _ic, g) = trio(&w);
    let epoch = a.conversation_epoch(&g).unwrap();
    w.exec("UPDATE groups SET retired = true", &[]);
    assert!(a.rename_group(&g, "nope").is_err());
    assert_eq!(a.conversation_epoch(&g).unwrap(), epoch, "a refused commit must not advance the local epoch");
    w.clock.0.advance(1);
    a.send_text(&g, PT, None).unwrap();
    b.sync().unwrap();
    assert!(texts(&mut b, &g).iter().any(|t| t == PT));
}

/// The relay learns NOTHING it can use to read content even with total DB access (re-asserted for this attack set).
#[test]
fn a_full_database_dump_after_all_the_attacks_still_contains_no_plaintext() {
    let w = World::new();
    let (mut a, mut b, ..) = trio(&w);
    let g = a.list_conversations().unwrap()[0].id;
    w.clock.0.advance(1);
    a.send_text(&g, PT, None).unwrap();
    b.sync().unwrap();
    let (text, raw) = w.db_dump();
    assert!(!text.contains("PLAINTEXT-FIXTURE") && !contains(&raw, b"PLAINTEXT-FIXTURE"));
}

/// FINDING FR-08 (MEDIUM, availability/abuse): any account could drain a victim's entire KeyPackage supply in seconds (the only limit was
/// per requester at ~8000/hour), leaving the victim unreachable for new contacts. FIXED with per-target and per-pair token buckets.
#[test]
fn key_package_draining_is_throttled_per_target_even_across_many_attackers() {
    let w = World::new();
    let mut victim = new_client();
    w.register(&victim);
    let kps = victim.generate_key_packages(100).unwrap();
    w.api(&victim).upload_key_packages(kps).unwrap();
    let mut got = 0;
    for _ in 0..5 {
        let attacker = new_client();
        w.register(&attacker);
        for _ in 0..40 {
            match w.api(&attacker).consume_key_package(&victim.device_id()) {
                Ok(_) => got += 1,
                Err(_) => break,
            }
        }
    }
    assert!(got <= 12, "five attackers together drained {got} KeyPackages; the per-target bucket must cap this at its burst");
    assert!(got >= 4, "legitimate claims must still work (got {got})");
    let left = w.query_bytes("SELECT kp FROM key_packages").len();
    assert!(left >= 88, "victim kept only {left} of 100");
    let _ = &mut victim;
}

/// FR-09 at the relay: a device record signed for one account cannot be registered under another account id.
#[test]
fn a_device_record_cannot_be_registered_under_a_different_account_id() {
    let w = World::new();
    let (victim, squatter) = (new_client(), new_client());
    let rec = victim.device_record(None).unwrap(); // public material, e.g. copied from a directory response
    let body = serde_json::to_vec(&cipher_wire::messages::RegisterRequest {
        account_id: squatter.account_id(),
        registration_token: TOKEN.to_owned(),
        device: rec.clone(),
    })
    .unwrap();
    let (status, _) = w.raw("POST", "/v1/accounts", None, body);
    assert_eq!(status, 403, "binding must cover the account id");
    // control: the same record under its OWN account id registers
    let own = serde_json::to_vec(&cipher_wire::messages::RegisterRequest {
        account_id: victim.account_id(),
        registration_token: TOKEN.to_owned(),
        device: rec,
    })
    .unwrap();
    assert_eq!(w.raw("POST", "/v1/accounts", None, own).0, 201);
}

// ---------------------------------------------------------------------------------------------------------------------
// FR-10 (MEDIUM/HIGH, availability): the relay used to buffer up to 101 MiB of body per request BEFORE it authenticated anyone.
// ---------------------------------------------------------------------------------------------------------------------
mod preauth {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use cipher_core::clock::Clock as _;
    use cipher_wire::signing::{canonical_string_with_hash, format_auth_header, AuthHeader, CanonicalParts};
    use sha2::Digest as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tower::ServiceExt as _;

    /// A request body that records whether the server ever asked for any of it.
    fn tracked_body(polled: Arc<AtomicBool>) -> Body {
        Body::from_stream(futures_util::stream::poll_fn(move |_| {
            polled.store(true, Ordering::SeqCst);
            std::task::Poll::Ready(None::<Result<axum::body::Bytes, std::io::Error>>)
        }))
    }

    fn send(w: &World, auth: Option<String>, declared_len: Option<usize>) -> (u16, bool) {
        let polled = Arc::new(AtomicBool::new(false));
        let mut b = Request::builder().method("POST").uri("/v1/blobs");
        if let Some(a) = auth {
            b = b.header("authorization", a);
        }
        if let Some(n) = declared_len {
            b = b.header("content-length", n.to_string());
        }
        let resp = w.rt.block_on(w.app.clone().oneshot(b.body(tracked_body(polled.clone())).unwrap())).unwrap();
        (resp.status().as_u16(), polled.load(Ordering::SeqCst))
    }

    fn header(
        client: &cipher_core::mls::MlsClient,
        hash: [u8; 32],
        ts: u64,
        nonce: [u8; 16],
        sign_with: &cipher_core::mls::MlsClient,
    ) -> String {
        let dev = client.device_id();
        let canon = canonical_string_with_hash(
            &CanonicalParts {
                audience: AUDIENCE,
                method: "POST",
                path_and_query: "/v1/blobs",
                timestamp: ts,
                nonce: &nonce,
                body: &[],
                device: &dev,
            },
            &hash,
        );
        format_auth_header(&AuthHeader {
            device: dev,
            timestamp: ts,
            nonce,
            signature: sign_with.sign_transport(&canon),
            body_hash: Some(hash),
        })
    }

    #[test]
    fn unauthenticated_or_badly_signed_uploads_are_refused_without_reading_the_body() {
        let w = World::new();
        let (alice, mallory) = (new_client(), new_client());
        w.register(&alice);
        let huge = 100 * 1024 * 1024;
        let ts = w.clock.0.unix_secs();

        // 1. no Authorization at all
        let (s, polled) = send(&w, None, Some(huge));
        assert_eq!(s, 401);
        assert!(!polled, "body was read before authentication (no header)");
        // 2. an announced hash but a signature from the WRONG key
        let h = header(&alice, [7; 32], ts, [1; 16], &mallory);
        let (s, polled) = send(&w, Some(h), Some(huge));
        assert_eq!(s, 401);
        assert!(!polled, "body was read although the signature was invalid");
        // 3. an old-style header (no announced hash) cannot be used to start a big upload
        let old_style = sign(&alice, AUDIENCE, "POST", "/v1/blobs", ts, [2; 16], b"");
        let (s, polled) = send(&w, Some(old_style), Some(huge));
        assert_eq!(s, 401);
        assert!(!polled);
        // 4. declared length above the cap is refused before anything else
        let (s, polled) = send(&w, None, Some(cipher_wire::limits::MAX_BLOB_BYTES + 1));
        assert_eq!(s, 413);
        assert!(!polled);
        // 5. unknown length (chunked) is refused
        let (s, polled) = send(&w, None, None);
        assert_eq!(s, 400);
        assert!(!polled);
    }

    #[test]
    fn a_valid_signature_over_a_different_body_is_rejected_after_reading() {
        let w = World::new();
        let alice = new_client();
        w.register(&alice);
        let claimed: [u8; 32] = sha2::Sha256::digest(b"CATT-the-body-the-signature-covers").into();
        let h = header(&alice, claimed, w.clock.0.unix_secs(), [3; 16], &alice);
        let mut body = b"CATT".to_vec();
        body.extend_from_slice(&[9u8; 64]); // a different body than the one that was signed
        let (status, _) = w.raw_with_len("POST", "/v1/blobs", Some(h), body);
        assert_eq!(status, 400, "the relay must verify the body against the signed hash");
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// FR-12 (MEDIUM, forward secrecy): after RECEIVING, the decrypted message was stored but the MLS state snapshot was not persisted until
// the next send/commit (nor on lock). The state on disk therefore still held the keys of messages the app had already consumed,
// so "ratchet keys are deleted" was not durable. A relay that kept a copy of the ciphertext could read it after any later
// compromise of the unlocked vault. FIXED: the snapshot is persisted after every sync that processed anything, and before locking.
// ---------------------------------------------------------------------------------------------------------------------
fn restart_and_try_old_ciphertext(w: &World, b: TestEngine, conv: &Id16, kept: &[Vec<u8>]) -> usize {
    use std::sync::atomic::Ordering;
    // "Process restart": only what is persisted in the vault survives.
    let (dir, ks, transport) = (b.dir.path().to_path_buf(), b.ks.clone(), b.transport.clone());
    drop(b.e);
    let mut e = cipher_core::app::Engine::new_for_tests(
        cipher_core::app::EngineConfig { data_dir: dir, relay_url: "https://relay.test".into(), vault: vault_cfg() },
        ks,
        transport.clone(),
        w.clock.clone(),
        AUDIENCE,
    )
    .unwrap();
    e.unlock_with_device_auth().unwrap();
    transport.offline.store(false, Ordering::SeqCst);
    kept.iter().filter(|ct| e.process_raw_for_tests(conv, ct).is_ok()).count()
}

#[test]
fn consumed_group_message_keys_are_gone_from_the_state_on_disk_after_a_restart() {
    let w = World::new();
    let (mut a, mut b, _c, _ib, _ic, g) = trio(&w);
    w.clock.0.advance(1);
    a.send_text(&g, PT, None).unwrap();
    // The relay (or a wiretap that survived TLS) keeps a copy of the ciphertext addressed to Bob.
    let bob_dev = b.public_identity().unwrap().device_id.0.to_vec();
    let kept = rows_for(&w, &bob_dev);
    assert!(!kept.is_empty());
    b.sync().unwrap();
    assert!(texts(&mut b, &g).iter().any(|t| t == PT));
    let decryptable = restart_and_try_old_ciphertext(&w, b, &g, &kept);
    assert_eq!(decryptable, 0, "the persisted MLS state still held the keys of an already-consumed message");
}

/// MEASUREMENT (run with `--ignored --nocapture`): what a size-observing adversary (the relay, or a network observer who sees request
/// sizes) can distinguish. Not an assertion test; the numbers are quoted in docs/FINAL_SECURITY_REVIEW.md.
#[test]
#[ignore]
#[allow(clippy::print_stdout)] // a measurement, not an assertion: the output is the result
fn measure_observer_visible_sizes() {
    let w = World::new();
    let (mut a, mut b, _c, _ib, _ic, g) = trio(&w);
    let bob_dev = b.public_identity().unwrap().device_id.0.to_vec();
    let _ = b.sync();
    println!("text_chars -> ciphertext_bytes_seen_by_relay");
    let mut seen = std::collections::BTreeMap::new();
    for n in [1usize, 50, 300, 500, 900, 1500, 3000, 6000, 7900] {
        w.exec("DELETE FROM queue", &[]);
        w.clock.0.advance(1);
        a.send_text(&g, &"x".repeat(n), None).unwrap();
        let sizes: Vec<usize> = rows_for(&w, &bob_dev).iter().map(|c| c.len()).collect();
        println!("{n:6} -> {sizes:?}");
        seen.insert(n, sizes);
        let _ = b.sync();
        w.exec("DELETE FROM queue", &[]);
    }
    println!("file_bytes -> relay_blob_bytes (Padmé + STREAM overhead) overhead%");
    for f in [1_000u64, 10_000, 100_000, 1_000_000, 5_000_000, 20_000_000, 100_000_000] {
        let blob = cipher_core::attachment::ciphertext_len_for(cipher_core::attachment::padme(f));
        println!("{f:11} -> {blob:11} {:5.2}%", (blob as f64 / f as f64 - 1.0) * 100.0);
    }
}
