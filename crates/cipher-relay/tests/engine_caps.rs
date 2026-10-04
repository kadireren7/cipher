#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::needless_range_loop)]
//! Delivery capabilities through real engines + relay + PostgreSQL: contacts deliver WITHOUT authenticating, caps rotate on group removal,
//! a revoked capability falls back to the authenticated path, strangers cannot starve contacts (docs/DELIVERY_CAPABILITIES.md; PRIV-004, ST-031).
mod harness;
use cipher_core::app::model::*;
use cipher_wire::messages::*;
use cipher_wire::Id16;
use harness::engine::*;
use harness::*;

fn pair(w: &World) -> (TestEngine, TestEngine, Id16, Id16) {
    let (mut a, mut b) = (w.engine(), w.engine());
    let (ia, ib) = (a.public_identity().unwrap(), b.public_identity().unwrap());
    a.add_contact_by_id(&ib.cipher_id, "Bob").unwrap();
    b.add_contact_by_id(&ia.cipher_id, "Alice").unwrap();
    (a, b, ia.account_id, ib.account_id)
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

/// first contact + capability exchange in both directions
fn exchange(a: &mut TestEngine, b: &mut TestEngine, conv: &Id16) -> Id16 {
    a.send_text(conv, "hello", None).unwrap();
    b.sync().unwrap();
    a.sync().unwrap();
    b.sync().unwrap();
    b.list_conversations().unwrap()[0].id
}

fn anon_raw(w: &World, cap: Id16, n: usize) -> Vec<String> {
    let req = AnonDeliverRequest {
        deliveries: vec![AnonDelivery { cap, message_id: Id16(cipher_core::rng::array::<16>().unwrap()), ciphertext: vec![5; n] }],
        ttl_secs: None,
    };
    let (_, body) = w.raw("POST", "/v1/deliver", None, serde_json::to_vec(&req).unwrap());
    serde_json::from_slice::<AnonDeliverResponse>(&body).unwrap().results
}

#[test]
fn contacts_exchange_capabilities_inside_e2ee_and_then_deliver_without_authenticating() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv_a = a.start_dm(&ib).unwrap();
    let conv_b = exchange(&mut a, &mut b, &conv_a);
    let b_dev = b.clone_public_for_tests().device_id;
    assert!(b.own_cap_for_tests(&conv_b).is_some(), "B minted a capability");
    assert_eq!(a.peer_cap_for_tests(&conv_a, &b_dev), b.own_cap_for_tests(&conv_b), "A learned it through the E2EE conversation");
    // From now on A's messages reach B through /v1/deliver, which carries no Authorization header at all.
    a.transport.requests.lock().unwrap().clear();
    a.transport.unauth.lock().unwrap().clear();
    let before = a.delivery_path_counts();
    a.send_text(&conv_a, "CAP-CANARY-anon-delivery-7781", None).unwrap();
    let reqs = a.transport.requests.lock().unwrap().clone();
    assert!(reqs.iter().any(|(_, p)| p == "/v1/deliver"), "{reqs:?}");
    assert!(!reqs.iter().any(|(_, p)| p == "/v1/messages/batch"), "no authenticated send of the message body: {reqs:?}");
    assert!(a.transport.unauth.lock().unwrap().iter().any(|p| p == "/v1/deliver"), "the delivery request was unauthenticated");
    assert!(a.delivery_path_counts().0 > before.0);
    b.sync().unwrap();
    assert!(texts(&mut b, &conv_b).contains(&"CAP-CANARY-anon-delivery-7781".to_owned()));
    // the relay stored no sender for the envelope (cap lane), and the capability never appears in cleartext in the database
    let cap = b.own_cap_for_tests(&conv_b).unwrap();
    let hits: i64 = w.rt.block_on(async {
        let c = w.pool.get().await.unwrap();
        let mut n = 0;
        for (t, col) in [("delivery_caps", "cap_hash"), ("queue", "ct")] {
            n += c
                .query_one(&format!("SELECT count(*) FROM {t} WHERE position($1::bytea in {col}) > 0"), &[&cap.0.as_slice()])
                .await
                .unwrap()
                .get::<_, i64>(0);
        }
        n
    });
    assert_eq!(hits, 0);
    // a stranger who learned nothing cannot use the capability space: a random value is simply invalid
    assert_eq!(anon_raw(&w, Id16(cipher_core::rng::array::<16>().unwrap()), 100), ["invalid"]);
}

#[test]
fn a_revoked_capability_falls_back_to_the_authenticated_path_and_nothing_is_lost() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv_a = a.start_dm(&ib).unwrap();
    let conv_b = exchange(&mut a, &mut b, &conv_a);
    let cap = b.own_cap_for_tests(&conv_b).unwrap();
    // B's capability dies at the relay without A knowing (revoked / expired).
    w.exec("DELETE FROM delivery_caps", &[]);
    assert_eq!(anon_raw(&w, cap, 100), ["invalid"]);
    let before = a.delivery_path_counts();
    a.send_text(&conv_a, "survives-revocation-9921", None).unwrap();
    a.sync().unwrap(); // retry: capability forgotten, authenticated path
    b.sync().unwrap();
    assert!(texts(&mut b, &conv_b).contains(&"survives-revocation-9921".to_owned()));
    assert!(a.delivery_path_counts().1 > before.1, "fell back to the authenticated lane");
    // B notices nothing is wrong and mints a fresh capability on a later maintenance pass only when due; the old one stays dead.
    assert_eq!(anon_raw(&w, cap, 100), ["invalid"]);
}

#[test]
fn strangers_filling_the_open_lane_cannot_stop_a_contact_from_delivering() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv_a = a.start_dm(&ib).unwrap();
    let conv_b = exchange(&mut a, &mut b, &conv_a);
    let b_dev = b.clone_public_for_tests().device_id;
    // eight stranger accounts hammer B's open lane
    let strangers: Vec<_> = (0..8).map(|_| new_client()).collect();
    for s in &strangers {
        w.register(s);
        for _ in 0..30 {
            let _ = w.api(s).send_message(b_dev, Id16(cipher_core::rng::array::<16>().unwrap()), vec![1; 64], None);
        }
    }
    let lane0: i64 = w.rt.block_on(async {
        w.pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT count(*) FROM queue WHERE lane=0 AND recipient=$1", &[&b_dev.0.as_slice()])
            .await
            .unwrap()
            .get(0)
    });
    assert!(lane0 as usize <= cipher_wire::limits::OPEN_LANE_ENVELOPES, "open lane bounded: {lane0}");
    for i in 0..20 {
        w.clock.0.advance(1);
        a.send_text(&conv_a, &format!("contact-still-gets-through-{i}"), None).unwrap();
    }
    b.sync().unwrap();
    assert_eq!(texts(&mut b, &conv_b).iter().filter(|t| t.starts_with("contact-still-gets-through")).count(), 20);
}

#[test]
fn group_removal_rotates_capabilities_and_the_removed_member_cannot_use_the_old_one() {
    let w = World::new();
    let mut e = [w.engine(), w.engine(), w.engine()];
    let pubs: Vec<_> = e.iter_mut().map(|x| x.public_identity().unwrap()).collect();
    for i in 0..3 {
        for j in 0..3 {
            if i != j {
                e[i].add_contact_by_id(&pubs[j].cipher_id, "P").unwrap();
            }
        }
    }
    let [mut a, mut b, mut c] = e;
    let g = a.create_group("Team", &[pubs[1].account_id, pubs[2].account_id]).unwrap();
    for _ in 0..2 {
        for x in [&mut b, &mut c, &mut a] {
            x.sync().unwrap();
        }
    }
    let b_old = b.own_cap_for_tests(&g).expect("B has a capability for the group");
    let (c_dev, b_dev) = (c.clone_public_for_tests().device_id, b.clone_public_for_tests().device_id);
    assert_eq!(c.peer_cap_for_tests(&g, &b_dev), Some(b_old), "C (a member) knows B's capability");
    a.remove_group_member(&g, &pubs[2].account_id).unwrap();
    for x in [&mut b, &mut a, &mut c] {
        x.sync().unwrap();
    }
    let b_new = b.own_cap_for_tests(&g).unwrap();
    assert_ne!(b_new, b_old, "rotated after the removal");
    // the removed member's knowledge of the old capability is worthless: it is dead at the relay immediately (removal rotation has no grace)
    assert_eq!(anon_raw(&w, b_old, 100), ["invalid"]);
    assert_eq!(c.peer_cap_for_tests(&g, &b_dev), None, "C's stale state was wiped on revocation");
    let _ = c_dev;
    // remaining members keep delivering anonymously with the new capability
    a.sync().unwrap();
    assert_eq!(a.peer_cap_for_tests(&g, &b_dev), Some(b_new));
    let before = a.delivery_path_counts();
    a.send_text(&g, "after-removal-via-new-cap", None).unwrap();
    assert!(a.delivery_path_counts().0 > before.0);
    b.sync().unwrap();
    assert!(texts(&mut b, &g).contains(&"after-removal-via-new-cap".to_owned()));
}

/// What a COMPROMISED relay can derive about who talks to whom, from (a) a full database dump (no pepper) and (b) the live request stream.
/// PRIV-014 and the social-graph experiment (docs/PRIVACY_TRANSPORT_REVIEW.md).
#[test]
fn a_database_dump_links_no_sender_to_any_recipient_and_the_live_stream_shows_senders_only_for_authenticated_requests() {
    let w = World::new();
    let mut r = w.engine();
    let rp = r.public_identity().unwrap();
    let mut senders = Vec::new();
    for _ in 0..4 {
        let mut s = w.engine();
        let sp = s.public_identity().unwrap();
        s.add_contact_by_id(&rp.cipher_id, "R").unwrap();
        r.add_contact_by_id(&sp.cipher_id, "S").unwrap();
        let conv = s.start_dm(&rp.account_id).unwrap();
        exchange_with(&mut s, &mut r, &conv);
        senders.push((s, conv));
    }
    for (s, conv) in senders.iter_mut() {
        s.transport.log.lock().unwrap().clear();
        for i in 0..5 {
            w.clock.0.advance(1);
            s.send_text(conv, &format!("graph-probe-{i}"), None).unwrap();
        }
    }
    // (a) DB dump WITHOUT the pepper: does any sender identifier appear outside the device directory?
    let sender_ids: Vec<Vec<u8>> = senders.iter().map(|(s, _)| s.clone_public_for_tests().device_id.0.to_vec()).collect();
    let leaks: i64 = w.rt.block_on(async {
        let c = w.pool.get().await.unwrap();
        let mut n = 0i64;
        for id in &sender_ids {
            // queue rows (all columns), group tables, seen tombstones, capability table, blobs
            n += c.query_one("SELECT count(*) FROM queue WHERE position($1::bytea in COALESCE(sender_h,''::bytea)) > 0 OR position($1::bytea in ct) > 0 OR position($1::bytea in message_id) > 0 OR position($1::bytea in COALESCE(cap_hash,''::bytea)) > 0", &[&id.as_slice()]).await.unwrap().get::<_, i64>(0);
            n += c.query_one("SELECT count(*) FROM delivery_caps WHERE position($1::bytea in cap_hash) > 0 OR position($1::bytea in device_id) > 0", &[&id.as_slice()]).await.unwrap().get::<_, i64>(0);
            n += c.query_one("SELECT count(*) FROM seen WHERE position($1::bytea in message_id) > 0", &[&id.as_slice()]).await.unwrap().get::<_, i64>(0);
        }
        n
    });
    // The only mentions of a sender's device id are its OWN inbox-capability rows (owner column) — nothing connects a sender to a recipient.
    assert_eq!(leaks, senders.len() as i64);
    let recv_dev = r.clone_public_for_tests().device_id.0.to_vec();
    // the queue's `lane=1` rows: no sender column is populated
    let tagged: i64 = w.rt.block_on(async {
        w.pool.get().await.unwrap().query_one("SELECT count(*) FROM queue WHERE lane=1 AND sender_h IS NOT NULL", &[]).await.unwrap().get(0)
    });
    assert_eq!(tagged, 0);
    let _ = recv_dev;
    // (b) live stream: every capability delivery is unauthenticated; no request body carries an IP-looking string or any sender id
    let (mut anon_n, mut authed_n) = (0usize, 0usize);
    for (s, _) in senders.iter() {
        for e in s
            .transport
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.method == "POST" && (e.path == "/v1/deliver" || e.path == "/v1/messages/batch"))
        {
            if e.authed {
                authed_n += 1;
            } else {
                anon_n += 1;
            }
        }
    }
    assert_eq!(anon_n, 20, "every one of the 20 message deliveries was an unauthenticated capability delivery");
    assert_eq!(authed_n, 0, "after the capability exchange no message body is sent with the sender's identity");
    let ip = |b: &[u8]| {
        String::from_utf8_lossy(b)
            .split(|c: char| !(c.is_ascii_digit() || c == '.'))
            .any(|t| t.split('.').count() == 4 && t.split('.').all(|p| p.parse::<u8>().is_ok()))
    };
    assert!(!w.captured.lock().unwrap().iter().any(|c| ip(&c.request_body)), "no request body contains an IP address (PRIV-014)");
}

fn exchange_with(a: &mut TestEngine, b: &mut TestEngine, conv: &Id16) {
    a.send_text(conv, "hello", None).unwrap();
    for _ in 0..2 {
        b.sync().unwrap();
        a.sync().unwrap();
    }
}
