#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::needless_range_loop)]
//! Network profiles and fail-closed behaviour through real engines + relay + PostgreSQL (docs/PRIVACY_TRANSPORT_REVIEW.md; PRIV-005/006/015).
mod harness;
use cipher_core::app::model::*;
use cipher_core::app::netprofile::{NetworkProfile, COVER_CIPHERTEXT_BYTES};
use cipher_wire::Id16;
use harness::engine::*;
use harness::*;
use std::sync::atomic::Ordering;

fn pair(w: &World) -> (TestEngine, TestEngine, Id16, Id16) {
    let (mut a, mut b) = (w.engine(), w.engine());
    let (ia, ib) = (a.public_identity().unwrap(), b.public_identity().unwrap());
    a.add_contact_by_id(&ib.cipher_id, "Bob").unwrap();
    b.add_contact_by_id(&ia.cipher_id, "Alice").unwrap();
    (a, b, ia.account_id, ib.account_id)
}

fn profile(e: &mut TestEngine, p: NetworkProfile) {
    let mut s = e.settings().unwrap();
    s.network_profile = p;
    e.set_settings(&s).unwrap();
}

/// first contact + capability exchange so that later sends are capability deliveries
fn warm(a: &mut TestEngine, b: &mut TestEngine, conv: &Id16) {
    a.send_text(conv, "hello", None).unwrap();
    for _ in 0..2 {
        b.sync().unwrap();
        a.sync().unwrap();
    }
}

fn is_send_shaped(e: &NetEvent) -> bool {
    e.method == "POST" && (e.path == "/v1/deliver" || e.path == "/v1/messages/batch" || e.path == "/v1/messages")
}

#[test]
fn enhanced_holds_sends_until_the_tick_and_every_tick_has_exactly_one_send_shaped_request() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv = a.start_dm(&ib).unwrap();
    warm(&mut a, &mut b, &conv);
    profile(&mut a, NetworkProfile::Enhanced);
    a.transport.log.lock().unwrap().clear();
    // a send does not touch the network by itself
    let m = a.send_text(&conv, "ENHANCED-CANARY-held-until-tick-4471", None).unwrap();
    assert_eq!(m.state, DeliveryState::Pending);
    assert!(a.transport.log.lock().unwrap().is_empty(), "nothing leaves before the tick");
    // ticks: one with a real message, then idle ones. Each has exactly one send-shaped POST and one GET.
    let mut per_tick = Vec::new();
    for _ in 0..5 {
        a.transport.log.lock().unwrap().clear();
        let t = a.network_tick().unwrap();
        assert!(t.next_delay_ms >= 7_500 && t.next_delay_ms <= 12_500);
        let log = a.transport.log.lock().unwrap().clone();
        per_tick.push((
            log.iter().filter(|e| e.method == "GET" && e.path == "/v1/messages").count(),
            log.iter().filter(|e| is_send_shaped(e)).count(),
        ));
        w.clock.0.advance(10);
    }
    assert!(per_tick.iter().all(|(gets, sends)| *gets == 1 && *sends == 1), "{per_tick:?}");
    b.sync().unwrap();
    let bc = b.list_conversations().unwrap()[0].id;
    assert_eq!(
        b.history(&bc, None, 5)
            .unwrap()
            .items
            .iter()
            .filter(|m| matches!(&m.content, Content::Text { body } if body.starts_with("ENHANCED-CANARY")))
            .count(),
        1,
        "the real message arrived exactly once"
    );
}

#[test]
fn standard_sends_immediately_and_sends_no_cover() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv = a.start_dm(&ib).unwrap();
    warm(&mut a, &mut b, &conv);
    a.transport.log.lock().unwrap().clear();
    let m = a.send_text(&conv, "standard-now", None).unwrap();
    assert_eq!(m.state, DeliveryState::Sent);
    assert_eq!(a.transport.log.lock().unwrap().iter().filter(|e| is_send_shaped(e)).count(), 1);
    a.transport.log.lock().unwrap().clear();
    let t = a.network_tick().unwrap();
    assert!(t.next_delay_ms >= 3_600 && t.next_delay_ms <= 4_400);
    assert_eq!(a.transport.log.lock().unwrap().iter().filter(|e| is_send_shaped(e)).count(), 0, "no cover traffic in STANDARD");
}

#[test]
fn cover_requests_store_nothing_and_share_the_real_message_size_class() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv = a.start_dm(&ib).unwrap();
    // the REAL ciphertext length of a minimal message, as stored by the relay
    a.send_text(&conv, "x", None).unwrap();
    let real_len: i64 = w.rt.block_on(async {
        w.pool.get().await.unwrap().query_one("SELECT max(octet_length(ct))::bigint FROM queue", &[]).await.unwrap().get(0)
    });
    assert_eq!(real_len as usize, COVER_CIPHERTEXT_BYTES, "COVER_CIPHERTEXT_BYTES must equal the real minimal message size class");
    warm(&mut a, &mut b, &conv);
    a.send_text(&conv, "an anonymous real send, so cover imitates the anonymous shape", None).unwrap();
    profile(&mut a, NetworkProfile::Enhanced);
    w.exec("DELETE FROM queue", &[]);
    let before: i64 =
        w.rt.block_on(async { w.pool.get().await.unwrap().query_one("SELECT count(*) FROM queue", &[]).await.unwrap().get(0) });
    for _ in 0..3 {
        a.transport.log.lock().unwrap().clear();
        a.network_tick().unwrap();
        w.clock.0.advance(10);
        let cover: Vec<_> = a.transport.log.lock().unwrap().iter().filter(|e| e.path == "/v1/deliver").cloned().collect();
        assert_eq!(cover.len(), 1);
        assert!(!cover[0].authed, "cover is unauthenticated: it does not even identify the sender to the relay");
    }
    let after: i64 =
        w.rt.block_on(async { w.pool.get().await.unwrap().query_one("SELECT count(*) FROM queue", &[]).await.unwrap().get(0) });
    assert_eq!(before, after, "cover requests are answered `invalid` and queue nothing");
}

#[test]
fn a_dead_privacy_route_keeps_the_encrypted_message_queued_and_nothing_is_sent_anywhere_else() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv = a.start_dm(&ib).unwrap();
    warm(&mut a, &mut b, &conv);
    for p in [NetworkProfile::Standard, NetworkProfile::Enhanced] {
        profile(&mut a, p);
        a.transport.route_down.store(true, Ordering::SeqCst);
        a.transport.log.lock().unwrap().clear();
        let text = format!("queued-while-route-down-{p:?}");
        let m = a.send_text(&conv, &text, None).unwrap();
        assert_eq!(m.state, DeliveryState::Pending, "stays queued, encrypted");
        let _ = a.network_tick();
        let _ = a.sync();
        assert!(a.transport.log.lock().unwrap().is_empty(), "no request reached any relay while the route was down");
        // the route returns: the SAME queued ciphertext is delivered, over the allowed route only
        a.transport.route_down.store(false, Ordering::SeqCst);
        w.clock.0.advance(3600); // past the retry back-off
        a.network_tick().unwrap();
        assert_eq!(a.message(&conv, &m.id).unwrap().unwrap().state, DeliveryState::Sent);
        b.sync().unwrap();
        let bc = b.list_conversations().unwrap()[0].id;
        assert!(b.history(&bc, None, 50).unwrap().items.iter().any(|x| matches!(&x.content, Content::Text { body } if *body == text)));
    }
}

#[test]
fn cover_imitates_the_shape_of_our_real_sends_authenticated_or_not() {
    let w = World::new();
    let (mut a, mut b, _ia, ib) = pair(&w);
    let conv = a.start_dm(&ib).unwrap();
    // Before any capability exists our real sends are authenticated: cover must look authenticated too (otherwise the request shape gives real sends away).
    a.send_text(&conv, "first contact, authenticated", None).unwrap();
    profile(&mut a, NetworkProfile::Enhanced);
    // the first ticks flush control frames (our own capability announcement); wait until a tick has nothing real to send
    for _ in 0..3 {
        a.network_tick().unwrap();
        w.clock.0.advance(3600);
    }
    w.exec("DELETE FROM queue", &[]);
    a.transport.log.lock().unwrap().clear();
    a.network_tick().unwrap();
    let cover: Vec<_> = a.transport.log.lock().unwrap().iter().filter(|e| is_send_shaped(e)).cloned().collect();
    assert_eq!(cover.len(), 1);
    assert!(cover[0].authed && cover[0].path == "/v1/messages/batch", "{cover:?}");
    let queued: i64 =
        w.rt.block_on(async { w.pool.get().await.unwrap().query_one("SELECT count(*) FROM queue", &[]).await.unwrap().get(0) });
    assert_eq!(queued, 0, "authenticated cover to a nonexistent device stores nothing");
    let _ = &mut b;
}
