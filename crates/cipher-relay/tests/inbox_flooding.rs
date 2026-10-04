#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! ST-031 inbox flooding: bounded per-recipient queues, per-sender share, distributed abuse across several attacker accounts.
//! The honest outcome is asserted, including the residual: N colluding registered accounts can still fill a queue (needs recipient-held capabilities).
mod harness;
use cipher_core::clock::Clock as _;
use cipher_relay::error::ApiError;
use cipher_relay::ratelimit::KeyHasher;
use cipher_relay::store::{Enqueue, Sender, MAX_QUEUED_ENVELOPES_PER_SENDER};
use cipher_wire::limits::*;
use cipher_wire::Id16;
use harness::*;

fn flood(w: &World, victim: Id16, from: Id16, keys: &KeyHasher, n: usize) -> (usize, usize) {
    let st = w.state.store.clone();
    let now = w.clock.unix_secs();
    let s = Sender { device: from, keys };
    let (mut ok, mut full) = (0, 0);
    for _ in 0..n {
        match w.rt.block_on(st.enqueue(&victim, &rid(), &[1u8; 64], MIN_TTL_SECS, now, Some(&s))) {
            Ok(Enqueue::Queued) => ok += 1,
            Err(ApiError::QueueFull) => full += 1,
            other => panic!("{other:?}"),
        }
    }
    (ok, full)
}

#[test]
fn one_account_cannot_take_more_than_the_open_lane_of_a_victims_queue() {
    let w = World::new();
    let keys = KeyHasher::new([7; 32]);
    let (victim, attacker, friend) = (new_client(), new_client(), new_client());
    for c in [&victim, &attacker, &friend] {
        w.register(c);
    }
    let (ok, full) = flood(&w, victim.device_id(), attacker.device_id(), &keys, OPEN_LANE_ENVELOPES + 100);
    assert_eq!(ok, OPEN_LANE_ENVELOPES, "a stranger gets the small OPEN lane (and never more than its per-sender share)");
    assert_eq!(full, 100, "the attacker is refused (backpressure: 429)");
    // the attacker's traffic to OTHER recipients is unaffected
    assert_eq!(flood(&w, friend.device_id(), attacker.device_id(), &keys, 10), (10, 0));
    const _: () = assert!(MAX_QUEUED_ENVELOPES_PER_SENDER >= OPEN_LANE_ENVELOPES);
    // the per-sender share is the outer bound, the lane the tighter one
}

#[test]
fn distributed_abuse_by_many_accounts_is_bounded_by_the_lane_not_by_accounts_times_share() {
    let w = World::new();
    let keys = KeyHasher::new([7; 32]);
    let victim = new_client();
    w.register(&victim);
    let attackers: Vec<_> = (0..5).map(|_| new_client()).collect();
    for a in &attackers {
        w.register(a);
    }
    let mut total = 0;
    for a in &attackers {
        total += flood(&w, victim.device_id(), a.device_id(), &keys, MAX_QUEUED_ENVELOPES_PER_SENDER + 50).0;
    }
    assert_eq!(
        total, OPEN_LANE_ENVELOPES,
        "five accounts share ONE open lane: they cannot take 5 x the share (they could before the lanes existed)"
    );
    // An honest STRANGER (no capability) is refused while the open lane is full — documented. Contacts use capabilities (`delivery_caps.rs`).
    let honest = new_client();
    w.register(&honest);
    assert_eq!(flood(&w, victim.device_id(), honest.device_id(), &keys, 1), (0, 1));
}

#[test]
fn the_share_accounting_stores_no_device_id_and_disappears_with_the_envelope() {
    let w = World::new();
    let keys = KeyHasher::new([7; 32]);
    let (victim, sender) = (new_client(), new_client());
    w.register(&victim);
    w.register(&sender);
    flood(&w, victim.device_id(), sender.device_id(), &keys, 3);
    let hits: i64 = w.rt.block_on(async {
        let c = w.pool.get().await.unwrap();
        c.query_one(
            "SELECT count(*) FROM queue WHERE sender_h IS NOT NULL AND position($1::bytea in sender_h) > 0",
            &[&sender.device_id().0.as_slice()],
        )
        .await
        .unwrap()
        .get(0)
    });
    assert_eq!(hits, 0, "the sender's device id never appears in the queue");
    w.exec("DELETE FROM queue", &[]);
    let left: i64 = w.rt.block_on(async {
        w.pool.get().await.unwrap().query_one("SELECT count(*) FROM queue WHERE sender_h IS NOT NULL", &[]).await.unwrap().get(0)
    });
    assert_eq!(left, 0);
}
