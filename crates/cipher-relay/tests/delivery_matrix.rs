#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::print_stdout)]
//! Phase 1 — the repeatable delivery matrix. Seeded, deterministic fault injection against REAL engines, the REAL relay router and PostgreSQL:
//! network flaps, responses lost after the relay executed the request, device restarts, relay restarts, clock jumps and concurrent senders, with the
//! invariants that define "reliable":
//!
//!   * EXACTLY ONCE at the application level: every message a sender created appears once, never twice, never zero times, at the recipient;
//!   * ORDER: per sender, in the order it was sent (even within one clock tick);
//!   * STATE: nothing is `Delivered` unless the recipient's device confirmed it; after the faults stop, every message becomes `Delivered`
//!     (a message that exhausted its retries is `Failed`, visible, and a manual retry delivers it) — none stays `Pending`/`Sent` forever.
//!
//! Failures print the seed; rerun with that seed to reproduce. Exactly-once is NOT claimed at the transport level: a lost response makes the sender
//! send again and the relay and the recipient suppress the duplicate by message id (see docs/DELIVERY_SEMANTICS.md).
mod harness;
use cipher_core::app::model::*;
use cipher_wire::{Id16, RelayDescriptor};
use harness::engine::*;
use harness::*;
use std::sync::atomic::Ordering;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[derive(Default, Debug)]
struct Injected {
    offline_flaps: u32,
    lost_responses: u32,
    device_restarts: u32,
    relay_restarts: u32,
    clock_jumps: u32,
    failed_then_retried: u32,
}

struct Party {
    name: &'static str,
    e: Option<TestEngine>,
    conv: Id16,
    sent: Vec<(Id16, String)>, // (message id, text) in send order
}

impl Party {
    fn e(&mut self) -> &mut TestEngine {
        self.e.as_mut().unwrap()
    }
}

fn texts_from(e: &mut TestEngine, conv: &Id16, sender_prefix: &str) -> Vec<String> {
    let mut v: Vec<String> = e
        .history(conv, None, 1000)
        .unwrap()
        .items
        .into_iter()
        .filter_map(|m| match m.content {
            Content::Text { body } if body.starts_with(sender_prefix) => Some(body),
            _ => None,
        })
        .collect();
    v.reverse();
    v
}

struct Mode {
    cross_relay: bool,
}

/// Runs one scenario. Returns what was injected.
fn run(seed: u64, steps: u32, mode: &Mode) -> Injected {
    let mut rng = Rng(seed);
    let mut inj = Injected::default();
    let (wa, wb) = (World::new(), World::new());
    let worlds: Vec<&World> = if mode.cross_relay { vec![&wa, &wb] } else { vec![&wa] };
    let (mut ea, mut eb) = if mode.cross_relay { (wa.engine(), wb.engine()) } else { (wa.engine(), wa.engine()) };
    if mode.cross_relay {
        ea.set_own_relay(RelayDescriptor::new("https://relay-a.test", None).unwrap()).unwrap();
        eb.set_own_relay(RelayDescriptor::new("https://relay-b.test", None).unwrap()).unwrap();
        ea.transport.reach("https://relay-b.test", wb.app.clone(), wb.rt.clone());
        eb.transport.reach("https://relay-a.test", wa.app.clone(), wa.rt.clone());
    }
    let (pa, pb) = (ea.public_identity().unwrap(), eb.public_identity().unwrap());
    // establish the conversation before any fault, so faults hit steady-state delivery
    if mode.cross_relay {
        let card = eb.create_contact_card(7).unwrap();
        ea.add_contact_by_card(&card, "B", true).unwrap();
    } else {
        ea.add_contact_by_id(&pb.cipher_id, "B").unwrap();
        eb.add_contact_by_id(&pa.cipher_id, "A").unwrap();
    }
    let conv_a = ea.start_dm(&pb.account_id).unwrap();
    ea.send_text(&conv_a, "A-0", None).unwrap();
    for _ in 0..3 {
        ea.sync().unwrap();
        eb.sync().unwrap();
        if let Some(c) = eb.list_conversations().unwrap().first() {
            if c.state == ConvState::Requested {
                eb.accept_conversation(&c.id).unwrap();
            }
        }
    }
    let conv_b = eb.list_conversations().unwrap()[0].id;
    let mut parties = [
        Party { name: "A", e: Some(ea), conv: conv_a, sent: Vec::new() },
        Party { name: "B", e: Some(eb), conv: conv_b, sent: Vec::new() },
    ];
    // the first message A-0 was sent before the faults began; track it so it is checked too
    let first = parties[0].e().history(&conv_a, None, 5).unwrap().items.into_iter().find(|m| m.outgoing).unwrap();
    parties[0].sent.push((first.id, "A-0".to_owned()));

    let tick = |worlds: &[&World], secs: u64| worlds.iter().for_each(|w| w.clock.0.advance(secs));
    let mut counters = [1u32, 0u32];
    for step in 0..steps {
        let who = rng.below(2) as usize;
        match rng.below(12) {
            0..=4 => {
                // send (possibly while a fault is active)
                let n = counters[who];
                counters[who] += 1;
                let text = format!("{}-{n}", parties[who].name);
                let conv = parties[who].conv;
                if let Ok(m) = parties[who].e().send_text(&conv, &text, None) {
                    parties[who].sent.push((m.id, text));
                }
            }
            5 | 6 => {
                parties[who].e().sync().ok();
            }
            7 => {
                let p = &mut parties[who];
                let off = p.e().transport.offline.load(Ordering::SeqCst);
                p.e().transport.offline.store(!off, Ordering::SeqCst);
                inj.offline_flaps += 1;
            }
            8 => {
                // the relay EXECUTES the next delivery request but its answer is lost
                let sfx = if mode.cross_relay || rng.below(2) == 0 { "/v1/deliver" } else { "/v1/messages/batch" };
                *parties[who].e().transport.lose_response_on.lock().unwrap() = Some(sfx.to_owned());
                inj.lost_responses += 1;
            }
            9 => {
                let w = if mode.cross_relay && who == 1 { &wb } else { &wa };
                let old = parties[who].e.take().unwrap();
                parties[who].e = Some(old.restart(w));
                inj.device_restarts += 1;
            }
            10 => {
                // relay restart(s): fresh routers (empty in-memory state) over the same databases; every device's open connections are gone
                let fresh_a = wa.instance(generous_limits());
                parties[0].e().transport.restart_relay(fresh_a.clone());
                if mode.cross_relay {
                    let fresh_b = wb.instance(generous_limits());
                    parties[1].e().transport.restart_relay(fresh_b.clone());
                    parties[0].e().transport.restart_other("https://relay-b.test", fresh_b);
                    parties[1].e().transport.restart_other("https://relay-a.test", fresh_a);
                } else {
                    parties[1].e().transport.restart_relay(fresh_a);
                }
                inj.relay_restarts += 1;
            }
            _ => {
                tick(&worlds, 1 + rng.below(3600));
                inj.clock_jumps += 1;
            }
        }
        tick(&worlds, rng.below(3)); // time passes between steps (also 0: same-tick sends)
        let _ = step;
    }

    // ---- heal: all faults stop; give the system time and rounds to converge ----
    for p in parties.iter_mut() {
        p.e().transport.offline.store(false, Ordering::SeqCst);
        *p.e().transport.lose_response_on.lock().unwrap() = None;
    }
    let all_delivered = |parties: &mut [Party; 2]| -> bool {
        for p in parties.iter_mut() {
            let conv = p.conv;
            let ids: Vec<Id16> = p.sent.iter().map(|(id, _)| *id).collect();
            for id in ids {
                if p.e().message(&conv, &id).unwrap().unwrap().state != DeliveryState::Delivered {
                    return false;
                }
            }
        }
        true
    };
    for round in 0..60 {
        tick(&worlds, 2 * 3600);
        for p in parties.iter_mut() {
            p.e().sync().ok();
        }
        // a message that exhausted its retries is Failed — visible to the user, who can retry it
        for p in parties.iter_mut() {
            let conv = p.conv;
            let ids: Vec<Id16> = p.sent.iter().map(|(id, _)| *id).collect();
            for id in ids {
                if p.e().message(&conv, &id).unwrap().unwrap().state == DeliveryState::Failed {
                    p.e().retry_message(&conv, &id).unwrap();
                    inj.failed_then_retried += 1;
                }
            }
        }
        if all_delivered(&mut parties) {
            let _ = round;
            break;
        }
    }

    // ---- invariants ----
    for (si, ri) in [(0usize, 1usize), (1, 0)] {
        let sent: Vec<String> = parties[si].sent.iter().map(|(_, t)| t.clone()).collect();
        let prefix = format!("{}-", parties[si].name);
        let conv = parties[ri].conv;
        let got = texts_from(parties[ri].e(), &conv, &prefix);
        assert_eq!(
            got, sent,
            "seed {seed}: {} -> {}: every message exactly once, in send order (injected {inj:?})",
            parties[si].name, parties[ri].name
        );
        let conv = parties[si].conv;
        for (id, text) in parties[si].sent.clone() {
            let m = parties[si].e().message(&conv, &id).unwrap().unwrap();
            assert_eq!(m.state, DeliveryState::Delivered, "seed {seed}: {text} must end Delivered, not {:?} (injected {inj:?})", m.state);
        }
    }
    inj
}

#[test]
fn single_relay_delivery_matrix() {
    let mode = Mode { cross_relay: false };
    let mut total = Injected::default();
    for seed in 1..=8u64 {
        let i = run(seed, 70, &mode);
        total.offline_flaps += i.offline_flaps;
        total.lost_responses += i.lost_responses;
        total.device_restarts += i.device_restarts;
        total.relay_restarts += i.relay_restarts;
        total.clock_jumps += i.clock_jumps;
        total.failed_then_retried += i.failed_then_retried;
    }
    println!("single relay, 8 seeds x 70 steps, injected: {total:?}");
    assert!(
        total.lost_responses > 5 && total.device_restarts > 5 && total.relay_restarts > 5 && total.offline_flaps > 10,
        "the matrix must really inject faults: {total:?}"
    );
}

#[test]
fn cross_relay_delivery_matrix() {
    let mode = Mode { cross_relay: true };
    let mut total = Injected::default();
    for seed in 101..=106u64 {
        let i = run(seed, 70, &mode);
        total.offline_flaps += i.offline_flaps;
        total.lost_responses += i.lost_responses;
        total.device_restarts += i.device_restarts;
        total.relay_restarts += i.relay_restarts;
        total.clock_jumps += i.clock_jumps;
        total.failed_then_retried += i.failed_then_retried;
    }
    println!("cross relay, 6 seeds x 70 steps, injected: {total:?}");
    assert!(
        total.lost_responses > 4 && total.device_restarts > 4 && total.relay_restarts > 4 && total.offline_flaps > 8,
        "the matrix must really inject faults: {total:?}"
    );
}
