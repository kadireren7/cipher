#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::print_stdout)]
//! Phase 5 (docs/MAILBOX_PRIVACY.md): metadata exposure MEASURED before and after, for the same user goal — "start a conversation with Bob and send
//! one message" — from the point of view of the relay that holds BOB's mailbox. Run with `--nocapture` to see the table.
//!
//! BEFORE: Alice and Bob share one relay; first contact is a directory lookup + KeyPackage claim + sequenced Welcome, all signed by Alice.
//! AFTER : Alice is on another relay and uses Bob's contact card; every request she makes to Bob's relay is unauthenticated.
//!
//! This measures what is in requests and storage. It does NOT measure traffic analysis (timing, sizes, source addresses): a relay still sees when
//! something arrives, how big it is and from which network address (hidden only if the client uses Tor).
mod harness;
use cipher_wire::{Id16, RelayDescriptor};
use harness::engine::*;
use harness::*;

#[derive(Debug, Default, PartialEq, Eq)]
struct View {
    /// Requests to the mailbox relay signed by the initiator (the relay learns WHO asked).
    signed_by_initiator: usize,
    /// Requests that name the target by a stable id (account or device) in the path or body.
    name_the_target: usize,
    /// Requests that are BOTH: the relay learns "initiator X asked about / wrote to target Y".
    initiator_to_target_links: usize,
    /// Rows in the mailbox relay's database that contain the initiator's account or device id.
    db_mentions_of_initiator: usize,
    /// Queue rows that carry a (keyed) sender hash.
    queue_rows_with_sender_hash: i64,
}

fn mentions(hay: &[u8], id: &Id16) -> bool {
    contains(hay, id.to_hex().as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn measure(
    initiator: &TestEngine,
    from: usize,
    base_filter: Option<&str>,
    target_acc: &Id16,
    target_dev: &Id16,
    init_acc: &Id16,
    init_dev: &Id16,
    w: &World,
) -> View {
    let log = initiator.transport.log.lock().unwrap();
    let bases = initiator.transport.requests_by_base.lock().unwrap();
    let mut v = View::default();
    for (i, ev) in log.iter().enumerate().skip(from) {
        if let Some(b) = base_filter {
            if bases.get(i).map(|(base, _)| !base.contains(b)).unwrap_or(true) {
                continue;
            }
        }
        let names = [target_acc, target_dev].iter().any(|t| ev.path.contains(&t.to_hex()) || mentions(&ev.req_body, t));
        v.signed_by_initiator += usize::from(ev.authed);
        v.name_the_target += usize::from(names);
        v.initiator_to_target_links += usize::from(ev.authed && names);
    }
    let (text, raw) = w.db_dump();
    // the DEVICE table necessarily lists devices registered on this relay; count mentions in everything EXCEPT that registration
    v.db_mentions_of_initiator =
        [init_acc, init_dev].iter().map(|id| text.matches(&id.to_hex()).count() + usize::from(mentions(&raw, id))).sum();
    v.queue_rows_with_sender_hash = w.rt.block_on(async {
        w.pool.get().await.unwrap().query_one("SELECT count(*) FROM queue WHERE sender_h IS NOT NULL", &[]).await.unwrap().get(0)
    });
    v
}

#[test]
fn first_contact_exposure_before_and_after() {
    // ---- BEFORE: one relay, directory flow ----
    let w = World::new();
    let (mut a, mut b) = (w.engine(), w.engine());
    let (ia, ib) = (a.public_identity().unwrap(), b.public_identity().unwrap());
    let mark = a.transport.log.lock().unwrap().len();
    a.add_contact_by_id(&ib.cipher_id, "Bob").unwrap();
    let conv = a.start_dm(&ib.account_id).unwrap();
    a.send_text(&conv, "hi", None).unwrap();
    a.sync().unwrap();
    let before = measure(&a, mark, None, &ib.account_id, &ib.device_id, &ia.account_id, &ia.device_id, &w);

    // ---- AFTER: two relays, card flow; the mailbox relay is B ----
    let (wa, wb) = (World::new(), World::new());
    let (mut alice, mut bob) = (wa.engine(), wb.engine());
    alice.set_own_relay(RelayDescriptor::new("https://relay-a.test", None).unwrap()).unwrap();
    bob.set_own_relay(RelayDescriptor::new("https://relay-b.test", None).unwrap()).unwrap();
    alice.transport.reach("https://relay-b.test", wb.app.clone(), wb.rt.clone());
    bob.transport.reach("https://relay-a.test", wa.app.clone(), wa.rt.clone());
    let (pa, pb) = (alice.public_identity().unwrap(), bob.public_identity().unwrap());
    let card = bob.create_contact_card(7).unwrap();
    let mark = alice.transport.log.lock().unwrap().len();
    alice.add_contact_by_card(&card, "Bob", true).unwrap();
    let conv = alice.start_dm(&pb.account_id).unwrap();
    alice.send_text(&conv, "hi", None).unwrap();
    alice.sync().unwrap();
    let after = measure(&alice, mark, Some("relay-b"), &pb.account_id, &pb.device_id, &pa.account_id, &pa.device_id, &wb);

    println!("\nWhat the relay holding BOB's mailbox sees of ALICE while she starts a conversation and sends one message");
    println!("{:<46} {:>8} {:>8}", "metric", "before", "after");
    println!("{:<46} {:>8} {:>8}", "requests signed by Alice (identity revealed)", before.signed_by_initiator, after.signed_by_initiator);
    println!("{:<46} {:>8} {:>8}", "requests naming Bob by stable id", before.name_the_target, after.name_the_target);
    println!("{:<46} {:>8} {:>8}", "requests linking Alice -> Bob", before.initiator_to_target_links, after.initiator_to_target_links);
    println!("{:<46} {:>8} {:>8}", "DB mentions of Alice's ids", before.db_mentions_of_initiator, after.db_mentions_of_initiator);
    println!(
        "{:<46} {:>8} {:>8}",
        "queue rows carrying a sender hash", before.queue_rows_with_sender_hash, after.queue_rows_with_sender_hash
    );

    assert!(
        before.initiator_to_target_links >= 2,
        "baseline: the same-relay flow links initiator and target in several signed requests: {before:?}"
    );
    assert!(before.signed_by_initiator >= 3 && before.db_mentions_of_initiator > 0);
    assert_eq!(after.signed_by_initiator, 0, "no request to Bob's relay identifies Alice");
    assert_eq!(after.initiator_to_target_links, 0);
    assert_eq!(after.db_mentions_of_initiator, 0, "Bob's relay never stores anything about Alice's account or device");
    assert_eq!(after.queue_rows_with_sender_hash, 0);
    // What REMAINS visible to Bob's relay (not hidden by any of this): that a holder of Bob's card capability connected, when, how often, how many bytes.
    assert!(after.name_the_target <= 3, "{after:?}: the card capability (not Bob's stable id) names the mailbox");
}
