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
