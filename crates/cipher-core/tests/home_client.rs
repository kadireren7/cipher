#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! What a client does with the answers of a HOSTILE home relay (docs/CROSS_RELAY_GROUPS.md §7.3): every deviation from an honest, gap-free,
//! hash-chained log is refused; equivocation between members is caught as soon as they compare heads.
use cipher_core::error::SecurityError;
use cipher_core::home::*;
use cipher_wire::home::{chain_genesis, chain_next, home_tag, HomeLogEntry};
use cipher_wire::Id16;

struct Honest {
    tag: Id16,
    entries: Vec<HomeLogEntry>,
}

fn pubs(n: u64, branch: u8) -> ([u8; 32], [u8; 32]) {
    let mut c = [branch; 32];
    c[..8].copy_from_slice(&n.to_be_bytes());
    let mut r = [branch ^ 0x55; 32];
    r[..8].copy_from_slice(&n.to_be_bytes());
    (c, r)
}

/// A log of `n` entries; `branch` lets two relays-views diverge after a shared prefix.
fn log(n: u64, fork_at: Option<(u64, u8)>) -> Honest {
    let tag = home_tag(&[3; 16]);
    let mut prev = chain_genesis(&tag);
    let mut entries = vec![];
    for seq in 1..=n {
        let branch = match fork_at {
            Some((f, b)) if seq >= f => b,
            _ => 0,
        };
        let (c, r) = pubs(seq, branch);
        let id = Id16([seq as u8; 16]);
        let commit = format!("commit-{seq}-{branch}").into_bytes();
        prev = chain_next(&prev, seq, &id, &commit, &c, &r);
        entries.push(HomeLogEntry { seq, commit_id: id, commit, chain: prev.to_vec(), commit_pub: c.to_vec(), read_pub: r.to_vec() });
    }
    Honest { tag, entries }
}

fn protocol_msg<T>(r: cipher_core::Result<T>) -> &'static str {
    match r {
        Err(SecurityError::Protocol(m)) => m,
        Err(e) => panic!("unexpected error {e:?}"),
        Ok(_) => "accepted",
    }
}

#[test]
fn an_honest_log_verifies_page_by_page_and_resumes_from_any_verified_head() {
    let h = log(6, None);
    let mut ledger = HomeLedger::new(HomeHead::genesis(&h.tag));
    for chunk in h.entries.chunks(4) {
        for v in verify_page(&h.tag, &ledger.head, chunk).unwrap() {
            ledger.apply(&v);
        }
    }
    assert_eq!(ledger.head.seq, 6);
    assert_eq!(ledger.head.chain, h.entries[5].chain);
}

#[test]
fn a_dropped_entry_is_a_gap() {
    let h = log(5, None);
    let mut e = h.entries.clone();
    e.remove(2);
    assert_eq!(protocol_msg(verify_page(&h.tag, &HomeHead::genesis(&h.tag), &e)), FORK_GAP);
}

#[test]
fn reordered_or_repeated_entries_are_refused() {
    let h = log(5, None);
    let mut swapped = h.entries.clone();
    swapped.swap(1, 2);
    assert_eq!(protocol_msg(verify_page(&h.tag, &HomeHead::genesis(&h.tag), &swapped)), FORK_GAP);
    let mut repeated = h.entries.clone();
    repeated.insert(2, h.entries[1].clone());
    assert_eq!(protocol_msg(verify_page(&h.tag, &HomeHead::genesis(&h.tag), &repeated)), FORK_ROLLBACK);
}

#[test]
fn a_stale_log_is_a_rollback_not_news() {
    let h = log(6, None);
    let head = HomeHead::at(4, h.entries[3].chain.clone().try_into().unwrap());
    // the relay serves entries this device has already verified (it "rewound")
    assert_eq!(protocol_msg(verify_page(&h.tag, &head, &h.entries[1..3])), FORK_ROLLBACK);
    assert_eq!(
        check_reported_head(&HomeHead::at(4, h.entries[3].chain.clone().try_into().unwrap()), 3, &h.entries[2].chain)
            .unwrap_err()
            .to_string(),
        "protocol error: home log is behind what this device already verified"
    );
    // a re-statement of the same head is fine; the same position with another hash is not
    assert!(check_reported_head(&head, 4, &h.entries[3].chain).is_ok());
    assert!(check_reported_head(&head, 4, &[9; 32]).is_err());
    assert!(check_reported_head(&head, 6, &h.entries[5].chain).is_ok());
}

#[test]
fn rewritten_commits_or_swapped_epoch_keys_break_the_chain() {
    let h = log(4, None);
    let g = HomeHead::genesis(&h.tag);
    let mut a = h.entries.clone();
    a[1].commit.push(0);
    assert_eq!(protocol_msg(verify_page(&h.tag, &g, &a)), FORK_CHAIN);
    // the relay substitutes the keys of epoch 3 (to take over commit rights) but keeps the original chain value
    let mut b = h.entries.clone();
    b[2].commit_pub = vec![0xEE; 32];
    assert_eq!(protocol_msg(verify_page(&h.tag, &g, &b)), FORK_CHAIN);
    // ... or recomputes the chain to match: the page verifies (the chain alone cannot know), the members' own derivation catches it
    let mut c = h.entries.clone();
    let prev: [u8; 32] = c[1].chain.clone().try_into().unwrap();
    c[2].commit_pub = vec![0xEE; 32];
    c[2].chain = chain_next(&prev, 3, &c[2].commit_id, &c[2].commit, &[0xEE; 32], &c[2].read_pub.clone().try_into().unwrap()).to_vec();
    let verified = verify_page(&h.tag, &g, &c[..3]).unwrap();
    // what the members actually derived for epoch 3 (the honest keys)
    let honest = pubs(3, 0);
    assert_ne!(verified[2].commit_pub, honest.0);
    assert_eq!(protocol_msg(check_keys(&verified[2], honest)), FORK_KEYS);
    assert_eq!(check_keys(&verified[1], pubs(2, 0)).map(|_| "ok").unwrap(), "ok");
}

fn check_keys(v: &VerifiedEntry, expected: ([u8; 32], [u8; 32])) -> cipher_core::Result<()> {
    if v.commit_pub != expected.0 || v.read_pub != expected.1 {
        return Err(SecurityError::Protocol(FORK_KEYS));
    }
    Ok(())
}

#[test]
fn two_members_shown_different_histories_disagree_as_soon_as_they_compare_heads() {
    // The relay equivocates from entry 3 on: Alice is shown history A, Bob history B. Each log is internally perfect.
    let (a, b) = (log(5, None), log(5, Some((3, 7))));
    let tag = a.tag;
    let (mut alice, mut bob) = (HomeLedger::new(HomeHead::genesis(&tag)), HomeLedger::new(HomeHead::genesis(&tag)));
    for v in verify_page(&tag, &alice.head, &a.entries).unwrap() {
        alice.apply(&v);
    }
    for v in verify_page(&tag, &bob.head, &b.entries).unwrap() {
        bob.apply(&v);
    }
    assert_ne!(alice.head, bob.head, "no single-view check can tell");
    // they share entries 1 and 2, then diverge: a message carrying (seq, chain) exposes it in both directions
    assert_eq!(alice.gossip(2, &bob.chain_at(2).unwrap()), Gossip::Consistent);
    assert_eq!(alice.gossip(5, &bob.head.chain), Gossip::Fork);
    assert_eq!(bob.gossip(5, &alice.head.chain), Gossip::Fork);
    assert_eq!(alice.gossip(3, &b.entries[2].chain), Gossip::Fork);
    // a member that has not caught up yet cannot judge; one far behind the remembered window has nothing to compare with
    let behind = HomeLedger::new(HomeHead::at(1, a.entries[0].chain.clone().try_into().unwrap()));
    assert_eq!(behind.gossip(5, &alice.head.chain), Gossip::Ahead);
    let long = log(LEDGER_WINDOW as u64 + 10, None);
    let mut l = HomeLedger::new(HomeHead::genesis(&long.tag));
    for v in verify_page(&long.tag, &l.head, &long.entries).unwrap() {
        l.apply(&v);
    }
    assert_eq!(l.gossip(1, &long.entries[0].chain), Gossip::Unknown);
    assert_eq!(l.gossip(long.entries.len() as u64, &long.entries.last().unwrap().chain), Gossip::Consistent);
}
