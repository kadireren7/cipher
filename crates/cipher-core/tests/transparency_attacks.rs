#![cfg(feature = "transparency-experimental")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Attack tests for the EXPERIMENTAL key-transparency verifier (NOT PRODUCTION READY). They exercise a malicious or broken
//! log / relay: forged heads, rollback, forks, history rewrites, key substitution, malformed proofs, split views.
use cipher_core::transparency::*;
use cipher_wire::Id16;
use ct_merkle::mem_backed_tree::MemoryBackedTree;
use ed25519_dalek::{Signer, SigningKey};
use proptest::prelude::*;
use sha2_011::Sha256;

type Tree = MemoryBackedTree<Sha256, Vec<u8>>;
const NOW: u64 = 1_800_000_000;

fn log_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}
fn pinned() -> LogKey {
    LogKey::from_bytes(&log_key().verifying_key().to_bytes()).unwrap()
}
fn leaf(i: u8, seq: u64) -> BindingLeaf {
    BindingLeaf { account: Id16([i; 16]), identity_key: [i.wrapping_add(100); 32], seq }
}
fn tree(n: u8) -> Tree {
    let mut t = Tree::new();
    for i in 0..n {
        t.push(leaf(i, 0).to_bytes());
    }
    t
}
fn sign_with(sk: &SigningKey, t: &Tree, ts: u64) -> SignedTreeHead {
    let root: [u8; 32] = t.root().as_bytes().as_slice().try_into().unwrap();
    let size = t.len();
    let signature = sk.sign(&SignedTreeHead::signed_bytes(size, &root, ts)).to_bytes();
    SignedTreeHead { size, root, timestamp: ts, signature }
}
fn sth(t: &Tree) -> SignedTreeHead {
    sign_with(&log_key(), t, NOW)
}
fn incl(t: &Tree, idx: usize) -> InclusionEvidence {
    InclusionEvidence { head: sth(t), leaf_index: idx as u64, proof: t.prove_inclusion(idx).as_bytes().to_vec() }
}
fn cons(t: &Tree, added: usize) -> ConsistencyEvidence {
    ConsistencyEvidence { proof: t.prove_consistency(added).as_bytes().to_vec() }
}
fn verifier_at(t: &Tree) -> LogVerifier {
    let mut v = LogVerifier::new(pinned(), None).unwrap();
    assert_eq!(v.advance(&sth(t), None, NOW).unwrap(), Advance::Initial);
    v
}

#[test]
fn honest_log_inclusion_and_extension_work() {
    let mut t = tree(5);
    let mut v = verifier_at(&t);
    assert_eq!(v.check_inclusion(&leaf(2, 0), &incl(&t, 2)).unwrap(), Verdict::Included);
    for i in 5..8 {
        t.push(leaf(i, 0).to_bytes());
    }
    assert_eq!(v.advance(&sth(&t), Some(&cons(&t, 3)), NOW).unwrap(), Advance::Extended);
    assert_eq!(v.check_inclusion(&leaf(7, 0), &incl(&t, 7)).unwrap(), Verdict::Included);
    // evidence issued under the OLD head is no longer accepted against the new head
    let old = tree(5);
    assert_eq!(v.check_inclusion(&leaf(2, 0), &incl(&old, 2)), Err(KtError::HeadMismatch));
    assert_eq!(v.advance(&sth(&t), None, NOW).unwrap(), Advance::Unchanged);
}

#[test]
fn forged_or_tampered_heads_are_rejected() {
    let t = tree(4);
    let mut v = LogVerifier::new(pinned(), None).unwrap();
    // signed by someone else
    let evil = SigningKey::from_bytes(&[9u8; 32]);
    assert_eq!(v.advance(&sign_with(&evil, &t, NOW), None, NOW), Err(KtError::BadSignature));
    // each field tampered after signing
    let good = sth(&t);
    let mut a = good.clone();
    a.root[0] ^= 1;
    let mut b = good.clone();
    b.size += 1;
    let mut c = good.clone();
    c.timestamp += 1;
    let mut d = good.clone();
    d.signature[10] ^= 1;
    for bad in [a, b, c, d] {
        assert_eq!(v.advance(&bad, None, NOW), Err(KtError::BadSignature));
    }
    assert!(v.head().is_none(), "a rejected head must not change state");
}

#[test]
fn persisted_head_is_reverified_because_storage_is_not_trusted() {
    let t = tree(4);
    let mut h = sth(&t);
    h.size = 400; // rolled-forward by someone with file access
    assert!(matches!(LogVerifier::new(pinned(), Some(h)), Err(KtError::BadSignature)));
    assert!(LogVerifier::new(pinned(), Some(sth(&t))).is_ok());
}

#[test]
fn rollback_to_a_smaller_tree_is_refused() {
    let t8 = tree(8);
    let mut v = verifier_at(&t8);
    let t5 = tree(5);
    assert_eq!(v.advance(&sth(&t5), Some(&cons(&t8, 3)), NOW), Err(KtError::Rollback));
    assert_eq!(v.head().unwrap().size, 8);
}

#[test]
fn a_fork_at_the_same_size_yields_transferable_evidence() {
    let t = tree(6);
    let mut v = verifier_at(&t);
    let mut fork = tree(5);
    fork.push(leaf(99, 0).to_bytes()); // same size, different last leaf, validly signed by the (malicious) log
    match v.advance(&sth(&fork), None, NOW) {
        Err(KtError::Fork(ev)) => {
            ev.a.verify(&pinned()).unwrap();
            ev.b.verify(&pinned()).unwrap();
            assert_eq!(ev.a.size, ev.b.size);
            assert_ne!(ev.a.root, ev.b.root);
        }
        other => panic!("expected Fork, got {other:?}"),
    }
}

#[test]
fn extension_needs_a_valid_proof_and_a_rewritten_history_has_none() {
    let t = tree(4);
    let mut v = verifier_at(&t);
    let mut grown = tree(4);
    grown.push(leaf(4, 0).to_bytes());
    grown.push(leaf(5, 0).to_bytes());
    assert_eq!(v.advance(&sth(&grown), None, NOW), Err(KtError::NotConsistent), "no proof, no extension");
    // history rewrite: the log changed leaf 1 and then appended; any proof it can build is for the REWRITTEN tree
    let mut rewritten = Tree::new();
    for i in 0..4u8 {
        rewritten.push(leaf(if i == 1 { 77 } else { i }, 0).to_bytes());
    }
    rewritten.push(leaf(4, 0).to_bytes());
    rewritten.push(leaf(5, 0).to_bytes());
    assert_eq!(v.advance(&sth(&rewritten), Some(&cons(&rewritten, 2)), NOW), Err(KtError::NotConsistent));
    // a proof that belongs to a different extension size
    assert_eq!(
        v.advance(&sth(&grown), Some(&cons(&grown, 1)), NOW),
        Err(KtError::Malformed("consistency proof")).or(Err(KtError::NotConsistent))
    );
    assert_eq!(v.head().unwrap().size, 4);
}

#[test]
fn substituted_key_wrong_index_and_tampered_proofs_fail_inclusion() {
    let t = tree(7);
    let v = verifier_at(&t);
    // the relay claims a different key for account 3
    let mut swapped = leaf(3, 0);
    swapped.identity_key = [0xEE; 32];
    assert_eq!(v.check_inclusion(&swapped, &incl(&t, 3)), Err(KtError::InclusionFailed));
    // wrong sequence number
    assert_eq!(v.check_inclusion(&leaf(3, 1), &incl(&t, 3)), Err(KtError::InclusionFailed));
    // right leaf, wrong index
    let mut e = incl(&t, 3);
    e.leaf_index = 4;
    assert_eq!(v.check_inclusion(&leaf(3, 0), &e), Err(KtError::InclusionFailed));
    // out-of-range index
    e.leaf_index = 7;
    assert_eq!(v.check_inclusion(&leaf(3, 0), &e), Err(KtError::InclusionFailed));
    e.leaf_index = u64::MAX;
    assert_eq!(v.check_inclusion(&leaf(3, 0), &e), Err(KtError::InclusionFailed));
    // every single bit of the proof matters
    let good = incl(&t, 3);
    for byte in 0..good.proof.len() {
        let mut bad = good.clone();
        bad.proof[byte] ^= 0x80;
        assert_eq!(v.check_inclusion(&leaf(3, 0), &bad), Err(KtError::InclusionFailed), "byte {byte}");
    }
    // truncated / oversized / misaligned proofs are malformed, never a panic
    for len in [0usize, 1, 31, 33] {
        let mut bad = good.clone();
        bad.proof.truncate(len);
        assert!(v.check_inclusion(&leaf(3, 0), &bad).is_err());
    }
    let mut huge = good.clone();
    huge.proof = vec![0u8; MAX_PROOF_BYTES + 32];
    assert_eq!(v.check_inclusion(&leaf(3, 0), &huge), Err(KtError::Malformed("proof length")));
}

#[test]
fn heads_from_the_future_and_empty_logs_are_refused() {
    let t = tree(3);
    let mut v = LogVerifier::new(pinned(), None).unwrap();
    assert_eq!(v.advance(&sign_with(&log_key(), &t, NOW + MAX_FUTURE_SKEW_SECS + 1), None, NOW), Err(KtError::FutureTimestamp));
    assert!(v.advance(&sign_with(&log_key(), &t, NOW + MAX_FUTURE_SKEW_SECS), None, NOW).is_ok());
    let empty = Tree::new();
    let mut v2 = LogVerifier::new(pinned(), None).unwrap();
    assert_eq!(v2.advance(&sth(&empty), None, NOW), Err(KtError::EmptyLog));
}

#[test]
fn gossip_detects_a_split_view_and_is_not_fooled_by_garbage() {
    let honest = tree(6);
    let mut forked = tree(5);
    forked.push(leaf(50, 0).to_bytes());
    // same size, different roots, both signed by the log: a split view
    match gossip_compare(&sth(&honest), &sth(&forked), &pinned(), None).unwrap() {
        GossipOutcome::SplitView(ev) => {
            ev.a.verify(&pinned()).unwrap();
            ev.b.verify(&pinned()).unwrap();
        }
        other => panic!("{other:?}"),
    }
    // identical heads
    assert_eq!(gossip_compare(&sth(&honest), &sth(&honest), &pinned(), None).unwrap(), GossipOutcome::Consistent);
    // honest extension with a real proof
    let mut longer = tree(6);
    longer.push(leaf(6, 0).to_bytes());
    assert_eq!(gossip_compare(&sth(&honest), &sth(&longer), &pinned(), Some(&cons(&longer, 1))).unwrap(), GossipOutcome::Consistent);
    assert_eq!(
        gossip_compare(&sth(&longer), &sth(&honest), &pinned(), Some(&cons(&longer, 1))).unwrap(),
        GossipOutcome::Consistent,
        "argument order is irrelevant"
    );
    // different sizes and no proof: neither confirmed nor refuted
    assert_eq!(gossip_compare(&sth(&honest), &sth(&longer), &pinned(), None).unwrap(), GossipOutcome::Inconclusive);
    // garbage proof must NOT be treated as an accusation of the log
    let junk = ConsistencyEvidence { proof: vec![1u8; 32] };
    assert_eq!(gossip_compare(&sth(&honest), &sth(&longer), &pinned(), Some(&junk)).unwrap(), GossipOutcome::Inconclusive);
    // an unsigned head can never be used to accuse anyone
    let evil = SigningKey::from_bytes(&[3u8; 32]);
    assert_eq!(gossip_compare(&sth(&honest), &sign_with(&evil, &forked, NOW), &pinned(), None), Err(KtError::BadSignature));
}

#[test]
fn default_is_not_available_and_missing_evidence_never_means_included() {
    let t = tree(3);
    let mut none = NoTransparency;
    assert_eq!(none.check_binding(&leaf(1, 0), Some(&incl(&t, 1)), NOW).unwrap(), Verdict::NotAvailable);
    let mut v = verifier_at(&t);
    assert_eq!(v.check_binding(&leaf(1, 0), None, NOW).unwrap(), Verdict::NotAvailable);
    assert_eq!(v.check_binding(&leaf(1, 0), Some(&incl(&t, 1)), NOW).unwrap(), Verdict::Included);
}

/// Manual QR / safety-number verification must stay independent: this module can neither read nor write a trust state, and a
/// verdict has no "Verified" variant (this `match` must stay exhaustive with exactly these two arms).
#[test]
fn transparency_is_structurally_independent_of_manual_verification() {
    let v = Verdict::Included;
    match v {
        Verdict::NotAvailable | Verdict::Included => {}
    }
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/transparency.rs")).unwrap();
    let code: String = src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
    for banned in ["TrustState", "Trust::", "Contact", "crate::verification", "crate::app", "Verified", "set_trust", "pin_identity"] {
        assert!(!code.contains(banned), "transparency must not touch trust decisions (found `{banned}`)");
    }
    // and nothing outside the module (and its tests) depends on it
    for f in ["app/engine.rs", "app/engine_msg.rs", "verification.rs", "mls.rs", "protocol.rs"] {
        let s = std::fs::read_to_string(format!("{}/src/{f}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let uses =
            s.lines().filter(|l| !l.trim_start().starts_with("//")).any(|l| l.contains("transparency::") || l.contains("mod transparency"));
        assert!(!uses, "{f} must not depend on the experimental transparency module");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn every_leaf_of_every_small_tree_verifies_and_any_other_leaf_does_not(n in 1u8..40, pick in any::<u8>(), other in any::<u8>()) {
        let t = tree(n);
        let v = verifier_at(&t);
        let idx = (pick % n) as usize;
        prop_assert_eq!(v.check_inclusion(&leaf(idx as u8, 0), &incl(&t, idx)), Ok(Verdict::Included));
        let wrong = other % 200;
        if wrong as usize != idx {
            prop_assert!(v.check_inclusion(&leaf(wrong, 0), &incl(&t, idx)).is_err());
        }
    }

    #[test]
    fn consistency_holds_for_honest_growth_and_fails_for_any_edit(old in 1u8..30, add in 1u8..20, edit in any::<u8>()) {
        let t_old = tree(old);
        let mut t_new = tree(old);
        for i in 0..add { t_new.push(leaf(old + i, 0).to_bytes()); }
        let mut v = verifier_at(&t_old);
        prop_assert_eq!(v.advance(&sth(&t_new), Some(&cons(&t_new, add as usize)), NOW), Ok(Advance::Extended));
        // same growth but one of the OLD leaves differs in the new tree -> must be refused
        let mut edited = Tree::new();
        let victim = edit % old;
        for i in 0..old { edited.push(leaf(if i == victim { 200 } else { i }, 0).to_bytes()); }
        for i in 0..add { edited.push(leaf(old + i, 0).to_bytes()); }
        let mut v2 = verifier_at(&t_old);
        prop_assert!(v2.advance(&sth(&edited), Some(&cons(&edited, add as usize)), NOW).is_err());
    }
}
