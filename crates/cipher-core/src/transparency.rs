//! EXPERIMENTAL KEY TRANSPARENCY VERIFIER — **NOT PRODUCTION READY**.
//!
//! What this is: the *client-side verification half* of an append-only, publicly auditable log of
//! `(account, identity key)` bindings, so a relay that shows different keys to different people can be caught.
//! What it is not: there is no log server, nothing in the app calls this, and nothing here is wired to trust decisions.
//!
//! Design (docs/KEY_TRANSPARENCY.md):
//!  * Merkle tree proofs (inclusion, consistency) are RFC 6962/9162; they come from the `ct-merkle` crate, we do not
//!    re-implement them. Tree heads are signed with Ed25519 by a log key the client has PINNED out of band.
//!  * The verifier keeps one accepted head and only ever moves forward, and only with a valid consistency proof:
//!    rollback, a fork at the same size, and an unprovable extension are all errors that carry the evidence.
//!  * `gossip_compare` lets two clients that saw different heads detect a split view (two validly signed heads that are
//!    not consistent with each other are transferable proof of log misbehaviour).
//!  * INDEPENDENCE FROM MANUAL VERIFICATION: no function in this module takes or returns a trust state, and the only
//!    verdicts are `NotAvailable` and `Included`. A log can ADD a warning; it can never mark a contact VERIFIED, and it
//!    can never override a safety-number / QR comparison. `tests/transparency_attacks.rs` asserts this.
//!
//! Known gaps (all open): first-head trust (TOFU on the log head), no gossip transport, no monitor for the account's own
//! keys, no log-operator key rotation, `ct-merkle` is unaudited, and the leaf format is a draft.
use cipher_wire::Id16;
use ct_merkle::{ConsistencyProof, InclusionProof, RootHash};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2_011::Sha256;

pub const STH_CONTEXT: &[u8] = b"cipher-kt-sth-v1";
pub const LEAF_CONTEXT: &[u8] = b"cipher-kt-leaf-v1";
/// A head stamped further in the future than this is rejected (a log cannot pre-date heads to dodge a freshness policy).
pub const MAX_FUTURE_SKEW_SECS: u64 = 300;
/// Hard cap on proof size accepted from the network: 64 hashes covers a tree of 2^64 leaves.
pub const MAX_PROOF_BYTES: usize = 64 * 32;

type Root = RootHash<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KtError {
    Malformed(&'static str),
    BadSignature,
    FutureTimestamp,
    EmptyLog,
    /// The new head is smaller than the accepted one.
    Rollback,
    /// Two validly signed heads of the same size with different roots: transferable proof of a split view.
    Fork(Box<SplitViewEvidence>),
    /// A larger head without (or with an invalid) consistency proof.
    NotConsistent,
    InclusionFailed,
    /// Inclusion evidence was issued under a head other than the verifier's current head.
    HeadMismatch,
}

/// The pinned public key of the log operator. Pinning is out of band (shipped with the app or provisioned by the operator).
#[derive(Clone)]
pub struct LogKey(VerifyingKey);

impl LogKey {
    pub fn from_bytes(b: &[u8; 32]) -> Result<Self, KtError> {
        VerifyingKey::from_bytes(b).map(Self).map_err(|_| KtError::Malformed("log key"))
    }
}

impl std::fmt::Debug for LogKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LogKey(..)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTreeHead {
    pub size: u64,
    pub root: [u8; 32],
    pub timestamp: u64,
    pub signature: [u8; 64],
}

impl SignedTreeHead {
    /// Domain-separated bytes the log signs: context || size || root || timestamp (big endian).
    pub fn signed_bytes(size: u64, root: &[u8; 32], timestamp: u64) -> Vec<u8> {
        let mut m = Vec::with_capacity(STH_CONTEXT.len() + 48);
        m.extend_from_slice(STH_CONTEXT);
        m.extend_from_slice(&size.to_be_bytes());
        m.extend_from_slice(root);
        m.extend_from_slice(&timestamp.to_be_bytes());
        m
    }

    pub fn verify(&self, key: &LogKey) -> Result<(), KtError> {
        let sig = Signature::from_slice(&self.signature).map_err(|_| KtError::BadSignature)?;
        key.0.verify(&Self::signed_bytes(self.size, &self.root, self.timestamp), &sig).map_err(|_| KtError::BadSignature)
    }

    fn root_hash(&self) -> Root {
        Root::new(self.root.into(), self.size)
    }
}

/// Two heads signed by the same log that cannot both belong to one append-only history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitViewEvidence {
    pub a: SignedTreeHead,
    pub b: SignedTreeHead,
}

/// What the log binds: an account's identity key and a sequence number (a key change is a NEW leaf, never an overwrite).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingLeaf {
    pub account: Id16,
    pub identity_key: [u8; 32],
    pub seq: u64,
}

impl BindingLeaf {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(LEAF_CONTEXT.len() + 56);
        v.extend_from_slice(LEAF_CONTEXT);
        v.extend_from_slice(&self.account.0);
        v.extend_from_slice(&self.identity_key);
        v.extend_from_slice(&self.seq.to_be_bytes());
        v
    }
}

#[derive(Debug, Clone)]
pub struct InclusionEvidence {
    pub head: SignedTreeHead,
    pub leaf_index: u64,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ConsistencyEvidence {
    pub proof: Vec<u8>,
}

/// The only two outcomes. There is deliberately no `Verified`: this signal can warn, never vouch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    NotAvailable,
    Included,
}

/// Interface the rest of the app can program against while no log exists.
pub trait KeyTransparency {
    fn check_binding(&mut self, leaf: &BindingLeaf, evidence: Option<&InclusionEvidence>, now: u64) -> Result<Verdict, KtError>;
}

/// The default: transparency is not available, and says so.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoTransparency;

impl KeyTransparency for NoTransparency {
    fn check_binding(&mut self, _: &BindingLeaf, _: Option<&InclusionEvidence>, _: u64) -> Result<Verdict, KtError> {
        Ok(Verdict::NotAvailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advance {
    /// First head accepted (trust on first use of the head; documented gap).
    Initial,
    Unchanged,
    Extended,
}

#[derive(Debug)]
pub struct LogVerifier {
    key: LogKey,
    head: Option<SignedTreeHead>,
}

fn proof_ok(b: &[u8]) -> Result<(), KtError> {
    if b.len() > MAX_PROOF_BYTES || b.len() % 32 != 0 {
        return Err(KtError::Malformed("proof length"));
    }
    Ok(())
}

impl LogVerifier {
    /// `trusted_head` is the last head this client persisted (re-verified here: storage is not trusted either).
    pub fn new(key: LogKey, trusted_head: Option<SignedTreeHead>) -> Result<Self, KtError> {
        if let Some(h) = &trusted_head {
            h.verify(&key)?;
            if h.size == 0 {
                return Err(KtError::EmptyLog);
            }
        }
        Ok(Self { key, head: trusted_head })
    }

    pub fn head(&self) -> Option<&SignedTreeHead> {
        self.head.as_ref()
    }

    /// Move to a newer head. Never moves backwards, never accepts a fork, never accepts an unprovable extension.
    pub fn advance(&mut self, new: &SignedTreeHead, proof: Option<&ConsistencyEvidence>, now: u64) -> Result<Advance, KtError> {
        new.verify(&self.key)?;
        if new.timestamp > now.saturating_add(MAX_FUTURE_SKEW_SECS) {
            return Err(KtError::FutureTimestamp);
        }
        if new.size == 0 {
            return Err(KtError::EmptyLog);
        }
        let Some(old) = self.head.clone() else {
            self.head = Some(new.clone());
            return Ok(Advance::Initial);
        };
        if new.size < old.size {
            return Err(KtError::Rollback);
        }
        if new.size == old.size {
            if new.root != old.root {
                return Err(KtError::Fork(Box::new(SplitViewEvidence { a: old, b: new.clone() })));
            }
            return Ok(Advance::Unchanged);
        }
        let proof = proof.ok_or(KtError::NotConsistent)?;
        proof_ok(&proof.proof)?;
        let cp = ConsistencyProof::<Sha256>::try_from_bytes(proof.proof.clone()).map_err(|_| KtError::Malformed("consistency proof"))?;
        new.root_hash().verify_consistency(&old.root_hash(), &cp).map_err(|_| KtError::NotConsistent)?;
        self.head = Some(new.clone());
        Ok(Advance::Extended)
    }

    /// Is `leaf` included in the log under the verifier's CURRENT head?
    pub fn check_inclusion(&self, leaf: &BindingLeaf, ev: &InclusionEvidence) -> Result<Verdict, KtError> {
        let head = self.head.as_ref().ok_or(KtError::HeadMismatch)?;
        ev.head.verify(&self.key)?;
        if ev.head != *head {
            return Err(KtError::HeadMismatch);
        }
        proof_ok(&ev.proof)?;
        let proof = InclusionProof::<Sha256>::try_from_bytes(ev.proof.clone()).map_err(|_| KtError::Malformed("inclusion proof"))?;
        head.root_hash().verify_inclusion(&leaf.to_bytes(), ev.leaf_index, &proof).map_err(|_| KtError::InclusionFailed)?;
        Ok(Verdict::Included)
    }
}

impl KeyTransparency for LogVerifier {
    fn check_binding(&mut self, leaf: &BindingLeaf, evidence: Option<&InclusionEvidence>, _now: u64) -> Result<Verdict, KtError> {
        match evidence {
            None => Ok(Verdict::NotAvailable),
            Some(ev) => self.check_inclusion(leaf, ev),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipOutcome {
    Consistent,
    /// Both heads are validly signed by the log and cannot belong to one history.
    SplitView(Box<SplitViewEvidence>),
    /// Different sizes and no proof available: neither confirmed nor refuted.
    Inconclusive,
}

/// Compare two heads (e.g. ours and one a peer showed us). `proof` must prove `smaller` is a prefix of `larger`.
pub fn gossip_compare(
    a: &SignedTreeHead,
    b: &SignedTreeHead,
    key: &LogKey,
    proof: Option<&ConsistencyEvidence>,
) -> Result<GossipOutcome, KtError> {
    a.verify(key)?;
    b.verify(key)?;
    if a.size == 0 || b.size == 0 {
        return Err(KtError::EmptyLog);
    }
    if a.size == b.size {
        return Ok(if a.root == b.root {
            GossipOutcome::Consistent
        } else {
            GossipOutcome::SplitView(Box::new(SplitViewEvidence { a: a.clone(), b: b.clone() }))
        });
    }
    let (small, large) = if a.size < b.size { (a, b) } else { (b, a) };
    let Some(p) = proof else { return Ok(GossipOutcome::Inconclusive) };
    proof_ok(&p.proof)?;
    let cp = ConsistencyProof::<Sha256>::try_from_bytes(p.proof.clone()).map_err(|_| KtError::Malformed("consistency proof"))?;
    match large.root_hash().verify_consistency(&small.root_hash(), &cp) {
        Ok(()) => Ok(GossipOutcome::Consistent),
        // A bad proof alone proves nothing (anyone can send garbage); it is only "inconclusive", never an accusation.
        Err(_) => Ok(GossipOutcome::Inconclusive),
    }
}
