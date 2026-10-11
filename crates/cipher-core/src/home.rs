//! Client side of a cross-relay group's home-relay log (docs/CROSS_RELAY_GROUPS.md §7): credentials derived from the MLS exporter, request signing,
//! and the strict verification of what a (possibly hostile) relay returns.
//!
//! The relay is trusted for ordering and availability ONLY. Everything it returns is checked here: gap-free sequence numbers, the hash chain, and
//! that the public keys it stored for an epoch are the ones the members themselves derive. Any deviation is a fork alarm, never a silent accept.
use crate::error::{Result, SecurityError};
use crate::mls::HomeKeys;
use cipher_wire::home::{chain_genesis, chain_next, request_message, HomeLogEntry};
use cipher_wire::Id16;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};

/// The signing keys of ONE epoch. `epoch` is the MLS epoch the exporter secrets belong to.
pub struct HomeCreds {
    pub epoch: u64,
    commit: SigningKey,
    read: SigningKey,
}

impl std::fmt::Debug for HomeCreds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HomeCreds(epoch {}, keys redacted)", self.epoch)
    }
}

impl HomeCreds {
    /// The exporter output is uniformly random, so it is used directly as the Ed25519 seed (one label per key, never reused for anything else).
    pub fn new(epoch: u64, keys: &HomeKeys) -> Self {
        Self { epoch, commit: SigningKey::from_bytes(&keys.commit), read: SigningKey::from_bytes(&keys.read) }
    }

    pub fn commit_pub(&self) -> [u8; 32] {
        self.commit.verifying_key().to_bytes()
    }

    pub fn read_pub(&self) -> [u8; 32] {
        self.read.verifying_key().to_bytes()
    }

    pub fn sign_commit(&self, method: &str, path: &str, body: &[u8]) -> String {
        cipher_wire::home::auth_value(self.epoch, &self.commit.sign(&request_message(self.epoch, method, path, body)).to_bytes())
    }

    pub fn sign_read(&self, method: &str, path: &str, body: &[u8]) -> String {
        cipher_wire::home::auth_value(self.epoch, &self.read.sign(&request_message(self.epoch, method, path, body)).to_bytes())
    }
}

/// What this device has verified of a group's log: the last entry it applied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeHead {
    pub seq: u64,
    pub chain: Vec<u8>,
}

impl HomeHead {
    /// The state before the first entry.
    pub fn genesis(tag: &Id16) -> Self {
        Self { seq: 0, chain: chain_genesis(tag).to_vec() }
    }

    /// A head learned from a trusted source (the committer's own accepted commit).
    pub fn at(seq: u64, chain: [u8; 32]) -> Self {
        Self { seq, chain: chain.to_vec() }
    }

    fn chain32(&self) -> Result<[u8; 32]> {
        self.chain.as_slice().try_into().map_err(|_| SecurityError::StorageCorrupt)
    }
}

/// An entry whose position and hash chain were verified against the previous head.
#[derive(Clone, Debug)]
pub struct VerifiedEntry {
    pub seq: u64,
    pub commit_id: Id16,
    pub commit: Vec<u8>,
    pub chain: [u8; 32],
    pub commit_pub: [u8; 32],
    pub read_pub: [u8; 32],
}

/// Why a log was refused. All of these mean the relay (or something between us and it) is not behaving as a log: the caller raises a fork alarm.
pub const FORK_GAP: &str = "home log has a gap or is out of order";
pub const FORK_CHAIN: &str = "home log hash chain does not match";
pub const FORK_ROLLBACK: &str = "home log is behind what this device already verified";
pub const FORK_EQUIVOCATION: &str = "members were shown different histories by the home relay";
pub const FORK_KEYS: &str = "home log public keys differ from the ones the members derived";

/// Verify a page of entries that should directly follow `head`. Entries older than `head` are tolerated only if they equal what was already
/// verified (a re-delivery); anything else is a rollback or a rewrite.
pub fn verify_page(tag: &Id16, head: &HomeHead, entries: &[HomeLogEntry]) -> Result<Vec<VerifiedEntry>> {
    let mut prev = head.chain32()?;
    let mut next_seq = head.seq + 1;
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        if e.seq != next_seq {
            return Err(SecurityError::Protocol(if e.seq < next_seq { FORK_ROLLBACK } else { FORK_GAP }));
        }
        let (commit_pub, read_pub) = e.keys().map_err(|_| SecurityError::Protocol(FORK_CHAIN))?;
        let chain = chain_next(&prev, e.seq, &e.commit_id, &e.commit, &commit_pub, &read_pub);
        if e.chain.as_slice() != chain.as_slice() {
            return Err(SecurityError::Protocol(FORK_CHAIN));
        }
        out.push(VerifiedEntry { seq: e.seq, commit_id: e.commit_id, commit: e.commit.clone(), chain, commit_pub, read_pub });
        prev = chain;
        next_seq += 1;
    }
    let _ = tag;
    Ok(out)
}

/// After applying entry `entry` locally, the members' own derivation of that epoch's public keys must equal what the relay stored.
pub fn check_epoch_keys(entry: &VerifiedEntry, derived: &HomeCreds) -> Result<()> {
    if derived.epoch != entry.seq || derived.commit_pub() != entry.commit_pub || derived.read_pub() != entry.read_pub {
        return Err(SecurityError::Protocol(FORK_KEYS));
    }
    Ok(())
}

/// The head a relay reports for a reader at the head epoch must extend (or equal) what this device verified.
pub fn check_reported_head(local: &HomeHead, reported_seq: u64, reported_chain: &[u8]) -> Result<()> {
    if reported_seq < local.seq {
        return Err(SecurityError::Protocol(FORK_ROLLBACK));
    }
    if reported_seq == local.seq && reported_chain != local.chain.as_slice() {
        return Err(SecurityError::Protocol(FORK_CHAIN));
    }
    Ok(())
}

/// Recent positions of the verified chain, so a head claimed by ANOTHER member (carried in an authenticated group message) can be compared with
/// what this device verified itself. Two members that were shown different histories by the home relay disagree here as soon as they exchange
/// one message; this is the equivocation detector of docs/CROSS_RELAY_GROUPS.md §7.3. (A permanent partition that never exchanges a message is
/// not detectable by any single-sequencer design.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeLedger {
    pub head: HomeHead,
    recent: Vec<(u64, Vec<u8>)>,
}

pub const LEDGER_WINDOW: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum Gossip {
    /// The other member's head is on the chain this device verified.
    Consistent,
    /// The other member is further ahead than this device has verified: compare again after catching up.
    Ahead,
    /// Older than the remembered window: nothing to compare against.
    Unknown,
    /// Same position, different history: the relay equivocated (or someone lies). Raise the alarm.
    Fork,
}

impl HomeLedger {
    pub fn new(head: HomeHead) -> Self {
        Self { recent: vec![(head.seq, head.chain.clone())], head }
    }

    pub fn apply(&mut self, e: &VerifiedEntry) {
        self.head = HomeHead { seq: e.seq, chain: e.chain.to_vec() };
        self.recent.push((e.seq, e.chain.to_vec()));
        if self.recent.len() > LEDGER_WINDOW {
            self.recent.remove(0);
        }
    }

    /// The chain value this device verified at `seq`, if still remembered.
    pub fn chain_at(&self, seq: u64) -> Option<Vec<u8>> {
        self.recent.iter().find(|(s, _)| *s == seq).map(|(_, c)| c.clone())
    }

    pub fn gossip(&self, seq: u64, chain: &[u8]) -> Gossip {
        if seq > self.head.seq {
            return Gossip::Ahead;
        }
        match self.recent.iter().find(|(s, _)| *s == seq) {
            Some((_, c)) if c.as_slice() == chain => Gossip::Consistent,
            Some(_) => Gossip::Fork,
            None => Gossip::Unknown,
        }
    }
}
