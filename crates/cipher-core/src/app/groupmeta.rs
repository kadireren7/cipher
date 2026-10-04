//! Group metadata carried in an MLS **GroupContext extension**, and the authorization rules for changing it.
//!
//! Why here: GroupContext extensions are authenticated by the MLS key schedule and signed into every epoch,
//! so every member holds the *same* role table for the same epoch and the relay cannot alter it. Authorization
//! is enforced by each client when it processes a staged commit (`authorize_commit`), *before* merging: a
//! commit that violates the rules is dropped and the group state is unchanged. The relay is never consulted.
//!
//! Roles: OWNER (exactly one), ADMIN, MEMBER (implicit: no table entry).
//!
//! | Operation                         | OWNER | ADMIN                | MEMBER                  |
//! | --------------------------------- | ----- | -------------------- | ----------------------- |
//! | add a new account                 | yes   | yes                  | no                      |
//! | add a device of an existing member| yes   | yes                  | only for their own account |
//! | remove a member (all devices)     | any other member | MEMBERs only | no                    |
//! | remove own device(s) / leave      | via admin commit (cannot self-commit) | same | same        |
//! | promote / demote / transfer owner | yes   | no                   | no                      |
//! | rename group                      | yes   | yes                  | no                      |
//! | refresh own keys (self-update)    | yes   | yes                  | yes                     |
use super::model::Role;
use cipher_wire::Id16;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const META_EXTENSION_TYPE: u16 = 0xF1A0;
pub const MAX_NAME_CHARS: usize = 64;
pub const MAX_ADMINS: usize = 50;
pub const MAX_META_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetaKind {
    Dm,
    Group,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleEntry {
    pub account: Id16,
    pub role: Role, // Owner or Admin only
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMeta {
    pub v: u8,
    pub kind: MetaKind,
    /// Relay routing tag (rotates on removals).
    pub tag: Id16,
    pub name: String,
    /// Sorted by account id; contains only OWNER and ADMIN entries.
    pub roles: Vec<RoleEntry>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum MetaError {
    #[error("malformed group metadata")]
    Malformed,
    #[error("group metadata violates invariants")]
    Invariant,
}

impl GroupMeta {
    pub fn new_group(tag: Id16, name: &str, owner: Id16) -> Self {
        Self {
            v: 1,
            kind: MetaKind::Group,
            tag,
            name: name.chars().take(MAX_NAME_CHARS).collect(),
            roles: vec![RoleEntry { account: owner, role: Role::Owner }],
        }
    }

    pub fn new_dm(tag: Id16) -> Self {
        Self { v: 1, kind: MetaKind::Dm, tag, name: String::new(), roles: Vec::new() }
    }

    pub fn role_of(&self, account: &Id16) -> Role {
        self.roles.iter().find(|r| &r.account == account).map_or(Role::Member, |r| r.role)
    }

    pub fn owner(&self) -> Option<Id16> {
        self.roles.iter().find(|r| r.role == Role::Owner).map(|r| r.account)
    }

    pub fn normalised(mut self) -> Self {
        self.roles.sort_by_key(|r| r.account);
        self
    }

    pub fn encode(&self) -> Result<Vec<u8>, MetaError> {
        self.validate_shape()?;
        let b = serde_json::to_vec(&self.clone().normalised()).map_err(|_| MetaError::Malformed)?;
        if b.len() > MAX_META_BYTES {
            return Err(MetaError::Malformed);
        }
        Ok(b)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MetaError> {
        if bytes.len() > MAX_META_BYTES {
            return Err(MetaError::Malformed);
        }
        let m: GroupMeta = serde_json::from_slice(bytes).map_err(|_| MetaError::Malformed)?;
        m.validate_shape()?;
        // Canonical form only: a non-canonical encoding could let two honest clients disagree about equality.
        if m.encode()? != bytes {
            return Err(MetaError::Malformed);
        }
        Ok(m)
    }

    /// Shape invariants independent of membership.
    pub fn validate_shape(&self) -> Result<(), MetaError> {
        if self.v != 1 || self.name.chars().count() > MAX_NAME_CHARS || self.name.chars().any(super::model::is_disguising_char) {
            return Err(MetaError::Invariant);
        }
        let mut seen = BTreeSet::new();
        for r in &self.roles {
            if r.role == Role::Member || !seen.insert(r.account) {
                return Err(MetaError::Invariant);
            }
        }
        let owners = self.roles.iter().filter(|r| r.role == Role::Owner).count();
        let admins = self.roles.iter().filter(|r| r.role == Role::Admin).count();
        match self.kind {
            MetaKind::Dm => {
                if !self.roles.is_empty() || !self.name.is_empty() {
                    return Err(MetaError::Invariant);
                }
            }
            MetaKind::Group => {
                if owners != 1 || admins > MAX_ADMINS {
                    return Err(MetaError::Invariant);
                }
            }
        }
        Ok(())
    }
}

/// What a staged commit does, extracted from the MLS structures by the protocol adapter.
#[derive(Clone, Debug, Default)]
pub struct CommitInfo {
    pub sender_account: Option<Id16>,
    /// (account, device) of devices being added.
    pub adds: Vec<(Id16, Id16)>,
    /// (account, device) of devices being removed.
    pub removes: Vec<(Id16, Id16)>,
    /// Proposed new metadata (decoded), if the commit changes it.
    pub new_meta: Option<GroupMeta>,
    /// Number of proposals of a kind we do not authorise at all (PSK, ReInit, external init, unknown …).
    pub unsupported_proposals: usize,
    pub has_update_path_only: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum Violation {
    #[error("unsupported proposal type in commit")]
    Unsupported,
    #[error("sender is not a group member")]
    NotAMember,
    #[error("role does not permit adding this account")]
    AddNotAllowed,
    #[error("role does not permit removing this member")]
    RemoveNotAllowed,
    #[error("role does not permit changing roles")]
    RoleChangeNotAllowed,
    #[error("role does not permit renaming the group")]
    RenameNotAllowed,
    #[error("metadata change not allowed")]
    MetaChangeNotAllowed,
    #[error("resulting metadata is invalid")]
    InvalidResult,
}

/// Member accounts and their devices in the epoch *before* the commit.
pub type Members = BTreeMap<Id16, BTreeSet<Id16>>;

/// Pure authorization function. Deterministic: every honest client reaches the same verdict for the same
/// commit and epoch state. Removing another account's devices must cover **all** of that account's devices
/// (membership is per account; there is no "partial removal" of someone else).
pub fn authorize_commit(old: &GroupMeta, devices_before: &Members, c: &CommitInfo) -> Result<(), Violation> {
    let members_before: BTreeSet<Id16> = devices_before.keys().copied().collect();
    let members_before = &members_before;
    if c.unsupported_proposals > 0 {
        return Err(Violation::Unsupported);
    }
    let sender = c.sender_account.ok_or(Violation::NotAMember)?;
    if !members_before.contains(&sender) {
        return Err(Violation::NotAMember);
    }
    let role = if old.kind == MetaKind::Group { old.role_of(&sender) } else { Role::Member };
    let privileged = matches!(role, Role::Owner | Role::Admin);

    // Members after the commit (an account stays while it has any device; we compute by account sets).
    let mut after = members_before.clone();
    for (acc, _) in &c.adds {
        after.insert(*acc);
    }
    // An account leaves when ALL its devices are removed: callers pass full removal lists for an account removal;
    // we conservatively treat an account as removed if the commit removes any device AND the account is not the
    // sender's own (device unlink keeps the account). The adapter supplies `removed_accounts` implicitly through
    // `removes` covering every device of that account (checked by the engine before committing).
    let mut removed_accounts: BTreeSet<Id16> = BTreeSet::new();
    for (acc, _) in &c.removes {
        if *acc != sender {
            removed_accounts.insert(*acc);
        }
    }
    for acc in &removed_accounts {
        let all = devices_before.get(acc).ok_or(Violation::RemoveNotAllowed)?;
        let removed: BTreeSet<Id16> = c.removes.iter().filter(|(a, _)| a == acc).map(|(_, d)| *d).collect();
        if !all.is_subset(&removed) {
            return Err(Violation::RemoveNotAllowed);
        }
    }

    for (acc, _) in &c.adds {
        let existing = members_before.contains(acc);
        let ok = match old.kind {
            // A DM gains its single peer on creation (only the creator is present); afterwards it never gains an account.
            MetaKind::Dm => existing || members_before.len() < 2,
            MetaKind::Group => (existing && (*acc == sender || privileged)) || (!existing && privileged),
        };
        if !ok {
            return Err(Violation::AddNotAllowed);
        }
    }
    for (acc, _) in &c.removes {
        let ok = if *acc == sender {
            true // unlinking one's own device
        } else {
            match old.kind {
                MetaKind::Dm => false,
                MetaKind::Group => match role {
                    Role::Owner => true,
                    Role::Admin => old.role_of(acc) == Role::Member,
                    Role::Member => false,
                },
            }
        };
        if !ok {
            return Err(Violation::RemoveNotAllowed);
        }
    }
    for acc in &removed_accounts {
        after.remove(acc);
    }

    // Metadata changes.
    let new = c.new_meta.as_ref().unwrap_or(old);
    if new.v != old.v || new.kind != old.kind {
        return Err(Violation::MetaChangeNotAllowed);
    }
    if new.name != old.name && !(old.kind == MetaKind::Group && privileged) {
        return Err(Violation::RenameNotAllowed);
    }
    if new.roles != old.clone().normalised().roles && !(old.kind == MetaKind::Group && role == Role::Owner) {
        return Err(Violation::RoleChangeNotAllowed);
    }
    if new.tag != old.tag && c.removes.is_empty() {
        return Err(Violation::MetaChangeNotAllowed); // tags rotate only together with a removal
    }
    if new.tag == old.tag && !c.removes.is_empty() && old.kind == MetaKind::Group && removed_accounts.iter().next().is_some() {
        return Err(Violation::MetaChangeNotAllowed); // removing a member must rotate the routing tag
    }
    new.validate_shape().map_err(|_| Violation::InvalidResult)?;
    if old.kind == MetaKind::Group {
        // After-state: owner is still a member; role entries only for members.
        let owner = new.owner().ok_or(Violation::InvalidResult)?;
        if !after.contains(&owner) {
            return Err(Violation::InvalidResult);
        }
        if new.roles.iter().any(|r| !after.contains(&r.account)) {
            return Err(Violation::InvalidResult);
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn id(n: u8) -> Id16 {
        Id16([n; 16])
    }
    fn members(accs: &[u8]) -> Members {
        accs.iter().map(|n| (id(*n), [id(n.wrapping_mul(10))].into_iter().collect())).collect()
    }
    fn group() -> (GroupMeta, Members) {
        // 1 = owner, 2 = admin, 3,4 = members
        let mut m = GroupMeta::new_group(id(100), "Team", id(1));
        m.roles.push(RoleEntry { account: id(2), role: Role::Admin });
        let m = m.normalised();
        (m, members(&[1, 2, 3, 4]))
    }
    fn commit(sender: u8) -> CommitInfo {
        CommitInfo { sender_account: Some(id(sender)), ..CommitInfo::default() }
    }

    #[test]
    fn encode_decode_roundtrip_and_canonical_only() {
        let (m, _) = group();
        let b = m.encode().unwrap();
        assert_eq!(GroupMeta::decode(&b).unwrap(), m);
        let mut v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        v["roles"].as_array_mut().unwrap().reverse(); // same content, non-canonical order
        assert!(GroupMeta::decode(&serde_json::to_vec(&v).unwrap()).is_err());
        assert!(GroupMeta::decode(b"{}").is_err());
        assert!(GroupMeta::decode(&vec![b' '; MAX_META_BYTES + 1]).is_err());
    }

    #[test]
    fn shape_invariants() {
        let (mut m, _) = group();
        m.roles.push(RoleEntry { account: id(9), role: Role::Owner });
        assert!(m.validate_shape().is_err(), "two owners");
        let (mut m, _) = group();
        m.roles.retain(|r| r.role != Role::Owner);
        assert!(m.validate_shape().is_err(), "no owner");
        let (mut m, _) = group();
        m.roles.push(RoleEntry { account: id(3), role: Role::Member });
        assert!(m.validate_shape().is_err(), "explicit member entries are not allowed");
        let (mut m, _) = group();
        m.name = "x\u{0007}".into();
        assert!(m.validate_shape().is_err());
        assert!(GroupMeta::new_dm(id(1)).validate_shape().is_ok());
    }

    #[test]
    fn adding_members() {
        let (m, mem) = group();
        for (sender, ok) in [(1, true), (2, true), (3, false)] {
            let mut c = commit(sender);
            c.adds = vec![(id(9), id(90))];
            assert_eq!(authorize_commit(&m, &mem, &c).is_ok(), ok, "sender {sender}");
        }
        // a member may add a new device of their OWN account only
        let mut c = commit(3);
        c.adds = vec![(id(3), id(31))];
        assert!(authorize_commit(&m, &mem, &c).is_ok());
        c.adds = vec![(id(4), id(41))];
        assert_eq!(authorize_commit(&m, &mem, &c), Err(Violation::AddNotAllowed));
    }

    #[test]
    fn removing_members_requires_tag_rotation_and_role_cleanup() {
        let (m, mem) = group();
        let mut rotated = m.clone();
        rotated.tag = id(101);
        // owner removes admin: roles must drop the admin entry and the tag must rotate
        let mut c = commit(1);
        c.removes = vec![(id(2), id(20))];
        let mut meta = rotated.clone();
        meta.roles.retain(|r| r.account != id(2));
        c.new_meta = Some(meta);
        assert_eq!(authorize_commit(&m, &mem, &c), Ok(()));
        // stale admin entry for a removed account is rejected
        c.new_meta = Some(rotated.clone());
        assert_eq!(authorize_commit(&m, &mem, &c), Err(Violation::InvalidResult));
        // no tag rotation -> rejected
        let mut c2 = commit(1);
        c2.removes = vec![(id(3), id(30))];
        assert_eq!(authorize_commit(&m, &mem, &c2), Err(Violation::MetaChangeNotAllowed));
        c2.new_meta = Some(rotated.clone());
        assert_eq!(authorize_commit(&m, &mem, &c2), Ok(()));
        // admin may remove a plain member but not the owner or another admin
        let mut c3 = commit(2);
        c3.removes = vec![(id(3), id(30))];
        c3.new_meta = Some(rotated.clone());
        assert_eq!(authorize_commit(&m, &mem, &c3), Ok(()));
        c3.removes = vec![(id(1), id(10))];
        assert_eq!(authorize_commit(&m, &mem, &c3), Err(Violation::RemoveNotAllowed));
        // plain member removes nobody else
        let mut c4 = commit(3);
        c4.removes = vec![(id(4), id(40))];
        c4.new_meta = Some(rotated);
        assert_eq!(authorize_commit(&m, &mem, &c4), Err(Violation::RemoveNotAllowed));
    }

    #[test]
    fn removing_someone_elses_account_must_cover_all_their_devices() {
        let (m, mut mem) = group();
        mem.get_mut(&id(3)).unwrap().insert(id(31)); // account 3 has two devices
        let mut rotated = m.clone();
        rotated.tag = id(101);
        let mut c = commit(1);
        c.new_meta = Some(rotated);
        c.removes = vec![(id(3), id(30))];
        assert_eq!(authorize_commit(&m, &mem, &c), Err(Violation::RemoveNotAllowed), "partial removal of another account");
        c.removes = vec![(id(3), id(30)), (id(3), id(31))];
        assert_eq!(authorize_commit(&m, &mem, &c), Ok(()));
        c.removes = vec![(id(77), id(1))];
        assert_eq!(authorize_commit(&m, &mem, &c), Err(Violation::RemoveNotAllowed), "unknown account");
    }

    #[test]
    fn owner_cannot_remove_themselves_out_from_under_the_group() {
        let (m, mem) = group();
        // owner removes own (last) device: sender == removed account, not counted as account removal by the pure rule,
        // so the engine must also forbid emptying an account. Here: owner removed via admin -> owner not a member after.
        let mut rotated = m.clone();
        rotated.tag = id(101);
        let mut c = commit(2); // admin tries to remove the owner
        c.removes = vec![(id(1), id(10))];
        c.new_meta = Some(rotated);
        assert!(authorize_commit(&m, &mem, &c).is_err());
    }

    #[test]
    fn role_changes_owner_only_and_keep_one_owner() {
        let (m, mem) = group();
        let mut promote = m.clone();
        promote.roles.push(RoleEntry { account: id(3), role: Role::Admin });
        let promote = promote.normalised();
        let mut c = commit(1);
        c.new_meta = Some(promote.clone());
        assert_eq!(authorize_commit(&m, &mem, &c), Ok(()));
        let mut c = commit(2);
        c.new_meta = Some(promote);
        assert_eq!(authorize_commit(&m, &mem, &c), Err(Violation::RoleChangeNotAllowed), "admins cannot promote");
        // transfer ownership: 1 -> 2, 1 becomes admin
        let mut t = m.clone();
        t.roles = vec![RoleEntry { account: id(1), role: Role::Admin }, RoleEntry { account: id(2), role: Role::Owner }];
        let mut c = commit(1);
        c.new_meta = Some(t.clone().normalised());
        assert_eq!(authorize_commit(&m, &mem, &c), Ok(()));
        let mut c = commit(2);
        c.new_meta = Some(t.normalised());
        assert_eq!(authorize_commit(&m, &mem, &c), Err(Violation::RoleChangeNotAllowed), "only the current owner transfers");
        // two owners is invalid even for the owner
        let mut bad = m.clone();
        bad.roles.push(RoleEntry { account: id(3), role: Role::Owner });
        let mut c = commit(1);
        c.new_meta = Some(bad.normalised());
        assert_eq!(authorize_commit(&m, &mem, &c), Err(Violation::InvalidResult));
    }

    #[test]
    fn renaming_and_immutable_fields() {
        let (m, mem) = group();
        let mut renamed = m.clone();
        renamed.name = "New".into();
        for (sender, ok) in [(1, true), (2, true), (3, false)] {
            let mut c = commit(sender);
            c.new_meta = Some(renamed.clone());
            assert_eq!(authorize_commit(&m, &mem, &c).is_ok(), ok);
        }
        let mut kind = m.clone();
        kind.kind = MetaKind::Dm;
        let mut c = commit(1);
        c.new_meta = Some(kind);
        assert!(authorize_commit(&m, &mem, &c).is_err());
    }

    #[test]
    fn self_update_by_anyone_and_outsiders_and_unsupported_proposals_are_rejected() {
        let (m, mem) = group();
        assert_eq!(authorize_commit(&m, &mem, &commit(4)), Ok(()));
        assert_eq!(authorize_commit(&m, &mem, &commit(77)), Err(Violation::NotAMember));
        let mut c = commit(1);
        c.unsupported_proposals = 1;
        assert_eq!(authorize_commit(&m, &mem, &c), Err(Violation::Unsupported));
        let c = CommitInfo::default();
        assert_eq!(authorize_commit(&m, &mem, &c), Err(Violation::NotAMember));
    }

    #[test]
    fn dm_rules() {
        let m = GroupMeta::new_dm(id(100));
        let mem = members(&[1, 2]);
        let mut c = commit(1);
        c.adds = vec![(id(3), id(30))];
        assert_eq!(authorize_commit(&m, &mem, &c), Err(Violation::AddNotAllowed), "a DM can never gain a third account");
        let solo = members(&[1]);
        let mut c0 = commit(1);
        c0.adds = vec![(id(2), id(20))];
        assert_eq!(authorize_commit(&m, &solo, &c0), Ok(()), "creation: the creator adds the single peer");
        c.adds = vec![(id(2), id(21))];
        assert_eq!(authorize_commit(&m, &mem, &c), Ok(()), "new device of an existing participant");
        let mut c = commit(1);
        c.removes = vec![(id(2), id(20))];
        assert_eq!(authorize_commit(&m, &mem, &c), Err(Violation::RemoveNotAllowed), "cannot remove the other participant");
        let mut c = commit(1);
        c.removes = vec![(id(1), id(11))];
        assert_eq!(authorize_commit(&m, &mem, &c), Ok(()));
    }

    proptest! {
        /// No sequence of arbitrary commits by a plain MEMBER can ever be authorised if it changes membership of
        /// other accounts, roles, or the name.
        #[test]
        fn plain_member_never_gains_privileges(adds in proptest::collection::vec((3u8..40, 0u8..40), 0..4), removes in proptest::collection::vec((1u8..6, 0u8..40), 0..4), rename in any::<bool>(), promote in any::<bool>()) {
            let (m, mem) = group();
            let mut c = commit(3);
            c.adds = adds.iter().map(|(a, d)| (id(*a), id(*d))).collect();
            c.removes = removes.iter().map(|(a, d)| (id(*a), id(*d))).collect();
            let mut meta = m.clone();
            if rename { meta.name = "x".into(); }
            if promote { meta.roles.push(RoleEntry { account: id(3), role: Role::Admin }); meta.roles.sort_by_key(|r| r.account); }
            c.new_meta = Some(meta);
            if authorize_commit(&m, &mem, &c).is_ok() {
                // allowed only if it is purely: own-account device adds, own-device removals, nothing else
                prop_assert!(!rename && !promote);
                prop_assert!(c.adds.iter().all(|(a, _)| *a == id(3)));
                prop_assert!(c.removes.iter().all(|(a, _)| *a == id(3)));
            }
        }

        #[test]
        fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = GroupMeta::decode(&bytes);
        }
    }
}

#[cfg(test)]
mod name_policy_tests {
    use super::*;

    /// FR-13: a (possibly malicious) committer cannot install a group name that disguises itself; every receiver rejects it.
    #[test]
    fn group_names_with_bidi_overrides_or_zero_width_characters_are_rejected_by_shape_validation() {
        let mut m = GroupMeta::new_group(Id16([1; 16]), "Team", Id16([2; 16]));
        assert!(m.validate_shape().is_ok());
        for bad in ["Bank\u{202E}gnirts", "Team\u{200B}", "\u{FEFF}Team", "Te\u{2066}am", "ok\u{0007}"] {
            m.name = bad.to_owned();
            assert!(m.validate_shape().is_err(), "{bad:?} must be rejected");
        }
        m.name = "Family 👨\u{200D}👩\u{200D}👧 – مرحبا".to_owned();
        assert!(m.validate_shape().is_ok(), "emoji joiners and RTL text remain valid");
    }
}
