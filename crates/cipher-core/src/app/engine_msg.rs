//! Messaging: conversations, DMs, groups with roles, outbox/retry, sync, history, PCS maintenance.
use super::codec;
use super::engine::*;
use super::groupmeta::{GroupMeta, MetaKind, RoleEntry};
use super::model::*;
use crate::error::{Result, SecurityError};
use crate::events::SecurityEvent;
use crate::history;
use crate::mls::MemberInfo;
use crate::protocol::{CommitValidator, ExpectedPeer, GroupOp, GroupProtocol as _, GroupRef, Header, ProcessedEx};
use crate::storage::EncryptedStore;
use crate::verification::IdentityPins;
use cipher_wire::messages::{Delivery, Envelope};
use cipher_wire::Id16;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_GROUP_MEMBERS: usize = 100;
pub const MAX_OUTBOX_ATTEMPTS: u32 = 8;
const SELF_UPDATE_INTERVAL_MS: u64 = 24 * 3600 * 1000;
const SELF_UPDATE_MIN_SPACING_MS: u64 = 3600 * 1000;
const MAX_MSGS_BETWEEN_UPDATES: u32 = 100;
/// Hourly (was daily): the relay now caps claims per target at 12/hour (FR-08), so the pool is topped up at about the same pace.
const KP_REFILL_INTERVAL_MS: u64 = 3600 * 1000;
const MAX_HELD_PER_CONV: usize = 64;

/// Recipients (device, capability) that are reached at one relay (`None` = our own).
type RelayGroup = (Option<cipher_wire::RelayDescriptor>, Vec<(Id16, Id16)>);

/// What a commit builder returns: MLS operations, devices to welcome, and an optional new routing tag.
type CommitPlan = (Vec<GroupOp>, Vec<Id16>, Option<Id16>);
const MAX_TS_FUTURE_MS: u64 = 5 * 60 * 1000;
const MAX_TS_PAST_MS: u64 = 7 * 24 * 3600 * 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryPage {
    pub items: Vec<StoredMessage>,
    /// Pass back as `before` to load older messages; `None` at the start of history.
    pub next: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberView {
    pub account: Id16,
    pub name: String,
    pub role: Role,
    pub devices: u32,
    pub is_me: bool,
    pub trust: Option<TrustState>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub new_messages: u32,
    pub conversations_changed: Vec<Id16>,
    pub notices: Vec<super::notify::Notice>,
}

fn rid() -> Result<Id16> {
    Ok(Id16(crate::rng::array::<16>()?))
}

pub(crate) fn ns_m(conv: &Id16) -> String {
    format!("m:{}", conv.to_hex())
}
pub(crate) fn ns_mi(conv: &Id16) -> String {
    format!("mi:{}", conv.to_hex())
}

fn preview_of(c: &Content) -> String {
    let clip = |s: &str| -> String { s.chars().filter(|c| !is_disguising_char(*c)).take(80).collect() };
    match c {
        Content::Text { body } => clip(body),
        Content::Attachment { caption, att } => {
            let kind = match att.kind {
                AttachmentKind::Image => "Photo",
                AttachmentKind::Video => "Video",
                AttachmentKind::Audio => "Audio",
                AttachmentKind::Voice => "Voice message",
                AttachmentKind::Pdf => "PDF",
                AttachmentKind::File => "File",
            };
            if caption.is_empty() {
                kind.to_owned()
            } else {
                format!("{kind}: {}", clip(caption))
            }
        }
        Content::Receipt { .. } | Content::LeaveRequest | Content::DeliveryCap { .. } => String::new(),
    }
}

fn placeholder() -> Content {
    Content::Text { body: String::new() }
}

/// Persist a message. GROUP messages (`epoch` set) never reach the vault in plaintext: the body is sealed under the epoch's history key
/// (docs/HISTORY_REVOCATION.md). A message that is already `unavailable` keeps its sealed body untouched.
pub(crate) fn put_message(s: &mut EncryptedStore, m: &StoredMessage) -> Result<()> {
    let key = msg_sort_key(m.ts_ms, &m.id);
    let mut rec = m.clone();
    if let Some(epoch) = m.epoch {
        if !m.unavailable {
            let hek = history::get_epoch_key(s, &m.conv, epoch)?.ok_or(SecurityError::Denied("history key unavailable"))?;
            rec.sealed = Some(history::seal(&hek, &m.conv, epoch, &m.id, &m.sender_account, &m.content)?);
        }
        rec.content = placeholder();
        rec.unavailable = false;
    }
    super::engine::put_json(s, &ns_m(&m.conv), &key, &rec)?;
    s.put(&ns_mi(&m.conv), &m.id.to_hex(), key.as_bytes())
}

/// Load a message, opening a sealed body if (and only if) this device still holds the epoch's history key. Otherwise the message is
/// returned as an `unavailable` stub with an empty placeholder body. A body that fails authentication is treated the same (fail closed).
pub(crate) fn get_message_rec(s: &EncryptedStore, ns: &str, key: &str) -> Result<Option<StoredMessage>> {
    let Some(mut m) = super::engine::get_json::<StoredMessage>(s, ns, key)? else { return Ok(None) };
    if let (Some(epoch), Some(sealed)) = (m.epoch, m.sealed.clone()) {
        let opened = match history::get_epoch_key(s, &m.conv, epoch)? {
            Some(hek) => history::unseal(&hek, &m.conv, epoch, &m.id, &m.sender_account, &sealed).ok(),
            None => None,
        };
        match opened {
            Some(c) => {
                m.content = c;
                m.unavailable = false;
            }
            None => {
                m.content = placeholder();
                m.unavailable = true;
            }
        }
    }
    Ok(Some(m))
}

/// Commit validator backed by the pins loaded before processing. Unknown accounts are accepted (trust-on-first-use);
/// a pinned account's device with a DIFFERENT key is refused; a pinned account's NEW device is refused until the engine has
/// re-checked the directory (endorsement), then the commit is retried once.
struct PinValidator {
    pinned: BTreeMap<Id16, BTreeMap<Id16, Vec<u8>>>,
    lookups: RefCell<BTreeSet<Id16>>,
}

impl CommitValidator for PinValidator {
    fn approve_add(&self, account: &Id16, device: &Id16, identity_key: &[u8]) -> bool {
        match self.pinned.get(account) {
            None => true,
            Some(devs) => match devs.get(device) {
                Some(k) => k.as_slice() == identity_key,
                None => {
                    self.lookups.borrow_mut().insert(*account);
                    false
                }
            },
        }
    }
}

/// A group commit sent to the relay whose outcome is not yet known (persisted with the MLS pending commit).
#[derive(serde::Serialize, serde::Deserialize)]
struct PendingCommit {
    conv: Id16,
    tag: Id16,
    expected: u64,
    new_tag: Option<Id16>,
    deliveries: Vec<Delivery>,
    removed: bool,
    self_update: bool,
}

impl Engine {
    // --------------------------------------------------------------------------------------------- records

    pub fn conversation(&mut self, id: &Id16) -> Result<Conversation> {
        self.guard()?;
        self.vault.with_store(|s| get_json(s, NS_CONV, &id.to_hex()))?.ok_or(SecurityError::NotFound("conversation"))
    }

    fn save_conv(&mut self, c: &Conversation) -> Result<()> {
        self.vault.with_store(|s| put_json(s, NS_CONV, &c.id.to_hex(), c))
    }

    pub fn list_conversations(&mut self) -> Result<Vec<Conversation>> {
        self.guard()?;
        self.vault.with_store(|s| {
            let mut out = Vec::new();
            for id in s.list_ids(NS_CONV)? {
                if let Some(c) = get_json::<Conversation>(s, NS_CONV, &id)? {
                    out.push(c);
                }
            }
            out.sort_by_key(|c| std::cmp::Reverse(c.last_activity_ms));
            Ok(out)
        })
    }

    /// Display name for an account: the local contact name, or a short Cipher id.
    pub fn display_name(&mut self, account: &Id16) -> String {
        self.account_name(account)
    }

    fn account_name(&mut self, account: &Id16) -> String {
        match self.vault.with_store(|s| get_json::<Contact>(s, NS_CONTACT, &account.to_hex())) {
            Ok(Some(c)) => c.name,
            _ => clean_name("", account),
        }
    }

    fn own_ids(&mut self) -> Result<(Id16, Id16)> {
        let s = self.session()?;
        Ok((s.ident.account_id, s.ident.device_id))
    }

    pub fn my_role(&mut self, conv: &Id16) -> Result<Role> {
        let c = self.conversation(conv)?;
        if c.kind == ConvKind::Dm {
            return Ok(Role::Member);
        }
        let me = self.own_ids()?.0;
        let s = self.session()?;
        Ok(s.mls.group_meta(&GroupRef(c.id.0.to_vec()))?.map_or(Role::Member, |m| m.role_of(&me)))
    }

    pub fn members(&mut self, conv: &Id16) -> Result<Vec<MemberView>> {
        let c = self.conversation(conv)?;
        let (me, _) = self.own_ids()?;
        let (meta, infos) = {
            let s = self.session()?;
            let g = GroupRef(c.id.0.to_vec());
            (s.mls.group_meta(&g)?, s.mls.members_detailed(&g)?)
        };
        let mut by: BTreeMap<Id16, u32> = BTreeMap::new();
        for i in &infos {
            *by.entry(i.account).or_default() += 1;
        }
        let mut out = Vec::new();
        for (account, devices) in by {
            let name = if account == me { "You".to_owned() } else { self.account_name(&account) };
            let trust = self.contact(&account).ok().flatten().map(|c| c.trust);
            out.push(MemberView {
                account,
                name,
                role: meta.as_ref().map_or(Role::Member, |m| m.role_of(&account)),
                devices,
                is_me: account == me,
                trust,
            });
        }
        out.sort_by_key(|m| (m.role, m.name.to_lowercase()));
        Ok(out)
    }

    // ------------------------------------------------------------------------------------- conversation setup

    /// Trusted, non-blocked devices of the given contacts (fresh directory evaluation). Fails closed on identity problems.
    fn peer_devices(&mut self, accounts: &[Id16]) -> Result<Vec<(Id16, Id16, [u8; 32])>> {
        let mut out = Vec::new();
        for a in accounts {
            let c = self.contact(a)?.ok_or(SecurityError::NotFound("contact"))?;
            if c.blocked {
                return Err(SecurityError::Denied("contact is blocked"));
            }
            if c.trust == TrustState::IdentityChanged {
                return Err(SecurityError::IdentityUntrusted("identity changed: verify the contact first"));
            }
            let trust = self.refresh_peer(a)?;
            if self.contact(a)?.is_some_and(|c| c.trust == TrustState::IdentityChanged) {
                return Err(SecurityError::IdentityUntrusted("identity changed: verify the contact first"));
            }
            for r in &trust.trusted {
                let key: [u8; 32] = r.identity_key.as_slice().try_into().map_err(|_| SecurityError::IdentityUntrusted("bad key"))?;
                out.push((*a, r.device_id, key));
            }
        }
        if out.is_empty() {
            return Err(SecurityError::IdentityUntrusted("no trusted devices"));
        }
        Ok(out)
    }

    fn claim_key_packages(&mut self, devs: &[(Id16, Id16, [u8; 32])]) -> Result<Vec<GroupOp>> {
        let mut ops = Vec::new();
        for (account, device, key) in devs {
            let kp = match self.home_of(account) {
                Some(h) => {
                    let ep = crate::relay_client::RelayEndpoint::from_descriptor(&h.relay)?;
                    self.api_at(&ep)?.intro_key_package(&h.intro, device)
                }
                None => self.api()?.consume_key_package(device),
            };
            match kp {
                Ok(kp) => ops.push(GroupOp::Add {
                    key_package: kp,
                    expected: ExpectedPeer { account_id: *account, device_id: *device, identity_key: *key },
                }),
                Err(SecurityError::Transport("not found")) => {} // device has no KeyPackages left: skip it
                Err(e) => return Err(e),
            }
        }
        if ops.is_empty() {
            return Err(SecurityError::Transport("peer has no key packages available"));
        }
        Ok(ops)
    }

    fn welcome_deliveries(out: &crate::protocol::CommitOutput, new_devices: &[Id16]) -> Result<Vec<Delivery>> {
        let w = out.welcome.as_ref().ok_or(SecurityError::Protocol("missing welcome"))?;
        new_devices.iter().map(|d| Ok(Delivery { recipient_device: *d, message_id: rid()?, ciphertext: w.clone() })).collect()
    }

    /// History key of the CURRENT epoch of a group (docs/HISTORY_REVOCATION.md). Must be stored in the SAME atomic commit as the MLS state
    /// that reached this epoch, otherwise a crash could advance MLS while losing the key.
    fn current_epoch_key(&mut self, conv: &Id16) -> Result<(u64, zeroize::Zeroizing<[u8; 32]>)> {
        let g = GroupRef(conv.0.to_vec());
        let s = self.session()?;
        Ok((crate::protocol::GroupProtocol::epoch(&s.mls, &g)?, s.mls.export_epoch_key(&g)?))
    }

    /// THIS device was removed from the group. Cryptographic erasure of its history access, committed atomically with the dropped MLS state:
    /// every epoch history key of the group is deleted (so all sealed bodies become undecryptable here), a tombstone records the epoch at which
    /// access ended (so a stale Welcome cannot silently restore it), the group's outbox/held ciphertext and preview are deleted.
    fn revoke_group_access(&mut self, conv_id: &Id16, epoch: u64) -> Result<()> {
        let mut conv = self.conversation(conv_id)?;
        conv.state = ConvState::Left;
        conv.access_revoked = true;
        conv.last_preview = String::new();
        conv.unread = 0;
        let group = GroupRef(conv_id.0.to_vec());
        let _ = self.session()?.mls.leave_group_state(&group);
        let prefix = conv_id.to_hex();
        self.commit_state(|s| {
            history::delete_all_epoch_keys(s, &conv.id)?;
            history::put_tombstone(s, &conv.id, epoch)?;
            for id in s.list_ids(NS_OUTBOX)? {
                if get_json::<OutboxItem>(s, NS_OUTBOX, &id)?.is_some_and(|i| i.conv == conv.id) {
                    s.delete(NS_OUTBOX, &id)?;
                }
            }
            for id in s.list_ids(NS_HELD)?.into_iter().filter(|i| i.starts_with(&prefix)) {
                s.delete(NS_HELD, &id)?;
            }
            s.delete(NS_PENDING_COMMIT, &prefix)?;
            for id in s.list_ids(NS_CAPS)?.into_iter().filter(|i| i.contains(prefix.as_str())) {
                s.delete(NS_CAPS, &id)?;
            }
            put_json(s, NS_CONV, &conv.id.to_hex(), &conv)
        })?;
        self.push_event(SecurityEvent::GroupAccessRevoked { conversation_id: conv_id.to_hex() });
        Ok(())
    }

    fn create_conversation(&mut self, kind: ConvKind, name: &str, accounts: &[Id16]) -> Result<Id16> {
        self.guard()?;
        let (me, _) = self.own_ids()?;
        let remote_home = if kind == ConvKind::Dm { accounts.first().and_then(|a| self.home_of(a)) } else { None };
        if kind == ConvKind::Group && accounts.iter().any(|a| self.home_of(a).is_some()) {
            // docs/MULTI_RELAY_PROTOCOL.md §9: no sequencer exists for members on different relays; refuse instead of improvising one.
            return Err(SecurityError::Denied("groups with members on another relay are not supported"));
        }
        let devs = self.peer_devices(accounts)?;
        let ops = self.claim_key_packages(&devs)?;
        let tag = rid()?;
        let meta = match kind {
            ConvKind::Dm => GroupMeta::new_dm(tag),
            ConvKind::Group => GroupMeta::new_group(tag, name, me),
        };
        let (group, out) = {
            let s = self.session()?;
            let g = s.mls.create_group_with_meta(&meta)?;
            match s.mls.commit(&g, &ops) {
                Ok(o) => (g, o),
                Err(e) => {
                    let _ = s.mls.leave_group_state(&g);
                    return Err(e);
                }
            }
        };
        let new_devices: Vec<Id16> =
            ops.iter().filter_map(|o| if let GroupOp::Add { expected, .. } = o { Some(expected.device_id) } else { None }).collect();
        if let Some(home) = remote_home {
            // A conversation with a peer on another relay has NO sequencer: the commit is merged locally and the Welcome is delivered to the peer's
            // mailbox on THEIR relay through the intro capability of their card (queued in the encrypted outbox, so it survives process death and
            // an unreachable relay). The conversation then performs no further commits.
            let welcome = out.welcome.clone().ok_or(SecurityError::Protocol("missing welcome"))?;
            self.session()?.mls.merge_pending_commit(&group)?;
            let id = Id16(group.0.as_slice().try_into().map_err(|_| SecurityError::Protocol("group id"))?);
            let peer = accounts.first().copied().ok_or(SecurityError::Malformed("no peer"))?;
            let now = self.now_ms();
            let conv = Conversation {
                id,
                kind,
                state: ConvState::Active,
                title: self.account_name(&peer),
                peer: Some(peer),
                tag,
                relay_seq: 0,
                unread: 0,
                last_activity_ms: now,
                last_preview: String::new(),
                last_self_update_ms: now,
                sent_since_update: 0,
                access_revoked: false,
                remote: true,
            };
            let item = OutboxItem {
                id: rid()?,
                conv: id,
                devices: new_devices.clone(),
                ciphertext: welcome,
                attempts: 0,
                next_attempt_ms: 0,
                is_leave: false,
                welcome: true,
                order: self.next_ts_ms(),
            };
            let seeds = StoredPeerCap::Full(PeerCap { cap: home.intro, relay: Some(home.relay.clone()) });
            self.commit_state(|s| {
                put_json(s, NS_CONV, &id.to_hex(), &conv)?;
                put_json(s, NS_OUTBOX, &item.id.to_hex(), &item)?;
                for d in &new_devices {
                    put_json(s, NS_CAPS, &format!("peer/{}/{}", id.to_hex(), d.to_hex()), &seeds)?;
                }
                Ok(())
            })?;
            let _ = self.flush_outbox();
            return Ok(id);
        }
        let deliveries = Self::welcome_deliveries(&out, &new_devices)?;
        let result = self.api()?.group_commit(&tag, 0, None, deliveries);
        let seq = match result {
            Ok(crate::relay_client::GroupCommitResult::Accepted(seq)) => seq,
            other => {
                let s = self.session()?;
                let _ = s.mls.clear_pending_commit(&group);
                let _ = s.mls.leave_group_state(&group);
                return match other {
                    Err(e) => Err(e),
                    _ => Err(SecurityError::Transport("relay refused the new group")),
                };
            }
        };
        self.session()?.mls.merge_pending_commit(&group)?;
        let id = Id16(group.0.as_slice().try_into().map_err(|_| SecurityError::Protocol("group id"))?);
        let peer = if kind == ConvKind::Dm { accounts.first().copied() } else { None };
        let title = match kind {
            ConvKind::Dm => self.account_name(accounts.first().ok_or(SecurityError::Malformed("no peer"))?),
            ConvKind::Group => meta.name.clone(),
        };
        let now = self.now_ms();
        let conv = Conversation {
            id,
            kind,
            state: ConvState::Active,
            title,
            peer,
            tag,
            relay_seq: seq,
            unread: 0,
            last_activity_ms: now,
            last_preview: String::new(),
            last_self_update_ms: now,
            sent_since_update: 0,
            access_revoked: false,
            remote: false,
        };
        let hk = if kind == ConvKind::Group { Some(self.current_epoch_key(&id)?) } else { None };
        self.commit_state(|s| {
            if let Some((e, k)) = &hk {
                history::put_epoch_key(s, &id, *e, k)?;
            }
            put_json(s, NS_CONV, &id.to_hex(), &conv)
        })?;
        Ok(id)
    }

    /// Start (or return the existing) 1:1 conversation with a contact.
    pub fn start_dm(&mut self, peer: &Id16) -> Result<Id16> {
        self.guard()?;
        for c in self.list_conversations()? {
            if c.kind == ConvKind::Dm && c.peer == Some(*peer) && c.state != ConvState::Left {
                return Ok(c.id);
            }
        }
        self.create_conversation(ConvKind::Dm, "", &[*peer])
    }

    pub fn create_group(&mut self, name: &str, members: &[Id16]) -> Result<Id16> {
        self.guard()?;
        let name: String = name.chars().filter(|c| !is_disguising_char(*c)).take(super::groupmeta::MAX_NAME_CHARS).collect();
        if name.trim().is_empty() || members.is_empty() || members.len() + 1 > MAX_GROUP_MEMBERS {
            return Err(SecurityError::Malformed("group name or members"));
        }
        self.create_conversation(ConvKind::Group, name.trim(), members)
    }

    // ---------------------------------------------------------------------------------------- group commits

    /// Run one membership/metadata commit through the sequencer, rebasing on contention. The inbox is drained first so the commit
    /// is built on the latest state; a lost race clears the staged commit, re-syncs and retries (deterministic: exactly one
    /// concurrent commit wins per sequence number).
    fn run_commit(&mut self, conv_id: &Id16, build: &dyn Fn(&mut Engine, &Conversation) -> Result<CommitPlan>) -> Result<()> {
        self.guard()?;
        if self.conversation(conv_id)?.remote {
            return Err(SecurityError::Denied(
                "conversations with a peer on another relay cannot be changed (no sequencer; MULTI_RELAY_PROTOCOL.md §9)",
            ));
        }
        self.resolve_pending_commits()?;
        let mut last_err = SecurityError::Transport("commit contention");
        for _ in 0..4 {
            self.pull()?;
            let conv = self.conversation(conv_id)?;
            if conv.state != ConvState::Active {
                return Err(SecurityError::Denied("conversation is not active"));
            }
            let group = GroupRef(conv.id.0.to_vec());
            let (ops, new_devices, new_tag) = build(self, &conv)?;
            let (me_account, me_device) = self.own_ids()?;
            let existing: Vec<MemberInfo> = self.session()?.mls.members_detailed(&group)?;
            let out = self.session()?.mls.commit(&group, &ops)?;
            let mut deliveries: Vec<Delivery> = Vec::new();
            for m in existing.iter().filter(|m| m.device != me_device) {
                deliveries.push(Delivery { recipient_device: m.device, message_id: rid()?, ciphertext: out.commit.clone() });
            }
            if !new_devices.is_empty() {
                deliveries.extend(Self::welcome_deliveries(&out, &new_devices)?);
            }
            let _ = me_account;
            // Persist the in-flight commit (with the MLS pending commit, which is part of the snapshot) BEFORE the relay can accept it, so a lost
            // response or a crash cannot leave this member diverged from a group that already advanced (resolved by `resolve_pending_commits`).
            let pc = PendingCommit {
                conv: conv.id,
                tag: conv.tag,
                expected: conv.relay_seq,
                new_tag,
                deliveries: deliveries.clone(),
                removed: ops.iter().any(|o| matches!(o, GroupOp::Remove { .. })),
                self_update: ops.iter().any(|o| matches!(o, GroupOp::SelfUpdate)),
            };
            self.commit_state(|s| put_json(s, NS_PENDING_COMMIT, &conv.id.to_hex(), &pc))?;
            let res = self.api()?.group_commit(&conv.tag, pc.expected, pc.new_tag, deliveries);
            match res {
                Ok(crate::relay_client::GroupCommitResult::Accepted(seq)) => {
                    self.finish_commit(&pc, seq)?;
                    return Ok(());
                }
                Ok(crate::relay_client::GroupCommitResult::Stale(current)) => {
                    self.drop_pending_commit(&pc)?;
                    last_err = SecurityError::Transport("commit contention");
                    // FR-07: the relay is the ordering authority. If it reports a value BELOW what we stored, its counter was reset
                    // (restored backup / hostile operator). Adopt it, otherwise `relay_seq` (which only ever grows from deliveries) would
                    // stay ahead of the relay forever and this member could never commit again (renames, adds, removals, key refreshes).
                    if current < conv.relay_seq {
                        let mut c = self.conversation(conv_id)?;
                        c.relay_seq = current;
                        self.save_conv(&c)?;
                    }
                }
                Ok(crate::relay_client::GroupCommitResult::Gone) => {
                    self.drop_pending_commit(&pc)?;
                    return Err(SecurityError::Transport("group routing tag retired"));
                }
                // OUTCOME UNKNOWN (network error, lost response): the relay may have accepted. Keep the pending commit; the next sync/commit
                // re-sends the identical request, which the relay answers idempotently.
                Err(e) => return Err(e),
            }
        }
        Err(last_err)
    }

    /// The relay accepted our commit at `seq`: merge it and record the new epoch + its history key atomically; remove the in-flight record.
    fn finish_commit(&mut self, pc: &PendingCommit, seq: u64) -> Result<()> {
        let group = GroupRef(pc.conv.0.to_vec());
        self.session()?.mls.merge_pending_commit(&group)?;
        let meta = self.session()?.mls.group_meta(&group)?;
        let mut c = self.conversation(&pc.conv)?;
        c.relay_seq = seq;
        if let Some(m) = meta {
            c.tag = m.tag;
            if m.kind == MetaKind::Group {
                c.title = m.name;
            }
        }
        if pc.self_update {
            c.last_self_update_ms = self.now_ms();
            c.sent_since_update = 0;
        }
        // New epoch => new history-access generation, persisted atomically with the MLS state that reached it.
        let hk = if c.kind == ConvKind::Group { Some(self.current_epoch_key(&pc.conv)?) } else { None };
        let key = pc.conv.to_hex();
        self.commit_state(|s| {
            if let Some((e, k)) = &hk {
                history::put_epoch_key(s, &c.id, *e, k)?;
            }
            s.delete(NS_PENDING_COMMIT, &key)?;
            put_json(s, NS_CONV, &c.id.to_hex(), &c)
        })?;
        if pc.removed {
            self.mark_caps_stale(&pc.conv);
            // Only reported AFTER the transition is durable (REV-006/REV-007): the removal is not "done" before this point.
            self.push_event(SecurityEvent::GroupMemberRemoved { conversation_id: pc.conv.to_hex() });
        }
        Ok(())
    }

    fn drop_pending_commit(&mut self, pc: &PendingCommit) -> Result<()> {
        let group = GroupRef(pc.conv.0.to_vec());
        self.session()?.mls.clear_pending_commit(&group)?;
        let key = pc.conv.to_hex();
        self.commit_state(|s| s.delete(NS_PENDING_COMMIT, &key))
    }

    /// Resolves commits whose outcome was unknown (lost response, crash). Must run before anything else touches the group's MLS state.
    pub(crate) fn resolve_pending_commits(&mut self) -> Result<()> {
        let ids = self.vault.with_store(|s| s.list_ids(NS_PENDING_COMMIT))?;
        for id in ids {
            let Some(pc) = self.vault.with_store(|s| get_json::<PendingCommit>(s, NS_PENDING_COMMIT, &id))? else { continue };
            match self.api()?.group_commit(&pc.tag, pc.expected, pc.new_tag, pc.deliveries.clone())? {
                crate::relay_client::GroupCommitResult::Accepted(seq) => self.finish_commit(&pc, seq)?,
                // someone else's commit won, or the tag was retired by another removal: ours never happened; their commit arrives via pull
                _ => self.drop_pending_commit(&pc)?,
            }
        }
        Ok(())
    }

    fn require_group(&mut self, conv: &Id16) -> Result<Conversation> {
        let c = self.conversation(conv)?;
        if c.kind != ConvKind::Group {
            return Err(SecurityError::Denied("not a group"));
        }
        Ok(c)
    }

    pub fn add_group_members(&mut self, conv: &Id16, accounts: &[Id16]) -> Result<()> {
        self.require_group(conv)?;
        let accounts = accounts.to_vec();
        self.run_commit(conv, &move |e, _c| {
            let devs = e.peer_devices(&accounts)?;
            let ops = e.claim_key_packages(&devs)?;
            let new_devices =
                ops.iter().filter_map(|o| if let GroupOp::Add { expected, .. } = o { Some(expected.device_id) } else { None }).collect();
            Ok((ops, new_devices, None))
        })
    }

    pub fn remove_group_member(&mut self, conv: &Id16, account: &Id16) -> Result<()> {
        self.require_group(conv)?;
        let account = *account;
        self.run_commit(conv, &move |e, c| {
            let g = GroupRef(c.id.0.to_vec());
            let s = e.session()?;
            let meta = s.mls.group_meta(&g)?.ok_or(SecurityError::Protocol("no metadata"))?;
            let devices: Vec<Id16> = s.mls.members_detailed(&g)?.into_iter().filter(|m| m.account == account).map(|m| m.device).collect();
            if devices.is_empty() {
                return Err(SecurityError::NotFound("member"));
            }
            let mut m2 = meta.clone();
            m2.roles.retain(|r| r.account != account);
            m2.tag = rid()?;
            let tag = m2.tag;
            Ok((vec![GroupOp::Remove { devices }, GroupOp::SetMeta(m2.normalised())], Vec::new(), Some(tag)))
        })
    }

    fn change_meta(&mut self, conv: &Id16, f: impl Fn(&mut GroupMeta) + 'static) -> Result<()> {
        self.require_group(conv)?;
        self.run_commit(conv, &move |e, c| {
            let g = GroupRef(c.id.0.to_vec());
            let mut meta = e.session()?.mls.group_meta(&g)?.ok_or(SecurityError::Protocol("no metadata"))?;
            f(&mut meta);
            Ok((vec![GroupOp::SetMeta(meta.normalised())], Vec::new(), None))
        })
    }

    pub fn rename_group(&mut self, conv: &Id16, name: &str) -> Result<()> {
        let name: String = name.chars().filter(|c| !is_disguising_char(*c)).take(super::groupmeta::MAX_NAME_CHARS).collect();
        if name.trim().is_empty() {
            return Err(SecurityError::Malformed("group name"));
        }
        self.change_meta(conv, move |m| m.name = name.trim().to_owned())
    }

    pub fn promote_admin(&mut self, conv: &Id16, account: &Id16) -> Result<()> {
        let a = *account;
        self.change_meta(conv, move |m| {
            if m.role_of(&a) == Role::Member {
                m.roles.push(RoleEntry { account: a, role: Role::Admin });
            }
        })
    }

    pub fn demote_admin(&mut self, conv: &Id16, account: &Id16) -> Result<()> {
        let a = *account;
        self.change_meta(conv, move |m| m.roles.retain(|r| !(r.account == a && r.role == Role::Admin)))
    }

    /// Owner hands ownership to another member; the previous owner becomes an admin.
    pub fn transfer_ownership(&mut self, conv: &Id16, to: &Id16) -> Result<()> {
        let (me, _) = self.own_ids()?;
        let to = *to;
        self.change_meta(conv, move |m| {
            m.roles.retain(|r| r.account != to && r.account != me);
            m.roles.push(RoleEntry { account: to, role: Role::Owner });
            m.roles.push(RoleEntry { account: me, role: Role::Admin });
        })
    }

    /// A member cannot commit their own removal in MLS: they ask the admins, and stop participating immediately.
    pub fn leave_group(&mut self, conv: &Id16) -> Result<()> {
        let c = self.require_group(conv)?;
        if self.my_role(conv)? == Role::Owner {
            return Err(SecurityError::Denied("transfer ownership before leaving"));
        }
        let frame = Frame { v: 1, id: rid()?, ts_ms: self.now_ms(), reply_to: None, content: Content::LeaveRequest };
        self.queue_app_message(&c.id, frame, false, true)?;
        let mut c = self.conversation(conv)?;
        c.state = ConvState::Left;
        self.save_conv(&c)?;
        let _ = self.flush_outbox();
        Ok(())
    }

    /// Refresh this device's keys in a conversation (post-compromise security). Also called automatically.
    pub fn refresh_keys(&mut self, conv: &Id16) -> Result<()> {
        self.run_commit(conv, &|_, _| Ok((vec![GroupOp::SelfUpdate], Vec::new(), None)))
    }

    // ------------------------------------------------------------------------------------------- sending

    pub fn send_text(&mut self, conv: &Id16, body: &str, reply_to: Option<Id16>) -> Result<StoredMessage> {
        self.guard()?;
        let n = body.chars().count();
        if n == 0 || n > codec::MAX_TEXT_CHARS || body.trim().is_empty() {
            return Err(SecurityError::Malformed("message text"));
        }
        let frame = Frame { v: 1, id: rid()?, ts_ms: self.next_ts_ms(), reply_to, content: Content::Text { body: body.to_owned() } };
        let m = self.queue_app_message(conv, frame, true, false)?.ok_or(SecurityError::InvalidState)?;
        self.flush_if_immediate(); // best effort; failures stay in the outbox for retry
        Ok(self.message(conv, &m.id)?.unwrap_or(m))
    }

    /// Encrypt now (ratchet state persisted atomically with the outbox entry), deliver later.
    pub(crate) fn queue_app_message(&mut self, conv_id: &Id16, frame: Frame, store: bool, is_leave: bool) -> Result<Option<StoredMessage>> {
        let mut conv = self.conversation(conv_id)?;
        if conv.state != ConvState::Active && !(is_leave && conv.state == ConvState::Active) {
            return Err(SecurityError::Denied("conversation is not active"));
        }
        let (me, me_dev) = self.own_ids()?;
        let bytes = codec::encode(&frame)?;
        let group = GroupRef(conv.id.0.to_vec());
        let (ct, devices, epoch) = {
            let s = self.session()?;
            let epoch = if conv.kind == ConvKind::Group { Some(crate::protocol::GroupProtocol::epoch(&s.mls, &group)?) } else { None };
            let ct = s.mls.encrypt(&group, &bytes)?;
            let devices: Vec<Id16> = s.mls.members_detailed(&group)?.into_iter().filter(|m| m.device != me_dev).map(|m| m.device).collect();
            (ct, devices, epoch)
        };
        if devices.is_empty() {
            return Err(SecurityError::Denied("no recipients"));
        }
        let now = self.now_ms();
        let order = self.next_ts_ms();
        let item = OutboxItem {
            id: frame.id,
            conv: conv.id,
            devices,
            ciphertext: ct,
            attempts: 0,
            next_attempt_ms: 0,
            is_leave,
            welcome: false,
            order,
        };
        let msg = StoredMessage {
            id: frame.id,
            conv: conv.id,
            outgoing: true,
            sender_account: me,
            ts_ms: frame.ts_ms,
            reply_to: frame.reply_to,
            content: frame.content.clone(),
            state: DeliveryState::Pending,
            read: true,
            epoch,
            unavailable: false,
            sealed: None,
        };
        if store {
            conv.last_activity_ms = now;
            conv.last_preview = preview_of(&frame.content);
            conv.sent_since_update += 1;
        }
        let last_ts = self.last_ts_ms;
        self.commit_state(|s| {
            put_json(s, NS_META, "last_ts", &last_ts)?; // survives restarts: later messages never get an earlier timestamp
            put_json(s, NS_OUTBOX, &item.id.to_hex(), &item)?;
            if store {
                put_message(s, &msg)?;
                put_json(s, NS_CONV, &conv.id.to_hex(), &conv)?;
            }
            Ok(())
        })?;
        Ok(if store { Some(msg) } else { None })
    }

    /// Try to deliver everything in the outbox. Network failures back off exponentially; after `MAX_OUTBOX_ATTEMPTS` the
    /// message is marked FAILED (the user can retry).
    pub fn flush_outbox(&mut self) -> Result<u32> {
        self.guard()?;
        let now = self.now_ms();
        let items: Vec<OutboxItem> = self.vault.with_store(|s| {
            let mut v = Vec::new();
            for id in s.list_ids(NS_OUTBOX)? {
                if let Some(i) = get_json::<OutboxItem>(s, NS_OUTBOX, &id)? {
                    v.push(i);
                }
            }
            Ok(v)
        })?;
        let mut items = items;
        // STRICT per-conversation FIFO: ciphertexts leave in the order they were encrypted. A head that is waiting (back-off), failed or only partly
        // delivered holds back its successors, so the relay's queue — and therefore the recipient — never sees generation 9 before generation 2.
        items.sort_by_key(|i| (i.order, i.id.0));
        let mut blocked: std::collections::HashSet<Id16> = std::collections::HashSet::new();
        let mut delivered = 0;
        // Nothing else of a conversation is sent while its Welcome is still waiting for the peer's relay to accept it.
        let welcome_pending: std::collections::HashSet<Id16> = items.iter().filter(|i| i.welcome).map(|i| i.conv).collect();
        for mut item in items {
            if !item.welcome && (welcome_pending.contains(&item.conv) || blocked.contains(&item.conv)) {
                continue;
            }
            if item.attempts >= MAX_OUTBOX_ATTEMPTS {
                // Retries exhausted. A user-visible message stays FAILED and keeps holding its successors back until the user retries or deletes it;
                // a control frame (receipt, capability) nobody sees is simply dropped — the next one supersedes it.
                let visible = self.vault.with_store(|s| Ok(msg_key_for(s, &item.conv, &item.id)?.is_some()))?;
                if visible || item.welcome || item.is_leave {
                    blocked.insert(item.conv);
                } else {
                    self.vault.with_store(|s| s.delete(NS_OUTBOX, &item.id.to_hex()))?;
                }
                continue;
            }
            if item.next_attempt_ms > now {
                blocked.insert(item.conv);
                continue;
            }
            let mut remaining: Vec<Id16> = Vec::new();
            let mut net_failed = false;
            // A peer on another relay is reachable ONLY through its capability: the authenticated path would hit OUR relay, which has never heard of
            // them and answers `not_found` (counted as delivered) — a message would be silently lost.
            let conv_remote = self.conversation(&item.conv).map(|c| c.remote).unwrap_or(false);
            for chunk in item.devices.chunks(cipher_wire::limits::MAX_BATCH_DELIVERIES) {
                // Recipients whose inbox capability we hold are reached WITHOUT authenticating (the relay learns neither us nor their stable id).
                // A capability names the relay it is valid at: peers on another relay are reached THERE, directly from this device (client-mediated,
                // docs/MULTI_RELAY_PROTOCOL.md §5) and never through the authenticated path, which does not exist for them.
                let mut by_relay: Vec<RelayGroup> = Vec::new();
                let mut without = Vec::new();
                for d in chunk {
                    match self.peer_cap(&item.conv, d) {
                        Some(pc) => match by_relay.iter_mut().find(|(r, _)| *r == pc.relay) {
                            Some((_, v)) => v.push((*d, pc.cap)),
                            None => by_relay.push((pc.relay, vec![(*d, pc.cap)])),
                        },
                        None => without.push(*d),
                    }
                }
                let chunk = without;
                let mut fallback: Vec<Id16> = Vec::new();
                for (relay, anon_chunk) in by_relay {
                    let items: Vec<cipher_wire::messages::AnonDelivery> = anon_chunk
                        .iter()
                        .map(|(_, cap)| cipher_wire::messages::AnonDelivery {
                            cap: *cap,
                            message_id: item.id,
                            ciphertext: item.ciphertext.clone(),
                        })
                        .collect();
                    let sent = match &relay {
                        None => self.api()?.anon_deliver(items, None),
                        Some(r) => match crate::relay_client::RelayEndpoint::from_descriptor(r) {
                            Ok(ep) => self.api_at(&ep)?.anon_deliver(items, None),
                            Err(e) => Err(e),
                        },
                    };
                    match sent {
                        Ok(results) => {
                            for ((d, _), r) in anon_chunk.iter().zip(results) {
                                match r.as_str() {
                                    "queued" | "duplicate" => {
                                        self.delivery_counts.0 += 1;
                                        self.last_real_authed = false;
                                    }
                                    "invalid" => {
                                        // revoked/expired: forget it. A same-relay peer falls back to the authenticated path in this very attempt;
                                        // a peer on another relay has no such path, so the message waits for their next DeliveryCap.
                                        self.forget_peer_cap(&item.conv, d);
                                        if relay.is_none() {
                                            fallback.push(*d);
                                        } else {
                                            remaining.push(*d);
                                        }
                                    }
                                    _ => remaining.push(*d),
                                }
                            }
                        }
                        Err(_) => {
                            net_failed = true;
                            remaining.extend(anon_chunk.iter().map(|(d, _)| *d));
                        }
                    }
                }
                let mut chunk = chunk;
                if conv_remote {
                    remaining.append(&mut chunk);
                    remaining.extend(fallback);
                    continue;
                }
                chunk.extend(fallback); // revoked/expired capability: authenticated path right now, in the same attempt
                if chunk.is_empty() {
                    continue;
                }
                let chunk = chunk.as_slice();
                let ds: Vec<Delivery> = chunk
                    .iter()
                    .map(|d| Delivery { recipient_device: *d, message_id: item.id, ciphertext: item.ciphertext.clone() })
                    .collect();
                match self.api()?.send_batch(ds, None) {
                    Ok(results) => {
                        for (d, r) in chunk.iter().zip(results) {
                            match r.as_str() {
                                "queued" | "duplicate" | "not_found" => {
                                    self.delivery_counts.1 += 1;
                                    self.last_real_authed = true;
                                }
                                _ => remaining.push(*d), // queue_full etc: retry later
                            }
                        }
                    }
                    Err(_) => {
                        net_failed = true;
                        remaining.extend_from_slice(chunk);
                    }
                }
            }
            if remaining.is_empty() {
                let leaving = item.is_leave;
                let conv = item.conv;
                self.vault.with_store(|s| {
                    s.delete(NS_OUTBOX, &item.id.to_hex())?;
                    if let Some(mut m) = get_message_rec(s, &ns_m(&conv), &msg_key_for(s, &conv, &item.id)?.unwrap_or_default())? {
                        if m.state == DeliveryState::Pending {
                            m.state = DeliveryState::Sent;
                            put_message(s, &m)?;
                        }
                    }
                    Ok(())
                })?;
                if leaving {
                    let _ = self.session()?.mls.leave_group_state(&GroupRef(conv.0.to_vec()));
                    self.commit_state(|_| Ok(()))?;
                }
                delivered += 1;
            } else {
                blocked.insert(item.conv);
                item.devices = remaining;
                item.attempts += 1;
                item.next_attempt_ms = now + backoff_ms(item.attempts);
                let failed = item.attempts >= MAX_OUTBOX_ATTEMPTS;
                let _ = net_failed;
                self.vault.with_store(|s| {
                    put_json(s, NS_OUTBOX, &item.id.to_hex(), &item)?;
                    if failed {
                        if let Some(mut m) =
                            get_message_rec(s, &ns_m(&item.conv), &msg_key_for(s, &item.conv, &item.id)?.unwrap_or_default())?
                        {
                            m.state = DeliveryState::Failed;
                            put_message(s, &m)?;
                        }
                    }
                    Ok(())
                })?;
            }
        }
        Ok(delivered)
    }

    /// Manual retry of a FAILED message.
    pub fn retry_message(&mut self, conv: &Id16, id: &Id16) -> Result<()> {
        self.guard()?;
        self.vault.with_store(|s| {
            if let Some(mut item) = get_json::<OutboxItem>(s, NS_OUTBOX, &id.to_hex())? {
                item.attempts = 0;
                item.next_attempt_ms = 0;
                put_json(s, NS_OUTBOX, &id.to_hex(), &item)?;
            }
            if let Some(key) = msg_key_for(s, conv, id)? {
                if let Some(mut m) = get_message_rec(s, &ns_m(conv), &key)? {
                    if m.state == DeliveryState::Failed {
                        m.state = DeliveryState::Pending;
                        put_message(s, &m)?;
                    }
                }
            }
            Ok(())
        })?;
        self.flush_outbox().map(|_| ())
    }

    // ------------------------------------------------------------------------------------------- history

    pub fn message(&mut self, conv: &Id16, id: &Id16) -> Result<Option<StoredMessage>> {
        self.guard()?;
        self.vault.with_store(|s| match msg_key_for(s, conv, id)? {
            Some(k) => get_message_rec(s, &ns_m(conv), &k),
            None => Ok(None),
        })
    }

    /// Newest-first page. Never loads more than `limit` (<= 200) messages.
    pub fn history(&mut self, conv: &Id16, before: Option<String>, limit: usize) -> Result<HistoryPage> {
        self.guard()?;
        let limit = limit.clamp(1, 200);
        self.vault.with_store(|s| {
            let ids = s.list_ids_page(&ns_m(conv), before.as_deref(), limit)?;
            let mut items = Vec::new();
            for id in &ids {
                if let Some(m) = get_message_rec(s, &ns_m(conv), id)? {
                    items.push(m);
                }
            }
            let next = if ids.len() == limit { ids.last().cloned() } else { None };
            Ok(HistoryPage { items, next })
        })
    }

    pub fn mark_read(&mut self, conv: &Id16) -> Result<()> {
        let mut c = self.conversation(conv)?;
        if c.unread != 0 {
            c.unread = 0;
            self.save_conv(&c)?;
        }
        Ok(())
    }

    /// Delete one message from THIS device only. A tombstone keeps a late duplicate from resurrecting it.
    pub fn delete_message_local(&mut self, conv: &Id16, id: &Id16) -> Result<()> {
        self.guard()?;
        self.vault.with_store(|s| {
            if let Some(key) = msg_key_for(s, conv, id)? {
                s.delete(&ns_m(conv), &key)?;
                s.put(&ns_mi(conv), &id.to_hex(), b"")?; // tombstone: empty sort key
            }
            // Deleting a message that has not been delivered yet CANCELS its sending (and releases the messages queued behind it, if it was stuck).
            s.delete(NS_OUTBOX, &id.to_hex())?;
            Ok(())
        })
    }

    pub fn delete_conversation_local(&mut self, conv: &Id16) -> Result<()> {
        let c = self.conversation(conv)?;
        if c.kind == ConvKind::Group && c.state == ConvState::Active {
            return Err(SecurityError::Denied("leave the group first"));
        }
        let _ = self.session()?.mls.leave_group_state(&GroupRef(c.id.0.to_vec()));
        self.commit_state(|s| {
            for ns in [ns_m(conv), ns_mi(conv)] {
                for id in s.list_ids(&ns)? {
                    s.delete(&ns, &id)?;
                }
            }
            let hex = conv.to_hex();
            for id in s.list_ids(NS_OUTBOX)? {
                if get_json::<OutboxItem>(s, NS_OUTBOX, &id)?.is_some_and(|i| i.conv == *conv) {
                    s.delete(NS_OUTBOX, &id)?;
                }
            }
            for id in s.list_ids(NS_CAPS)?.into_iter().filter(|i| i.contains(hex.as_str())) {
                s.delete(NS_CAPS, &id)?;
            }
            s.delete(NS_CONV, &conv.to_hex())
        })
    }

    /// Accept an invitation from a non-contact.
    pub fn accept_conversation(&mut self, conv: &Id16) -> Result<()> {
        let mut c = self.conversation(conv)?;
        if c.state == ConvState::Requested {
            c.state = ConvState::Active;
            self.save_conv(&c)?;
        }
        Ok(())
    }

    /// Decline: leave and delete.
    pub fn decline_conversation(&mut self, conv: &Id16) -> Result<()> {
        let c = self.conversation(conv)?;
        if c.kind == ConvKind::Group {
            let mut c2 = c.clone();
            c2.state = ConvState::Active;
            self.save_conv(&c2)?;
            let _ = self.leave_group(conv);
        }
        let mut c = self.conversation(conv)?;
        c.state = ConvState::Left;
        self.save_conv(&c)?;
        self.delete_conversation_local(conv)
    }

    // ----------------------------------------------------------------------------------------------- sync

    /// Full cycle: pull + decrypt, deliver the outbox, act on pending admin duties, PCS/KeyPackage maintenance.
    pub fn sync(&mut self) -> Result<SyncReport> {
        self.guard()?;
        let mut report = self.pull()?;
        let _ = self.flush_outbox();
        if !self.in_commit {
            self.in_commit = true;
            let _ = self.process_pending_actions();
            let _ = self.maintenance();
            let _ = self.maintain_caps();
            self.in_commit = false;
        }
        let _ = self.send_pending_receipts();
        report.notices.shrink_to_fit();
        Ok(report)
    }

    /// Fetch, decrypt and process everything queued for this device. Poison messages are dropped (and acknowledged) so one
    /// bad envelope can never block the queue; local storage failures abort WITHOUT acknowledging so nothing is lost.
    pub(crate) fn pull(&mut self) -> Result<SyncReport> {
        self.guard()?;
        self.resolve_pending_commits()?;
        let mut report = SyncReport::default();
        let mut processed_any = false;
        for _ in 0..50 {
            let fetched = self.api()?.fetch_messages()?;
            let mut acks = Vec::new();
            for env in &fetched.envelopes {
                match self.handle_envelope(env, &mut report) {
                    Ok(()) => {
                        processed_any = true;
                        acks.push(env.message_id);
                    }
                    Err(SecurityError::StorageCorrupt)
                    | Err(SecurityError::Locked)
                    | Err(SecurityError::Invalidated)
                    | Err(SecurityError::KeyStore(_)) => {
                        // never acknowledge what we could not durably process
                        if !acks.is_empty() {
                            let _ = self.api()?.ack(acks);
                        }
                        return Err(SecurityError::StorageCorrupt);
                    }
                    Err(SecurityError::Replay) => {
                        self.push_event(SecurityEvent::ReplayRejected);
                        acks.push(env.message_id);
                    }
                    Err(_) => acks.push(env.message_id), // malformed / unauthorised / unknown group: drop
                }
            }
            if !acks.is_empty() {
                // FR-12: make the ratchet advance durable BEFORE the relay is told it may forget the ciphertext.
                if processed_any {
                    self.commit_state(|_| Ok(()))?;
                    processed_any = false;
                }
                for chunk in acks.chunks(cipher_wire::limits::MAX_ACK_BATCH) {
                    self.api()?.ack(chunk.to_vec())?;
                }
            }
            if !fetched.more {
                break;
            }
        }
        report.conversations_changed.sort();
        report.conversations_changed.dedup();
        Ok(report)
    }

    fn handle_envelope(&mut self, env: &Envelope, report: &mut SyncReport) -> Result<()> {
        match crate::mls::MlsClient::peek_header(&env.ciphertext)? {
            Header::Welcome => self.handle_welcome(env, report),
            Header::Group { group_id, epoch } => {
                let id = Id16(group_id.as_slice().try_into().map_err(|_| SecurityError::Malformed("group id"))?);
                let Some(conv) = self.vault.with_store(|s| get_json::<Conversation>(s, NS_CONV, &id.to_hex()))? else {
                    return Err(SecurityError::NotFound("conversation")); // unknown/left group: drop
                };
                if conv.access_revoked {
                    return Err(SecurityError::NotFound("conversation")); // access ended: nothing for this group is processed any more
                }
                if let Some(seq) = env.group_seq {
                    // every commit seen (valid or not) advances the position we CAS against
                    let mut c = conv.clone();
                    c.relay_seq = c.relay_seq.max(seq);
                    self.save_conv(&c)?;
                }
                let conv = self.conversation(&id)?;
                let r = self.process_group_message(&conv, &env.ciphertext);
                match r {
                    Err(SecurityError::FutureEpoch) => self.hold(&conv, epoch, &env.ciphertext),
                    other => {
                        let ok = other.is_ok();
                        let r = other.and_then(|p| self.apply_processed(&id, p, report));
                        if ok && r.is_ok() {
                            self.retry_held(&id, report)?;
                        }
                        match &r {
                            Err(SecurityError::Unauthorized("sender is no longer a member")) => {
                                self.push_event(SecurityEvent::RemovedMemberMessageRejected { conversation_id: id.to_hex() })
                            }
                            Err(SecurityError::Unauthorized(_)) => {
                                self.push_event(SecurityEvent::UnauthorizedGroupChange { conversation_id: id.to_hex() })
                            }
                            _ => {}
                        }
                        r
                    }
                }
            }
            Header::Other => Err(SecurityError::Malformed("unsupported message")),
        }
    }

    fn process_group_message(&mut self, conv: &Conversation, ct: &[u8]) -> Result<ProcessedEx> {
        let group = GroupRef(conv.id.0.to_vec());
        for attempt in 0..2 {
            let pinned = self.vault.with_store(|s| IdentityPins::new(s).pinned_devices())?;
            let v = PinValidator { pinned, lookups: RefCell::new(BTreeSet::new()) };
            let r = self.session()?.mls.process_ex(&group, ct, &v);
            let lookups: Vec<Id16> = v.lookups.borrow().iter().copied().collect();
            if attempt == 0 && matches!(r, Err(SecurityError::IdentityUntrusted(_))) && !lookups.is_empty() {
                for a in lookups {
                    let _ = self.refresh_peer(&a); // may endorse a new device of a known contact
                }
                continue;
            }
            return r;
        }
        Err(SecurityError::IdentityUntrusted("unapproved device"))
    }

    fn hold(&mut self, conv: &Conversation, epoch: u64, ct: &[u8]) -> Result<()> {
        let id = format!("{}-{:016}-{}", conv.id.to_hex(), epoch, hex8(ct));
        let prefix = conv.id.to_hex();
        self.vault.with_store(|s| {
            let held: Vec<String> = s.list_ids(NS_HELD)?.into_iter().filter(|i| i.starts_with(&prefix)).collect();
            if held.len() >= MAX_HELD_PER_CONV {
                if let Some(oldest) = held.first() {
                    s.delete(NS_HELD, oldest)?;
                }
            }
            s.put(NS_HELD, &id, ct)
        })
    }

    fn retry_held(&mut self, conv_id: &Id16, report: &mut SyncReport) -> Result<()> {
        let prefix = conv_id.to_hex();
        for _ in 0..8 {
            let held: Vec<String> =
                self.vault.with_store(|s| Ok(s.list_ids(NS_HELD)?.into_iter().filter(|i| i.starts_with(&prefix)).collect()))?;
            let mut progressed = false;
            for id in held {
                let Some(ct) = self.vault.with_store(|s| s.get(NS_HELD, &id))? else { continue };
                let conv = self.conversation(conv_id)?;
                match self.process_group_message(&conv, &ct) {
                    Err(SecurityError::FutureEpoch) => {}
                    other => {
                        self.vault.with_store(|s| s.delete(NS_HELD, &id))?;
                        if let Ok(p) = other {
                            let _ = self.apply_processed(conv_id, p, report);
                            progressed = true;
                        }
                    }
                }
            }
            if !progressed {
                break;
            }
        }
        Ok(())
    }

    fn handle_welcome(&mut self, env: &Envelope, report: &mut SyncReport) -> Result<()> {
        let joined = self.session()?.mls.join_welcome_ex(&env.ciphertext)?;
        let id = Id16(joined.group.0.as_slice().try_into().map_err(|_| SecurityError::Malformed("group id"))?);
        let (me, _) = self.own_ids()?;
        let meta = joined.meta.clone().ok_or(SecurityError::Unauthorized("missing group metadata"))?;
        // REV-004: an access tombstone survives everything (even deleting the conversation locally). A Welcome that is not strictly NEWER than the
        // epoch at which this device lost access is a stale/replayed invitation and cannot restore access.
        let tomb = self.vault.with_store(|s| history::tombstone(s, &id))?;
        if tomb.is_some_and(|t| joined.epoch <= t) {
            let _ = self.session()?.mls.leave_group_state(&joined.group);
            return Err(SecurityError::Unauthorized("stale welcome for a group this device was removed from"));
        }
        let existing: Option<Conversation> = self.vault.with_store(|s| get_json(s, NS_CONV, &id.to_hex()))?;
        if existing.as_ref().is_some_and(|c| !c.access_revoked) {
            return Err(SecurityError::Replay);
        }
        let inviter_known = self.contact(&joined.inviter.0)?.is_some_and(|c| !c.blocked);
        let blocked = self.contact(&joined.inviter.0)?.is_some_and(|c| c.blocked);
        if blocked {
            let _ = self.session()?.mls.leave_group_state(&joined.group);
            return Ok(());
        }
        // Check the identity keys in the (authenticated) tree against what we have pinned for known contacts.
        let pinned = self.vault.with_store(|s| IdentityPins::new(s).pinned_devices())?;
        for m in &joined.members {
            if let Some(devs) = pinned.get(&m.account) {
                if devs.get(&m.device).is_some_and(|k| k != &m.identity_key) {
                    self.push_event(SecurityEvent::IdentityChanged { account_id: m.account.to_hex() });
                    if let Some(mut c) = self.contact(&m.account)? {
                        c.trust = TrustState::IdentityChanged;
                        self.vault.with_store(|s| put_json(s, NS_CONTACT, &c.account_id.to_hex(), &c))?;
                    }
                }
            }
        }
        let kind = if meta.kind == MetaKind::Dm { ConvKind::Dm } else { ConvKind::Group };
        let peer = if kind == ConvKind::Dm { joined.members.iter().map(|m| m.account).find(|a| *a != me) } else { None };
        let title = match (kind, peer) {
            (ConvKind::Dm, Some(p)) => self.account_name(&p),
            _ => meta.name.clone(),
        };
        let now = self.now_ms();
        let conv = Conversation {
            id,
            kind,
            state: if inviter_known { ConvState::Active } else { ConvState::Requested },
            title,
            peer,
            tag: meta.tag,
            relay_seq: env.group_seq.unwrap_or(0),
            unread: 0,
            last_activity_ms: now,
            last_preview: String::new(),
            last_self_update_ms: now,
            sent_since_update: 0,
            access_revoked: false,
            // A DM Welcome that was not stamped by a sequencer came through a capability, i.e. from a peer on another relay.
            remote: kind == ConvKind::Dm && env.group_seq.is_none(),
        };
        // History keys exist only from the epoch this device joined at: no pre-join history, and nothing from a previous membership era.
        let hk = if kind == ConvKind::Group { Some((joined.epoch, self.session()?.mls.export_epoch_key(&joined.group)?)) } else { None };
        self.commit_state(|s| {
            if let Some((e, k)) = &hk {
                history::put_epoch_key(s, &id, *e, k)?;
            }
            put_json(s, NS_CONV, &id.to_hex(), &conv)
        })?;
        report.conversations_changed.push(id);
        Ok(())
    }

    fn apply_processed(&mut self, conv_id: &Id16, p: ProcessedEx, report: &mut SyncReport) -> Result<()> {
        let (me, _) = self.own_ids()?;
        match p {
            ProcessedEx::Application { plaintext, sender, epoch } => {
                let frame = codec::decode(&plaintext)?;
                self.apply_frame(conv_id, sender.0, sender.1, frame, epoch, report)?;
            }
            ProcessedEx::Commit { self_removed, sender, removed, epoch, .. } => {
                let group = GroupRef(conv_id.0.to_vec());
                let mut conv = self.conversation(conv_id)?;
                if self_removed {
                    self.revoke_group_access(conv_id, epoch)?;
                    report.conversations_changed.push(*conv_id);
                    return Ok(());
                }
                if let Some(meta) = self.session()?.mls.group_meta(&group)? {
                    conv.tag = meta.tag;
                    if meta.kind == MetaKind::Group {
                        conv.title = meta.name;
                    }
                }
                let _ = (me, sender);
                let hk = if conv.kind == ConvKind::Group { Some(self.current_epoch_key(conv_id)?) } else { None };
                self.commit_state(|s| {
                    if let Some((e, k)) = &hk {
                        history::put_epoch_key(s, &conv.id, *e, k)?;
                    }
                    put_json(s, NS_CONV, &conv.id.to_hex(), &conv)
                })?;
                if !removed.is_empty() {
                    self.push_event(SecurityEvent::GroupMemberRemoved { conversation_id: conv_id.to_hex() });
                    // A removed member may know our capability for this group: rotate it (old one revoked at once) into the NEW epoch.
                    self.mark_caps_stale(conv_id);
                }
                report.conversations_changed.push(*conv_id);
                // Refresh keys of known contacts that were just added (a new device must be endorsed).
            }
            ProcessedEx::Ignored => {}
        }
        Ok(())
    }

    fn apply_frame(
        &mut self,
        conv_id: &Id16,
        sender: Id16,
        sender_device: Id16,
        frame: Frame,
        epoch: u64,
        report: &mut SyncReport,
    ) -> Result<()> {
        let mut conv = self.conversation(conv_id)?;
        let now = self.now_ms();
        match frame.content.clone() {
            Content::Text { .. } | Content::Attachment { .. } => {
                if let Content::Text { body } = &frame.content {
                    if body.chars().count() > codec::MAX_TEXT_CHARS {
                        return Err(SecurityError::Malformed("text too long"));
                    }
                }
                let dup = self.vault.with_store(|s| Ok(s.get(&ns_mi(conv_id), &frame.id.to_hex())?.is_some()))?;
                if dup {
                    return Ok(()); // duplicate (or locally deleted): suppressed
                }
                let ts = frame.ts_ms.clamp(now.saturating_sub(MAX_TS_PAST_MS), now + MAX_TS_FUTURE_MS);
                let msg = StoredMessage {
                    id: frame.id,
                    conv: *conv_id,
                    outgoing: false,
                    sender_account: sender,
                    ts_ms: ts,
                    reply_to: frame.reply_to,
                    content: frame.content.clone(),
                    state: DeliveryState::Received,
                    read: false,
                    epoch: if conv.kind == ConvKind::Group { Some(epoch) } else { None },
                    unavailable: false,
                    sealed: None,
                };
                conv.unread += 1;
                conv.sent_since_update += 1; // counts activity of either direction since the last key refresh
                conv.last_activity_ms = ts.max(conv.last_activity_ms);
                conv.last_preview = preview_of(&frame.content);
                let requested = conv.state == ConvState::Requested;
                self.vault.with_store(|s| {
                    s.atomic(|s| {
                        put_message(s, &msg)?;
                        put_json(s, NS_CONV, &conv.id.to_hex(), &conv)?;
                        if conv.kind == ConvKind::Dm {
                            // remember to acknowledge delivery (batched in `send_pending_receipts`)
                            let mut pending: Vec<(Id16, Id16)> = get_json(s, NS_META, "pending_receipts")?.unwrap_or_default();
                            pending.push((conv.id, frame.id));
                            put_json(s, NS_META, "pending_receipts", &pending)?;
                        }
                        Ok(())
                    })
                })?;
                report.new_messages += 1;
                report.conversations_changed.push(*conv_id);
                if !requested {
                    let name = self.account_name(&sender);
                    report.notices.push(super::notify::Notice {
                        conversation_title: conv.title.clone(),
                        sender_name: name,
                        preview: preview_of(&frame.content),
                        is_group: conv.kind == ConvKind::Group,
                    });
                }
            }
            Content::Receipt { ids } => {
                if conv.kind == ConvKind::Dm {
                    self.vault.with_store(|s| {
                        for id in ids.iter().take(200) {
                            if let Some(key) = msg_key_for(s, conv_id, id)? {
                                if let Some(mut m) = get_message_rec(s, &ns_m(conv_id), &key)? {
                                    if m.outgoing && matches!(m.state, DeliveryState::Pending | DeliveryState::Sent) {
                                        m.state = DeliveryState::Delivered;
                                        put_message(s, &m)?;
                                    }
                                }
                            }
                        }
                        Ok(())
                    })?;
                    report.conversations_changed.push(*conv_id);
                }
            }
            Content::DeliveryCap { cap, relay } => {
                // Authenticated by MLS (it arrived inside this conversation from this member device): remember it as THEIR inbox capability, together
                // with the relay it is valid at. A malformed descriptor is dropped (the old capability, if any, stays); the sender's relay can never
                // redirect it, because this frame is end-to-end encrypted.
                let relay = match relay {
                    None => None,
                    Some(d) => match d.validated() {
                        Ok(d) if self.own_relay.as_ref().is_some_and(|o| o.url() == d.url()) => None, // same relay as ours: local path
                        Ok(d) => Some(d),
                        Err(_) => return Ok(()),
                    },
                };
                let key = format!("peer/{}/{}", conv_id.to_hex(), sender_device.to_hex());
                self.vault.with_store(|s| put_json(s, NS_CAPS, &key, &StoredPeerCap::Full(PeerCap { cap, relay })))?;
                // Whatever was only waiting for this capability must not sit out an exponential back-off that was never about a failure.
                self.wake_outbox(conv_id)?;
            }
            Content::LeaveRequest => {
                if conv.kind == ConvKind::Group {
                    self.vault.with_store(|s| {
                        let mut pending: Vec<(Id16, Id16)> = get_json(s, NS_META, "pending_removals")?.unwrap_or_default();
                        if !pending.contains(&(*conv_id, sender)) {
                            pending.push((*conv_id, sender));
                        }
                        put_json(s, NS_META, "pending_removals", &pending)
                    })?;
                }
            }
        }
        Ok(())
    }

    fn send_pending_receipts(&mut self) -> Result<()> {
        if !self.settings()?.send_receipts {
            self.vault.with_store(|s| s.delete(NS_META, "pending_receipts"))?;
            return Ok(());
        }
        let pending: Vec<(Id16, Id16)> = self.vault.with_store(|s| Ok(get_json(s, NS_META, "pending_receipts")?.unwrap_or_default()))?;
        if pending.is_empty() {
            return Ok(());
        }
        let mut by: BTreeMap<Id16, Vec<Id16>> = BTreeMap::new();
        for (c, m) in pending {
            by.entry(c).or_default().push(m);
        }
        // A receipt tells the sender "your message reached my device", so it is withheld while the conversation is still an unanswered message
        // request, and sent once it is accepted. (They used to be discarded, leaving the sender's first message at `Sent` forever.)
        // Receipts for conversations that no longer exist or are no longer active are dropped.
        let mut keep: Vec<(Id16, Id16)> = Vec::new();
        for (conv, ids) in by {
            match self.conversation(&conv).map(|c| c.state) {
                Ok(ConvState::Active) => {
                    for chunk in ids.chunks(100) {
                        let frame = Frame {
                            v: 1,
                            id: rid()?,
                            ts_ms: self.next_ts_ms(),
                            reply_to: None,
                            content: Content::Receipt { ids: chunk.to_vec() },
                        };
                        if self.queue_app_message(&conv, frame, false, false).is_err() {
                            keep.extend(chunk.iter().map(|m| (conv, *m))); // could not be queued now: try again next time
                        }
                    }
                }
                Ok(ConvState::Requested) => keep.extend(ids.iter().map(|m| (conv, *m))),
                _ => {}
            }
        }
        self.vault.with_store(|s| {
            if keep.is_empty() {
                s.delete(NS_META, "pending_receipts")
            } else {
                put_json(s, NS_META, "pending_receipts", &keep)
            }
        })?;
        let _ = self.flush_outbox();
        Ok(())
    }

    /// Admin duty: remove members who asked to leave. Only acts if THIS device's account is OWNER/ADMIN; deterministic and idempotent
    /// (if another admin already did it, the commit is simply not needed any more).
    fn process_pending_actions(&mut self) -> Result<()> {
        let pending: Vec<(Id16, Id16)> = self.vault.with_store(|s| Ok(get_json(s, NS_META, "pending_removals")?.unwrap_or_default()))?;
        if pending.is_empty() {
            return Ok(());
        }
        let mut keep = Vec::new();
        for (conv, account) in pending {
            let still_member = self.members(&conv).is_ok_and(|m| m.iter().any(|x| x.account == account));
            let role = self.my_role(&conv).unwrap_or(Role::Member);
            if !still_member || !self.conversation(&conv).is_ok_and(|c| c.state == ConvState::Active) {
                continue; // already handled / not relevant
            }
            if matches!(role, Role::Owner | Role::Admin) && self.remove_group_member(&conv, &account).is_err() {
                keep.push((conv, account)); // retry on the next sync
            }
        }
        self.vault.with_store(|s| put_json(s, NS_META, "pending_removals", &keep))
    }

    /// Post-compromise security scheduling + KeyPackage replenishment.
    ///
    /// Exact guarantee (see docs/SECURITY_ARCHITECTURE.md): if an attacker obtains this device's state at time T, MLS secrecy of messages
    /// sent after this device's next `SelfUpdate` commit is restored once that commit is processed by the group and the attacker no
    /// longer has access to later state. Until the next update, the attacker can read new traffic. We refresh after
    /// 24 h of use, or 100 sent messages, never more often than hourly.
    pub fn maintenance(&mut self) -> Result<()> {
        self.guard()?;
        let now = self.now_ms();
        for c in self.list_conversations()? {
            if c.state != ConvState::Active || c.remote {
                continue; // a conversation with a peer on another relay performs no commits (docs/MULTI_RELAY_PROTOCOL.md §9)
            }
            let due = (now.saturating_sub(c.last_self_update_ms) >= SELF_UPDATE_INTERVAL_MS && c.sent_since_update > 0)
                || c.sent_since_update >= MAX_MSGS_BETWEEN_UPDATES;
            if due && now.saturating_sub(c.last_self_update_ms) >= SELF_UPDATE_MIN_SPACING_MS {
                let _ = self.refresh_keys(&c.id);
            }
        }
        let last = self.session()?.ident.last_kp_upload_ms;
        if now.saturating_sub(last) >= KP_REFILL_INTERVAL_MS {
            let kps = crate::protocol::GroupProtocol::generate_key_packages(&mut self.session()?.mls, 10)?;
            let _ = self.api()?.upload_key_packages(kps); // QueueFull when the relay already holds plenty: fine
            let mut ident = self.session()?.ident.clone();
            ident.last_kp_upload_ms = now;
            self.session()?.ident = ident.clone();
            self.commit_state(|s| put_json(s, NS_META, "identity", &ident))?;
        }
        Ok(())
    }

    /// Notification text for the privacy mode and CURRENT vault state (a locked vault always yields the generic text).
    pub fn notification_for(&mut self, notices: &[super::notify::Notice]) -> super::notify::NotificationText {
        let unlocked = self.vault.state() == crate::vault::LockState::Unlocked;
        let mode =
            if unlocked { self.settings().map(|s| s.privacy_mode).unwrap_or_default() } else { super::notify::PrivacyMode::NoContent };
        super::notify::build(mode, unlocked, notices)
    }
}

fn backoff_ms(attempt: u32) -> u64 {
    (5_000u64 << attempt.min(10)).min(3_600_000)
}

fn hex8(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b).iter().take(4).map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn msg_key_for(s: &EncryptedStore, conv: &Id16, id: &Id16) -> Result<Option<String>> {
    match s.get(&ns_mi(conv), &id.to_hex())? {
        Some(k) if !k.is_empty() => Ok(Some(String::from_utf8(k.to_vec()).map_err(|_| SecurityError::StorageCorrupt)?)),
        _ => Ok(None),
    }
}

// ------------------------------------------------------------------------------------------ delivery capabilities

/// Rotate our own capability per conversation at least this often.
const CAP_ROTATE_MS: u64 = 7 * 24 * 3600 * 1000;
/// Grace for a rotated capability, so sends already in flight do not fail.
const CAP_ROTATE_GRACE_SECS: u64 = 3600;

/// Where to deliver to one peer device: its capability and, for a peer on another relay, that relay.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct PeerCap {
    pub(crate) cap: Id16,
    pub(crate) relay: Option<cipher_wire::RelayDescriptor>,
}

/// Stored form; capabilities saved before multi-relay support are a bare id.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(untagged)]
pub(crate) enum StoredPeerCap {
    Full(PeerCap),
    Legacy(Id16),
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct OwnCap {
    cap: Id16,
    minted_ms: u64,
    /// Old capabilities still to be revoked at the relay, with the grace to use.
    revoke: Vec<Id16>,
    revoke_grace_secs: u64,
}

impl Engine {
    fn peer_cap(&mut self, conv: &Id16, device: &Id16) -> Option<PeerCap> {
        let key = format!("peer/{}/{}", conv.to_hex(), device.to_hex());
        match self.vault.with_store(|s| get_json::<StoredPeerCap>(s, NS_CAPS, &key)).ok().flatten()? {
            StoredPeerCap::Legacy(cap) => Some(PeerCap { cap, relay: None }),
            StoredPeerCap::Full(p) => Some(p),
        }
    }

    /// (capability, relay) for a peer device, if known.
    pub(crate) fn peer_cap_pub(&mut self, conv: &Id16, device: &Id16) -> Option<(Id16, Option<cipher_wire::RelayDescriptor>)> {
        self.peer_cap(conv, device).map(|p| (p.cap, p.relay))
    }

    /// Make every outbox item of `conv` due now.
    fn wake_outbox(&mut self, conv: &Id16) -> Result<()> {
        self.vault.with_store(|s| {
            for id in s.list_ids(NS_OUTBOX)? {
                if let Some(mut i) = get_json::<OutboxItem>(s, NS_OUTBOX, &id)? {
                    if i.conv == *conv && i.next_attempt_ms != 0 {
                        i.next_attempt_ms = 0;
                        put_json(s, NS_OUTBOX, &id, &i)?;
                    }
                }
            }
            Ok(())
        })
    }

    fn forget_peer_cap(&mut self, conv: &Id16, device: &Id16) {
        let key = format!("peer/{}/{}", conv.to_hex(), device.to_hex());
        let _ = self.vault.with_store(|s| s.delete(NS_CAPS, &key));
    }

    /// Ask for a capability rotation of this conversation on the next sync (group removal, suspected leak).
    pub(crate) fn mark_caps_stale(&mut self, conv: &Id16) {
        let _ = self.vault.with_store(|s| put_json(s, NS_CAPS, &format!("stale/{}", conv.to_hex()), &true));
    }

    /// (anonymous, authenticated) recipient deliveries made so far in this process — evidence for tests and the privacy status.
    pub fn delivery_path_counts(&self) -> (u64, u64) {
        self.delivery_counts
    }

    /// Mints/rotates our inbox capability per active conversation and tells the members inside the E2EE conversation. Best effort: a failure
    /// leaves the authenticated (open-lane) path in use, never a weaker one.
    pub(crate) fn maintain_caps(&mut self) -> Result<()> {
        self.guard()?;
        let now = self.now_ms();
        for c in self.list_conversations()? {
            if c.state != ConvState::Active || c.access_revoked {
                continue;
            }
            let own_key = format!("own/{}", c.id.to_hex());
            let stale_key = format!("stale/{}", c.id.to_hex());
            let (own, stale) = self.vault.with_store(|s| {
                Ok((get_json::<OwnCap>(s, NS_CAPS, &own_key)?, get_json::<bool>(s, NS_CAPS, &stale_key)?.unwrap_or(false)))
            })?;
            // retry pending revocations first
            if let Some(o) = &own {
                if !o.revoke.is_empty() && self.api()?.revoke_caps(o.revoke.clone(), Some(o.revoke_grace_secs)).is_ok() {
                    let mut o2 = o.clone();
                    o2.revoke.clear();
                    self.vault.with_store(|s| put_json(s, NS_CAPS, &own_key, &o2))?;
                }
            }
            let due = own.as_ref().is_none_or(|o| now.saturating_sub(o.minted_ms) >= CAP_ROTATE_MS) || stale;
            if !due {
                continue;
            }
            if c.remote && self.own_relay.is_none() {
                // A peer on another relay would take a capability without a relay for one valid at ITS OWN relay and silently fail to deliver.
                continue;
            }
            let group = GroupRef(c.id.0.to_vec());
            let (_, me_dev) = self.own_ids()?;
            if !self.session()?.mls.members_detailed(&group)?.iter().any(|m| m.device != me_dev) {
                continue; // nobody to tell
            }
            let cap = rid()?;
            if self.api()?.mint_caps(vec![cap]).is_err() {
                continue;
            }
            let frame = Frame {
                v: 1,
                id: rid()?,
                ts_ms: now,
                reply_to: None,
                content: Content::DeliveryCap { cap, relay: self.own_relay.clone() },
            };
            if self.queue_app_message(&c.id, frame, false, false).is_err() {
                continue; // the minted capability simply expires unused
            }
            let mut revoke = own.as_ref().map(|o| o.revoke.clone()).unwrap_or_default();
            if let Some(o) = &own {
                revoke.push(o.cap);
            }
            // After a removal the old capability must die at once (the removed member may know it); a routine rotation keeps a grace window.
            let grace = if stale { 0 } else { CAP_ROTATE_GRACE_SECS };
            let rec = OwnCap { cap, minted_ms: now, revoke: revoke.clone(), revoke_grace_secs: grace };
            self.vault.with_store(|s| {
                s.atomic(|s| {
                    put_json(s, NS_CAPS, &own_key, &rec)?;
                    s.delete(NS_CAPS, &stale_key)
                })
            })?;
            if self.api()?.revoke_caps(revoke, Some(grace)).is_ok() {
                let mut r2 = rec.clone();
                r2.revoke.clear();
                self.vault.with_store(|s| put_json(s, NS_CAPS, &own_key, &r2))?;
            }
        }
        let _ = self.flush_outbox();
        Ok(())
    }
}

// ------------------------------------------------------------------------------------------ network profile

/// What one foreground tick did, and when the next one is due.
#[derive(Debug)]
pub struct TickReport {
    pub report: SyncReport,
    pub next_delay_ms: u64,
}

impl Engine {
    fn profile(&mut self) -> super::netprofile::NetworkProfile {
        self.settings().map(|s| s.network_profile).unwrap_or_default()
    }

    /// Sends leave at once in STANDARD; in ENHANCED they wait for the next tick (the outbox keeps them, encrypted).
    pub(crate) fn flush_if_immediate(&mut self) {
        if !self.profile().holds_sends_until_tick() {
            let _ = self.flush_outbox();
        }
    }

    /// One foreground tick: sync (pull, deliver, maintenance), then — in ENHANCED — exactly one send-shaped request per tick (a bounded dummy when
    /// nothing real was sent). Returns the jittered delay before the next tick.
    pub fn network_tick(&mut self) -> Result<TickReport> {
        self.guard()?;
        let profile = self.profile();
        let before = self.delivery_counts.0 + self.delivery_counts.1;
        let report = self.sync()?;
        let sent_real = self.delivery_counts.0 + self.delivery_counts.1 > before;
        if profile.sends_cover() && !sent_real {
            self.send_cover();
        }
        let entropy = u32::from_be_bytes(crate::rng::array::<4>()?);
        Ok(TickReport { report, next_delay_ms: profile.next_delay_ms(entropy) })
    }

    /// A dummy unauthenticated delivery to a random (therefore invalid) capability, same size class as a real message. The relay answers `invalid`
    /// and stores nothing. Never contains plaintext, cannot trigger any application action, one per tick at most.
    fn send_cover(&mut self) {
        let mut ct = vec![0u8; super::netprofile::COVER_CIPHERTEXT_BYTES];
        let (Ok(cap), Ok(())) = (rid(), crate::rng::fill(&mut ct)) else { return };
        let Ok(mid) = rid() else { return };
        let authed = self.last_real_authed;
        if let Ok(api) = self.api() {
            if authed {
                // Imitate the shape of our real sends: an authenticated batch to a device that does not exist (answered `not_found`, stored nowhere).
                let _ = api.send_batch(vec![Delivery { recipient_device: cap, message_id: mid, ciphertext: ct }], None);
            } else {
                let _ = api.anon_deliver(vec![cipher_wire::messages::AnonDelivery { cap, message_id: mid, ciphertext: ct }], None);
            }
        }
    }
}
