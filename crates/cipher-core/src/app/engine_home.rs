//! Groups whose members live on different relays (docs/CROSS_RELAY_GROUPS.md §7).
//!
//! The creator's relay is the group's HOME relay. It orders the group's commits in a hash-chained log it cannot read; members poll that log with
//! credentials derived from the MLS exporter. Application messages never touch the home relay: they travel to each member's own relay
//! through that member's capability, exactly as in a 1:1 conversation. The home relay is trusted for ordering and availability only — every
//! entry it returns is verified here (position, hash chain, and that the epoch keys it stored are the ones the members derived).
use super::engine::*;
use super::engine_msg::{CommitPlan, PeerCap, StoredPeerCap, SyncReport};
use super::groupmeta::GroupMeta;
use super::model::*;
use crate::error::{Result, SecurityError};
use crate::events::SecurityEvent;
use crate::history;
use crate::home::{check_epoch_keys, check_reported_head, verify_page, Gossip, HomeCreds, HomeHead, HomeLedger, VerifiedEntry};
use crate::protocol::{GroupOp, GroupProtocol as _, GroupRef, ProcessedEx};
use crate::relay_client::{HomeCommitResult, RelayEndpoint};
use cipher_wire::home::{home_tag, HomeCommitRequest};
use cipher_wire::{Id16, RelayDescriptor};
use serde::{Deserialize, Serialize};

pub(crate) const NS_HOME_PENDING: &str = "hpc";
pub(crate) const FREEZE_BLOCKED: &str = "an invalid commit occupies the home log: membership changes are blocked";
const FREEZE_MISMATCH: &str = "the home log and the group state disagree about the epoch";
const MAX_LOG_PAGES: usize = 64;

fn rid() -> Result<Id16> {
    Ok(Id16(crate::rng::array::<16>()?))
}

/// A commit submitted (or about to be) to the home log. Persisted BEFORE it is sent, together with everything that must follow an acceptance
/// (the Welcome for new members, their capability seeds), so a crash or a lost response cannot strand a joiner or diverge the committer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct HomePending {
    conv: Id16,
    /// The log position the commit was built on (== the MLS epoch before it).
    expected: u64,
    commit_id: Id16,
    commit: Vec<u8>,
    next_commit_pub: Vec<u8>,
    next_read_pub: Vec<u8>,
    welcome: Option<Vec<u8>>,
    new_devices: Vec<Id16>,
    /// New devices on another relay: (device, their card's intro capability, their relay).
    seeds: Vec<(Id16, Id16, RelayDescriptor)>,
    /// New devices known to be on OUR relay.
    local_new: Vec<Id16>,
    removed: bool,
    self_update: bool,
}

impl Engine {
    fn home_creds_now(&mut self, group: &GroupRef) -> Result<HomeCreds> {
        let s = self.session()?;
        let epoch = crate::protocol::GroupProtocol::epoch(&s.mls, group)?;
        Ok(HomeCreds::new(epoch, &s.mls.home_keys(group)?))
    }

    fn mls_epoch(&mut self, group: &GroupRef) -> Result<u64> {
        crate::protocol::GroupProtocol::epoch(&self.session()?.mls, group)
    }

    /// Stop membership changes for this group and tell the user. Application messages keep flowing (they do not depend on the home relay).
    pub(crate) fn freeze_group(&mut self, conv_id: &Id16, reason: &'static str) -> Result<()> {
        let mut conv = self.conversation(conv_id)?;
        if let Some(h) = conv.home.as_mut() {
            if h.frozen.is_none() {
                h.frozen = Some(reason.to_owned());
                self.commit_state(|s| put_json(s, NS_CONV, &conv.id.to_hex(), &conv))?;
                self.push_event(SecurityEvent::GroupForkDetected { conversation_id: conv_id.to_hex(), reason: reason.to_owned() });
            }
        }
        Ok(())
    }

    /// Hours of continuous failure before the user is told. A relay that does not recognise the group is a stronger signal than one that is
    /// merely unreachable (maintenance, a phone without coverage), so it is reported sooner.
    const UNRECOGNIZED_ALERT_SECS: u64 = 3_600;
    const UNREACHABLE_ALERT_SECS: u64 = 72 * 3_600;

    /// Records one failed poll of the home log. Persists only on a change of state, and raises `HomeRelayUnavailable` once per streak.
    fn note_home_failure(&mut self, conv_id: &Id16, err: &SecurityError) -> Result<()> {
        let kind = match err {
            SecurityError::Transport("unauthorized" | "not found") => "unrecognized",
            SecurityError::Transport(_) => "unreachable",
            _ => return Ok(()), // local problems (locked, corrupt ...) are reported elsewhere and say nothing about the home relay
        };
        let now = self.clock.unix_secs();
        let mut conv = self.conversation(conv_id)?;
        let Some(h) = conv.home.as_mut() else { return Ok(()) };
        let limit = if kind == "unrecognized" { Self::UNRECOGNIZED_ALERT_SECS } else { Self::UNREACHABLE_ALERT_SECS };
        let mut raise = false;
        match h.issue.as_mut() {
            Some(i) if i.kind == kind => {
                if !i.alerted && now.saturating_sub(i.since) >= limit {
                    i.alerted = true;
                    raise = true;
                } else {
                    return Ok(());
                }
            }
            _ => h.issue = Some(crate::app::model::HomeIssue { kind: kind.to_owned(), since: now, alerted: false }),
        }
        self.commit_state(|s| put_json(s, NS_CONV, &conv.id.to_hex(), &conv))?;
        if raise {
            self.push_event(SecurityEvent::HomeRelayUnavailable { conversation_id: conv_id.to_hex(), kind: kind.to_owned() });
        }
        Ok(())
    }

    fn clear_home_issue(&mut self, conv_id: &Id16) -> Result<()> {
        let mut conv = self.conversation(conv_id)?;
        if conv.home.as_mut().is_some_and(|h| h.issue.take().is_some()) {
            self.commit_state(|s| put_json(s, NS_CONV, &conv.id.to_hex(), &conv))?;
        }
        Ok(())
    }

    /// Replace a group whose commit channel is lost or blocked by a NEW group with the same members and name (docs/CROSS_RELAY_GROUPS.md §9).
    /// Nothing is migrated silently: the new group has a new MLS group id, a new home relay (this device's own) and fresh membership, and every
    /// member must accept the invitation again (a new Welcome, delivered the same authenticated way as any invitation). The old group stays
    /// readable and keeps working for messages.
    pub fn create_successor_group(&mut self, conv_id: &Id16) -> Result<Id16> {
        self.guard()?;
        let conv = self.conversation(conv_id)?;
        let home = conv.home.as_ref().ok_or(SecurityError::Denied("not a cross-relay group"))?;
        let broken = home.frozen.is_some() || home.issue.as_ref().is_some_and(|i| i.alerted);
        if conv.kind != ConvKind::Group || conv.state != ConvState::Active || conv.access_revoked || !broken {
            return Err(SecurityError::Denied("only an active group whose commit channel is blocked or lost can be replaced"));
        }
        if home.superseded_by.is_some() {
            return Err(SecurityError::Denied("this group has already been replaced"));
        }
        let members: Vec<Id16> = self.members(conv_id)?.into_iter().filter(|m| !m.is_me).map(|m| m.account).collect();
        if members.is_empty() {
            return Err(SecurityError::Denied("no other members to invite"));
        }
        let new_id = self.create_group(&conv.title, &members)?;
        let mut conv = self.conversation(conv_id)?;
        if let Some(h) = conv.home.as_mut() {
            h.superseded_by = Some(new_id.to_hex());
        }
        self.commit_state(|s| put_json(s, NS_CONV, &conv.id.to_hex(), &conv))?;
        Ok(new_id)
    }

    fn save_ledger(&mut self, conv_id: &Id16, ledger: &HomeLedger) -> Result<()> {
        let mut conv = self.conversation(conv_id)?;
        if let Some(h) = conv.home.as_mut() {
            h.ledger = Some(ledger.clone());
        }
        self.commit_state(|s| put_json(s, NS_CONV, &conv.id.to_hex(), &conv))
    }

    // --------------------------------------------------------------------------------------------------------------- creation

    /// Create a group with members on other relays. The creator's relay becomes the home relay (named in the MLS-authenticated metadata).
    pub(crate) fn create_homed_group(&mut self, name: &str, accounts: &[Id16]) -> Result<Id16> {
        let relay = self.own_relay.clone().ok_or(SecurityError::Denied(
            "this relay must be named (set_own_relay) before creating a group with members on other relays",
        ))?;
        let (me, _) = self.own_ids()?;
        let devs = self.peer_devices(accounts)?;
        let ops = self.claim_key_packages(&devs)?;
        let tag = rid()?;
        let meta = GroupMeta::new_group(tag, name, me).with_home(relay.clone());
        let (group, out, creds1) = {
            let s = self.session()?;
            let g = s.mls.create_group_with_meta(&meta)?;
            let built = s.mls.commit(&g, &ops).and_then(|o| s.mls.home_keys_after_pending_commit(&g).map(|k| (o, k)));
            match built {
                Ok((o, k)) => (g, o, HomeCreds::new(1, &k)),
                Err(e) => {
                    let _ = s.mls.clear_pending_commit(&g);
                    let _ = s.mls.leave_group_state(&g);
                    return Err(e);
                }
            }
        };
        let abort = |e: &mut Engine, err: SecurityError| -> SecurityError {
            if let Ok(s) = e.session() {
                let _ = s.mls.clear_pending_commit(&group);
                let _ = s.mls.leave_group_state(&group);
            }
            err
        };
        let welcome = match out.welcome.clone() {
            Some(w) => w,
            None => return Err(abort(self, SecurityError::Protocol("missing welcome"))),
        };
        let req = HomeCommitRequest {
            expected_seq: 0,
            commit_id: rid()?,
            commit: out.commit.clone(),
            next_commit_pub: creds1.commit_pub().to_vec(),
            next_read_pub: creds1.read_pub().to_vec(),
        };
        let htag = home_tag(&group.0);
        let submitted = RelayEndpoint::from_descriptor(&relay).and_then(|ep| self.api_at(&ep)?.home_commit(&htag, &creds1, &req));
        let chain = match submitted {
            Ok(HomeCommitResult::Accepted { seq: 1, chain }) => chain,
            Ok(_) => return Err(abort(self, SecurityError::Transport("home relay refused the new group"))),
            Err(e) => return Err(abort(self, e)),
        };
        self.session()?.mls.merge_pending_commit(&group)?;
        let now_creds = HomeCreds::new(1, &self.session()?.mls.home_keys(&group)?);
        if now_creds.commit_pub() != creds1.commit_pub() || now_creds.read_pub() != creds1.read_pub() {
            return Err(SecurityError::Protocol("home credentials differ after the merge"));
        }
        let id = Id16(group.0.as_slice().try_into().map_err(|_| SecurityError::Protocol("group id"))?);
        let new_devices: Vec<Id16> =
            ops.iter().filter_map(|o| if let GroupOp::Add { expected, .. } = o { Some(expected.device_id) } else { None }).collect();
        let (local, seeds) = self.classify_new_devices(&devs, &new_devices);
        let now = self.now_ms();
        let conv = Conversation {
            id,
            kind: ConvKind::Group,
            state: ConvState::Active,
            title: meta.name.clone(),
            peer: None,
            tag,
            relay_seq: 0,
            unread: 0,
            last_activity_ms: now,
            last_preview: String::new(),
            last_self_update_ms: now,
            sent_since_update: 0,
            access_revoked: false,
            remote: false,
            home: Some(HomedGroup {
                relay,
                ledger: Some(HomeLedger::new(HomeHead::at(1, chain))),
                local_devices: local,
                frozen: None,
                issue: None,
                superseded_by: None,
            }),
        };
        let hk = self.current_epoch_key(&id)?;
        let item = self.welcome_item(id, welcome, new_devices)?;
        self.commit_state(|s| {
            history::put_epoch_key(s, &id, hk.0, &hk.1)?;
            put_json(s, NS_CONV, &id.to_hex(), &conv)?;
            put_json(s, NS_OUTBOX, &item.id.to_hex(), &item)?;
            for (d, intro, relay) in &seeds {
                put_json(
                    s,
                    NS_CAPS,
                    &format!("peer/{}/{}", id.to_hex(), d.to_hex()),
                    &StoredPeerCap::Full(PeerCap { cap: *intro, relay: Some(relay.clone()) }),
                )?;
            }
            Ok(())
        })?;
        let _ = self.flush_outbox();
        Ok(id)
    }

    /// Split newly added devices into those on our relay and those reached through their card's intro capability.
    fn classify_new_devices(
        &mut self,
        devs: &[(Id16, Id16, [u8; 32])],
        new_devices: &[Id16],
    ) -> (Vec<Id16>, Vec<(Id16, Id16, RelayDescriptor)>) {
        let mut local = Vec::new();
        let mut seeds = Vec::new();
        for (account, device, _) in devs {
            if !new_devices.contains(device) {
                continue;
            }
            match self.home_of(account) {
                Some(h) => seeds.push((*device, h.intro, h.relay)),
                None => local.push(*device),
            }
        }
        (local, seeds)
    }

    fn welcome_item(&mut self, conv: Id16, welcome: Vec<u8>, devices: Vec<Id16>) -> Result<OutboxItem> {
        Ok(OutboxItem {
            id: rid()?,
            conv,
            devices,
            ciphertext: welcome,
            attempts: 0,
            next_attempt_ms: 0,
            is_leave: false,
            welcome: true,
            order: self.next_ts_ms(),
        })
    }

    // --------------------------------------------------------------------------------------------------------------- commits

    /// One membership/metadata commit through the home log, rebasing on contention (compare-and-swap on the log head).
    pub(crate) fn run_home_commit(
        &mut self,
        conv_id: &Id16,
        build: &dyn Fn(&mut Engine, &Conversation) -> Result<CommitPlan>,
    ) -> Result<()> {
        self.guard()?;
        self.resolve_home_pending()?;
        if self.vault.with_store(|s| Ok(s.get(NS_HOME_PENDING, &conv_id.to_hex())?.is_some()))? {
            return Err(SecurityError::Transport("an earlier commit of this group is still unresolved"));
        }
        let mut last_err = SecurityError::Transport("commit contention");
        for _ in 0..4 {
            let mut report = SyncReport::default();
            self.pull_home_one(conv_id, &mut report)?;
            let conv = self.conversation(conv_id)?;
            if conv.state != ConvState::Active {
                return Err(SecurityError::Denied("conversation is not active"));
            }
            let home = conv.home.clone().ok_or(SecurityError::Denied("not a cross-relay group"))?;
            if home.frozen.is_some() {
                return Err(SecurityError::Denied("membership changes are blocked: the home log of this group is no longer trustworthy"));
            }
            if home.issue.as_ref().is_some_and(|i| i.alerted && i.kind == "unrecognized") {
                return Err(SecurityError::Denied(
                    "membership changes are blocked: the home relay no longer recognises this group (create a successor group)",
                ));
            }
            let ledger = home.ledger.clone().ok_or(SecurityError::Transport("this device has not caught up with the home log yet"))?;
            let group = GroupRef(conv.id.0.to_vec());
            let epoch = self.mls_epoch(&group)?;
            if ledger.head.seq != epoch {
                self.freeze_group(conv_id, FREEZE_BLOCKED)?;
                return Err(SecurityError::Denied("membership changes are blocked: the home log is ahead of the group state"));
            }
            let cur = self.home_creds_now(&group)?;
            let (ops, new_devices, new_tag) = build(self, &conv)?;
            let out = self.session()?.mls.commit(&group, &ops)?;
            let next = match self.session()?.mls.home_keys_after_pending_commit(&group) {
                Ok(k) => HomeCreds::new(epoch + 1, &k),
                Err(e) => {
                    let _ = self.session()?.mls.clear_pending_commit(&group);
                    return Err(e);
                }
            };
            let devs_for_new = self.devs_of_new(&new_devices, &ops);
            let (local_new, seeds) = self.classify_new_devices(&devs_for_new, &new_devices);
            let pending = HomePending {
                conv: conv.id,
                expected: epoch,
                commit_id: rid()?,
                commit: out.commit.clone(),
                next_commit_pub: next.commit_pub().to_vec(),
                next_read_pub: next.read_pub().to_vec(),
                welcome: out.welcome.clone(),
                new_devices: new_devices.clone(),
                seeds,
                local_new,
                removed: ops.iter().any(|o| matches!(o, GroupOp::Remove { .. })),
                self_update: ops.iter().any(|o| matches!(o, GroupOp::SelfUpdate)),
            };
            let _ = new_tag; // the routing tag of an ordinary group; a homed group's mailbox routing does not use it
            self.commit_state(|s| put_json(s, NS_HOME_PENDING, &conv.id.to_hex(), &pending))?;
            let res = self.submit_home(&home.relay, &group, &cur, &pending);
            match res {
                Ok(HomeCommitResult::Accepted { seq, chain }) => {
                    self.finish_home_commit(&pending, seq, chain)?;
                    return Ok(());
                }
                Ok(HomeCommitResult::Stale { .. }) => {
                    self.drop_home_pending(&pending)?;
                    last_err = SecurityError::Transport("commit contention");
                }
                Ok(HomeCommitResult::Full) => {
                    self.drop_home_pending(&pending)?;
                    return Err(SecurityError::Denied("the home relay's log for this group is full: create a new group"));
                }
                // OUTCOME UNKNOWN: keep the pending record; the next sync re-sends the identical request (idempotent by commit id).
                Err(e) => return Err(e),
            }
        }
        Err(last_err)
    }

    fn devs_of_new(&mut self, new_devices: &[Id16], ops: &[GroupOp]) -> Vec<(Id16, Id16, [u8; 32])> {
        ops.iter()
            .filter_map(|o| match o {
                GroupOp::Add { expected, .. } if new_devices.contains(&expected.device_id) => {
                    Some((expected.account_id, expected.device_id, expected.identity_key))
                }
                _ => None,
            })
            .collect()
    }

    fn submit_home(&mut self, relay: &RelayDescriptor, group: &GroupRef, cur: &HomeCreds, p: &HomePending) -> Result<HomeCommitResult> {
        let req = HomeCommitRequest {
            expected_seq: p.expected,
            commit_id: p.commit_id,
            commit: p.commit.clone(),
            next_commit_pub: p.next_commit_pub.clone(),
            next_read_pub: p.next_read_pub.clone(),
        };
        let ep = RelayEndpoint::from_descriptor(relay)?;
        self.api_at(&ep)?.home_commit(&home_tag(&group.0), cur, &req)
    }

    /// The home relay accepted our commit at `seq`: merge, record the new epoch's history key and ledger head atomically, and hand the Welcome to
    /// the outbox (it was written ahead, so it cannot be lost).
    fn finish_home_commit(&mut self, p: &HomePending, seq: u64, chain: [u8; 32]) -> Result<()> {
        let group = GroupRef(p.conv.0.to_vec());
        if seq != p.expected + 1 {
            return Err(SecurityError::Protocol("home relay accepted the commit at an unexpected position"));
        }
        self.session()?.mls.merge_pending_commit(&group)?;
        let creds = self.home_creds_now(&group)?;
        let entry = VerifiedEntry {
            seq,
            commit_id: p.commit_id,
            commit: p.commit.clone(),
            chain,
            commit_pub: creds.commit_pub(),
            read_pub: creds.read_pub(),
        };
        if creds.epoch != seq
            || creds.commit_pub().as_slice() != p.next_commit_pub.as_slice()
            || creds.read_pub().as_slice() != p.next_read_pub.as_slice()
        {
            return Err(SecurityError::Protocol("home credentials differ after the merge"));
        }
        let meta = self.session()?.mls.group_meta(&group)?;
        let mut conv = self.conversation(&p.conv)?;
        if let Some(m) = meta {
            conv.tag = m.tag;
            conv.title = m.name;
        }
        if p.self_update {
            conv.last_self_update_ms = self.now_ms();
            conv.sent_since_update = 0;
        }
        if let Some(h) = conv.home.as_mut() {
            let mut ledger = h.ledger.clone().unwrap_or_else(|| HomeLedger::new(HomeHead::at(seq - 1, [0; 32])));
            ledger.apply(&entry);
            h.ledger = Some(ledger);
            for d in &p.local_new {
                if !h.local_devices.contains(d) {
                    h.local_devices.push(*d);
                }
            }
        }
        let hk = self.current_epoch_key(&p.conv)?;
        let item = match (&p.welcome, p.new_devices.is_empty()) {
            (Some(w), false) => Some(self.welcome_item(p.conv, w.clone(), p.new_devices.clone())?),
            _ => None,
        };
        self.commit_state(|s| {
            history::put_epoch_key(s, &conv.id, hk.0, &hk.1)?;
            s.delete(NS_HOME_PENDING, &p.conv.to_hex())?;
            put_json(s, NS_CONV, &conv.id.to_hex(), &conv)?;
            if let Some(item) = &item {
                put_json(s, NS_OUTBOX, &item.id.to_hex(), item)?;
            }
            for (d, intro, relay) in &p.seeds {
                put_json(
                    s,
                    NS_CAPS,
                    &format!("peer/{}/{}", p.conv.to_hex(), d.to_hex()),
                    &StoredPeerCap::Full(PeerCap { cap: *intro, relay: Some(relay.clone()) }),
                )?;
            }
            Ok(())
        })?;
        if p.removed {
            self.mark_caps_stale(&p.conv);
            self.push_event(SecurityEvent::GroupMemberRemoved { conversation_id: p.conv.to_hex() });
        }
        if !p.new_devices.is_empty() {
            // Introduce the new members to everyone we can reach (their Welcome is delivered first, per device).
            let _ = self.send_group_caps(&p.conv);
        }
        let _ = self.flush_outbox();
        Ok(())
    }

    pub(crate) fn drop_home_pending(&mut self, p: &HomePending) -> Result<()> {
        let group = GroupRef(p.conv.0.to_vec());
        if let Ok(s) = self.session() {
            let _ = s.mls.clear_pending_commit(&group);
        }
        self.commit_state(|s| s.delete(NS_HOME_PENDING, &p.conv.to_hex()))
    }

    /// Re-send commits whose outcome was unknown (lost response, crash). Network errors leave them pending; they never abort a sync.
    pub(crate) fn resolve_home_pending(&mut self) -> Result<()> {
        let ids = self.vault.with_store(|s| s.list_ids(NS_HOME_PENDING))?;
        for id in ids {
            let Some(p) = self.vault.with_store(|s| get_json::<HomePending>(s, NS_HOME_PENDING, &id))? else { continue };
            let conv = self.vault.with_store(|s| get_json::<Conversation>(s, NS_CONV, &p.conv.to_hex()))?;
            let Some(home) = conv.filter(|c| !c.access_revoked).and_then(|c| c.home) else {
                self.commit_state(|s| s.delete(NS_HOME_PENDING, &id))?;
                continue;
            };
            let group = GroupRef(p.conv.0.to_vec());
            let cur = self.home_creds_now(&group)?;
            if cur.epoch != p.expected {
                self.commit_state(|s| s.delete(NS_HOME_PENDING, &id))?; // the state moved on without this commit
                continue;
            }
            match self.submit_home(&home.relay, &group, &cur, &p) {
                Ok(HomeCommitResult::Accepted { seq, chain }) => self.finish_home_commit(&p, seq, chain)?,
                Ok(_) => self.drop_home_pending(&p)?,
                Err(_) => {} // still unknown: try again next time
            }
        }
        Ok(())
    }

    // --------------------------------------------------------------------------------------------------------------- reading the log

    /// Poll the home log of every cross-relay group. Failures of the home relay never abort the sync of the rest.
    pub(crate) fn pull_home(&mut self, report: &mut SyncReport) -> Result<()> {
        let _ = self.resolve_home_pending();
        let ids: Vec<Id16> = self
            .list_conversations()?
            .into_iter()
            .filter(|c| c.home.is_some() && c.state == ConvState::Active && !c.access_revoked)
            .map(|c| c.id)
            .collect();
        for id in ids {
            if let Err(
                e @ (SecurityError::StorageCorrupt | SecurityError::Locked | SecurityError::Invalidated | SecurityError::KeyStore(_)),
            ) = self.pull_home_one(&id, report)
            {
                return Err(e);
            }
        }
        Ok(())
    }

    pub(crate) fn pull_home_one(&mut self, conv_id: &Id16, report: &mut SyncReport) -> Result<()> {
        for _ in 0..MAX_LOG_PAGES {
            let conv = self.conversation(conv_id)?;
            let Some(home) = conv.home.clone() else { return Ok(()) };
            if conv.access_revoked || conv.state == ConvState::Left || home.frozen.is_some() {
                return Ok(());
            }
            let group = GroupRef(conv_id.0.to_vec());
            let htag = home_tag(&group.0);
            let creds = self.home_creds_now(&group)?;
            let after = home.ledger.as_ref().map_or(creds.epoch.saturating_sub(1), |l| l.head.seq);
            let ep = RelayEndpoint::from_descriptor(&home.relay)?;
            let resp = match self.api_at(&ep)?.home_log(&htag, &creds, after) {
                Ok(r) => {
                    self.clear_home_issue(conv_id)?;
                    r
                }
                Err(e) => {
                    // Try again next sync, but do not let a lost or unreachable commit channel stay invisible for ever.
                    self.note_home_failure(conv_id, &e)?;
                    return Ok(());
                }
            };
            let mut entries = resp.entries.clone();
            let mut ledger = home.ledger.clone();
            let mut anchored_now = false;
            if ledger.is_none() {
                // A joiner anchors itself at the entry that ADDED it: that entry must carry exactly the epoch keys this device derived.
                let Some(pos) = entries.iter().position(|e| e.seq == creds.epoch) else { return Ok(()) };
                let Some(e0) = entries.get(pos).cloned() else { return Ok(()) };
                let keys_ok = e0.keys().map(|(c, r)| c == creds.commit_pub() && r == creds.read_pub()).unwrap_or(false);
                if !keys_ok {
                    self.freeze_group(conv_id, crate::home::FORK_KEYS)?;
                    return Ok(());
                }
                ledger = Some(HomeLedger::new(HomeHead { seq: e0.seq, chain: e0.chain.clone() }));
                entries.drain(..=pos);
                anchored_now = true;
            }
            let mut ledger = ledger.ok_or(SecurityError::InvalidState)?;
            if entries.is_empty() {
                if let Some(h) = &resp.head {
                    if let Err(SecurityError::Protocol(m)) = check_reported_head(&ledger.head, h.seq, &h.chain) {
                        self.freeze_group(conv_id, m)?;
                        return Ok(());
                    }
                }
                if anchored_now {
                    self.save_ledger(conv_id, &ledger)?;
                }
                return Ok(());
            }
            let verified = match verify_page(&htag, &ledger.head, &entries) {
                Ok(v) => v,
                Err(SecurityError::Protocol(m)) => {
                    self.freeze_group(conv_id, m)?;
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            for v in verified {
                let epoch_before = self.mls_epoch(&group)?;
                if v.seq <= epoch_before {
                    ledger.apply(&v); // already applied (crash between the group state and the ledger): nothing to redo
                    continue;
                }
                let conv_now = self.conversation(conv_id)?;
                let members_before = self.session()?.mls.members_detailed(&group)?.len();
                match self.process_group_message(&conv_now, &v.commit) {
                    Ok(p) => {
                        let removed_self = matches!(p, ProcessedEx::Commit { self_removed: true, .. });
                        self.apply_processed(conv_id, p, report)?;
                        if removed_self {
                            return Ok(());
                        }
                        // Messages of the new epoch that reached the mailbox before this commit were held: they can be read now.
                        self.retry_held(conv_id, report)?;
                        // New members cannot know our capability (it is only announced on rotation): announce it again, directly.
                        if self.session()?.mls.members_detailed(&group)?.len() > members_before {
                            let _ = self.reannounce_own_cap(conv_id);
                        }
                        let after_creds = self.home_creds_now(&group)?;
                        if after_creds.epoch != v.seq {
                            ledger.apply(&v);
                            self.save_ledger(conv_id, &ledger)?;
                            self.freeze_group(conv_id, FREEZE_MISMATCH)?;
                            return Ok(());
                        }
                        if let Err(SecurityError::Protocol(m)) = check_epoch_keys(&v, &after_creds) {
                            ledger.apply(&v);
                            self.save_ledger(conv_id, &ledger)?;
                            self.freeze_group(conv_id, m)?;
                            return Ok(());
                        }
                        ledger.apply(&v);
                        self.save_ledger(conv_id, &ledger)?;
                    }
                    Err(
                        e @ (SecurityError::StorageCorrupt
                        | SecurityError::Locked
                        | SecurityError::Invalidated
                        | SecurityError::KeyStore(_)),
                    ) => return Err(e),
                    Err(SecurityError::Unauthorized(_)) => {
                        self.push_event(SecurityEvent::UnauthorizedGroupChange { conversation_id: conv_id.to_hex() });
                        ledger.apply(&v);
                        self.save_ledger(conv_id, &ledger)?;
                        self.freeze_group(conv_id, FREEZE_BLOCKED)?;
                        return Ok(());
                    }
                    Err(_) => {
                        // Refused (malformed, wrong epoch, unknown sender ...): the entry occupies a log position but changed nothing.
                        ledger.apply(&v);
                        self.save_ledger(conv_id, &ledger)?;
                        self.freeze_group(conv_id, FREEZE_BLOCKED)?;
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }
}

// ------------------------------------------------------------------------------------------------------- capability introductions

#[derive(Deserialize)]
struct OwnCapRead {
    cap: Id16,
}

impl Engine {
    /// A sender's log position (carried in an authenticated frame) is compared with ours.
    pub(crate) fn check_gossip(&mut self, conv_id: &Id16, h: &LogHead) -> Result<()> {
        let conv = self.conversation(conv_id)?;
        let Some(ledger) = conv.home.and_then(|g| g.ledger) else { return Ok(()) };
        if ledger.gossip(h.seq, &h.chain) == Gossip::Fork {
            self.freeze_group(conv_id, crate::home::FORK_EQUIVOCATION)?;
        }
        Ok(())
    }

    /// A member announced its OWN capability in this group (end-to-end authenticated). The first time that happens, owners and admins introduce
    /// everyone to everyone: two members that have never been in contact otherwise cannot learn each other's relay and capability.
    pub(super) fn homed_cap_learned(&mut self, conv_id: &Id16, device: Id16, first_direct: bool) -> Result<()> {
        let key = format!("src/{}/{}", conv_id.to_hex(), device.to_hex());
        self.vault.with_store(|s| put_json(s, NS_CAPS, &key, &"direct"))?;
        if first_direct && matches!(self.my_role(conv_id)?, Role::Owner | Role::Admin) {
            self.send_group_caps(conv_id)?;
        }
        Ok(())
    }

    /// Tell the group every capability this device knows (including its own), so members can reach each other.
    pub(crate) fn send_group_caps(&mut self, conv_id: &Id16) -> Result<()> {
        let group = GroupRef(conv_id.0.to_vec());
        let (_, me_dev) = self.own_ids()?;
        let members = self.session()?.mls.members_detailed(&group)?;
        let own_relay = self.own_relay.clone();
        let mut entries: Vec<GroupCapEntry> = Vec::new();
        for m in members.iter().filter(|m| m.device != me_dev) {
            if let Some(pc) = self.peer_cap(conv_id, &m.device) {
                // `None` means "valid at OUR relay": for other members that must be spelled out.
                if let Some(relay) = pc.relay.or_else(|| own_relay.clone()) {
                    entries.push(GroupCapEntry { device: m.device, cap: pc.cap, relay: Some(relay) });
                }
            }
        }
        let own = self.vault.with_store(|s| get_json::<OwnCapRead>(s, NS_CAPS, &format!("own/{}", conv_id.to_hex())))?;
        if let (Some(o), Some(relay)) = (own, own_relay) {
            entries.push(GroupCapEntry { device: me_dev, cap: o.cap, relay: Some(relay) });
        }
        entries.truncate(100);
        if entries.len() < 2 {
            return Ok(()); // nobody to introduce to anybody
        }
        let frame =
            Frame { v: 1, id: rid()?, ts_ms: self.next_ts_ms(), reply_to: None, content: Content::GroupCaps { entries }, head: None };
        self.queue_app_message(conv_id, frame, false, false)?;
        Ok(())
    }

    /// Queue our CURRENT inbox capability for the group again (no new capability is minted).
    pub(crate) fn reannounce_own_cap(&mut self, conv_id: &Id16) -> Result<()> {
        let Some(relay) = self.own_relay.clone() else { return Ok(()) };
        let own = self.vault.with_store(|s| get_json::<OwnCapRead>(s, NS_CAPS, &format!("own/{}", conv_id.to_hex())))?;
        let Some(o) = own else { return Ok(()) };
        let frame = Frame {
            v: 1,
            id: rid()?,
            ts_ms: self.next_ts_ms(),
            reply_to: None,
            content: Content::DeliveryCap { cap: o.cap, relay: Some(relay) },
            head: None,
        };
        self.queue_app_message(conv_id, frame, false, false)?;
        Ok(())
    }

    /// Hearsay from a member about OTHER members' capabilities. Never overrides a device's own announcement, never concerns this device or the
    /// sender, and only names devices that are members. (A malicious member can misdirect messages to a relay it controls — it can already read
    /// them; the worst effect is that the real recipient does not get them. Documented in docs/CROSS_RELAY_GROUPS.md.)
    pub(super) fn apply_group_caps(&mut self, conv_id: &Id16, sender_device: Id16, entries: Vec<GroupCapEntry>) -> Result<()> {
        let group = GroupRef(conv_id.0.to_vec());
        let (_, me_dev) = self.own_ids()?;
        let members: Vec<Id16> = self.session()?.mls.members_detailed(&group)?.into_iter().map(|m| m.device).collect();
        for e in entries.into_iter().take(100) {
            if e.device == me_dev || !members.contains(&e.device) {
                continue;
            }
            // An entry about the SENDER is that device announcing its own capability (authenticated by MLS): as good as a DeliveryCap frame.
            let own_announcement = e.device == sender_device;
            let relay = match e.relay {
                Some(d) => match d.validated() {
                    Ok(d) if self.own_relay.as_ref().is_some_and(|o| o.url() == d.url()) => None,
                    Ok(d) => Some(d),
                    Err(_) => continue,
                },
                None => continue, // a relay-less entry is ambiguous between two members: ignore
            };
            let src = format!("src/{}/{}", conv_id.to_hex(), e.device.to_hex());
            let key = format!("peer/{}/{}", conv_id.to_hex(), e.device.to_hex());
            self.vault.with_store(|s| {
                if !own_announcement && s.get(NS_CAPS, &src)?.is_some_and(|v| v.as_slice() == b"\"direct\"".as_slice()) {
                    return Ok(());
                }
                put_json(s, NS_CAPS, &key, &StoredPeerCap::Full(PeerCap { cap: e.cap, relay }))?;
                put_json(s, NS_CAPS, &src, &if own_announcement { "direct" } else { "gossip" })
            })?;
        }
        self.wake_outbox(conv_id)
    }
}

// ------------------------------------------------------------------------------------------------------------------ test support

/// What a malicious MEMBER (who holds the real credentials of the current epoch) can put into the home log.
#[cfg(any(test, feature = "insecure-test-support"))]
#[derive(Debug)]
pub enum HomeForgery {
    /// A well-formed commit the group's policy forbids (its sender skips its own pre-check).
    Unauthorized(Vec<GroupOp>),
    /// Unparseable bytes, announcing public keys of the attacker's choosing for the next epoch.
    Garbage,
}

#[cfg(any(test, feature = "insecure-test-support"))]
impl Engine {
    /// Submit a forged commit with this member's REAL credentials and never merge it locally. Receivers must refuse it.
    pub fn inject_forged_home_commit_for_tests(&mut self, conv: &Id16, forgery: HomeForgery) -> Result<()> {
        let mut report = SyncReport::default();
        self.pull_home_one(conv, &mut report)?;
        let c = self.conversation(conv)?;
        let home = c.home.ok_or(SecurityError::Denied("not a cross-relay group"))?;
        let group = GroupRef(c.id.0.to_vec());
        let epoch = self.mls_epoch(&group)?;
        let cur = self.home_creds_now(&group)?;
        let (commit, next_commit_pub, next_read_pub) = match forgery {
            HomeForgery::Unauthorized(ops) => {
                let out = self.session()?.mls.commit_unchecked_for_tests(&group, &ops)?;
                let next = HomeCreds::new(epoch + 1, &self.session()?.mls.home_keys_after_pending_commit(&group)?);
                self.session()?.mls.clear_pending_commit(&group)?;
                (out.commit, next.commit_pub(), next.read_pub())
            }
            HomeForgery::Garbage => (vec![0xAB; 200], [7u8; 32], [8u8; 32]),
        };
        let p = HomePending {
            conv: c.id,
            expected: epoch,
            commit_id: rid()?,
            commit,
            next_commit_pub: next_commit_pub.to_vec(),
            next_read_pub: next_read_pub.to_vec(),
            welcome: None,
            new_devices: Vec::new(),
            seeds: Vec::new(),
            local_new: Vec::new(),
            removed: false,
            self_update: false,
        };
        self.submit_home(&home.relay, &group, &cur, &p).map(|_| ())
    }
}
