//! Private invitations, client side (docs/INVITATIONS.md §6–§7).
//!
//! A link is a bearer permission to ASK, never a membership. The joiner sends a request that (1) opens only under a key derived from the link, so a
//! relay cannot read or forge it, and (2) is SIGNED by the joiner's root identity key over this invitation id and a fresh nonce, so a link holder can
//! never get somebody else's account added by replaying that person's public contact card. The issuing admin verifies everything, shows who is asking,
//! and on approval runs the EXISTING, receiver-verified path: `add_contact_by_card` (directory check against the card's pinned root key) and
//! `add_group_members` (authorised MLS Add + Welcome). The Welcome opens the group at the epoch of the Add: a new member gets no earlier history.
use super::engine::{get_json, put_json, Engine};
use super::model::{ConvKind, Role};
use crate::contact_card::ContactCard;
use crate::error::{Result, SecurityError};
use crate::invite::{InviteKeys, InviteSecret};
use crate::protocol::{GroupProtocol as _, GroupRef};
use crate::relay_client::RelayEndpoint;
use cipher_wire::invite::{id_hash, InviteLink, InvitePolicy, JoinMode};
use cipher_wire::{b64, Id16};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

const NS_INVITE: &str = "invites";
const NS_JOIN: &str = "joinreq";
const JOIN_DOMAIN: &[u8] = b"cipher-join-v1\0";
const MAX_NAME_CHARS: usize = 64;
const MAX_TEXT_CHARS: usize = 200;
const SKEW_MS: u64 = 5 * 60_000;
/// Per invitation: how many distinct requests (nonces/accounts) are remembered for replay protection before new ones are refused.
const MAX_SEEN: usize = 1000;
/// The contact card a joiner attaches must outlive the admin's decision.
const JOIN_CARD_DAYS: u32 = 7;

#[derive(Clone, Serialize, Deserialize)]
struct InviteRecord {
    id: Id16,
    /// The link secret: it lives only in the encrypted vault of the issuing device.
    secret: [u8; 16],
    conv: Id16,
    auto: bool,
    max_uses: u32,
    created_ms: u64,
    expires_ms: u64,
    revoked: bool,
    admitted: u32,
    /// Nonces and account ids already seen on this invitation (replay and one-request-per-account protection).
    seen: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum JoinState {
    Pending,
    /// Admitted locally (the MLS Add is durable); the relay has not been told yet.
    Admitted,
    /// Rejected locally; the relay has not been told yet.
    Rejected,
}

#[derive(Clone, Serialize, Deserialize)]
struct PendingJoin {
    request_id: Id16,
    invite: Id16,
    conv: Id16,
    account: Id16,
    root_key: [u8; 32],
    name: String,
    card: String,
    received_ms: u64,
    state: JoinState,
}

/// What the joiner signs and the issuer parses: the exact string `r` is what the signature covers.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinBody {
    v: u8,
    id: String,
    nonce: String,
    ts: u64,
    name: String,
    card: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    r: String,
    s: String,
}

/// The preview a link holder can read BEFORE asking to join (it is encrypted to the link, so the relay cannot read it). These are the issuer's own
/// claims: they are not proof of who the issuer is. Identity is established by the safety-number comparison after joining.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewBody {
    v: u8,
    group: String,
    inviter: String,
    account: String,
    root_key: String,
    auto: bool,
    expires_ms: u64,
    /// Only a group created with a HOME relay can take members whose account lives on another relay (docs/CROSS_RELAY_GROUPS.md).
    #[serde(default)]
    other_relays: bool,
}

#[derive(Clone, Debug)]
pub struct InvitePreview {
    pub group_name: String,
    pub inviter_name: String,
    pub inviter_account: Id16,
    pub inviter_root_key: [u8; 32],
    pub auto_admission: bool,
    pub expires_ms: u64,
    /// False: only people whose account is on the inviter's relay can join; asking from another relay will be refused.
    pub accepts_other_relays: bool,
}

#[derive(Clone, Debug)]
pub struct InviteCreated {
    pub id: Id16,
    pub link: String,
    pub expires_ms: u64,
}

/// No secret: the link itself is shown once, at creation.
#[derive(Clone, Debug)]
pub struct InviteInfo {
    pub id: Id16,
    pub conversation: Id16,
    pub expires_ms: u64,
    pub max_uses: u32,
    pub admitted: u32,
    pub auto_admission: bool,
    pub revoked: bool,
}

#[derive(Clone, Debug)]
pub struct JoinRequestView {
    pub request_id: Id16,
    pub invite: Id16,
    pub conversation: Id16,
    pub account: Id16,
    pub name: String,
    /// Compare with the person out of band before approving.
    pub safety_number: String,
    pub received_ms: u64,
}

fn clean_text(s: &str, max: usize) -> Option<String> {
    let t = s.trim();
    if t.is_empty()
        || t.chars().count() > max
        || t.chars().any(|c| c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
    {
        return None;
    }
    Some(t.to_owned())
}

impl Engine {
    fn invite_record(&mut self, id: &Id16) -> Result<Option<InviteRecord>> {
        let key = id.to_hex();
        self.vault.with_store(|s| get_json::<InviteRecord>(s, NS_INVITE, &key))
    }

    fn invite_records(&mut self) -> Result<Vec<InviteRecord>> {
        let ids = self.vault.with_store(|s| s.list_ids(NS_INVITE))?;
        let mut out = Vec::new();
        for id in ids {
            if let Some(r) = self.vault.with_store(|s| get_json::<InviteRecord>(s, NS_INVITE, &id))? {
                out.push(r);
            }
        }
        Ok(out)
    }

    fn pending_joins(&mut self) -> Result<Vec<PendingJoin>> {
        let ids = self.vault.with_store(|s| s.list_ids(NS_JOIN))?;
        let mut out = Vec::new();
        for id in ids {
            if let Some(p) = self.vault.with_store(|s| get_json::<PendingJoin>(s, NS_JOIN, &id))? {
                out.push(p);
            }
        }
        out.sort_by_key(|p| (p.received_ms, p.request_id.0));
        Ok(out)
    }

    fn require_admin_of_group(&mut self, conv: &Id16) -> Result<()> {
        let c = self.conversation(conv)?;
        if c.kind != ConvKind::Group {
            return Err(SecurityError::Denied("only groups have invitation links"));
        }
        if self.my_role(conv)? == Role::Member {
            return Err(SecurityError::Denied("only an owner or admin can invite"));
        }
        Ok(())
    }

    // ------------------------------------------------------------------------------------------------------------------------------ issuer

    /// Creates an invitation link for a group the caller owns or administers. The link is returned ONCE; only its secret (inside the encrypted
    /// vault) and the relay's hash/ciphertext remain.
    pub fn create_invite(&mut self, conv: &Id16, policy: InvitePolicy) -> Result<InviteCreated> {
        self.guard()?;
        self.require_admin_of_group(conv)?;
        policy.validate().map_err(|_| SecurityError::Malformed("invitation policy"))?;
        let relay = self
            .own_relay
            .clone()
            .ok_or(SecurityError::Denied("this relay cannot be named in a link (onion relays need set_own_relay with a pin)"))?;
        let (title, accepts_other_relays) = {
            let c = self.conversation(conv)?;
            (c.title, c.home.is_some())
        };
        let (account, _) = self.own_ids()?;
        let inviter = self.display_name(&account);
        let root_key = self.session()?.mls.identity_public();

        let secret = InviteSecret::generate()?;
        let keys = secret.keys();
        let id = Id16(*keys.id());
        let now = self.now_ms();
        let expires_ms = now.checked_add(policy.lifetime_ms).ok_or(SecurityError::Malformed("invitation lifetime"))?;
        let preview = PreviewBody {
            v: 1,
            group: title.chars().take(MAX_TEXT_CHARS).collect(),
            inviter: inviter.chars().take(MAX_TEXT_CHARS).collect(),
            account: account.to_hex(),
            root_key: b64::encode(&root_key),
            auto: policy.mode == JoinMode::Auto,
            expires_ms,
            other_relays: accepts_other_relays,
        };
        let sealed = keys.seal_preview(&serde_json::to_vec(&preview).map_err(|_| SecurityError::Malformed("preview"))?)?;
        self.api()?.invite_create(id, sealed, policy.lifetime_ms, policy.max_uses)?;

        let rec = InviteRecord {
            id,
            secret: *secret.as_bytes(),
            conv: *conv,
            auto: policy.mode == JoinMode::Auto,
            max_uses: policy.max_uses,
            created_ms: now,
            expires_ms,
            revoked: false,
            admitted: 0,
            seen: Vec::new(),
        };
        self.commit_state(|s| put_json(s, NS_INVITE, &id.to_hex(), &rec))?;
        let link = InviteLink::new(*secret.as_bytes(), relay).encode();
        Ok(InviteCreated { id, link, expires_ms })
    }

    pub fn list_invites(&mut self, conv: &Id16) -> Result<Vec<InviteInfo>> {
        self.guard()?;
        Ok(self
            .invite_records()?
            .into_iter()
            .filter(|r| r.conv == *conv)
            .map(|r| InviteInfo {
                id: r.id,
                conversation: r.conv,
                expires_ms: r.expires_ms,
                max_uses: r.max_uses,
                admitted: r.admitted,
                auto_admission: r.auto,
                revoked: r.revoked,
            })
            .collect())
    }

    /// Revokes at once: at the relay (new requests are refused, pending ones dropped) and locally (nothing pending is admitted any more).
    pub fn revoke_invite(&mut self, id: &Id16) -> Result<()> {
        self.guard()?;
        let mut rec = self.invite_record(id)?.ok_or(SecurityError::NotFound("invitation"))?;
        rec.revoked = true;
        self.commit_state(|s| put_json(s, NS_INVITE, &id.to_hex(), &rec))?;
        match self.api()?.invite_revoke(id) {
            Ok(()) | Err(SecurityError::Transport("not found")) => Ok(()), // already expired or purged at the relay
            Err(e) => Err(e),
        }
    }

    /// Fetches new join requests from the relay, verifies each, and returns every request waiting for a decision. In automatic mode a verified request
    /// within the invitation's limits is approved here; everything else waits for [`Engine::resolve_join_request`].
    pub fn poll_join_requests(&mut self) -> Result<Vec<JoinRequestView>> {
        self.guard()?;
        let now = self.now_ms();
        let remote = self.api()?.invite_pending()?;
        let known: Vec<Id16> = self.pending_joins()?.into_iter().map(|p| p.request_id).collect();
        for p in remote {
            if known.contains(&p.request_id) {
                continue;
            }
            let records = self.invite_records()?;
            let Some(mut rec) = records.into_iter().find(|r| b64::encode(&id_hash(&r.id.0)) == p.id_hash) else {
                continue; // not one of this device's invitations (or one it has forgotten)
            };
            match self.verify_join(&mut rec, &p.body, now) {
                Ok(mut pj) => {
                    pj.request_id = p.request_id;
                    let key = p.request_id.to_hex();
                    let id_key = rec.id.to_hex();
                    self.commit_state(|s| {
                        put_json(s, NS_JOIN, &key, &pj)?;
                        put_json(s, NS_INVITE, &id_key, &rec)
                    })?;
                }
                Err(_) => {
                    // Not from a link holder, malformed, a replay, or beyond the invitation's limits: refuse it and return its slot.
                    let _ = self.api()?.invite_resolve(p.request_id, false);
                }
            }
        }
        self.settle_relay_state()?;
        for pj in self.pending_joins()? {
            if pj.state == JoinState::Pending && self.invite_record(&pj.invite)?.is_some_and(|r| r.auto) {
                let _ = self.resolve_join_request(&pj.request_id, true); // an automatic admission that fails stays pending for a human
            }
        }
        self.join_views()
    }

    fn join_views(&mut self) -> Result<Vec<JoinRequestView>> {
        let (me, _) = self.own_ids()?;
        let my_key: [u8; 32] =
            self.session()?.mls.identity_public().as_slice().try_into().map_err(|_| SecurityError::Malformed("identity key"))?;
        Ok(self
            .pending_joins()?
            .into_iter()
            .filter(|p| p.state == JoinState::Pending)
            .map(|p| JoinRequestView {
                request_id: p.request_id,
                invite: p.invite,
                conversation: p.conv,
                account: p.account,
                name: p.name.clone(),
                safety_number: crate::verification::safety_number(&me, &my_key, &p.account, &p.root_key),
                received_ms: p.received_ms,
            })
            .collect())
    }

    /// Tells the relay about decisions already made locally (a lost response must not leave a slot or a request dangling).
    fn settle_relay_state(&mut self) -> Result<()> {
        for pj in self.pending_joins()? {
            let approved = match pj.state {
                JoinState::Pending => continue,
                JoinState::Admitted => true,
                JoinState::Rejected => false,
            };
            match self.api()?.invite_resolve(pj.request_id, approved) {
                Ok(()) | Err(SecurityError::Transport("not found")) => {
                    let key = pj.request_id.to_hex();
                    self.commit_state(|s| s.delete(NS_JOIN, &key))?;
                }
                Err(_) => {} // retried on the next poll
            }
        }
        Ok(())
    }

    /// Every check on one request; nothing here changes group membership.
    fn verify_join(&mut self, rec: &mut InviteRecord, sealed: &[u8], now: u64) -> std::result::Result<PendingJoin, &'static str> {
        if rec.revoked || now >= rec.expires_ms {
            return Err("invitation is no longer live");
        }
        if rec.seen.len() >= MAX_SEEN {
            return Err("too many requests for this invitation");
        }
        let keys: InviteKeys = InviteSecret::from_bytes(rec.secret).keys();
        let plain = keys.open_request(sealed).map_err(|_| "does not open under this link")?;
        let env: Envelope = serde_json::from_slice(&plain).map_err(|_| "malformed envelope")?;
        let body: JoinBody = serde_json::from_str(&env.r).map_err(|_| "malformed request")?;
        if body.v != 1 || body.id != rec.id.to_hex() {
            return Err("request names another invitation");
        }
        let name = clean_text(&body.name, MAX_NAME_CHARS).ok_or("invalid display name")?;
        if body.ts.saturating_add(SKEW_MS) < rec.created_ms || body.ts > rec.expires_ms.saturating_add(SKEW_MS) {
            return Err("request outside the invitation's lifetime");
        }
        let nonce = b64::decode(&body.nonce).filter(|n| n.len() == 16).ok_or("invalid nonce")?;
        let card = ContactCard::parse(&body.card, now).map_err(|_| "invalid or expired contact card")?;
        let vk = VerifyingKey::from_bytes(&card.root_key).map_err(|_| "invalid identity key")?;
        let sig = b64::decode(&env.s).and_then(|s| Signature::from_slice(&s).ok()).ok_or("invalid signature")?;
        let mut signed = JOIN_DOMAIN.to_vec();
        signed.extend_from_slice(env.r.as_bytes());
        vk.verify(&signed, &sig).map_err(|_| "the card's owner did not sign this request")?;
        let me = self.own_ids().map_err(|_| "locked")?.0;
        if card.account == me {
            return Err("cannot invite yourself");
        }
        let (nonce_key, account_key) = (format!("n:{}", b64::encode(&nonce)), format!("a:{}", card.account.to_hex()));
        if rec.seen.contains(&nonce_key) || rec.seen.contains(&account_key) {
            return Err("replay, or this account already asked");
        }
        rec.seen.push(nonce_key);
        rec.seen.push(account_key);
        Ok(PendingJoin {
            request_id: Id16([0u8; 16]),
            invite: rec.id,
            conv: rec.conv,
            account: card.account,
            root_key: card.root_key,
            name,
            card: body.card,
            received_ms: now,
            state: JoinState::Pending,
        })
    }

    /// Approve (admit through the normal authorised MLS Add) or reject one request. Approval re-checks, at this moment, that the invitation is still
    /// live and has a use left and that the caller may add members; a failure leaves the request pending so nothing is half-done.
    pub fn resolve_join_request(&mut self, request: &Id16, approve: bool) -> Result<()> {
        self.guard()?;
        let key = request.to_hex();
        let mut pj =
            self.vault.with_store(|s| get_json::<PendingJoin>(s, NS_JOIN, &key))?.ok_or(SecurityError::NotFound("join request"))?;
        if pj.state != JoinState::Pending {
            return Err(SecurityError::InvalidState);
        }
        if !approve {
            pj.state = JoinState::Rejected;
            self.commit_state(|s| put_json(s, NS_JOIN, &key, &pj))?;
            return self.settle_relay_state();
        }
        let mut rec = self.invite_record(&pj.invite)?.ok_or(SecurityError::NotFound("invitation"))?;
        let now = self.now_ms();
        if rec.revoked || now >= rec.expires_ms || rec.admitted >= rec.max_uses {
            pj.state = JoinState::Rejected;
            self.commit_state(|s| put_json(s, NS_JOIN, &key, &pj))?;
            self.settle_relay_state()?;
            return Err(SecurityError::Denied("the invitation is no longer valid"));
        }
        self.require_admin_of_group(&pj.conv)?;
        let group = GroupRef(pj.conv.0.to_vec());
        if self.session()?.mls.members(&group)?.iter().any(|(a, _)| *a == pj.account) {
            return Err(SecurityError::Denied("already a member"));
        }
        // A group created without a home relay has no sequencer reachable from another relay: refuse such a joiner now, before anything is stored.
        let card = ContactCard::parse(&pj.card, now).map_err(|_| SecurityError::Denied("the joiner's card has expired"))?;
        let same_relay = self.own_relay.as_ref().is_some_and(|o| o.url() == card.relay.url());
        if !same_relay && self.conversation(&pj.conv)?.home.is_none() {
            return Err(SecurityError::Denied("this group only accepts members from its own relay"));
        }
        // The existing, tested path: the card's signature pins the root key and the joiner's own relay must confirm it BEFORE anything is stored;
        // the Add is authorised and every receiver re-verifies it. The Welcome opens the group at the epoch of this Add, so no earlier history.
        self.add_contact_by_card(&pj.card, &pj.name, false)?;
        self.add_group_members(&pj.conv, &[pj.account])?;
        rec.admitted += 1;
        pj.state = JoinState::Admitted;
        let id_key = rec.id.to_hex();
        self.commit_state(|s| {
            put_json(s, NS_JOIN, &key, &pj)?;
            put_json(s, NS_INVITE, &id_key, &rec)
        })?;
        self.settle_relay_state()
    }

    // ------------------------------------------------------------------------------------------------------------------------------- joiner

    /// What a link holder may see before asking to join. Reads the preview from the issuer's relay and decrypts it with the key derived from the link.
    pub fn preview_invite(&mut self, link: &str) -> Result<InvitePreview> {
        self.guard()?;
        let (link, keys, id) = Self::open_link(link)?;
        let ep = RelayEndpoint::from_descriptor(link.relay())?;
        let sealed = self.api_at(&ep)?.invite_lookup(&id)?;
        let body: PreviewBody =
            serde_json::from_slice(&keys.open_preview(&sealed)?).map_err(|_| SecurityError::Malformed("invitation preview"))?;
        if body.v != 1 {
            return Err(SecurityError::Malformed("invitation preview version"));
        }
        Ok(InvitePreview {
            group_name: clean_text(&body.group, MAX_TEXT_CHARS).ok_or(SecurityError::Malformed("invitation preview"))?,
            inviter_name: clean_text(&body.inviter, MAX_TEXT_CHARS).ok_or(SecurityError::Malformed("invitation preview"))?,
            inviter_account: Id16::parse(&body.account).map_err(|_| SecurityError::Malformed("invitation preview"))?,
            inviter_root_key: b64::decode(&body.root_key)
                .and_then(|k| k.try_into().ok())
                .ok_or(SecurityError::Malformed("invitation preview"))?,
            auto_admission: body.auto,
            expires_ms: body.expires_ms,
            accepts_other_relays: body.other_relays,
        })
    }

    fn open_link(text: &str) -> Result<(InviteLink, InviteKeys, Id16)> {
        let link = InviteLink::parse(text).map_err(|_| SecurityError::Malformed("invitation link"))?;
        let keys = InviteSecret::from_bytes(*link.secret()).keys();
        let id = Id16(*keys.id());
        Ok((link, keys, id))
    }

    /// Asks to join. Sends, to the issuer's relay, a request sealed under the link and signed with this account's root identity key; it carries this
    /// account's own contact card so the admin can add it through the normal path. Nothing is joined until an admin approves and the Welcome arrives.
    pub fn request_to_join(&mut self, link: &str, display_name: &str) -> Result<Id16> {
        self.guard()?;
        let name = clean_text(display_name, MAX_NAME_CHARS).ok_or(SecurityError::Malformed("display name"))?;
        let (link, keys, id) = Self::open_link(link)?;
        let ep = RelayEndpoint::from_descriptor(link.relay())?;
        // Only hand over a card to an invitation that is live right now.
        self.api_at(&ep)?.invite_lookup(&id)?;
        let card = self.create_contact_card(JOIN_CARD_DAYS)?;
        let body = JoinBody { v: 1, id: id.to_hex(), nonce: b64::encode(&crate::rng::array::<16>()?), ts: self.now_ms(), name, card };
        let r = serde_json::to_string(&body).map_err(|_| SecurityError::Malformed("join request"))?;
        let mut signed = JOIN_DOMAIN.to_vec();
        signed.extend_from_slice(r.as_bytes());
        let sig = self.session()?.mls.sign_identity_raw(&signed)?;
        let env = serde_json::to_vec(&Envelope { r, s: b64::encode(&sig) }).map_err(|_| SecurityError::Malformed("join request"))?;
        let sealed = keys.seal_request(&env)?;
        self.api_at(&ep)?.invite_submit(&id, sealed)
    }
}
