//! The application engine: the single high-level surface the Android app (through a narrow FFI) talks to.
//!
//! Sensitive material never leaves this struct: identity/MLS private state, the vault data key and attachment keys stay
//! in Rust. The UI receives only display data (names, text it is about to render, ids, public keys, safety numbers).
//! Every method fails closed when the vault is not UNLOCKED.
use super::model::*;
use super::notify::PrivacyMode;
use super::transport::{HttpTransport, TransportAdapter};
use crate::clock::Clock;
use crate::error::{Result, SecurityError};
use crate::events::SecurityEvent;
use crate::keystore::{ProtectionLevel, SecureKeyStore};
use crate::mls::MlsClient;
use crate::relay_client::{RelayApi, RelayEndpoint};
use crate::storage::EncryptedStore;
use crate::vault::{DeviceSecurityEvent, LockState, Vault, VaultConfig, ALIAS_DEVICE};
use crate::verification::{self, IdentityPins};
use cipher_wire::Id16;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

pub(crate) const NS_META: &str = "meta";
pub(crate) const NS_MLS: &str = "mls";
pub(crate) const NS_CONTACT: &str = "contacts";
pub(crate) const NS_CONV: &str = "convs";
pub(crate) const NS_OUTBOX: &str = "outbox";
pub(crate) const NS_HELD: &str = "held";
pub(crate) const NS_PENDING_COMMIT: &str = "pc";
pub(crate) const NS_CAPS: &str = "caps";
pub(crate) const NS_EVENTS: &str = "events";
pub(crate) const NS_SETTINGS: &str = "settings";
pub(crate) const MAX_EVENTS: usize = 200;

pub struct EngineConfig {
    pub data_dir: PathBuf,
    pub relay_url: String,
    pub vault: VaultConfig,
}

impl std::fmt::Debug for EngineConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineConfig").finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultStatus {
    pub state: LockState,
    pub provisioned: bool,
    pub has_identity: bool,
    pub has_pin: bool,
    pub pin_only: bool,
    pub pin_retry_after_secs: u64,
    pub protection: Option<ProtectionLevel>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IdentityRecord {
    pub account_id: Id16,
    pub device_id: Id16,
    pub root_identity_key: Vec<u8>,
    pub created_ms: u64,
    pub last_kp_upload_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    pub cipher_id: String,
    pub account_id: Id16,
    pub device_id: Id16,
    /// Payload to render as a QR code (account id + identity key).
    pub qr_payload: String,
    /// 30-digit fingerprint of this identity (half of a safety number).
    pub fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub privacy_mode: PrivacyMode,
    pub send_receipts: bool,
    #[serde(default)]
    pub network_profile: super::netprofile::NetworkProfile,
}

impl Default for Settings {
    fn default() -> Self {
        Self { privacy_mode: PrivacyMode::NoContent, send_receipts: true, network_profile: Default::default() }
    }
}

pub(crate) struct Session {
    pub mls: MlsClient,
    pub ident: IdentityRecord,
}

pub struct Engine {
    pub(crate) cfg: EngineConfig,
    pub(crate) vault: Vault,
    pub(crate) keystore: Arc<dyn SecureKeyStore>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) transport: TransportAdapter,
    pub(crate) endpoint: RelayEndpoint,
    pub(crate) session: Option<Session>,
    pub(crate) events: Vec<SecurityEvent>,
    pub(crate) in_commit: bool,
    /// (anonymous capability deliveries, authenticated deliveries) per recipient device, this process only.
    pub(crate) delivery_counts: (u64, u64),
    /// Whether our most recent real delivery used the authenticated path (cover then imitates that request shape).
    pub(crate) last_real_authed: bool,
    /// How other relays' users name OUR relay (put into the `DeliveryCap` frames and contact cards we issue). `None` when it cannot be expressed
    /// (an onion relay needs its certificate pin: call `set_own_relay`).
    pub(crate) own_relay: Option<cipher_wire::RelayDescriptor>,
    /// Timestamp given to the most recent outgoing message: outgoing timestamps are strictly increasing, so message order never depends on random ids.
    pub(crate) last_ts_ms: u64,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine").field("state", &self.vault.state()).finish_non_exhaustive()
    }
}

pub(crate) fn put_json<T: Serialize>(s: &mut EncryptedStore, ns: &str, id: &str, v: &T) -> Result<()> {
    let b = serde_json::to_vec(v).map_err(|_| SecurityError::Malformed("record encode"))?;
    s.put(ns, id, &b)
}

pub(crate) fn get_json<T: DeserializeOwned>(s: &EncryptedStore, ns: &str, id: &str) -> Result<Option<T>> {
    match s.get(ns, id)? {
        None => Ok(None),
        Some(b) => serde_json::from_slice(&b).map(Some).map_err(|_| SecurityError::StorageCorrupt),
    }
}

impl Engine {
    pub fn new(cfg: EngineConfig, keystore: Arc<dyn SecureKeyStore>, http: Arc<dyn HttpTransport>, clock: Arc<dyn Clock>) -> Result<Self> {
        let endpoint = RelayEndpoint::new(&cfg.relay_url)?;
        std::fs::create_dir_all(&cfg.data_dir).map_err(|_| SecurityError::Malformed("data dir"))?;
        let vault = Vault::open(Some(&cfg.data_dir.join("vault.db")), keystore.clone(), clock.clone(), cfg.vault.clone())?;
        let mut e = Self {
            cfg,
            vault,
            keystore,
            clock,
            transport: TransportAdapter { inner: http },
            endpoint,
            session: None,
            events: Vec::new(),
            in_commit: false,
            delivery_counts: (0, 0),
            last_real_authed: false,
            own_relay: None,
            last_ts_ms: 0,
        };
        e.own_relay = cipher_wire::RelayDescriptor::new(&e.cfg.relay_url, None).ok();
        e.cleanup_temp_files();
        Ok(e)
    }

    /// Test/dev constructor used with a relay endpoint that is not a real https URL (in-process transports).
    #[cfg(any(test, feature = "insecure-test-support"))]
    pub fn new_for_tests(
        cfg: EngineConfig,
        keystore: Arc<dyn SecureKeyStore>,
        http: Arc<dyn HttpTransport>,
        clock: Arc<dyn Clock>,
        audience: &str,
    ) -> Result<Self> {
        let mut e = Self::new_inner_unchecked(cfg, keystore, http, clock, RelayEndpoint::for_tests(audience))?;
        e.cleanup_temp_files();
        Ok(e)
    }

    #[cfg(any(test, feature = "insecure-test-support"))]
    fn new_inner_unchecked(
        cfg: EngineConfig,
        keystore: Arc<dyn SecureKeyStore>,
        http: Arc<dyn HttpTransport>,
        clock: Arc<dyn Clock>,
        endpoint: RelayEndpoint,
    ) -> Result<Self> {
        std::fs::create_dir_all(&cfg.data_dir).map_err(|_| SecurityError::Malformed("data dir"))?;
        let vault = Vault::open(Some(&cfg.data_dir.join("vault.db")), keystore.clone(), clock.clone(), cfg.vault.clone())?;
        Ok(Self {
            cfg,
            vault,
            keystore,
            clock,
            transport: TransportAdapter { inner: http },
            endpoint,
            session: None,
            events: Vec::new(),
            in_commit: false,
            delivery_counts: (0, 0),
            last_real_authed: false,
            own_relay: None,
            last_ts_ms: 0,
        })
    }

    // ------------------------------------------------------------------------------------------- lifecycle

    pub(crate) fn now_ms(&self) -> u64 {
        self.clock.unix_millis()
    }

    /// Timestamp for an outgoing message: the clock, but never equal to or below the previous one (two messages in the same millisecond, or a clock that
    /// steps back, must not reorder a conversation — ties would otherwise be broken by the random message id).
    pub(crate) fn next_ts_ms(&mut self) -> u64 {
        let t = self.now_ms().max(self.last_ts_ms.saturating_add(1));
        self.last_ts_ms = t;
        t
    }

    pub fn status(&mut self) -> Result<VaultStatus> {
        self.vault.tick();
        self.drop_session_if_not_unlocked();
        let provisioned = self.vault.is_provisioned()?;
        Ok(VaultStatus {
            state: self.vault.state(),
            provisioned,
            has_identity: self.has_identity_flag()?,
            has_pin: if provisioned { self.vault.has_pin()? } else { false },
            pin_only: if provisioned { self.vault.is_pin_only()? } else { false },
            pin_retry_after_secs: if provisioned { self.vault.pin_retry_after_secs()? } else { 0 },
            protection: self.keystore.key_protection(ALIAS_DEVICE).or_else(|_| self.keystore.key_protection(crate::vault::ALIAS_PIN)).ok(),
        })
    }

    fn has_identity_flag(&mut self) -> Result<bool> {
        if self.vault.state() == LockState::Unlocked {
            return self.vault.with_store(|s| Ok(s.get(NS_META, "identity")?.is_some()));
        }
        Ok(false)
    }

    fn drop_session_if_not_unlocked(&mut self) {
        if self.vault.state() != LockState::Unlocked {
            self.session = None; // MlsClient (identity + all MLS state) is dropped the moment the vault is not unlocked
        }
    }

    /// First run: create hardware keys and the vault. Leaves the vault UNLOCKED.
    pub fn provision_vault(&mut self) -> Result<()> {
        self.vault.provision()
    }

    /// First run, PIN-only mode: no biometric / keystore-only unlock path exists for this vault.
    pub fn provision_vault_pin_only(&mut self, pin: &str) -> Result<()> {
        self.vault.provision_pin_only(pin)
    }

    pub fn enable_pin(&mut self, pin: &str) -> Result<()> {
        self.vault.enable_pin(pin)
    }

    pub fn unlock_with_device_auth(&mut self) -> Result<()> {
        self.vault.unlock_with_device_auth()?;
        self.load_session()
    }

    pub fn unlock_with_pin(&mut self, pin: &str) -> Result<()> {
        self.vault.unlock_with_pin(pin)?;
        self.load_session()
    }

    /// FR-12: persist the MLS state (best effort). Ratchet keys that were consumed in memory must also disappear from DISK, otherwise
    /// "message keys are deleted after use" is not durable and an old state could re-derive them after a crash/restart.
    pub(crate) fn flush_mls_state(&mut self) {
        if self.session.is_some() {
            let _ = self.commit_state(|_| Ok(()));
        }
    }

    pub fn lock(&mut self) {
        self.flush_mls_state();
        self.vault.lock(crate::events::LockReason::Manual);
        self.drop_session_if_not_unlocked();
        self.cleanup_temp_files();
    }

    pub fn on_background(&mut self) {
        self.flush_mls_state();
        self.vault.on_background();
        self.drop_session_if_not_unlocked();
        self.cleanup_temp_files();
    }

    pub fn on_foreground(&mut self) {
        self.vault.on_foreground();
    }

    pub fn on_device_event(&mut self, ev: DeviceSecurityEvent) {
        if ev == DeviceSecurityEvent::ScreenLocked {
            self.flush_mls_state(); // only while the vault is still open; invalidating events cannot (and need not) flush
        }
        self.vault.on_device_security_event(ev);
        self.drop_session_if_not_unlocked();
    }

    pub fn tick(&mut self) {
        self.vault.tick();
        self.drop_session_if_not_unlocked();
    }

    /// Every data-touching method starts here: fail closed unless UNLOCKED, and count as activity.
    pub(crate) fn guard(&mut self) -> Result<()> {
        self.vault.tick();
        self.drop_session_if_not_unlocked();
        match self.vault.state() {
            LockState::Unlocked => {
                self.vault.touch();
                Ok(())
            }
            LockState::Invalidated => Err(SecurityError::Invalidated),
            _ => Err(SecurityError::Locked),
        }
    }

    fn load_session(&mut self) -> Result<()> {
        let loaded = self.vault.with_store(|s| {
            let ident: Option<IdentityRecord> = get_json(s, NS_META, "identity")?;
            let snap = s.get(NS_MLS, "state")?;
            Ok((ident, snap))
        })?;
        self.session = match loaded {
            (Some(ident), Some(snap)) => Some(Session { mls: MlsClient::restore(&snap)?, ident }),
            (None, None) => None,
            _ => return Err(SecurityError::StorageCorrupt), // half-initialised identity: refuse
        };
        if let Some(t) = self.vault.with_store(|s| get_json::<u64>(s, NS_META, "last_ts"))? {
            self.last_ts_ms = self.last_ts_ms.max(t);
        }
        // How others name our relay (with its certificate pin, for onion relays) survives restarts. A descriptor for a DIFFERENT relay than the one
        // configured now (the user switched relays) is ignored.
        let persisted: Option<cipher_wire::RelayDescriptor> = self.vault.with_store(|s| get_json(s, NS_META, "own_relay"))?;
        if let Some(p) = persisted.and_then(|p| p.validated().ok()) {
            let configured = cipher_wire::RelayDescriptor::new(&self.cfg.relay_url, None).ok();
            if self.own_relay.is_none() || configured.as_ref().is_some_and(|c| c.url() == p.url()) {
                self.own_relay = Some(p);
            }
        }
        Ok(())
    }

    pub(crate) fn session(&mut self) -> Result<&mut Session> {
        self.guard()?;
        self.session.as_mut().ok_or(SecurityError::NotFound("identity"))
    }

    /// Persist MLS state together with `f`'s records in ONE atomic batch. Anything that advances the ratchet must go through
    /// here BEFORE its ciphertext is released: a crash can then never lead to key/nonce reuse.
    pub(crate) fn commit_state(&mut self, f: impl FnOnce(&mut EncryptedStore) -> Result<()>) -> Result<()> {
        let snap = self.session.as_ref().ok_or(SecurityError::Locked)?.mls.snapshot()?;
        self.vault.with_store(|s| {
            s.atomic(|s| {
                s.put(NS_MLS, "state", &snap)?;
                f(s)
            })
        })
    }

    pub(crate) fn api(&self) -> Result<RelayApi<'_>> {
        let s = self.session.as_ref().ok_or(SecurityError::Locked)?;
        Ok(RelayApi { transport: &self.transport, endpoint: &self.endpoint, client: &s.mls, clock: &*self.clock })
    }

    /// The same signed-request client, pointed at ANOTHER relay (a contact's). Only the unauthenticated calls are used there.
    pub(crate) fn api_at<'a>(&'a self, endpoint: &'a RelayEndpoint) -> Result<RelayApi<'a>> {
        let s = self.session.as_ref().ok_or(SecurityError::Locked)?;
        Ok(RelayApi { transport: &self.transport, endpoint, client: &s.mls, clock: &*self.clock })
    }

    pub(crate) fn push_event(&mut self, e: SecurityEvent) {
        self.events.push(e.clone());
        let id = format!("{:020}-{}", self.now_ms(), self.events.len());
        let _ = self.vault.with_store(|s| {
            put_json(s, NS_EVENTS, &id, &e)?;
            let ids = s.list_ids(NS_EVENTS)?;
            for old in ids.iter().take(ids.len().saturating_sub(MAX_EVENTS)) {
                s.delete(NS_EVENTS, old)?;
            }
            Ok(())
        });
    }

    /// Security events raised since the last call (UI banners / notifications about identity changes etc.).
    pub fn take_events(&mut self) -> Vec<SecurityEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn security_event_log(&mut self, limit: usize) -> Result<Vec<SecurityEvent>> {
        self.guard()?;
        self.vault.with_store(|s| {
            let mut out = Vec::new();
            for id in s.list_ids_page(NS_EVENTS, None, limit)? {
                if let Some(e) = get_json::<SecurityEvent>(s, NS_EVENTS, &id)? {
                    out.push(e);
                }
            }
            Ok(out)
        })
    }

    pub fn settings(&mut self) -> Result<Settings> {
        self.guard()?;
        self.vault.with_store(|s| Ok(get_json(s, NS_SETTINGS, "app")?.unwrap_or_default()))
    }

    pub fn set_settings(&mut self, v: &Settings) -> Result<()> {
        self.guard()?;
        self.vault.with_store(|s| put_json(s, NS_SETTINGS, "app", v))
    }

    // ---------------------------------------------------------------------------------------------- identity

    pub fn has_identity(&mut self) -> Result<bool> {
        self.guard()?;
        Ok(self.session.is_some())
    }

    /// Onboarding: generate a device identity ON the device, register it with the relay, upload KeyPackages.
    /// `registration_token` is the relay operator's invite credential (an *account* credential; it never grants access to content).
    pub fn create_identity(&mut self, registration_token: &str) -> Result<PublicIdentity> {
        self.guard()?;
        if self.session.is_some() {
            return Err(SecurityError::InvalidState);
        }
        let account = Id16(crate::rng::array::<16>()?);
        let device = Id16(crate::rng::array::<16>()?);
        let mut mls = MlsClient::generate(account, device)?;
        {
            let api = RelayApi { transport: &self.transport, endpoint: &self.endpoint, client: &mls, clock: &*self.clock };
            api.register_account(registration_token)?;
        }
        let kps = crate::protocol::GroupProtocol::generate_key_packages(&mut mls, 20)?;
        {
            let api = RelayApi { transport: &self.transport, endpoint: &self.endpoint, client: &mls, clock: &*self.clock };
            api.upload_key_packages(kps)?;
        }
        let now = self.now_ms();
        let ident = IdentityRecord {
            account_id: account,
            device_id: device,
            root_identity_key: mls.identity_public().to_vec(),
            created_ms: now,
            last_kp_upload_ms: now,
        };
        let snap = mls.snapshot()?;
        self.vault.with_store(|s| {
            s.atomic(|s| {
                s.put(NS_MLS, "state", &snap)?;
                put_json(s, NS_META, "identity", &ident)
            })
        })?;
        self.session = Some(Session { mls, ident });
        self.public_identity()
    }

    pub fn public_identity(&mut self) -> Result<PublicIdentity> {
        let s = self.session()?;
        let key: [u8; 32] = s.ident.root_identity_key.as_slice().try_into().map_err(|_| SecurityError::StorageCorrupt)?;
        Ok(PublicIdentity {
            cipher_id: super::cipher_id::format(&s.ident.account_id),
            account_id: s.ident.account_id,
            device_id: s.ident.device_id,
            qr_payload: verification::qr_payload(&s.ident.account_id, &key),
            fingerprint: verification::safety_number(&s.ident.account_id, &key, &s.ident.account_id, &key).chars().take(35).collect(),
        })
    }

    // ------------------------------------------------------------------------------------------------ contacts

    pub fn list_contacts(&mut self) -> Result<Vec<Contact>> {
        self.guard()?;
        self.vault.with_store(|s| {
            let mut out = Vec::new();
            for id in s.list_ids(NS_CONTACT)? {
                if let Some(c) = get_json::<Contact>(s, NS_CONTACT, &id)? {
                    out.push(c);
                }
            }
            out.sort_by_key(|c| c.name.to_lowercase());
            Ok(out)
        })
    }

    pub fn contact(&mut self, account: &Id16) -> Result<Option<Contact>> {
        self.guard()?;
        self.vault.with_store(|s| get_json(s, NS_CONTACT, &account.to_hex()))
    }

    fn save_contact(&mut self, c: &Contact) -> Result<()> {
        self.vault.with_store(|s| put_json(s, NS_CONTACT, &c.account_id.to_hex(), c))
    }

    /// Fetch the peer's device list from the (untrusted) relay and evaluate it against our pins. Emits security events and
    /// flips the contact to IDENTITY_CHANGED when keys changed unexpectedly. Never silently accepts a replacement key.
    pub(crate) fn refresh_peer(&mut self, account: &Id16) -> Result<verification::DirectoryTrust> {
        let home = self.vault.with_store(|s| get_json::<Contact>(s, NS_CONTACT, &account.to_hex()))?.and_then(|c| c.home);
        let dir = match home {
            // A contact on another relay: ask THEIR relay through the intro capability of their card. The records are self-authenticating and are
            // evaluated against our pins exactly like any directory answer, so that relay cannot substitute keys.
            Some(h) => {
                let ep = RelayEndpoint::from_descriptor(&h.relay)?;
                self.api_at(&ep)?.intro_directory(&h.intro)?
            }
            None => self.api()?.directory(account)?,
        };
        let trust = self.vault.with_store(|s| IdentityPins::new(s).evaluate_directory(account, &dir.devices))?;
        let changed =
            trust.events.iter().any(|e| matches!(e, SecurityEvent::IdentityChanged { .. } | SecurityEvent::UnendorsedDevice { .. }));
        for e in trust.events.clone() {
            self.push_event(e);
        }
        if changed {
            if let Some(mut c) = self.vault.with_store(|s| get_json::<Contact>(s, NS_CONTACT, &account.to_hex()))? {
                c.trust = TrustState::IdentityChanged;
                self.save_contact(&c)?;
            }
        }
        Ok(trust)
    }

    fn root_key_of(trust: &verification::DirectoryTrust) -> Result<Vec<u8>> {
        trust
            .trusted
            .iter()
            .find(|r| r.endorsement.is_none())
            .map(|r| r.identity_key.clone())
            .ok_or(SecurityError::IdentityUntrusted("no trusted root device"))
    }

    /// Add a contact by Cipher identifier. Trust starts UNVERIFIED (trust-on-first-use of the relay's answer).
    pub fn add_contact_by_id(&mut self, cipher_id: &str, name: &str) -> Result<Contact> {
        self.guard()?;
        let account = super::cipher_id::parse(cipher_id)?;
        let own = self.session()?.ident.account_id;
        if account == own {
            return Err(SecurityError::Denied("cannot add yourself"));
        }
        if let Some(existing) = self.contact(&account)? {
            self.refresh_peer(&account)?;
            return Ok(self.contact(&account)?.unwrap_or(existing));
        }
        let trust = self.refresh_peer(&account)?;
        let c = Contact {
            account_id: account,
            name: clean_name(name, &account),
            trust: TrustState::Unverified,
            root_identity_key: Self::root_key_of(&trust)?,
            verified_key: None,
            blocked: false,
            home: None,
        };
        self.save_contact(&c)?;
        Ok(c)
    }

    /// Add (or verify) a contact by scanning their QR code. The QR carries the key the peer's device really holds, so a match with
    /// the relay's answer makes the contact VERIFIED; a mismatch means the relay lied (or the QR is stale) and nothing is trusted.
    pub fn add_contact_by_qr(&mut self, payload: &str, name: &str) -> Result<Contact> {
        self.guard()?;
        let (account, qr_key) = verification::parse_qr(payload)?;
        let own = self.session()?.ident.account_id;
        if account == own {
            return Err(SecurityError::Denied("cannot add yourself"));
        }
        let trust = self.refresh_peer(&account)?;
        let relay_root = Self::root_key_of(&trust);
        let matches = relay_root
            .as_ref()
            .is_ok_and(|k| verification::verify_scanned_qr(payload, &account, &qr_key).is_ok() && k.as_slice() == qr_key.as_slice());
        if !matches {
            self.push_event(SecurityEvent::IdentityChanged { account_id: account.to_hex() });
            return Err(SecurityError::IdentityUntrusted("scanned identity does not match what the relay reports"));
        }
        let mut c = match self.contact(&account)? {
            Some(c) => c,
            None => Contact {
                account_id: account,
                name: clean_name(name, &account),
                trust: TrustState::Unverified,
                root_identity_key: qr_key.to_vec(),
                verified_key: None,
                blocked: false,
                home: None,
            },
        };
        if c.root_identity_key != qr_key {
            return Err(SecurityError::IdentityUntrusted("scanned identity differs from the pinned identity"));
        }
        c.trust = TrustState::Verified;
        c.verified_key = Some(qr_key.to_vec());
        self.save_contact(&c)?;
        Ok(c)
    }

    /// Verify an EXISTING contact by scanning their QR code. The code must be for that same account; a code for anyone else is refused.
    pub fn verify_contact_with_qr(&mut self, account: &Id16, payload: &str) -> Result<Contact> {
        let (qr_account, _) = verification::parse_qr(payload)?;
        if &qr_account != account {
            return Err(SecurityError::IdentityUntrusted("scanned code belongs to a different account"));
        }
        let name = self.contact(account)?.map(|c| c.name).ok_or(SecurityError::NotFound("contact"))?;
        self.add_contact_by_qr(payload, &name)
    }

    /// The user compared the safety number out-of-band.
    pub fn mark_verified(&mut self, account: &Id16) -> Result<()> {
        let mut c = self.contact(account)?.ok_or(SecurityError::NotFound("contact"))?;
        if c.trust == TrustState::IdentityChanged {
            return Err(SecurityError::Denied("acknowledge the identity change first"));
        }
        c.trust = TrustState::Verified;
        c.verified_key = Some(c.root_identity_key.clone());
        self.save_contact(&c)
    }

    /// The ONLY way a changed identity becomes trusted: explicit user acknowledgement. The contact returns to UNVERIFIED
    /// (the new key must be re-verified); the old verification is not carried over.
    pub fn acknowledge_identity_change(&mut self, account: &Id16) -> Result<()> {
        self.guard()?;
        let mut c = self.contact(account)?.ok_or(SecurityError::NotFound("contact"))?;
        let dir = self.api()?.directory(account)?;
        self.vault.with_store(|s| {
            let mut pins = IdentityPins::new(s);
            for rec in &dir.devices {
                let _ = pins.acknowledge(account, &rec.device_id); // ignore devices that are not pending
            }
            Ok(())
        })?;
        let trust = self.refresh_peer(account)?;
        c.root_identity_key = Self::root_key_of(&trust).unwrap_or(c.root_identity_key);
        c.trust = TrustState::Unverified;
        c.verified_key = None;
        self.save_contact(&c)
    }

    pub fn rename_contact(&mut self, account: &Id16, name: &str) -> Result<()> {
        let mut c = self.contact(account)?.ok_or(SecurityError::NotFound("contact"))?;
        c.name = clean_name(name, account);
        self.save_contact(&c)
    }

    pub fn set_blocked(&mut self, account: &Id16, blocked: bool) -> Result<()> {
        let mut c = self.contact(account)?.ok_or(SecurityError::NotFound("contact"))?;
        c.blocked = blocked;
        self.save_contact(&c)
    }

    pub fn safety_number(&mut self, account: &Id16) -> Result<String> {
        let own = {
            let s = self.session()?;
            (s.ident.account_id, s.ident.root_identity_key.clone())
        };
        let c = self.contact(account)?.ok_or(SecurityError::NotFound("contact"))?;
        let (a, b): ([u8; 32], [u8; 32]) = (
            own.1.as_slice().try_into().map_err(|_| SecurityError::StorageCorrupt)?,
            c.root_identity_key.as_slice().try_into().map_err(|_| SecurityError::StorageCorrupt)?,
        );
        Ok(verification::safety_number(&own.0, &a, account, &b))
    }

    /// Devices of our own account as the relay reports them (display only).
    pub fn own_devices(&mut self) -> Result<Vec<(Id16, bool, bool)>> {
        let (account, me) = {
            let s = self.session()?;
            (s.ident.account_id, s.ident.device_id)
        };
        let dir = self.api()?.directory(&account)?;
        Ok(dir.devices.iter().map(|d| (d.device_id, d.device_id == me, d.endorsement.is_some())).collect())
    }

    // ------------------------------------------------------------------------------------------------ cleanup

    pub(crate) fn temp_dir(&self, sub: &str) -> PathBuf {
        self.cfg.data_dir.join("tmp").join(sub)
    }

    /// Remove ciphertext temp files left by interrupted transfers. (Plaintext is never written to disk by the engine.)
    pub fn cleanup_temp_files(&mut self) {
        let _ = std::fs::remove_dir_all(self.cfg.data_dir.join("tmp"));
    }
}

pub(crate) fn clean_name(name: &str, account: &Id16) -> String {
    let n: String = name.chars().filter(|c| !super::model::is_disguising_char(*c)).take(48).collect();
    let n = n.trim().to_owned();
    if n.is_empty() {
        let id = super::cipher_id::format(account);
        id.chars().take(14).collect()
    } else {
        n
    }
}

/// Test-only inspection helpers (never compiled into production builds).
#[cfg(any(test, feature = "insecure-test-support"))]
#[derive(Debug)]
pub struct PublicForTests {
    pub account_id: Id16,
    pub device_id: Id16,
    pub identity_key: [u8; 32],
}

#[cfg(any(test, feature = "insecure-test-support"))]
#[allow(clippy::expect_used)] // test-support only: never compiled into a shipped build (CI asserts the feature is absent)
impl Engine {
    pub fn clone_public_for_tests(&self) -> PublicForTests {
        let s = self.session.as_ref().expect("identity");
        PublicForTests { account_id: s.ident.account_id, device_id: s.ident.device_id, identity_key: s.mls.identity_public() }
    }

    /// A directory record claiming to be `(account, device)` but carrying THIS engine's keys (models a relay-forged identity).
    pub fn forged_record_for_tests(&self, account: Id16, device: Id16) -> cipher_wire::messages::DeviceRecord {
        // The attacker signs the binding for the VICTIM's account with its OWN key (v2 bindings cover the account id).
        let imp = MlsClient::generate(account, device).expect("generate");
        imp.device_record(None).expect("record")
    }

    pub fn key_package_for_tests(&mut self) -> Vec<u8> {
        use crate::protocol::GroupProtocol as _;
        self.session.as_mut().expect("identity").mls.generate_key_packages(1).expect("kp").remove(0)
    }

    /// Models a malicious/modified group member: builds a commit WITHOUT its own policy pre-check, submits it through the
    /// sequencer to every other member, and never merges it locally. Receivers must reject it.
    pub fn inject_forged_commit_for_tests(&mut self, conv: &Id16, ops: &[crate::protocol::GroupOp]) -> Result<()> {
        use cipher_wire::messages::Delivery;
        self.pull()?;
        let c = self.conversation(conv)?;
        let group = crate::protocol::GroupRef(c.id.0.to_vec());
        let me_dev = self.session()?.ident.device_id;
        let members = self.session()?.mls.members_detailed(&group)?;
        let out = self.session()?.mls.commit_unchecked_for_tests(&group, ops)?;
        let deliveries: Vec<Delivery> = members
            .iter()
            .filter(|m| m.device != me_dev)
            .map(|m| Delivery {
                recipient_device: m.device,
                message_id: Id16(crate::rng::array::<16>().expect("rng")),
                ciphertext: out.commit.clone(),
            })
            .collect();
        let _ = self.api()?.group_commit(&c.tag, c.relay_seq, None, deliveries)?;
        crate::protocol::GroupProtocol::clear_pending_commit(&mut self.session()?.mls, &group)?;
        Ok(())
    }

    /// TEST ONLY: the raw sealed body of a stored group message `(epoch, sender, sealed)` — i.e. "the retained ciphertext".
    pub fn sealed_body_for_tests(&mut self, conv: &Id16, msg: &Id16) -> Result<Option<(u64, Id16, crate::history::SealedBody)>> {
        self.vault.with_store(|s| {
            let Some(k) = super::engine_msg::msg_key_for(s, conv, msg)? else { return Ok(None) };
            let Some(m) = get_json::<StoredMessage>(s, &format!("m:{}", conv.to_hex()), &k)? else { return Ok(None) };
            Ok(match (m.epoch, m.sealed) {
                (Some(e), Some(sb)) => Some((e, m.sender_account, sb)),
                _ => None,
            })
        })
    }

    /// TEST ONLY: the DECRYPTION OPERATION itself — open a sealed body with whatever history keys THIS device currently holds. Errors when the
    /// key is gone (as opposed to a UI deciding not to display something).
    pub fn open_sealed_for_tests(
        &mut self,
        conv: &Id16,
        epoch: u64,
        msg: &Id16,
        sender: &Id16,
        sealed: &crate::history::SealedBody,
    ) -> Result<Content> {
        self.vault.with_store(|s| {
            let hek = crate::history::get_epoch_key(s, conv, epoch)?.ok_or(SecurityError::Denied("history key unavailable"))?;
            crate::history::unseal(&hek, conv, epoch, msg, sender, sealed)
        })
    }

    /// TEST ONLY: our current delivery capability for `conv`, and the one we hold for a peer device.
    pub fn own_cap_for_tests(&mut self, conv: &Id16) -> Option<Id16> {
        let key = format!("own/{}", conv.to_hex());
        self.vault
            .with_store(|s| get_json::<serde_json::Value>(s, NS_CAPS, &key))
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_value(v.get("cap")?.clone()).ok())
    }

    pub fn peer_cap_for_tests(&mut self, conv: &Id16, device: &Id16) -> Option<Id16> {
        let key = format!("peer/{}/{}", conv.to_hex(), device.to_hex());
        match self.vault.with_store(|s| get_json::<super::engine_msg::StoredPeerCap>(s, NS_CAPS, &key)).ok().flatten()? {
            super::engine_msg::StoredPeerCap::Legacy(c) => Some(c),
            super::engine_msg::StoredPeerCap::Full(p) => Some(p.cap),
        }
    }

    /// TEST ONLY: the relay a peer device's capability is valid at (None = our own relay).
    pub fn peer_relay_for_tests(&mut self, conv: &Id16, device: &Id16) -> Option<String> {
        let key = format!("peer/{}/{}", conv.to_hex(), device.to_hex());
        match self.vault.with_store(|s| get_json::<super::engine_msg::StoredPeerCap>(s, NS_CAPS, &key)).ok().flatten()? {
            super::engine_msg::StoredPeerCap::Full(p) => p.relay.map(|r| r.url().to_owned()),
            super::engine_msg::StoredPeerCap::Legacy(_) => None,
        }
    }

    /// TEST ONLY: epochs of `conv` for which this device still holds a history key.
    pub fn history_epochs_for_tests(&mut self, conv: &Id16) -> Result<Vec<u64>> {
        self.vault.with_store(|s| crate::history::epochs_held(s, conv))
    }

    /// TEST ONLY: how many vault records (every namespace, decrypted) contain `needle`. A zero count after revocation proves no plaintext remains.
    pub fn vault_plaintext_hits_for_tests(&mut self, needle: &[u8]) -> Result<usize> {
        self.vault.with_store(|s| {
            let mut namespaces: Vec<String> = Vec::new();
            {
                let mut st = s.conn().prepare("SELECT DISTINCT ns FROM records").map_err(|_| SecurityError::StorageCorrupt)?;
                let rows = st.query_map([], |r| r.get::<_, String>(0)).map_err(|_| SecurityError::StorageCorrupt)?;
                for r in rows.flatten() {
                    namespaces.push(r);
                }
            }
            let mut hits = 0;
            for ns in namespaces {
                for id in s.list_ids(&ns)? {
                    if let Some(v) = s.get(&ns, &id)? {
                        if v.windows(needle.len()).any(|w| w == needle) {
                            hits += 1;
                        }
                    }
                }
            }
            Ok(hits)
        })
    }

    /// TEST ONLY: feed a raw MLS ciphertext straight to the MLS layer of this engine (models "what could the state on DISK decrypt?").
    pub fn process_raw_for_tests(&mut self, conv: &Id16, ct: &[u8]) -> Result<()> {
        struct AllowAll;
        impl crate::protocol::CommitValidator for AllowAll {
            fn approve_add(&self, _: &Id16, _: &Id16, _: &[u8]) -> bool {
                true
            }
        }
        let group = crate::protocol::GroupRef(conv.0.to_vec());
        self.session()?.mls.process_ex(&group, ct, &AllowAll).map(|_| ())
    }

    pub fn conversation_epoch(&mut self, conv: &Id16) -> Result<u64> {
        use crate::protocol::GroupProtocol as _;
        let s = self.session()?;
        s.mls.epoch(&crate::protocol::GroupRef(conv.0.to_vec()))
    }
}
