//! Vault: owns the data-encryption key (DEK), the lock state machine and the
//! unlock factors. Plaintext key material exists in memory only in `Unlocked`.
//!
//! States: LOCKED, UNLOCKING, UNLOCKED, BACKGROUND, INVALIDATED.
//!
//! Key hierarchy:
//!   DEK (random 256-bit)  --wrapped by-->  hardware keystore key (auth-gated)   [device envelope]
//!   DEK                   --wrapped by-->  HKDF( S || Argon2id(PIN) )           [PIN envelope]
//!                                           S: random secret wrapped by a hardware-bound,
//!                                              non-exportable keystore key
//! A stolen database file therefore cannot be brute-forced offline: the PIN
//! envelope also needs `S`, which only the device's keystore can release.
//! The software attempt limiter is defence in depth, not the primary bound.
use crate::clock::Clock;
use crate::error::{Result, SecurityError};
use crate::events::{InvalidationReason, LockReason, SecurityEvent, SecurityEventSink};
use crate::kdf::{self, KdfFloor, KdfParams};
use crate::keystore::{KeyPolicy, KeyStoreError, ProtectionLevel, SecureKeyStore};
use crate::storage::{open_conn, EncryptedStore};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

pub const ALIAS_DEVICE: &str = "cipher.vault.device.v1";
pub const ALIAS_PIN: &str = "cipher.vault.pin.v1";
const AAD_DEVICE: &[u8] = b"cipher/vault/env-device/v1";
const AAD_PIN_S: &[u8] = b"cipher/vault/pin-secret/v1";
const AAD_PIN_ENV: &[u8] = b"cipher/vault/env-pin/v1";
const KEK_INFO: &[u8] = b"cipher/vault/pin-kek/v1";
/// Authenticated (encrypted under the DEK) generation record + the keystore's monotonic counter = local rollback detection.
const NS_VAULT: &str = "__vault__";
const ID_GEN: &str = "generation";

fn read_gen(s: &EncryptedStore) -> Result<u64> {
    match s.get(NS_VAULT, ID_GEN)? {
        None => Ok(0),
        Some(b) => Ok(u64::from_be_bytes(b.as_slice().try_into().map_err(|_| SecurityError::StorageCorrupt)?)),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockState {
    Locked,
    Unlocking,
    Unlocked,
    Background,
    Invalidated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceSecurityEvent {
    ScreenLocked,
    PasscodeRemoved,
    BiometricEnrollmentChanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimiterPolicy {
    pub free_attempts: u32,
    pub base_delay_secs: u64,
    pub max_delay_secs: u64,
}

impl Default for LimiterPolicy {
    fn default() -> Self {
        Self { free_attempts: 5, base_delay_secs: 30, max_delay_secs: 3600 }
    }
}

#[derive(Clone, Debug)]
pub struct VaultConfig {
    /// Minimum acceptable keystore protection. Default: hardware-backed.
    pub min_protection: ProtectionLevel,
    /// Explicit opt-in to accept `OsSoftware` keystores. Emits an event; never silent.
    pub allow_software_keystore: bool,
    pub require_user_auth: bool,
    pub inactivity_timeout_secs: u64,
    pub kdf: KdfParams,
    pub kdf_floor: KdfFloor,
    pub limiter: LimiterPolicy,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            min_protection: ProtectionLevel::HardwareBacked,
            allow_software_keystore: false,
            require_user_auth: true,
            inactivity_timeout_secs: 60,
            kdf: KdfParams::MOBILE_DEFAULT,
            kdf_floor: KdfFloor::Enforced,
            limiter: LimiterPolicy::default(),
        }
    }
}

enum Inner {
    Closed(Connection),
    Open(EncryptedStore),
    Taken,
}

#[derive(Serialize, Deserialize)]
struct PinEnvelope {
    v: u8,
    params: KdfParams,
    salt: [u8; 16],
    #[serde(with = "cipher_wire::b64")]
    s_wrapped: Vec<u8>,
    #[serde(with = "cipher_wire::b64")]
    nonce: Vec<u8>,
    #[serde(with = "cipher_wire::b64")]
    ct: Vec<u8>,
}

#[derive(Serialize, Deserialize, Default)]
struct Limiter {
    failures: u32,
    locked_until: u64,
}

pub struct Vault {
    inner: Inner,
    state: LockState,
    cfg: VaultConfig,
    keystore: Arc<dyn SecureKeyStore>,
    clock: Arc<dyn Clock>,
    sink: Option<Arc<dyn SecurityEventSink>>,
    last_activity: u64,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").field("state", &self.state).finish_non_exhaustive()
    }
}

fn meta_get(c: &Connection, k: &str) -> Result<Option<Vec<u8>>> {
    c.query_row("SELECT v FROM vault_meta WHERE k=?1", params![k], |r| r.get(0)).optional().map_err(|_| SecurityError::StorageCorrupt)
}

fn meta_put(c: &Connection, k: &str, v: &[u8]) -> Result<()> {
    c.execute("INSERT OR REPLACE INTO vault_meta(k,v) VALUES(?1,?2)", params![k, v]).map(|_| ()).map_err(|_| SecurityError::StorageCorrupt)
}

fn pin_kek(s: &[u8], pin_key: &[u8; 32], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(s.len() + 32));
    ikm.extend_from_slice(s);
    ikm.extend_from_slice(pin_key);
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(KEK_INFO, out.as_mut_slice()).map_err(|_| SecurityError::CryptoAuthFailed)?;
    Ok(out)
}

impl Vault {
    /// Open (or create) the vault file. Starts `Locked`; call `provision` on first run.
    pub fn open(path: Option<&Path>, keystore: Arc<dyn SecureKeyStore>, clock: Arc<dyn Clock>, cfg: VaultConfig) -> Result<Self> {
        let conn = open_conn(path)?;
        let now = clock.monotonic_secs();
        Ok(Self { inner: Inner::Closed(conn), state: LockState::Locked, cfg, keystore, clock, sink: None, last_activity: now })
    }

    pub fn has_pin(&self) -> Result<bool> {
        Ok(meta_get(self.conn()?, "env_pin")?.is_some())
    }

    /// Seconds until PIN attempts are allowed again (0 = not rate limited).
    pub fn pin_retry_after_secs(&self) -> Result<u64> {
        Ok(self.limiter()?.locked_until.saturating_sub(self.clock.unix_secs()))
    }

    pub fn set_event_sink(&mut self, sink: Arc<dyn SecurityEventSink>) {
        self.sink = Some(sink);
    }

    pub fn state(&self) -> LockState {
        self.state
    }

    pub fn is_provisioned(&self) -> Result<bool> {
        Ok(meta_get(self.conn()?, "format")?.is_some())
    }

    /// True when the vault was created in PIN-only mode: there is NO keystore-only unlock path.
    pub fn is_pin_only(&self) -> Result<bool> {
        Ok(self.is_provisioned()? && meta_get(self.conn()?, "env_device")?.is_none())
    }

    fn emit(&self, e: SecurityEvent) {
        if let Some(s) = &self.sink {
            s.emit(e);
        }
    }

    fn conn(&self) -> Result<&Connection> {
        match &self.inner {
            Inner::Closed(c) => Ok(c),
            Inner::Open(s) => Ok(s.conn()),
            Inner::Taken => Err(SecurityError::InvalidState),
        }
    }

    fn check_level(&self, level: ProtectionLevel) -> Result<()> {
        if level >= self.cfg.min_protection {
            return Ok(());
        }
        if self.cfg.allow_software_keystore && level >= ProtectionLevel::OsSoftware {
            self.emit(SecurityEvent::ProtectionDowngradeAccepted { level });
            return Ok(());
        }
        Err(SecurityError::ProtectionBelowMinimum { required: self.cfg.min_protection, actual: level })
    }

    /// Create keys and the DEK. Fails closed if the keystore cannot meet policy.
    pub fn provision(&mut self) -> Result<()> {
        if self.state != LockState::Locked || self.is_provisioned()? {
            return Err(SecurityError::InvalidState);
        }
        let policy =
            KeyPolicy { require_user_auth: self.cfg.require_user_auth, invalidate_on_biometric_change: true, prefer_secure_element: true };
        let level = self.keystore.create_key(ALIAS_DEVICE, &policy)?;
        if let Err(e) = self.check_level(level) {
            let _ = self.keystore.delete_key(ALIAS_DEVICE);
            return Err(e);
        }
        let dek = crate::rng::secret32()?;
        let env = self.keystore.wrap(ALIAS_DEVICE, dek.as_slice(), AAD_DEVICE)?;
        let Inner::Closed(conn) = std::mem::replace(&mut self.inner, Inner::Taken) else {
            return Err(SecurityError::InvalidState);
        };
        let res = (|| {
            meta_put(&conn, "env_device", &env)?;
            meta_put(&conn, "format", &[1])
        })();
        if let Err(e) = res {
            self.inner = Inner::Closed(conn);
            return Err(e);
        }
        match EncryptedStore::open(conn, &dek, true) {
            Ok(store) => {
                self.inner = Inner::Open(store);
                self.finish_open(false)?;
                self.state = LockState::Unlocked;
                self.last_activity = self.clock.monotonic_secs();
                self.emit(SecurityEvent::Unlocked);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Create a vault whose data key is reachable ONLY with the PIN (plus the hardware-bound secret): there is no device-envelope,
    /// so neither biometrics nor in-process Keystore access alone can open it. Offline guessing still needs the device's Keystore.
    pub fn provision_pin_only(&mut self, pin: &str) -> Result<()> {
        if self.state != LockState::Locked || self.is_provisioned()? {
            return Err(SecurityError::InvalidState);
        }
        kdf::validate_pin(pin)?;
        self.cfg.kdf.validate_stored(self.cfg.kdf_floor)?;
        let level = self.keystore.create_key(
            ALIAS_PIN,
            &KeyPolicy { require_user_auth: false, invalidate_on_biometric_change: false, prefer_secure_element: true },
        )?;
        if let Err(e) = self.check_level(level) {
            let _ = self.keystore.delete_key(ALIAS_PIN);
            return Err(e);
        }
        let dek = crate::rng::secret32()?;
        let env = self.pin_envelope(dek.as_slice(), pin)?;
        let Inner::Closed(conn) = std::mem::replace(&mut self.inner, Inner::Taken) else {
            return Err(SecurityError::InvalidState);
        };
        let res = (|| {
            meta_put(&conn, "env_pin", &env)?;
            meta_put(&conn, "format", &[1])
        })();
        if let Err(e) = res {
            self.inner = Inner::Closed(conn);
            return Err(e);
        }
        match EncryptedStore::open(conn, &dek, true) {
            Ok(store) => {
                self.inner = Inner::Open(store);
                self.finish_open(false)?;
                self.state = LockState::Unlocked;
                self.last_activity = self.clock.monotonic_secs();
                self.emit(SecurityEvent::Unlocked);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Rollback detection. Called with the store open. `strict` (unlock): a vault generation BELOW the keystore's counter means the
    /// files were replaced by an older copy => refuse. `!strict` (fresh provisioning): leftover counters are simply overtaken.
    /// Then generation := max(vault, keystore) + 1, written to the vault FIRST and the keystore second, so a crash in between can only
    /// leave the vault ahead of the counter (harmless), never behind it.
    fn rollback_check_and_bump(&mut self, strict: bool) -> Result<()> {
        let Inner::Open(store) = &mut self.inner else {
            return Err(SecurityError::InvalidState);
        };
        let vg = read_gen(store)?;
        let kg = self.keystore.counter_read()?;
        if strict && vg < kg {
            return Err(SecurityError::StorageRolledBack);
        }
        let next = vg.max(kg).checked_add(1).ok_or(SecurityError::StorageCorrupt)?;
        store.put(NS_VAULT, ID_GEN, &next.to_be_bytes())?;
        self.keystore.counter_advance(next)?;
        Ok(())
    }

    /// Best effort at lock time: advance the generation so a snapshot taken during this session is behind the counter afterwards.
    fn bump_generation_on_lock(&mut self) {
        let Inner::Open(store) = &mut self.inner else { return };
        let Ok(vg) = read_gen(store) else { return };
        let Ok(kg) = self.keystore.counter_read() else { return };
        let next = vg.max(kg).saturating_add(1);
        if store.put(NS_VAULT, ID_GEN, &next.to_be_bytes()).is_ok() {
            let _ = self.keystore.counter_advance(next);
        }
    }

    /// After a store was opened: run the rollback check; on failure drop the store again and put the vault in the right state.
    fn finish_open(&mut self, strict: bool) -> Result<()> {
        match self.rollback_check_and_bump(strict) {
            Ok(()) => Ok(()),
            Err(SecurityError::StorageRolledBack) => {
                self.set_invalidated(InvalidationReason::StorageRolledBack);
                Err(SecurityError::StorageRolledBack)
            }
            Err(e) => {
                self.close_store_if_open();
                self.state = LockState::Locked;
                Err(e)
            }
        }
    }

    fn open_with_dek(&mut self, dek: &[u8]) -> Result<()> {
        let dek: &[u8; 32] = dek.try_into().map_err(|_| SecurityError::StorageCorrupt)?;
        let Inner::Closed(conn) = std::mem::replace(&mut self.inner, Inner::Taken) else {
            return Err(SecurityError::InvalidState);
        };
        // Re-open on failure is impossible (conn consumed); reopen path restores below.
        match EncryptedStore::open_keep_conn(conn, dek) {
            Ok(store) => {
                self.inner = Inner::Open(store);
                self.finish_open(true)?;
                self.state = LockState::Unlocked;
                self.last_activity = self.clock.monotonic_secs();
                self.emit(SecurityEvent::Unlocked);
                Ok(())
            }
            Err(boxed) => {
                let (conn, e) = *boxed;
                self.inner = Inner::Closed(conn);
                self.state = LockState::Locked;
                if matches!(e, SecurityError::StorageCorrupt | SecurityError::StorageWrongKey) {
                    self.emit(SecurityEvent::StorageCorruptionDetected);
                }
                Err(e)
            }
        }
    }

    fn map_keystore_err(&mut self, e: KeyStoreError) -> SecurityError {
        match e {
            KeyStoreError::Invalidated => {
                self.set_invalidated(InvalidationReason::KeystoreKeyInvalidated);
                SecurityError::Invalidated
            }
            KeyStoreError::Missing => {
                self.set_invalidated(InvalidationReason::KeystoreKeyMissing);
                SecurityError::Invalidated
            }
            KeyStoreError::Corrupt => {
                self.state = LockState::Locked;
                self.emit(SecurityEvent::StorageCorruptionDetected);
                SecurityError::StorageCorrupt
            }
            other => {
                self.state = LockState::Locked;
                SecurityError::KeyStore(other)
            }
        }
    }

    fn require_lockable_for_unlock(&self) -> Result<()> {
        match self.state {
            LockState::Locked => Ok(()),
            LockState::Invalidated => Err(SecurityError::Invalidated),
            _ => Err(SecurityError::InvalidState),
        }
    }

    /// Biometric / device-credential unlock. The native keystore performs the prompt.
    pub fn unlock_with_device_auth(&mut self) -> Result<()> {
        self.require_lockable_for_unlock()?;
        let env = match meta_get(self.conn()?, "env_device")? {
            Some(e) => e,
            None if self.is_pin_only()? => return Err(SecurityError::InvalidState), // PIN-only vault: no keystore-only path exists
            None => return Err(SecurityError::StorageCorrupt),
        };
        self.state = LockState::Unlocking;
        match self.keystore.unwrap(ALIAS_DEVICE, &env, AAD_DEVICE) {
            Ok(dek) => self.open_with_dek(&dek),
            Err(e) => Err(self.map_keystore_err(e)),
        }
    }

    fn limiter(&self) -> Result<Limiter> {
        match meta_get(self.conn()?, "limiter")? {
            None => Ok(Limiter::default()),
            Some(b) => serde_json::from_slice(&b).map_err(|_| SecurityError::StorageCorrupt),
        }
    }

    fn save_limiter(&self, l: &Limiter) -> Result<()> {
        let b = serde_json::to_vec(l).map_err(|_| SecurityError::StorageCorrupt)?;
        meta_put(self.conn()?, "limiter", &b)
    }

    /// PIN unlock. Attempts are counted *before* verification so killing the
    /// process mid-guess does not grant a free attempt.
    pub fn unlock_with_pin(&mut self, pin: &str) -> Result<()> {
        self.require_lockable_for_unlock()?;
        let now = self.clock.unix_secs();
        let mut lim = self.limiter()?;
        if lim.locked_until > now {
            let retry = lim.locked_until - now;
            self.emit(SecurityEvent::UnlockRateLimited { retry_after_secs: retry });
            return Err(SecurityError::RateLimited { retry_after_secs: retry });
        }
        let env_bytes = meta_get(self.conn()?, "env_pin")?.ok_or(SecurityError::InvalidState)?;
        let env: PinEnvelope = serde_json::from_slice(&env_bytes).map_err(|_| SecurityError::StorageCorrupt)?;
        if env.v != 1 {
            return Err(SecurityError::StorageCorrupt);
        }
        env.params.validate_stored(self.cfg.kdf_floor)?; // fail closed on downgraded KDF params

        lim.failures = lim.failures.saturating_add(1);
        self.save_limiter(&lim)?;

        self.state = LockState::Unlocking;
        let s = match self.keystore.unwrap(ALIAS_PIN, &env.s_wrapped, AAD_PIN_S) {
            Ok(s) => s,
            Err(e) => return Err(self.map_keystore_err(e)),
        };
        let pin_key =
            kdf::derive(pin.as_bytes(), &env.salt, env.params, self.cfg.kdf_floor).inspect_err(|_| self.state = LockState::Locked)?;
        let kek = pin_kek(&s, &pin_key, &env.salt)?;
        let c = XChaCha20Poly1305::new(Key::from_slice(kek.as_slice()));
        if env.nonce.len() != 24 {
            self.state = LockState::Locked;
            return Err(SecurityError::StorageCorrupt);
        }
        match c.decrypt(XNonce::from_slice(&env.nonce), Payload { msg: &env.ct, aad: AAD_PIN_ENV }) {
            Ok(dek) => {
                let dek = Zeroizing::new(dek);
                self.save_limiter(&Limiter::default())?;
                self.open_with_dek(&dek)
            }
            Err(_) => {
                self.state = LockState::Locked;
                let p = self.cfg.limiter;
                if lim.failures > p.free_attempts {
                    let exp = (lim.failures - p.free_attempts - 1).min(20);
                    let delay = p.base_delay_secs.saturating_mul(1u64 << exp).min(p.max_delay_secs);
                    lim.locked_until = now.saturating_add(delay);
                    self.save_limiter(&lim)?;
                }
                self.emit(SecurityEvent::UnlockFailed { consecutive_failures: lim.failures });
                Err(SecurityError::BadCredential)
            }
        }
    }

    /// Enable PIN unlock as a second factor/alternative. Requires `Unlocked`.
    pub fn enable_pin(&mut self, pin: &str) -> Result<()> {
        self.require_unlocked()?;
        if self.is_pin_only()? {
            return Err(SecurityError::InvalidState); // PIN-only vaults already have their PIN; change-PIN is a separate flow
        }
        kdf::validate_pin(pin)?;
        self.cfg.kdf.validate_stored(self.cfg.kdf_floor)?;
        let dek = self.dek_for_envelope()?;
        if self.keystore.key_protection(ALIAS_PIN).is_err() {
            let level = self.keystore.create_key(
                ALIAS_PIN,
                &KeyPolicy { require_user_auth: false, invalidate_on_biometric_change: false, prefer_secure_element: true },
            )?;
            if let Err(e) = self.check_level(level) {
                let _ = self.keystore.delete_key(ALIAS_PIN);
                return Err(e);
            }
        }
        let bytes = self.pin_envelope(&dek, pin)?;
        meta_put(self.conn()?, "env_pin", &bytes)?;
        self.save_limiter(&Limiter::default())
    }

    fn pin_envelope(&self, dek: &[u8], pin: &str) -> Result<Vec<u8>> {
        let s = crate::rng::secret32()?;
        let salt = crate::rng::array::<16>()?;
        let nonce = crate::rng::array::<24>()?;
        let pin_key = kdf::derive(pin.as_bytes(), &salt, self.cfg.kdf, self.cfg.kdf_floor)?;
        let kek = pin_kek(s.as_slice(), &pin_key, &salt)?;
        let c = XChaCha20Poly1305::new(Key::from_slice(kek.as_slice()));
        let ct =
            c.encrypt(XNonce::from_slice(&nonce), Payload { msg: dek, aad: AAD_PIN_ENV }).map_err(|_| SecurityError::CryptoAuthFailed)?;
        let s_wrapped = self.keystore.wrap(ALIAS_PIN, s.as_slice(), AAD_PIN_S)?;
        let env = PinEnvelope { v: 1, params: self.cfg.kdf, salt, s_wrapped, nonce: nonce.to_vec(), ct };
        serde_json::to_vec(&env).map_err(|_| SecurityError::StorageCorrupt)
    }

    fn dek_for_envelope(&self) -> Result<Zeroizing<Vec<u8>>> {
        // Re-derive the DEK from the device envelope: avoids keeping a second copy in memory.
        let env = meta_get(self.conn()?, "env_device")?.ok_or(SecurityError::StorageCorrupt)?;
        Ok(self.keystore.unwrap(ALIAS_DEVICE, &env, AAD_DEVICE)?)
    }

    fn require_unlocked(&self) -> Result<()> {
        match self.state {
            LockState::Unlocked => Ok(()),
            LockState::Invalidated => Err(SecurityError::Invalidated),
            _ => Err(SecurityError::Locked),
        }
    }

    fn close_store(&mut self) {
        if let Inner::Open(store) = std::mem::replace(&mut self.inner, Inner::Taken) {
            self.inner = Inner::Closed(store.into_conn()); // key zeroized on drop inside
        } else if matches!(self.inner, Inner::Taken) {
            // Should be unreachable; keep fail-closed by leaving Taken (all ops error).
        }
    }

    fn set_invalidated(&mut self, reason: InvalidationReason) {
        self.close_store_if_open();
        self.state = LockState::Invalidated;
        self.emit(SecurityEvent::VaultInvalidated(reason));
    }

    fn close_store_if_open(&mut self) {
        if matches!(self.inner, Inner::Open(_)) {
            self.close_store();
        }
    }

    pub fn lock(&mut self, reason: LockReason) {
        if matches!(self.state, LockState::Unlocked | LockState::Unlocking | LockState::Background) {
            self.bump_generation_on_lock();
            self.close_store_if_open();
            self.state = LockState::Locked;
            self.emit(SecurityEvent::Locked(reason));
        }
    }

    /// Keys are dropped immediately when backgrounded.
    pub fn on_background(&mut self) {
        if matches!(self.state, LockState::Unlocked | LockState::Unlocking) {
            self.bump_generation_on_lock();
            self.close_store_if_open();
            self.state = LockState::Background;
            self.emit(SecurityEvent::Locked(LockReason::Backgrounded));
        }
    }

    /// Returning to the foreground requires a fresh unlock.
    pub fn on_foreground(&mut self) {
        if self.state == LockState::Background {
            self.state = LockState::Locked;
        }
    }

    pub fn on_device_security_event(&mut self, ev: DeviceSecurityEvent) {
        match ev {
            DeviceSecurityEvent::ScreenLocked => self.lock(LockReason::DeviceScreenLocked),
            DeviceSecurityEvent::PasscodeRemoved => self.set_invalidated(InvalidationReason::PasscodeRemoved),
            DeviceSecurityEvent::BiometricEnrollmentChanged => self.set_invalidated(InvalidationReason::BiometricsChanged),
        }
    }

    /// Call periodically from the app; also invoked on every data access.
    pub fn tick(&mut self) {
        if self.state == LockState::Unlocked
            && self.clock.monotonic_secs().saturating_sub(self.last_activity) >= self.cfg.inactivity_timeout_secs
        {
            self.lock(LockReason::Inactivity);
        }
    }

    /// Record user activity (resets the inactivity timer).
    pub fn touch(&mut self) {
        if self.state == LockState::Unlocked {
            self.last_activity = self.clock.monotonic_secs();
        }
    }

    /// The only way to reach plaintext storage. Fails closed unless `Unlocked`.
    pub fn with_store<R>(&mut self, f: impl FnOnce(&mut EncryptedStore) -> Result<R>) -> Result<R> {
        self.tick();
        self.require_unlocked()?;
        self.touch();
        match &mut self.inner {
            Inner::Open(s) => f(s),
            _ => Err(SecurityError::Locked),
        }
    }
}
