#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod common;
use cipher_core::clock::testing::ManualClock;
use cipher_core::error::SecurityError;
use cipher_core::events::{SecurityEvent, SecurityEventSink};
use cipher_core::kdf::{KdfFloor, KdfParams};
use cipher_core::keystore::testing::InMemoryKeyStore;
use cipher_core::keystore::{KeyStoreError, ProtectionLevel};
use cipher_core::mls::MlsClient;
use cipher_core::vault::*;
use std::sync::{Arc, Mutex};

const FIXTURE: &[u8] = b"PLAINTEXT-FIXTURE-local-message-9921";
const PIN: &str = "493817";

#[derive(Default)]
struct Events(Mutex<Vec<SecurityEvent>>);
impl SecurityEventSink for Events {
    fn emit(&self, e: SecurityEvent) {
        self.0.lock().unwrap().push(e);
    }
}

struct Rig {
    ks: Arc<InMemoryKeyStore>,
    clock: Arc<ManualClock>,
    events: Arc<Events>,
    path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

fn cfg() -> VaultConfig {
    VaultConfig {
        min_protection: ProtectionLevel::HardwareBacked,
        kdf: KdfParams::INSECURE_FAST_FOR_TESTS,
        kdf_floor: KdfFloor::DisabledForTests,
        inactivity_timeout_secs: 60,
        ..VaultConfig::default()
    }
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    Rig {
        ks: Arc::new(InMemoryKeyStore::new(ProtectionLevel::HardwareBacked)),
        clock: Arc::new(ManualClock::new(1_700_000_000)),
        events: Arc::new(Events::default()),
        path: dir.path().join("vault.db"),
        _dir: dir,
    }
}

impl Rig {
    fn vault_with(&self, c: VaultConfig) -> Vault {
        let mut v = Vault::open(Some(&self.path), self.ks.clone(), self.clock.clone(), c).unwrap();
        v.set_event_sink(self.events.clone());
        v
    }
    fn vault(&self) -> Vault {
        self.vault_with(cfg())
    }
    fn file_bytes(&self) -> Vec<u8> {
        let mut all = std::fs::read(&self.path).unwrap();
        for ext in ["-journal", "-wal"] {
            let mut p = self.path.clone().into_os_string();
            p.push(ext);
            if let Ok(b) = std::fs::read(p) {
                all.extend(b);
            }
        }
        all
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn sec_009_database_file_contains_no_plaintext_and_roundtrips_after_unlock() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    v.with_store(|s| s.put("messages", "m1", FIXTURE)).unwrap();
    v.lock(cipher_core::events::LockReason::Manual);
    assert!(!contains(&r.file_bytes(), FIXTURE), "plaintext found in database file");
    assert!(!contains(&r.file_bytes(), b"PLAINTEXT-FIXTURE"));
    v.unlock_with_device_auth().unwrap();
    let got = v.with_store(|s| s.get("messages", "m1")).unwrap().unwrap();
    assert_eq!(got.as_slice(), FIXTURE);
}

#[test]
fn sec_008_identity_private_material_never_in_plaintext_on_disk() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    let client = common::new_client();
    let snap = client.snapshot().unwrap();
    let auth_secret = snap[36..68].to_vec(); // magic(4)+account(16)+device(16) | auth secret(32)
    assert_eq!(auth_secret.len(), 32);
    v.with_store(|s| s.put("mls", "state", &snap)).unwrap();
    v.lock(cipher_core::events::LockReason::Manual);
    let file = r.file_bytes();
    assert!(!contains(&file, &auth_secret), "transport auth secret in plaintext");
    assert!(!contains(&file, &snap[..40]), "snapshot header in plaintext");
    // And the state is recoverable after unlock.
    v.unlock_with_device_auth().unwrap();
    let back = v.with_store(|s| s.get("mls", "state")).unwrap().unwrap();
    let restored = MlsClient::restore(&back).unwrap();
    assert_eq!(restored.identity_public(), client.identity_public());
}

#[test]
fn lifecycle_states_and_keys_unreachable_when_not_unlocked() {
    let r = rig();
    let mut v = r.vault();
    assert_eq!(v.state(), LockState::Locked);
    assert!(matches!(v.with_store(|_| Ok(())), Err(SecurityError::Locked)));
    v.provision().unwrap();
    assert_eq!(v.state(), LockState::Unlocked);
    v.with_store(|s| s.put("n", "i", FIXTURE)).unwrap();

    v.on_background();
    assert_eq!(v.state(), LockState::Background);
    assert!(matches!(v.with_store(|s| s.get("n", "i")), Err(SecurityError::Locked)));
    v.on_foreground();
    assert_eq!(v.state(), LockState::Locked, "foreground requires a fresh unlock");
    assert!(matches!(v.with_store(|s| s.get("n", "i")), Err(SecurityError::Locked)));

    v.unlock_with_device_auth().unwrap();
    assert_eq!(v.state(), LockState::Unlocked);
    assert_eq!(v.with_store(|s| s.get("n", "i")).unwrap().unwrap().as_slice(), FIXTURE);
    v.lock(cipher_core::events::LockReason::Manual);
    assert_eq!(v.state(), LockState::Locked);
    assert!(matches!(v.with_store(|s| s.get("n", "i")), Err(SecurityError::Locked)));
}

#[test]
fn unlock_denied_by_user_authentication_stays_locked() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    v.lock(cipher_core::events::LockReason::Manual);
    r.ks.set_auth_ok(false);
    assert!(matches!(v.unlock_with_device_auth(), Err(SecurityError::KeyStore(KeyStoreError::AuthCancelled))));
    assert_eq!(v.state(), LockState::Locked);
    r.ks.set_auth_ok(true);
    v.unlock_with_device_auth().unwrap();
}

#[test]
fn inactivity_timeout_locks_and_activity_extends_it() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    r.clock.advance(50);
    v.with_store(|s| s.put("n", "i", b"x")).unwrap(); // activity resets the timer
    r.clock.advance(50);
    assert!(v.with_store(|s| s.get("n", "i")).is_ok(), "50s since last activity: still unlocked");
    r.clock.advance(61);
    assert!(matches!(v.with_store(|s| s.get("n", "i")), Err(SecurityError::Locked)));
    assert_eq!(v.state(), LockState::Locked);
    assert!(r.events.0.lock().unwrap().contains(&SecurityEvent::Locked(cipher_core::events::LockReason::Inactivity)));
}

#[test]
fn device_security_events_lock_or_invalidate() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    v.on_device_security_event(DeviceSecurityEvent::ScreenLocked);
    assert_eq!(v.state(), LockState::Locked);
    v.unlock_with_device_auth().unwrap();
    v.on_device_security_event(DeviceSecurityEvent::PasscodeRemoved);
    assert_eq!(v.state(), LockState::Invalidated);
    assert!(matches!(v.with_store(|_| Ok(())), Err(SecurityError::Invalidated)));
    assert!(matches!(v.unlock_with_device_auth(), Err(SecurityError::Invalidated)));
}

#[test]
fn key_invalidation_by_os_is_terminal_and_fails_closed() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    v.lock(cipher_core::events::LockReason::Manual);
    r.ks.invalidate(ALIAS_DEVICE);
    assert!(matches!(v.unlock_with_device_auth(), Err(SecurityError::Invalidated)));
    assert_eq!(v.state(), LockState::Invalidated);
    // A fresh process (new Vault object) must also fail closed rather than re-provision silently.
    let mut v2 = r.vault();
    assert!(matches!(v2.unlock_with_device_auth(), Err(SecurityError::Invalidated)));
    assert!(matches!(v2.provision(), Err(SecurityError::InvalidState)), "no silent re-provisioning over existing data");
}

#[test]
fn missing_secure_storage_key_fails_closed() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    drop(v);
    r.ks.remove_silently(ALIAS_DEVICE); // e.g. DB restored onto a device without the keystore key
    let mut v2 = r.vault();
    assert!(matches!(v2.unlock_with_device_auth(), Err(SecurityError::Invalidated)));
    assert_eq!(v2.state(), LockState::Invalidated);
}

#[test]
fn sec_016_provisioning_fails_closed_when_keystore_is_too_weak_and_never_silently_downgrades() {
    // Insecure (e.g. no hardware) with default policy -> hard error.
    let weak = Arc::new(InMemoryKeyStore::new(ProtectionLevel::Insecure));
    let mut v = Vault::open(None, weak.clone(), Arc::new(ManualClock::new(1)), cfg()).unwrap();
    assert!(matches!(v.provision(), Err(SecurityError::ProtectionBelowMinimum { .. })));
    assert!(!v.is_provisioned().unwrap());
    assert!(matches!(v.with_store(|_| Ok(())), Err(SecurityError::Locked)));

    // Even the explicit software opt-in does not accept *Insecure*.
    let mut c = cfg();
    c.allow_software_keystore = true;
    let mut v = Vault::open(None, weak, Arc::new(ManualClock::new(1)), c.clone()).unwrap();
    assert!(matches!(v.provision(), Err(SecurityError::ProtectionBelowMinimum { .. })));

    // Explicit opt-in accepts OsSoftware but surfaces an event.
    let soft = Arc::new(InMemoryKeyStore::new(ProtectionLevel::OsSoftware));
    let ev = Arc::new(Events::default());
    let mut v = Vault::open(None, soft.clone(), Arc::new(ManualClock::new(1)), cfg()).unwrap();
    assert!(matches!(v.provision(), Err(SecurityError::ProtectionBelowMinimum { .. })), "default policy rejects software keystore");
    let mut v = Vault::open(None, soft, Arc::new(ManualClock::new(1)), c).unwrap();
    v.set_event_sink(ev.clone());
    v.provision().unwrap();
    assert!(ev.0.lock().unwrap().iter().any(|e| matches!(e, SecurityEvent::ProtectionDowngradeAccepted { .. })));
}

#[test]
fn corrupted_record_ciphertext_is_detected_never_returned() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    v.with_store(|s| s.put("messages", "m1", FIXTURE)).unwrap();
    v.lock(cipher_core::events::LockReason::Manual);
    {
        let c = rusqlite::Connection::open(&r.path).unwrap();
        let mut ct: Vec<u8> = c.query_row("SELECT ct FROM records WHERE ns='messages'", [], |row| row.get(0)).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x80;
        c.execute("UPDATE records SET ct=?1 WHERE ns='messages'", [ct]).unwrap();
    }
    v.unlock_with_device_auth().unwrap(); // check-record is intact
    assert!(matches!(v.with_store(|s| s.get("messages", "m1")), Err(SecurityError::CryptoAuthFailed)));
}

#[test]
fn records_cannot_be_swapped_between_locations() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    v.with_store(|s| {
        s.put("messages", "a", b"alpha")?;
        s.put("messages", "b", b"bravo")
    })
    .unwrap();
    v.lock(cipher_core::events::LockReason::Manual);
    {
        let c = rusqlite::Connection::open(&r.path).unwrap();
        let ct_a: Vec<u8> = c.query_row("SELECT ct FROM records WHERE id='a'", [], |row| row.get(0)).unwrap();
        c.execute("UPDATE records SET ct=?1 WHERE id='b'", [ct_a]).unwrap();
    }
    v.unlock_with_device_auth().unwrap();
    assert!(matches!(v.with_store(|s| s.get("messages", "b")), Err(SecurityError::CryptoAuthFailed)));
}

#[test]
fn corrupted_check_record_or_wrong_dek_is_detected_at_unlock() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    v.lock(cipher_core::events::LockReason::Manual);
    {
        let c = rusqlite::Connection::open(&r.path).unwrap();
        c.execute("UPDATE records SET ct=zeroblob(64) WHERE ns='__vault__'", []).unwrap();
    }
    assert!(v.unlock_with_device_auth().is_err());
    assert_eq!(v.state(), LockState::Locked);
    assert!(r.events.0.lock().unwrap().contains(&SecurityEvent::StorageCorruptionDetected));
}

#[test]
fn tampered_device_envelope_fails_closed() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    v.lock(cipher_core::events::LockReason::Manual);
    {
        let c = rusqlite::Connection::open(&r.path).unwrap();
        let mut b: Vec<u8> = c.query_row("SELECT v FROM vault_meta WHERE k='env_device'", [], |row| row.get(0)).unwrap();
        b[30] ^= 1;
        c.execute("UPDATE vault_meta SET v=?1 WHERE k='env_device'", [b]).unwrap();
    }
    assert!(matches!(v.unlock_with_device_auth(), Err(SecurityError::StorageCorrupt)));
    assert_eq!(v.state(), LockState::Locked);
}

#[test]
fn pin_unlock_wrong_pin_rate_limiting_and_persistence() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    v.with_store(|s| s.put("n", "i", FIXTURE)).unwrap();
    assert!(matches!(v.enable_pin("123"), Err(SecurityError::WeakPin)));
    v.enable_pin(PIN).unwrap();
    v.lock(cipher_core::events::LockReason::Manual);
    assert!(!contains(&r.file_bytes(), PIN.as_bytes()), "raw PIN stored");

    // 5 free failures, then lockout with exponential backoff.
    for i in 1..=5 {
        assert!(matches!(v.unlock_with_pin("000111"), Err(SecurityError::BadCredential)), "attempt {i}");
    }
    assert!(matches!(v.unlock_with_pin("000111"), Err(SecurityError::BadCredential))); // 6th: wrong, starts 30s lockout
                                                                                       // Even the CORRECT pin is refused while locked out.
    match v.unlock_with_pin(PIN) {
        Err(SecurityError::RateLimited { retry_after_secs }) => assert!(retry_after_secs > 0 && retry_after_secs <= 30),
        other => panic!("{other:?}"),
    }
    // Counter survives a process restart (new Vault over the same file).
    drop(v);
    let mut v = r.vault();
    assert!(matches!(v.unlock_with_pin(PIN), Err(SecurityError::RateLimited { .. })));
    r.clock.advance(31);
    v.unlock_with_pin(PIN).unwrap();
    assert_eq!(v.with_store(|s| s.get("n", "i")).unwrap().unwrap().as_slice(), FIXTURE);
    // Success resets the counter.
    v.lock(cipher_core::events::LockReason::Manual);
    assert!(matches!(v.unlock_with_pin("000111"), Err(SecurityError::BadCredential)));
}

#[test]
fn pin_unlock_requires_the_hardware_bound_secret() {
    // A stolen DB copy on a device/keystore without the PIN-secret key cannot be attacked offline.
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    v.enable_pin(PIN).unwrap();
    drop(v);
    let other_ks = Arc::new(InMemoryKeyStore::new(ProtectionLevel::HardwareBacked));
    let mut thief = Vault::open(Some(&r.path), other_ks, r.clock.clone(), cfg()).unwrap();
    assert!(matches!(thief.unlock_with_pin(PIN), Err(SecurityError::Invalidated)));
}

#[test]
fn kdf_parameter_downgrade_in_storage_fails_closed() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    v.enable_pin(PIN).unwrap(); // created with weak test params (floor disabled)
    drop(v);
    // Same file, production floor enforced: stored params are below the floor -> refuse.
    let mut prod = r.vault_with(VaultConfig { kdf_floor: KdfFloor::Enforced, ..cfg() });
    assert!(matches!(prod.unlock_with_pin(PIN), Err(SecurityError::KdfParamsBelowFloor)));
    assert_eq!(prod.state(), LockState::Locked);
    // And enabling a PIN with weak params under the enforced floor is refused up front.
    let fresh_ks = Arc::new(InMemoryKeyStore::new(ProtectionLevel::HardwareBacked));
    let mut prod2 = Vault::open(
        None,
        fresh_ks,
        r.clock.clone(),
        VaultConfig { kdf_floor: KdfFloor::Enforced, kdf: KdfParams::INSECURE_FAST_FOR_TESTS, ..cfg() },
    )
    .unwrap();
    prod2.provision().unwrap();
    assert!(matches!(prod2.enable_pin(PIN), Err(SecurityError::KdfParamsBelowFloor)));
}

#[test]
fn debug_output_never_contains_key_material() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    v.with_store(|st| {
        assert_eq!(format!("{st:?}"), "EncryptedStore(<redacted>)");
        Ok(())
    })
    .unwrap();
    assert_eq!(format!("{v:?}"), "Vault { state: Unlocked, .. }");
    assert_eq!(format!("{:?}", r.ks), "InMemoryKeyStore(<redacted>)");
}

#[test]
fn pin_only_vault_has_no_keystore_only_unlock_path() {
    let r = rig();
    let mut v = r.vault();
    assert!(matches!(v.provision_pin_only("123"), Err(SecurityError::WeakPin)));
    v.provision_pin_only(PIN).unwrap();
    assert!(v.is_pin_only().unwrap() && v.is_provisioned().unwrap() && v.has_pin().unwrap());
    v.with_store(|s| s.put("n", "i", FIXTURE)).unwrap();
    assert!(matches!(v.enable_pin("111222"), Err(SecurityError::InvalidState)));
    v.lock(cipher_core::events::LockReason::Manual);
    assert!(!contains(&r.file_bytes(), FIXTURE) && !contains(&r.file_bytes(), PIN.as_bytes()));

    // Biometric / keystore-only unlock does not exist for this vault, even for code running in-process.
    assert!(matches!(v.unlock_with_device_auth(), Err(SecurityError::InvalidState)));
    {
        let c = rusqlite::Connection::open(&r.path).unwrap();
        let n: i64 = c.query_row("SELECT count(*) FROM vault_meta WHERE k='env_device'", [], |row| row.get(0)).unwrap();
        assert_eq!(n, 0, "no device envelope is ever written");
    }
    assert!(matches!(v.unlock_with_pin("000111"), Err(SecurityError::BadCredential)));
    v.unlock_with_pin(PIN).unwrap();
    assert_eq!(v.with_store(|s| s.get("n", "i")).unwrap().unwrap().as_slice(), FIXTURE);

    // Survives a restart, and a copy of the database on a device without the hardware-bound secret cannot be opened.
    drop(v);
    let mut again = r.vault();
    again.unlock_with_pin(PIN).unwrap();
    drop(again);
    let thief_ks = Arc::new(InMemoryKeyStore::new(ProtectionLevel::HardwareBacked));
    let mut thief = Vault::open(Some(&r.path), thief_ks, r.clock.clone(), cfg()).unwrap();
    assert!(matches!(thief.unlock_with_pin(PIN), Err(SecurityError::Invalidated)));
}

#[test]
fn pin_only_provisioning_fails_closed_on_weak_keystore_and_double_provision() {
    let weak = Arc::new(InMemoryKeyStore::new(ProtectionLevel::Insecure));
    let mut v = Vault::open(None, weak, Arc::new(ManualClock::new(1)), cfg()).unwrap();
    assert!(matches!(v.provision_pin_only(PIN), Err(SecurityError::ProtectionBelowMinimum { .. })));
    assert!(!v.is_provisioned().unwrap());
    let r = rig();
    let mut v = r.vault();
    v.provision_pin_only(PIN).unwrap();
    assert!(matches!(v.provision_pin_only(PIN), Err(SecurityError::InvalidState)));
    assert!(matches!(v.provision(), Err(SecurityError::InvalidState)));
}

// ---------------------------------------------------------------------------------------------------------------------
// Local rollback (final review FR-05): an attacker who can replace the app's files with an OLDER copy.
// The generation counter lives in the platform keystore (outside the data directory) and is mirrored by an authenticated
// record in the vault. MLS state restored from an old snapshot would REUSE ratchet keys/nonces for new messages.
// ---------------------------------------------------------------------------------------------------------------------

fn lock_unlock_cycles(r: &Rig, n: usize) {
    for _ in 0..n {
        let mut v = r.vault();
        v.unlock_with_device_auth().unwrap();
        v.lock(cipher_core::events::LockReason::Manual);
    }
}

#[test]
fn restoring_an_older_vault_file_is_detected_and_refused() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    v.with_store(|s| s.put("msg", "1", FIXTURE)).unwrap();
    v.lock(cipher_core::events::LockReason::Manual);
    let old_snapshot = std::fs::read(&r.path).unwrap(); // attacker copies the files NOW

    lock_unlock_cycles(&r, 2); // normal use continues (generation advances in vault AND keystore)
    let mut v = r.vault();
    v.unlock_with_device_auth().unwrap();
    v.with_store(|s| s.put("msg", "2", b"newer")).unwrap();
    v.lock(cipher_core::events::LockReason::Manual);

    // attacker restores the old copy (keystore is outside the app's files and is NOT rolled back)
    std::fs::write(&r.path, &old_snapshot).unwrap();
    let mut v = r.vault();
    assert!(matches!(v.unlock_with_device_auth(), Err(SecurityError::StorageRolledBack)));
    assert_eq!(v.state(), LockState::Invalidated);
    assert!(r
        .events
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, SecurityEvent::VaultInvalidated(cipher_core::events::InvalidationReason::StorageRolledBack))));
    // and no plaintext API works afterwards
    assert!(v.with_store(|s| s.get("msg", "1").map(|_| ())).is_err());
}

#[test]
fn rollback_is_detected_for_pin_only_vaults_too() {
    let r = rig();
    let mut v = r.vault();
    v.provision_pin_only(PIN).unwrap();
    v.lock(cipher_core::events::LockReason::Manual);
    let old = std::fs::read(&r.path).unwrap();
    for _ in 0..2 {
        let mut v = r.vault();
        v.unlock_with_pin(PIN).unwrap();
        v.lock(cipher_core::events::LockReason::Manual);
    }
    std::fs::write(&r.path, &old).unwrap();
    let mut v = r.vault();
    assert!(matches!(v.unlock_with_pin(PIN), Err(SecurityError::StorageRolledBack)));
}

#[test]
fn normal_use_never_trips_the_rollback_check() {
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    v.lock(cipher_core::events::LockReason::Manual);
    lock_unlock_cycles(&r, 5);
    // background transitions bump too
    let mut v = r.vault();
    v.unlock_with_device_auth().unwrap();
    v.on_background();
    v.on_foreground();
    let mut v = r.vault();
    assert!(v.unlock_with_device_auth().is_ok());
}

#[test]
fn an_attacker_cannot_forge_a_higher_generation_inside_the_vault() {
    // The generation record is encrypted under the DEK: editing the file cannot raise it to match the keystore counter.
    let r = rig();
    let mut v = r.vault();
    v.provision().unwrap();
    v.lock(cipher_core::events::LockReason::Manual);
    let old = std::fs::read(&r.path).unwrap();
    lock_unlock_cycles(&r, 3);
    let mut forged = old.clone();
    // flip bytes at a few positions of the old file: any tampering is caught as corruption, never accepted as a newer generation
    for i in (100..forged.len().min(3000)).step_by(97) {
        forged[i] ^= 0x5A;
    }
    std::fs::write(&r.path, &forged).unwrap();
    // Either the damaged file is refused at open, or unlocking fails: it is never accepted as a newer generation.
    match Vault::open(Some(&r.path), r.ks.clone(), r.clock.clone(), cfg()) {
        Err(_) => {}
        Ok(mut v) => {
            assert!(v.unlock_with_device_auth().is_err());
            assert_ne!(v.state(), LockState::Unlocked);
        }
    }
}

#[test]
fn a_fresh_install_over_a_stale_counter_is_not_flagged() {
    // Provisioning overtakes a leftover keystore counter (e.g. after a user-initiated reset) instead of reporting a rollback.
    let r = rig();
    r.ks.counter_advance_for_tests(40);
    let mut v = r.vault();
    v.provision().unwrap();
    v.lock(cipher_core::events::LockReason::Manual);
    let mut v = r.vault();
    assert!(v.unlock_with_device_auth().is_ok());
}
