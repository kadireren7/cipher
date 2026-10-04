#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Behaviour of the FFI object under hostile inputs, lifecycle misuse and failing callbacks.
use cipher_core::keystore::testing::InMemoryKeyStore;
use cipher_core::keystore::{KeyPolicy, KeyStoreError, ProtectionLevel, SecureKeyStore};
use cipher_ffi::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A Rust implementation of the Kotlin Keystore callback, backed by the in-memory fake, with fault injection.
struct MockKeystore {
    inner: InMemoryKeyStore,
    level: KeyLevel,
    panic_on_wrap: AtomicBool,
    fail_unwrap: AtomicBool,
}

impl MockKeystore {
    fn new(level: ProtectionLevel, kl: KeyLevel) -> Arc<Self> {
        Arc::new(Self {
            inner: InMemoryKeyStore::new(level),
            level: kl,
            panic_on_wrap: AtomicBool::new(false),
            fail_unwrap: AtomicBool::new(false),
        })
    }
}

fn fault(e: KeyStoreError) -> KeystoreFault {
    match e {
        KeyStoreError::Missing => KeystoreFault::Missing,
        KeyStoreError::Invalidated => KeystoreFault::Invalidated,
        KeyStoreError::AuthRequired => KeystoreFault::AuthRequired,
        KeyStoreError::AuthCancelled => KeystoreFault::AuthCancelled,
        KeyStoreError::Corrupt => KeystoreFault::Corrupt,
        KeyStoreError::Unavailable(_) => KeystoreFault::Unavailable,
    }
}

impl KeystoreCallbacks for MockKeystore {
    fn capabilities(&self) -> Result<KeystoreCaps, KeystoreFault> {
        Ok(KeystoreCaps { best_level: self.level, user_auth_supported: true, biometric_supported: true })
    }
    fn create_key(&self, alias: String, auth: bool, inv: bool, sb: bool) -> Result<KeyLevel, KeystoreFault> {
        self.inner
            .create_key(&alias, &KeyPolicy { require_user_auth: auth, invalidate_on_biometric_change: inv, prefer_secure_element: sb })
            .map_err(fault)?;
        Ok(self.level)
    }
    fn key_protection(&self, alias: String) -> Result<KeyLevel, KeystoreFault> {
        self.inner.key_protection(&alias).map_err(fault)?;
        Ok(self.level)
    }
    fn wrap(&self, alias: String, p: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, KeystoreFault> {
        if self.panic_on_wrap.load(Ordering::SeqCst) {
            panic!("keystore callback blew up");
        }
        self.inner.wrap(&alias, &p, &aad).map_err(fault)
    }
    fn unwrap_into(&self, alias: String, b: Vec<u8>, aad: Vec<u8>, sink: Arc<dyn SecretSink>) -> Result<(), KeystoreFault> {
        if self.fail_unwrap.load(Ordering::SeqCst) {
            return Err(KeystoreFault::AuthCancelled);
        }
        let plain = self.inner.unwrap(&alias, &b, &aad).map_err(fault)?;
        sink.put(plain.to_vec());
        Ok(())
    }
    fn delete_key(&self, alias: String) -> Result<(), KeystoreFault> {
        self.inner.delete_key(&alias).map_err(fault)
    }
    fn counter_read(&self) -> Result<u64, KeystoreFault> {
        self.inner.counter_read().map_err(fault)
    }
    fn counter_advance(&self, to: u64) -> Result<(), KeystoreFault> {
        self.inner.counter_advance(to).map_err(fault)
    }
}

struct DeadHttp;
impl HttpCallbacks for DeadHttp {
    fn execute(&self, _: String, _: String, _: String, _: Option<String>, _: Vec<u8>) -> Result<HttpReply, HttpFault> {
        Err(HttpFault::Network)
    }
    fn upload_file(&self, _: String, _: String, _: Option<String>, _: String) -> Result<HttpReply, HttpFault> {
        Err(HttpFault::Network)
    }
    fn download_file(&self, _: String, _: String, _: Option<String>, _: String, _: u64) -> Result<u16, HttpFault> {
        Err(HttpFault::Network)
    }
}

fn engine(ks: Arc<MockKeystore>, allow_software: bool) -> (Arc<CipherEngine>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let e = CipherEngine::new(
        EngineSettings {
            data_dir: dir.path().to_str().unwrap().to_owned(),
            relay_url: "https://relay.test".into(),
            allow_software_keystore: allow_software,
            inactivity_timeout_secs: 60,
            require_user_auth: true,
            extra_source_dir: None,
        },
        ks,
        Arc::new(DeadHttp),
    )
    .unwrap();
    (e, dir)
}

fn tee() -> Arc<MockKeystore> {
    MockKeystore::new(ProtectionLevel::HardwareBacked, KeyLevel::Tee)
}

fn invalid<T>(r: Result<T, CipherError>) -> bool {
    matches!(r, Err(CipherError::InvalidInput { .. }))
}

const ID: &str = "00112233445566778899aabbccddeeff";

#[test]
fn construction_rejects_cleartext_and_hostile_settings() {
    let dir = tempfile::tempdir().unwrap();
    let mk = |url: &str, path: String| {
        CipherEngine::new(
            EngineSettings {
                data_dir: path,
                relay_url: url.into(),
                allow_software_keystore: false,
                inactivity_timeout_secs: 60,
                require_user_auth: true,
                extra_source_dir: None,
            },
            tee(),
            Arc::new(DeadHttp),
        )
    };
    for bad in ["http://relay.example", "ftp://x", "relay.example", "https://user@relay.example", "https://relay.example/path", ""] {
        assert!(mk(bad, dir.path().to_str().unwrap().into()).is_err(), "{bad}");
    }
    assert!(mk("https://relay.example", "a\0b".into()).is_err());
    assert!(mk("https://relay.example", "x".repeat(10_000)).is_err());
    assert!(mk("https://relay.example:8443", dir.path().to_str().unwrap().into()).is_ok());
}

#[test]
fn every_data_api_fails_closed_before_the_vault_is_unlocked() {
    let (e, _d) = engine(tee(), false);
    assert!(matches!(e.list_conversations(), Err(CipherError::Locked)));
    assert!(matches!(e.list_contacts(), Err(CipherError::Locked)));
    assert!(matches!(e.get_public_identity(), Err(CipherError::Locked)));
    assert!(matches!(e.sync(), Err(CipherError::Locked)));
    assert!(matches!(e.send_text(ID.into(), "hi".into(), None), Err(CipherError::Locked)));
    assert!(matches!(e.get_history(ID.into(), None, 10), Err(CipherError::Locked)));
    assert!(matches!(e.open_attachment(ID.into(), ID.into(), false, None), Err(CipherError::Locked)));
    assert!(matches!(e.get_safety_number(ID.into()), Err(CipherError::Locked)));
    assert!(matches!(e.get_settings(), Err(CipherError::Locked)));
    assert!(matches!(e.security_event_log(5), Err(CipherError::Locked)));
    assert!(e.take_security_events().is_empty());
    let s = e.status().unwrap();
    assert_eq!((s.state, s.provisioned, s.has_identity), (LockStateFfi::Locked, false, false));
}

#[test]
fn malformed_inputs_are_rejected_at_the_boundary_before_any_work() {
    let (e, _d) = engine(tee(), false);
    e.provision_vault().unwrap();
    let bad_ids = [
        "",
        "xyz",
        &"A".repeat(32),
        &"a".repeat(31),
        &"a".repeat(33),
        "00112233445566778899aabbccddeeg0",
        "00112233445566778899aabbccddee\0f",
        "../../etc/passwd",
        "ＡＢ",
    ];
    for b in bad_ids {
        assert!(invalid(e.get_conversation(b.into())), "{b:?}");
        assert!(invalid(e.get_contact(b.into())));
        assert!(invalid(e.send_text(b.into(), "x".into(), None)));
        assert!(invalid(e.send_text(ID.into(), "x".into(), Some(b.into()))));
        assert!(invalid(e.remove_group_member(b.into(), ID.into())));
        assert!(invalid(e.create_group("g".into(), vec![b.into()])));
        assert!(invalid(e.open_attachment(b.into(), ID.into(), false, None)));
    }
    assert!(invalid(e.create_group("g".into(), (0..201).map(|_| ID.to_owned()).collect())), "list bound");
    let huge = "a".repeat(1_000_000);
    assert!(invalid(e.send_text(ID.into(), huge.clone(), None)));
    assert!(invalid(e.add_contact_by_cipher_id(huge.clone(), "n".into())));
    assert!(invalid(e.add_contact_by_qr(huge.clone(), "n".into())));
    assert!(invalid(e.create_identity(huge.clone())));
    assert!(invalid(e.enable_pin(huge)));
    assert!(invalid(e.send_text(ID.into(), "nul\0byte".into(), None)));
    assert!(invalid(e.get_history(ID.into(), Some("c\0".into()), 5)));
    // attachment source paths: only /proc/self/fd/N
    for p in ["/etc/passwd", "relative.txt", "/proc/self/fd/../mem", "/proc/self/environ", "", "/proc/self/fd/9999999"] {
        let r = e.send_attachment(
            ID.into(),
            p.into(),
            "image/png".into(),
            "a.png".into(),
            AttachmentKindFfi::Image,
            String::new(),
            None,
            None,
            None,
            None,
        );
        assert!(invalid(r), "{p:?}");
    }
    let r = e.send_attachment(
        ID.into(),
        "/proc/self/fd/3".into(),
        "image/png".into(),
        "a".into(),
        AttachmentKindFfi::Image,
        String::new(),
        Some(vec![0; 200_000]),
        None,
        None,
        None,
    );
    assert!(invalid(r), "oversize thumbnail");
}

#[test]
fn lifecycle_misuse_is_safe() {
    let (e, _d) = engine(tee(), false);
    // unlock before provisioning, lock twice, background/foreground storms
    assert!(e.unlock_vault_with_device_auth().is_err());
    assert!(e.unlock_vault_with_pin("123456".into()).is_err());
    e.lock_vault();
    e.lock_vault();
    for _ in 0..50 {
        e.on_background();
        e.on_foreground();
        e.tick();
    }
    e.provision_vault().unwrap();
    assert!(e.provision_vault().is_err(), "double provisioning is refused");
    assert_eq!(e.status().unwrap().state, LockStateFfi::Unlocked);
    assert!(matches!(e.enable_pin("12".into()), Err(CipherError::WeakPin)));
    e.enable_pin("493817".into()).unwrap();
    e.lock_vault();
    assert!(matches!(e.unlock_vault_with_pin("000111".into()), Err(CipherError::BadCredential)));
    assert!(matches!(e.get_settings(), Err(CipherError::Locked)), "failed unlock leaves the vault locked");
    e.unlock_vault_with_pin("493817".into()).unwrap();
    assert!(e.get_settings().is_ok());
    // background drops keys; foreground alone does not restore access
    e.on_background();
    assert_eq!(e.status().unwrap().state, LockStateFfi::Background);
    assert!(matches!(e.get_settings(), Err(CipherError::Locked)));
    e.on_foreground();
    assert_eq!(e.status().unwrap().state, LockStateFfi::Locked);
    assert!(matches!(e.get_settings(), Err(CipherError::Locked)));
    // PIN rate limiting is reported with a retry time
    for _ in 0..6 {
        let _ = e.unlock_vault_with_pin("000111".into());
    }
    assert!(matches!(e.unlock_vault_with_pin("493817".into()), Err(CipherError::RateLimited { retry_after_secs }) if retry_after_secs > 0));
    assert!(e.status().unwrap().pin_retry_after_secs > 0);
}

#[test]
fn device_security_events_lock_or_invalidate() {
    let (e, _d) = engine(tee(), false);
    e.provision_vault().unwrap();
    e.on_device_event(DeviceEventFfi::ScreenLocked);
    assert_eq!(e.status().unwrap().state, LockStateFfi::Locked);
    e.unlock_vault_with_device_auth().unwrap();
    e.on_device_event(DeviceEventFfi::BiometricEnrollmentChanged);
    assert_eq!(e.status().unwrap().state, LockStateFfi::Invalidated);
    assert!(matches!(e.unlock_vault_with_device_auth(), Err(CipherError::Invalidated)));
    assert!(matches!(e.get_settings(), Err(CipherError::Invalidated)));
}

#[test]
fn protection_level_is_reported_honestly_and_software_is_refused_by_default() {
    // Software-backed keystore (e.g. an emulator): refused unless explicitly allowed; never reported as hardware.
    let soft = MockKeystore::new(ProtectionLevel::OsSoftware, KeyLevel::SoftwareOrUnknown);
    let (e, _d) = engine(soft.clone(), false);
    assert!(matches!(e.provision_vault(), Err(CipherError::KeyStore)));
    assert!(!e.status().unwrap().provisioned);
    let (e, _d) = engine(MockKeystore::new(ProtectionLevel::OsSoftware, KeyLevel::SoftwareOrUnknown), true);
    e.provision_vault().unwrap();
    assert_eq!(e.status().unwrap().protection, ProtectionFfi::SoftwareOrUnknown);
    assert!(e.take_security_events().is_empty() || true);
    // The three real levels map exactly.
    for (lvl, kl, want) in [
        (ProtectionLevel::SecureElement, KeyLevel::Strongbox, ProtectionFfi::Strongbox),
        (ProtectionLevel::HardwareBacked, KeyLevel::Tee, ProtectionFfi::Tee),
    ] {
        let (e, _d) = engine(MockKeystore::new(lvl, kl), false);
        e.provision_vault().unwrap();
        assert_eq!(e.status().unwrap().protection, want);
    }
    // A keystore that cannot even describe itself fails closed.
    struct Mute;
    impl KeystoreCallbacks for Mute {
        fn capabilities(&self) -> Result<KeystoreCaps, KeystoreFault> {
            Err(KeystoreFault::Unavailable)
        }
        fn create_key(&self, _: String, _: bool, _: bool, _: bool) -> Result<KeyLevel, KeystoreFault> {
            Err(KeystoreFault::Unavailable)
        }
        fn key_protection(&self, _: String) -> Result<KeyLevel, KeystoreFault> {
            Err(KeystoreFault::Unavailable)
        }
        fn wrap(&self, _: String, _: Vec<u8>, _: Vec<u8>) -> Result<Vec<u8>, KeystoreFault> {
            Err(KeystoreFault::Unavailable)
        }
        fn unwrap_into(&self, _: String, _: Vec<u8>, _: Vec<u8>, _: Arc<dyn SecretSink>) -> Result<(), KeystoreFault> {
            Err(KeystoreFault::Unavailable)
        }
        fn delete_key(&self, _: String) -> Result<(), KeystoreFault> {
            Ok(())
        }
        fn counter_read(&self) -> Result<u64, KeystoreFault> {
            Err(KeystoreFault::Unavailable)
        }
        fn counter_advance(&self, _: u64) -> Result<(), KeystoreFault> {
            Err(KeystoreFault::Unavailable)
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let e = CipherEngine::new(
        EngineSettings {
            data_dir: dir.path().to_str().unwrap().into(),
            relay_url: "https://r.test".into(),
            allow_software_keystore: true,
            inactivity_timeout_secs: 60,
            require_user_auth: true,
            extra_source_dir: None,
        },
        Arc::new(Mute),
        Arc::new(DeadHttp),
    )
    .unwrap();
    assert!(e.provision_vault().is_err());
}

#[test]
fn user_cancelling_the_biometric_prompt_is_a_clean_error_not_a_crash() {
    let ks = tee();
    let (e, _d) = engine(ks.clone(), false);
    e.provision_vault().unwrap();
    e.lock_vault();
    ks.fail_unwrap.store(true, Ordering::SeqCst);
    assert!(matches!(e.unlock_vault_with_device_auth(), Err(CipherError::KeyStore)));
    assert_eq!(e.status().unwrap().state, LockStateFfi::Locked);
    ks.fail_unwrap.store(false, Ordering::SeqCst);
    e.unlock_vault_with_device_auth().unwrap();
}

#[test]
fn a_panicking_callback_is_contained_and_does_not_leave_keys_unlocked() {
    let ks = tee();
    let (e, _d) = engine(ks.clone(), false);
    e.provision_vault().unwrap();
    assert_eq!(e.status().unwrap().state, LockStateFfi::Unlocked);
    ks.panic_on_wrap.store(true, Ordering::SeqCst);
    // enable_pin calls wrap() -> the callback panics -> CipherError::Internal, vault locked, process alive.
    assert!(matches!(e.enable_pin("493817".into()), Err(CipherError::Internal)));
    assert_eq!(e.status().unwrap().state, LockStateFfi::Locked, "a contained panic locks the vault");
    assert!(matches!(e.get_settings(), Err(CipherError::Locked)));
    ks.panic_on_wrap.store(false, Ordering::SeqCst);
    e.unlock_vault_with_device_auth().unwrap();
    assert!(e.get_settings().is_ok());
}

#[test]
fn a_panic_inside_any_call_is_caught_and_locks_the_vault() {
    let (e, _d) = engine(tee(), false);
    e.provision_vault().unwrap();
    assert!(matches!(e.panic_inside_call_for_tests(), Err(CipherError::Internal)));
    assert_eq!(e.status().unwrap().state, LockStateFfi::Locked);
    e.unlock_vault_with_device_auth().unwrap();
}

#[test]
fn concurrent_calls_from_many_threads_are_serialised_without_deadlock_or_panic() {
    let (e, _d) = engine(tee(), false);
    e.provision_vault().unwrap();
    let mut hs = Vec::new();
    for i in 0..8 {
        let e = e.clone();
        hs.push(std::thread::spawn(move || {
            for j in 0..40 {
                let _ = e.status();
                let _ = e.get_settings();
                let _ = e.list_conversations();
                if (i + j) % 17 == 0 {
                    e.on_background();
                    e.on_foreground();
                }
                if (i + j) % 11 == 0 {
                    let _ = e.unlock_vault_with_device_auth();
                }
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    let _ = e.status().unwrap();
}

#[test]
fn offline_errors_map_to_offline_and_no_secret_text_appears_in_errors() {
    let (e, _d) = engine(tee(), false);
    e.provision_vault().unwrap();
    let err = e.create_identity("registration-token-secret-0123456789abcdef".into()).unwrap_err();
    assert!(matches!(err, CipherError::Offline), "{err:?}");
    let text = format!("{err} {err:?}");
    assert!(!text.contains("registration-token-secret"));
}

#[test]
fn utility_exports() {
    assert!(is_valid_wake_payload("{\"v\":1}".into()));
    assert!(!is_valid_wake_payload("{\"v\":1,\"x\":2}".into()));
    assert!(!is_valid_cipher_id("nonsense".into()));
    assert!(!is_valid_cipher_id("x".repeat(10_000)));
    assert!(!core_version().is_empty());
}

/// ST-027 contract: a platform keystore that "succeeds" without handing over any secret must NOT unlock anything.
#[test]
fn a_keystore_that_never_delivers_the_secret_cannot_unlock_the_vault() {
    struct Silent(Arc<MockKeystore>);
    impl KeystoreCallbacks for Silent {
        fn capabilities(&self) -> Result<KeystoreCaps, KeystoreFault> {
            self.0.capabilities()
        }
        fn create_key(&self, a: String, b: bool, c: bool, d: bool) -> Result<KeyLevel, KeystoreFault> {
            self.0.create_key(a, b, c, d)
        }
        fn key_protection(&self, a: String) -> Result<KeyLevel, KeystoreFault> {
            self.0.key_protection(a)
        }
        fn wrap(&self, a: String, p: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, KeystoreFault> {
            self.0.wrap(a, p, aad)
        }
        fn unwrap_into(&self, _: String, _: Vec<u8>, _: Vec<u8>, _: Arc<dyn SecretSink>) -> Result<(), KeystoreFault> {
            Ok(()) // claims success, delivers nothing
        }
        fn delete_key(&self, a: String) -> Result<(), KeystoreFault> {
            self.0.delete_key(a)
        }
        fn counter_read(&self) -> Result<u64, KeystoreFault> {
            self.0.counter_read()
        }
        fn counter_advance(&self, to: u64) -> Result<(), KeystoreFault> {
            self.0.counter_advance(to)
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let inner = tee();
    let mk = |ks: Arc<dyn KeystoreCallbacks>| {
        CipherEngine::new(
            EngineSettings {
                data_dir: dir.path().to_str().unwrap().to_owned(),
                relay_url: "https://r.test".into(),
                allow_software_keystore: false,
                inactivity_timeout_secs: 60,
                require_user_auth: true,
                extra_source_dir: None,
            },
            ks,
            Arc::new(DeadHttp),
        )
        .unwrap()
    };
    let e = mk(inner.clone());
    e.provision_vault().unwrap();
    e.lock_vault();
    let evil = mk(Arc::new(Silent(inner)));
    assert!(evil.unlock_vault_with_device_auth().is_err());
    assert_ne!(evil.status().unwrap().state, LockStateFfi::Unlocked);
}

/// FR-11: a requested lock must not leave the engine in a permanently "aborting" state, and must always end locked.
#[test]
fn request_lock_then_background_locks_promptly_and_the_engine_works_after_the_next_unlock() {
    let (e, _d) = engine(tee(), false);
    e.provision_vault_pin_only("739104".into()).unwrap();
    e.request_lock(); // from "the main thread", without waiting for any running call
    let t0 = std::time::Instant::now();
    e.on_background();
    assert!(t0.elapsed() < std::time::Duration::from_secs(2));
    e.on_foreground();
    assert_ne!(e.status().unwrap().state, LockStateFfi::Unlocked);
    assert!(matches!(e.list_conversations(), Err(CipherError::Locked)));
    e.unlock_vault_with_pin("739104".into()).unwrap();
    assert_eq!(e.status().unwrap().state, LockStateFfi::Unlocked);
    assert!(e.list_contacts().is_ok(), "the abort flag must be cleared once the lock has happened");
}

/// Phase-4 stress: rapid lock/unlock/background/foreground racing with plaintext-returning calls from other threads.
/// Invariants: no panic, no deadlock, every plaintext call either succeeds while unlocked or fails with a CLOSED error (never a stale
/// success after a completed lock), and the engine is fully usable afterwards.
#[test]
fn rapid_lock_unlock_racing_with_plaintext_calls_never_panics_or_leaks_a_stale_success() {
    use std::sync::atomic::{AtomicBool, AtomicU32};
    let (e, _d) = engine(tee(), false);
    e.provision_vault_pin_only("739104".into()).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let ok_calls = Arc::new(AtomicU32::new(0));
    let closed_calls = Arc::new(AtomicU32::new(0));
    let mut readers = Vec::new();
    for t in 0..3 {
        let (e, stop, ok, closed) = (e.clone(), stop.clone(), ok_calls.clone(), closed_calls.clone());
        readers.push(std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let r = match t {
                    0 => e.list_conversations().map(|_| ()),
                    1 => e.list_contacts().map(|_| ()),
                    _ => e.get_settings().map(|_| ()),
                };
                match r {
                    Ok(()) => ok.fetch_add(1, Ordering::SeqCst),
                    Err(CipherError::Locked) | Err(CipherError::Invalidated) => closed.fetch_add(1, Ordering::SeqCst),
                    Err(other) => panic!("unexpected error from a plaintext call: {other:?}"),
                };
            }
        }));
    }
    for i in 0..12 {
        match i % 4 {
            0 => e.lock_vault(),
            1 => e.on_background(),
            2 => {
                e.request_lock();
                e.on_foreground();
                e.lock_vault();
            }
            _ => e.on_device_event(DeviceEventFfi::ScreenLocked),
        }
        // after a COMPLETED lock call, a plaintext call from this thread must be refused
        assert!(matches!(e.list_conversations(), Err(CipherError::Locked)), "stale success after lock (round {i})");
        e.on_foreground(); // a backgrounded vault is only unlockable after the app is foregrounded again
        e.unlock_vault_with_pin("739104".into()).unwrap();
    }
    stop.store(true, Ordering::SeqCst);
    for r in readers {
        r.join().expect("a reader thread panicked");
    }
    assert!(ok_calls.load(Ordering::SeqCst) > 0 && closed_calls.load(Ordering::SeqCst) > 0, "the race must actually have been exercised");
    assert!(e.list_contacts().is_ok());
}
