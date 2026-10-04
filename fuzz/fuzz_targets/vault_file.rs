#![no_main]
use cipher_core::clock::testing::ManualClock;
use cipher_core::kdf::{KdfFloor, KdfParams};
use cipher_core::keystore::testing::InMemoryKeyStore;
use cipher_core::keystore::ProtectionLevel;
use cipher_core::vault::{Vault, VaultConfig};
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

// An attacker with file access can put ARBITRARY bytes where vault.db should be. Opening it and trying every unlock path must
// never panic, hang, or report "unlocked".
fuzz_target!(|data: &[u8]| {
    let base = if std::path::Path::new("/dev/shm").is_dir() { std::path::PathBuf::from("/dev/shm") } else { std::env::temp_dir() };
    let dir = base.join(format!("cipher-fuzz-vault-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("vault.db");
    for ext in ["", "-journal", "-wal", "-shm"] {
        let mut p = path.clone().into_os_string();
        p.push(ext);
        let _ = std::fs::remove_file(p);
    }
    if std::fs::write(&path, data).is_err() {
        return;
    }
    let cfg = VaultConfig {
        min_protection: ProtectionLevel::Insecure,
        kdf: KdfParams::INSECURE_FAST_FOR_TESTS,
        kdf_floor: KdfFloor::DisabledForTests,
        ..VaultConfig::default()
    };
    let ks = Arc::new(InMemoryKeyStore::new(ProtectionLevel::Insecure));
    if let Ok(mut v) = Vault::open(Some(&path), ks, Arc::new(ManualClock::new(1_700_000_000)), cfg) {
        let _ = v.is_provisioned();
        let _ = v.has_pin();
        let _ = v.is_pin_only();
        let _ = v.pin_retry_after_secs();
        let _ = v.unlock_with_device_auth();
        let _ = v.unlock_with_pin("493817");
        assert_ne!(v.state(), cipher_core::vault::LockState::Unlocked, "a garbage file must never unlock");
    }
});
