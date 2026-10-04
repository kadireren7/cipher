#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! History storage: keyset pagination and atomic multi-record updates.
use cipher_core::clock::testing::ManualClock;
use cipher_core::error::SecurityError;
use cipher_core::keystore::testing::InMemoryKeyStore;
use cipher_core::keystore::ProtectionLevel;
use cipher_core::vault::{Vault, VaultConfig};
use std::sync::Arc;

fn vault() -> Vault {
    let mut v = Vault::open(
        None,
        Arc::new(InMemoryKeyStore::new(ProtectionLevel::HardwareBacked)),
        Arc::new(ManualClock::new(1)),
        VaultConfig::default(),
    )
    .unwrap();
    v.provision().unwrap();
    v
}

#[test]
fn pages_are_newest_first_non_overlapping_and_bounded() {
    let mut v = vault();
    v.with_store(|s| {
        for i in 0..1050u32 {
            s.put("m", &format!("{i:020}"), b"x")?;
        }
        let mut seen = Vec::new();
        let mut before: Option<String> = None;
        let mut pages = 0;
        loop {
            let page = s.list_ids_page("m", before.as_deref(), 100)?;
            if page.is_empty() {
                break;
            }
            assert!(page.len() <= 100);
            assert!(page.windows(2).all(|w| w[0] > w[1]), "descending");
            before = page.last().cloned();
            seen.extend(page);
            pages += 1;
        }
        assert_eq!(pages, 11);
        assert_eq!(seen.len(), 1050);
        let mut sorted = seen.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(seen, sorted);
        assert_eq!(s.count("m")?, 1050);
        assert_eq!(s.list_ids_page("m", None, 1_000_000)?.len(), 500, "page size is clamped");
        Ok(())
    })
    .unwrap();
}

#[test]
fn atomic_batches_apply_fully_or_not_at_all() {
    let mut v = vault();
    v.with_store(|s| {
        s.put("a", "1", b"old")?;
        let r: Result<(), SecurityError> = s.atomic(|s| {
            s.put("a", "1", b"new")?;
            s.put("a", "2", b"two")?;
            Err(SecurityError::InvalidState)
        });
        assert!(r.is_err());
        assert_eq!(s.get("a", "1")?.unwrap().as_slice(), b"old", "rolled back");
        assert!(s.get("a", "2")?.is_none());
        s.atomic(|s| {
            s.put("a", "1", b"new")?;
            s.put("a", "2", b"two")
        })?;
        assert_eq!(s.get("a", "1")?.unwrap().as_slice(), b"new");
        assert_eq!(s.get("a", "2")?.unwrap().as_slice(), b"two");
        Ok(())
    })
    .unwrap();
}
