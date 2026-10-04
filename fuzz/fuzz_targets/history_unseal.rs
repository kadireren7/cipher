#![no_main]
use libfuzzer_sys::fuzz_target;

// Hostile sealed-history records (what a tampered or rolled-back vault could hand the engine): must never panic and never "open" under a wrong key/context.
fuzz_target!(|data: &[u8]| {
    let Ok(b) = serde_json::from_slice::<cipher_core::history::SealedBody>(data) else { return };
    let (conv, msg, sender) = (cipher_wire::Id16([1; 16]), cipher_wire::Id16([2; 16]), cipher_wire::Id16([3; 16]));
    // A random record authenticates under a fixed key only with negligible probability; if it ever does, the wrong context must still fail.
    if cipher_core::history::unseal(&[7u8; 32], &conv, 5, &msg, &sender, &b).is_ok() {
        assert!(cipher_core::history::unseal(&[7u8; 32], &conv, 6, &msg, &sender, &b).is_err());
        assert!(cipher_core::history::unseal(&[8u8; 32], &conv, 5, &msg, &sender, &b).is_err());
    }
});
