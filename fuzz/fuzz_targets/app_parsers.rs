#![no_main]
use libfuzzer_sys::fuzz_target;

// Hostile bytes into the app-layer parsers: Cipher ID, message frame codec, group metadata extension, wake payload.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(id) = cipher_core::app::cipher_id::parse(s) {
            // canonical: whatever parses re-formats to something that parses back to the same id
            assert_eq!(cipher_core::app::cipher_id::parse(&cipher_core::app::cipher_id::format(&id)).unwrap(), id);
        }
        let _ = cipher_core::app::notify::is_valid_wake(s);
    }
    let _ = cipher_core::app::codec::decode(data);
    if let Ok(m) = cipher_core::app::groupmeta::GroupMeta::decode(data) {
        let _ = m.validate_shape();
    }
});
