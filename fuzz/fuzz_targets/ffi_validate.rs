#![no_main]
use libfuzzer_sys::fuzz_target;

// Kotlin is hostile: arbitrary strings reach the FFI validators. They must never panic, and what they accept must be exactly canonical.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(id) = cipher_ffi::validate::id(s, "id") {
        // accepted ids are exactly 32 lowercase-hex characters and round-trip
        assert_eq!(s.len(), 32);
        assert!(s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(id.to_hex(), s);
    }
    let _ = cipher_ffi::validate::bounded(s, 64, "x");
    let _ = cipher_ffi::validate::opt_id(&Some(s.to_owned()), "x");
    let _ = cipher_ffi::validate::ids(&[s.to_owned(), s.to_owned()], "x");
    if let Ok(p) = cipher_ffi::validate::source_path(s, None) {
        // only /proc/self/fd/<digits>
        let rest = p.strip_prefix("/proc/self/fd/").expect("accepted path must be an fd path");
        assert!(!rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()));
    }
    let _ = cipher_ffi::validate::source_path(s, Some("/data/user/0/app/files"));
});
