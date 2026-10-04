#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let f = cipher_core::attachment::sanitize_filename(s);
        assert!(!f.is_empty() && f.len() <= cipher_core::attachment::MAX_FILENAME_BYTES);
        assert!(!f.contains('/') && !f.contains('\\') && !f.starts_with('.'));
        assert!(!f.chars().any(|c| c.is_control()));
        // idempotent: sanitising a sanitised name changes nothing (descriptor validation relies on this)
        assert_eq!(cipher_core::attachment::sanitize_filename(&f), f);
        let _ = cipher_core::relay_client::RelayEndpoint::new(s);
        let _ = cipher_core::verification::verify_scanned_qr(s, &cipher_wire::Id16([0; 16]), &[0; 32]);
    }
});
