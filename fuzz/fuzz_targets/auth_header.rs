#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(h) = cipher_wire::signing::parse_auth_header(s) {
            // Anything accepted must round-trip.
            let again = cipher_wire::signing::format_auth_header(&h);
            assert_eq!(cipher_wire::signing::parse_auth_header(&again), Some(h));
        }
    }
});
