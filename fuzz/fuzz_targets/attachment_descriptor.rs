#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cipher_core::attachment::AttachmentDescriptor::from_bytes(data);
});
