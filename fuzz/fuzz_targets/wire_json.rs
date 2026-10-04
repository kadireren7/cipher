#![no_main]
use cipher_wire::messages::*;
use libfuzzer_sys::fuzz_target;

// Every relay request body is attacker-controlled JSON. Contract: never panic; if it parses, validation
// must also never panic.
fuzz_target!(|data: &[u8]| {
    if let Ok(r) = serde_json::from_slice::<SendRequest>(data) {
        let _ = r.validate();
    }
    if let Ok(r) = serde_json::from_slice::<AckRequest>(data) {
        let _ = r.validate();
    }
    if let Ok(r) = serde_json::from_slice::<UploadKeyPackages>(data) {
        let _ = r.validate();
    }
    if let Ok(r) = serde_json::from_slice::<RegisterRequest>(data) {
        let _ = r.device.validate();
    }
    if let Ok(r) = serde_json::from_slice::<AddDeviceRequest>(data) {
        let _ = r.device.validate();
    }
    let _ = serde_json::from_slice::<PushTokenRequest>(data);
});
