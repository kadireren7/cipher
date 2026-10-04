#![no_main]
use libfuzzer_sys::fuzz_target;

// Hostile bytes into the new privacy-layer parsers: capability mint/revoke/anonymous-delivery requests and responses, the relay's
// route-level JSON, the frame decoder (which now carries a control content type) and the profile cadence function.
// Nothing may panic; accepted requests must satisfy their bounds.
fuzz_target!(|data: &[u8]| {
    use cipher_wire::messages::*;
    if let Ok(r) = serde_json::from_slice::<MintCapsRequest>(data) {
        if r.validate().is_ok() {
            assert!(!r.caps.is_empty() && r.caps.len() <= cipher_wire::limits::MAX_CAPS_PER_MINT);
        }
    }
    if let Ok(r) = serde_json::from_slice::<RevokeCapsRequest>(data) {
        let _ = r.validate();
    }
    if let Ok(r) = serde_json::from_slice::<AnonDeliverRequest>(data) {
        if let Ok(ttl) = r.validate() {
            assert!(ttl >= cipher_wire::limits::MIN_TTL_SECS && ttl <= cipher_wire::limits::MAX_TTL_SECS);
            assert!(r.deliveries.iter().all(|d| d.ciphertext.len() <= cipher_wire::limits::MAX_MESSAGE_CIPHERTEXT_BYTES));
        }
    }
    let _ = serde_json::from_slice::<AnonDeliverResponse>(data);
    let _ = serde_json::from_slice::<Envelope>(data);
    if let Some(b) = data.get(..4) {
        let e = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        for p in [cipher_core::app::netprofile::NetworkProfile::Standard, cipher_core::app::netprofile::NetworkProfile::Enhanced] {
            let d = p.next_delay_ms(e);
            assert!(d >= p.base_interval_ms() / 2 && d <= p.base_interval_ms() * 2);
        }
    }
    let _ = cipher_core::app::codec::decode(data);
});
