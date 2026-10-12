#![no_main]
use libfuzzer_sys::fuzz_target;

// The home relay of a cross-relay group is untrusted: whatever it returns for `GET /v1/home/{tag}/log` and whatever a member submits to it reaches
// these parsers and the client's verification. Nothing may panic, and a page that verifies must be a gap-free extension of the head it was checked
// against (docs/CROSS_RELAY_GROUPS.md §7.3).
fuzz_target!(|data: &[u8]| {
    let tag = cipher_wire::home::home_tag(&[7; 16]);
    if let Ok(req) = serde_json::from_slice::<cipher_wire::home::HomeCommitRequest>(data) {
        let _ = req.validate();
    }
    if let Ok(resp) = serde_json::from_slice::<cipher_wire::home::HomeLogResponse>(data) {
        let head = cipher_core::home::HomeHead::genesis(&tag);
        if let Ok(v) = cipher_core::home::verify_page(&tag, &head, &resp.entries) {
            assert_eq!(v.len(), resp.entries.len());
            for (i, e) in v.iter().enumerate() {
                assert_eq!(e.seq, head.seq + 1 + i as u64, "verified entries are consecutive");
            }
        }
        if let Some(h) = &resp.head {
            let _ = cipher_core::home::check_reported_head(&head, h.seq, &h.chain);
        }
    }
});
