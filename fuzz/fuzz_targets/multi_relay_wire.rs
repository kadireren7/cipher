#![no_main]
use libfuzzer_sys::fuzz_target;

// Hostile bytes into the multi-relay parsers (docs/MULTI_RELAY_PROTOCOL.md): contact cards (arrive from QR codes / links / a hostile peer),
// relay descriptors (arrive inside cards and inside end-to-end DeliveryCap frames), the intro request the relay parses without authentication,
// and the control frame. Nothing may panic; whatever is accepted must satisfy its stated invariants.
fuzz_target!(|data: &[u8]| {
    // 1. A card, as text (what a scanner hands over) and as raw base64 of arbitrary bytes.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(card) = cipher_core::contact_card::ContactCard::parse(text, 1_800_000_000_000) {
            // accepted cards are fresh, bounded and name a canonical https relay (onion => pinned)
            assert!(card.expires_ms > card.issued_ms);
            assert!(card.expires_ms - card.issued_ms <= cipher_core::contact_card::MAX_CARD_LIFETIME_MS);
            assert!(card.relay.url().starts_with("https://"));
            assert!(!card.relay.url().ends_with(".onion") || card.relay.pin().ok().flatten().is_some());
        }
    }
    let as_card = cipher_wire::b64::encode(data);
    let _ = cipher_core::contact_card::ContactCard::parse(&as_card, 1_800_000_000_000);

    // 2. Relay descriptors from JSON and from a bare URL.
    if let Ok(d) = serde_json::from_slice::<cipher_wire::RelayDescriptor>(data) {
        if let Ok(v) = d.validated() {
            let again = cipher_wire::RelayDescriptor::new(v.url(), v.pin().unwrap()).expect("canonical form re-validates");
            assert_eq!(again, v);
        }
    }
    if let Ok(url) = std::str::from_utf8(data) {
        if let Ok(d) = cipher_wire::RelayDescriptor::new(url, None) {
            let rest = d.url().strip_prefix("https://").expect("only https descriptors exist");
            assert!(!rest.is_empty() && !rest.contains(['@', '/', '?', '#', ' ']));
            let _ = cipher_core::relay_client::RelayEndpoint::from_descriptor(&d);
        }
    }

    // 3. Unauthenticated relay inputs and the control frame.
    let _ = serde_json::from_slice::<cipher_wire::messages::IntroRequest>(data);
    let _ = serde_json::from_slice::<cipher_wire::messages::MintCapsRequest>(data);
    let _ = cipher_core::app::codec::decode(data);
});
