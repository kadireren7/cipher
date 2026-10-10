//! Contact Card v1 (docs/MULTI_RELAY_PROTOCOL.md §3): signature, strictness, freshness, tamper-evidence.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::unnecessary_to_owned)]
use cipher_core::contact_card::{ContactCard, MAX_CARD_LIFETIME_MS};
use cipher_core::mls::MlsClient;
use cipher_wire::{b64, Id16, RelayDescriptor};

const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 24 * 3600 * 1000;

fn client(n: u8) -> MlsClient {
    MlsClient::generate(Id16([n; 16]), Id16([n + 100; 16])).unwrap()
}
fn relay() -> RelayDescriptor {
    RelayDescriptor::new("https://relay-b.example.org:8443", None).unwrap()
}
fn card(c: &MlsClient) -> String {
    ContactCard::issue(c, relay(), Id16([9; 16]), NOW, 7 * DAY).unwrap()
}

#[test]
fn a_card_roundtrips_and_names_exactly_what_was_issued() {
    let bob = client(1);
    let parsed = ContactCard::parse(&card(&bob), NOW + 1000).unwrap();
    assert_eq!(parsed.account, bob.account_id());
    assert_eq!(parsed.root_key, bob.identity_public());
    assert_eq!(parsed.relay, relay());
    assert_eq!(parsed.intro, Id16([9; 16]));
    assert_eq!(parsed.expires_ms, NOW + 7 * DAY);
}

#[test]
fn flipping_any_single_bit_of_a_card_is_rejected() {
    let bob = client(1);
    let raw = b64::decode(&card(&bob)).unwrap();
    assert!(raw.len() < 400, "a card must stay small enough for a QR code, was {}", raw.len());
    for i in 0..raw.len() {
        for bit in 0..8 {
            let mut t = raw.clone();
            t[i] ^= 1 << bit;
            assert!(ContactCard::parse(&b64::encode(&t), NOW + 1000).is_err(), "byte {i} bit {bit} was accepted");
        }
    }
}

#[test]
fn truncated_extended_and_foreign_inputs_are_rejected() {
    let bob = client(1);
    let raw = b64::decode(&card(&bob)).unwrap();
    for n in 0..raw.len() {
        assert!(ContactCard::parse(&b64::encode(&raw[..n]), NOW + 1000).is_err(), "prefix {n}");
    }
    let mut longer = raw.clone();
    longer.push(0);
    assert!(ContactCard::parse(&b64::encode(&longer), NOW + 1000).is_err());
    for junk in ["", "not base64!!", "Q0NEMQ", "AAAA"] {
        assert!(ContactCard::parse(junk, NOW).is_err());
    }
    // the identity QR payload of the existing format is not a card
    let qr = cipher_core::verification::qr_payload(&bob.account_id(), &bob.identity_public());
    assert!(ContactCard::parse(&qr, NOW).is_err());
}

#[test]
fn a_malicious_relay_cannot_retarget_a_card_without_the_issuers_key() {
    // The relay (or anyone on the path) swaps the relay and intro capability inside the payload but keeps Bob's signature.
    let bob = client(1);
    let raw = b64::decode(&card(&bob)).unwrap();
    let evil = RelayDescriptor::new("https://evil.example.org", None).unwrap();
    let payload_len = usize::from(u16::from_be_bytes([raw[4], raw[5]]));
    let payload = String::from_utf8(raw[6..6 + payload_len].to_vec()).unwrap();
    let swapped = payload.replace("relay-b.example.org:8443", &evil.host().to_owned());
    assert_ne!(swapped, payload);
    let mut forged = raw[..4].to_vec();
    forged.extend_from_slice(&(swapped.len() as u16).to_be_bytes());
    forged.extend_from_slice(swapped.as_bytes());
    forged.extend_from_slice(&raw[6 + payload_len..]);
    assert!(ContactCard::parse(&b64::encode(&forged), NOW + 1000).is_err());
}

#[test]
fn a_card_cannot_claim_someone_elses_key_with_a_valid_signature() {
    // Mallory signs her own card (valid) but cannot make it name Bob's identity key.
    let (bob, mallory) = (client(1), client(2));
    let m = ContactCard::parse(&card(&mallory), NOW + 1000).unwrap();
    assert_ne!(m.root_key, bob.identity_public());
    assert_eq!(m.account, mallory.account_id());
}

#[test]
fn freshness_is_enforced_and_lifetime_is_bounded() {
    let bob = client(1);
    let c = card(&bob);
    assert!(ContactCard::parse(&c, NOW + 7 * DAY - 1).is_ok());
    assert!(ContactCard::parse(&c, NOW + 7 * DAY).is_err(), "expired");
    assert!(ContactCard::parse(&c, NOW - 11 * 60 * 1000).is_err(), "issued in the future beyond tolerated skew");
    assert!(ContactCard::issue(&bob, relay(), Id16([9; 16]), NOW, 0).is_err());
    assert!(ContactCard::issue(&bob, relay(), Id16([9; 16]), NOW, MAX_CARD_LIFETIME_MS + 1).is_err());
    assert!(ContactCard::issue(&bob, relay(), Id16([9; 16]), u64::MAX, MAX_CARD_LIFETIME_MS).is_err(), "overflow");
}

#[test]
fn onion_cards_carry_their_pin_and_cannot_be_issued_without_one() {
    let bob = client(1);
    let onion = "https://46qfvf5rr4gulgasuzud7la5izd4fjm555gvynfnuipkwtwhz7shbcad.onion";
    assert!(RelayDescriptor::new(onion, None).is_err());
    let rd = RelayDescriptor::new(onion, Some([5; 32])).unwrap();
    let c = ContactCard::issue(&bob, rd.clone(), Id16([9; 16]), NOW, DAY).unwrap();
    let parsed = ContactCard::parse(&c, NOW + 1).unwrap();
    assert_eq!(parsed.relay.pin().unwrap(), Some([5; 32]));
    assert_eq!(parsed.relay, rd);
}
