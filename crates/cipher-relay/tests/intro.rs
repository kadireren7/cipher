#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Intro capabilities (docs/MULTI_RELAY_PROTOCOL.md §4) on the real relay router + PostgreSQL: what a contact-card holder can and cannot do
//! WITHOUT an account, and that it cannot be turned into an oracle, a drain, or a way to read anything else.
mod harness;
use cipher_core::clock::Clock as _;
use cipher_core::protocol::GroupProtocol as _;
use cipher_wire::limits::*;
use cipher_wire::messages::*;
use cipher_wire::Id16;
use harness::*;

fn authed_post(w: &World, who: &cipher_core::mls::MlsClient, path: &str, body: &impl serde::Serialize) -> u16 {
    let body = serde_json::to_vec(body).unwrap();
    let h = sign(who, AUDIENCE, "POST", path, w.clock.0.unix_secs(), cipher_core::rng::array::<16>().unwrap(), &body);
    w.raw("POST", path, Some(h), body).0
}

fn intro(w: &World, who: &cipher_core::mls::MlsClient) -> Id16 {
    let cap = rid();
    assert_eq!(authed_post(w, who, "/v1/caps", &MintCapsRequest { caps: vec![cap], intro: true }), 204);
    cap
}

fn post(w: &World, path: &str, cap: Id16, device: Option<Id16>) -> (u16, Vec<u8>) {
    w.raw("POST", path, None, serde_json::to_vec(&IntroRequest { cap, device }).unwrap())
}

#[test]
fn a_card_holder_without_an_account_gets_self_authenticating_records_and_key_packages() {
    let w = World::new();
    let mut bob = new_client();
    w.register(&bob);
    let kps = bob.generate_key_packages(2).unwrap();
    w.api(&bob).upload_key_packages(kps).unwrap();
    let cap = intro(&w, &bob);

    let (st, body) = post(&w, "/v1/intro/directory", cap, None);
    assert_eq!(st, 200);
    let dir: DirectoryResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(dir.account_id, bob.account_id());
    assert_eq!(dir.devices.len(), 1);
    assert!(cipher_core::verification::verify_binding(&dir.account_id, &dir.devices[0]), "records verify without trusting the relay");

    let (st, body) = post(&w, "/v1/intro/key-package", cap, Some(bob.device_id()));
    assert_eq!(st, 200);
    assert!(!serde_json::from_slice::<KeyPackageResponse>(&body).unwrap().key_package.is_empty());
    // the same capability also delivers (the Welcome), still without authenticating
    let d = AnonDeliverRequest { deliveries: vec![AnonDelivery { cap, message_id: rid(), ciphertext: vec![7; 200] }], ttl_secs: None };
    let (st, body) = w.raw("POST", "/v1/deliver", None, serde_json::to_vec(&d).unwrap());
    assert_eq!(st, 200);
    assert_eq!(serde_json::from_slice::<AnonDeliverResponse>(&body).unwrap().results, ["queued"]);
}

#[test]
fn ordinary_unknown_guessed_expired_and_revoked_capabilities_are_one_indistinguishable_not_found() {
    let w = World::new();
    let bob = new_client();
    w.register(&bob);
    // an ORDINARY delivery capability must not open the directory or KeyPackages
    let ordinary = rid();
    assert_eq!(authed_post(&w, &bob, "/v1/caps", &MintCapsRequest { caps: vec![ordinary], intro: false }), 204);
    let results = [
        post(&w, "/v1/intro/directory", ordinary, None),
        post(&w, "/v1/intro/directory", rid(), None),
        post(&w, "/v1/intro/key-package", rid(), Some(bob.device_id())),
    ];
    for (st, body) in &results {
        assert_eq!(*st, 404);
        assert_eq!(body, &results[0].1, "identical body: no oracle distinguishes the cases");
    }
    let revoked = intro(&w, &bob);
    assert_eq!(authed_post(&w, &bob, "/v1/caps/revoke", &RevokeCapsRequest { caps: vec![revoked], grace_secs: None }), 204);
    assert_eq!(post(&w, "/v1/intro/directory", revoked, None), results[0]);
    let expiring = intro(&w, &bob);
    w.clock.0.advance(CAP_TTL_SECS + 1);
    assert_eq!(post(&w, "/v1/intro/directory", expiring, None), results[0]);
}

#[test]
fn a_card_opens_only_its_issuers_devices() {
    let w = World::new();
    let (bob, mut carol) = (new_client(), new_client());
    w.register(&bob);
    w.register(&carol);
    let kps = carol.generate_key_packages(1).unwrap();
    w.api(&carol).upload_key_packages(kps).unwrap();
    let bobs_card = intro(&w, &bob);
    assert_eq!(
        post(&w, "/v1/intro/key-package", bobs_card, Some(carol.device_id())).0,
        404,
        "Bob's card must not reach Carol's KeyPackages"
    );
    assert_eq!(post(&w, "/v1/intro/key-package", bobs_card, Some(rid())).0, 404);
    assert_eq!(post(&w, "/v1/intro/key-package", bobs_card, None).0, 400);
}

#[test]
fn key_package_draining_through_a_leaked_card_is_bounded() {
    let w = World::new();
    let mut bob = new_client();
    w.register(&bob);
    let kps = bob.generate_key_packages(20).unwrap();
    w.api(&bob).upload_key_packages(kps).unwrap();
    let cap = intro(&w, &bob);
    let ok = (0..30).filter(|_| post(&w, "/v1/intro/key-package", cap, Some(bob.device_id())).0 == 200).count();
    assert_eq!(ok, 4, "per-capability burst is 4/h");
    assert_eq!(post(&w, "/v1/intro/key-package", cap, Some(bob.device_id())).0, 429);
    w.clock.0.advance(3600);
    assert!(post(&w, "/v1/intro/key-package", cap, Some(bob.device_id())).0 == 200, "refills with time");
}

#[test]
fn the_number_of_live_cards_is_bounded_and_garbage_requests_are_rejected() {
    let w = World::new();
    let bob = new_client();
    w.register(&bob);
    for _ in 0..MAX_INTRO_CAPS_PER_DEVICE {
        intro(&w, &bob);
    }
    assert_eq!(authed_post(&w, &bob, "/v1/caps", &MintCapsRequest { caps: vec![rid()], intro: true }), 429, "too many live cards");
    for body in [&b""[..], b"{}", b"not json", br#"{"cap":"zz"}"#, br#"{"cap":"00000000000000000000000000000000","extra":1}"#] {
        assert_eq!(w.raw("POST", "/v1/intro/directory", None, body.to_vec()).0, 400);
    }
    assert_eq!(w.raw("GET", "/v1/intro/directory", None, vec![]).0, 405);
}

#[test]
fn intro_responses_never_contain_secrets_or_queue_content() {
    let w = World::new();
    let bob = new_client();
    w.register(&bob);
    let cap = intro(&w, &bob);
    let d = AnonDeliverRequest { deliveries: vec![AnonDelivery { cap, message_id: rid(), ciphertext: vec![9; 300] }], ttl_secs: None };
    w.raw("POST", "/v1/deliver", None, serde_json::to_vec(&d).unwrap());
    let (_, body) = post(&w, "/v1/intro/directory", cap, None);
    let text = String::from_utf8(body).unwrap();
    assert!(!text.contains("ciphertext") && !text.contains(&cap.to_hex()), "{text}");
    // the database holds only the capability's hash
    let hits: i64 = w.rt.block_on(async {
        w.pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT count(*) FROM delivery_caps WHERE position($1::bytea in cap_hash) > 0", &[&cap.0.as_slice()])
            .await
            .unwrap()
            .get(0)
    });
    assert_eq!(hits, 0);
}
