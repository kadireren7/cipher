//! Availability on relays whose clients all arrive from one local address (onion service + Tor daemon, reverse proxy).
//! Regression for: failed authentication from ANY client exhausted a per-address bucket that gated every authenticated request, so a few garbage
//! requests locked every user out of an onion relay.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod harness;
use cipher_core::clock::Clock as _;
use harness::*;

fn strict() -> cipher_relay::api::Limits {
    cipher_relay::api::Limits { auth_fail_burst: 3, auth_fail_refill_per_sec: 0.0, ..generous_limits() }
}

fn status_of(w: &World, app: &axum::Router, who: &cipher_core::mls::MlsClient) -> u16 {
    let h = sign(who, AUDIENCE, "GET", "/v1/messages", w.clock.0.unix_secs(), cipher_core::rng::array::<16>().unwrap(), b"");
    w.raw_on(app, "GET", "/v1/messages", Some(h), vec![])
}

#[test]
fn garbage_requests_cannot_lock_legitimate_users_out_of_a_shared_source_relay() {
    let w = World::with_limits(strict());
    let alice = new_client();
    w.register(&alice);
    let stranger = new_client();
    let shared = w.instance_shared_source(strict());
    for _ in 0..50 {
        assert_eq!(status_of(&w, &shared, &stranger), 401, "an unknown device is simply refused");
    }
    assert_eq!(status_of(&w, &shared, &alice), 200, "the legitimate user is not affected by the garbage");
}

#[test]
fn an_attributable_source_still_gets_the_failed_auth_lockout() {
    // Control: the lockout is kept where the address identifies the client (documents that the fix is not a blanket removal).
    let w = World::with_limits(strict());
    let alice = new_client();
    w.register(&alice);
    let stranger = new_client();
    let codes: Vec<u16> = (0..10).map(|_| status_of(&w, &w.app, &stranger)).collect();
    assert!(codes.contains(&429), "{codes:?}");
}
