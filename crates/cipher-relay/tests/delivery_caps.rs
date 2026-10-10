#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::needless_range_loop)]
//! Delivery capabilities (docs/DELIVERY_CAPABILITIES.md) on the real relay router + PostgreSQL: unauthenticated delivery, lanes, rotation,
//! revocation, expiry, guessing, replay, and multi-account flooding (ST-031).
mod harness;
use cipher_core::clock::Clock as _;
use cipher_wire::limits::*;
use cipher_wire::messages::*;
use cipher_wire::Id16;
use harness::*;

fn authed_post(w: &World, who: &cipher_core::mls::MlsClient, path: &str, body: &impl serde::Serialize) -> u16 {
    let body = serde_json::to_vec(body).unwrap();
    let h = sign(who, AUDIENCE, "POST", path, w.clock.0.unix_secs(), cipher_core::rng::array::<16>().unwrap(), &body);
    w.raw("POST", path, Some(h), body).0
}

fn anon(w: &World, items: Vec<(Id16, Id16, usize)>) -> (u16, Vec<String>) {
    let req = AnonDeliverRequest {
        deliveries: items.into_iter().map(|(cap, message_id, n)| AnonDelivery { cap, message_id, ciphertext: vec![7u8; n] }).collect(),
        ttl_secs: None,
    };
    let (status, body) = w.raw("POST", "/v1/deliver", None, serde_json::to_vec(&req).unwrap());
    let results = serde_json::from_slice::<AnonDeliverResponse>(&body).map(|r| r.results).unwrap_or_default();
    (status, results)
}

fn mint(w: &World, who: &cipher_core::mls::MlsClient, n: usize) -> Vec<Id16> {
    let caps: Vec<Id16> = (0..n).map(|_| rid()).collect();
    assert_eq!(authed_post(w, who, "/v1/caps", &MintCapsRequest { caps: caps.clone(), intro: false }), 204);
    caps
}

fn queued(w: &World, dev: &Id16) -> i64 {
    w.rt.block_on(async {
        w.pool.get().await.unwrap().query_one("SELECT count(*) FROM queue WHERE recipient=$1", &[&dev.0.as_slice()]).await.unwrap().get(0)
    })
}

#[test]
fn a_capability_holder_delivers_without_authenticating_and_the_relay_stores_no_sender() {
    let w = World::new();
    let (bob, _carol) = (new_client(), new_client());
    w.register(&bob);
    let cap = mint(&w, &bob, 1)[0];
    let (status, r) = anon(&w, vec![(cap, rid(), 300)]);
    assert_eq!((status, r.as_slice()), (200, ["queued".to_owned()].as_slice()));
    let f = w.api(&bob).fetch_messages().unwrap();
    assert_eq!(f.envelopes.len(), 1);
    // nothing in the database links the envelope to a sender, and the capability itself is not stored (only its hash)
    let (sender_h, lane, cap_stored): (Option<Vec<u8>>, i16, i64) = w.rt.block_on(async {
        let c = w.pool.get().await.unwrap();
        let r = c.query_one("SELECT sender_h, lane FROM queue", &[]).await.unwrap();
        let hits: i64 = c
            .query_one("SELECT count(*) FROM delivery_caps WHERE position($1::bytea in cap_hash) > 0", &[&cap.0.as_slice()])
            .await
            .unwrap()
            .get(0);
        (r.get(0), r.get(1), hits)
    });
    assert_eq!((sender_h, lane, cap_stored), (None, 1, 0));
}

#[test]
fn unknown_guessed_revoked_and_expired_capabilities_are_all_just_invalid() {
    let w = World::new();
    let bob = new_client();
    w.register(&bob);
    let cap = mint(&w, &bob, 1)[0];
    // a guessed capability
    assert_eq!(anon(&w, vec![(rid(), rid(), 100)]).1, ["invalid"]);
    // revoked immediately
    assert_eq!(authed_post(&w, &bob, "/v1/caps/revoke", &RevokeCapsRequest { caps: vec![cap], grace_secs: None }), 204);
    assert_eq!(anon(&w, vec![(cap, rid(), 100)]).1, ["invalid"], "revoked");
    // revoked WITH grace keeps working until the grace ends (rotation without losing in-flight sends)
    let cap2 = mint(&w, &bob, 1)[0];
    assert_eq!(authed_post(&w, &bob, "/v1/caps/revoke", &RevokeCapsRequest { caps: vec![cap2], grace_secs: Some(600) }), 204);
    assert_eq!(anon(&w, vec![(cap2, rid(), 100)]).1, ["queued"]);
    w.clock.0.advance(601);
    assert_eq!(anon(&w, vec![(cap2, rid(), 100)]).1, ["invalid"], "grace over");
    // expiry
    let cap3 = mint(&w, &bob, 1)[0];
    w.clock.0.advance(CAP_TTL_SECS + 1);
    assert_eq!(anon(&w, vec![(cap3, rid(), 100)]).1, ["invalid"], "expired");
}

#[test]
fn a_capability_cannot_be_revoked_or_minted_for_someone_elses_device() {
    let w = World::new();
    let (bob, mallory) = (new_client(), new_client());
    w.register(&bob);
    w.register(&mallory);
    let cap = mint(&w, &bob, 1)[0];
    assert_eq!(
        authed_post(&w, &mallory, "/v1/caps/revoke", &RevokeCapsRequest { caps: vec![cap], grace_secs: None }),
        204,
        "ignored silently"
    );
    assert_eq!(anon(&w, vec![(cap, rid(), 100)]).1, ["queued"], "still valid: mallory does not own it");
    // minting the same value again (a collision / replayed mint) is refused
    assert_eq!(authed_post(&w, &mallory, "/v1/caps", &MintCapsRequest { caps: vec![cap], intro: false }), 409);
    // unauthenticated mint/revoke do not exist
    assert_eq!(w.raw("POST", "/v1/caps", None, serde_json::to_vec(&MintCapsRequest { caps: vec![rid()], intro: false }).unwrap()).0, 401);
}

#[test]
fn replaying_a_capability_is_idempotent_and_bounded_by_its_quota() {
    let w = World::new();
    let bob = new_client();
    w.register(&bob);
    let cap = mint(&w, &bob, 1)[0];
    let m = rid();
    assert_eq!(anon(&w, vec![(cap, m, 100)]).1, ["queued"]);
    assert_eq!(anon(&w, vec![(cap, m, 100)]).1, ["duplicate"], "same message id replayed");
    // many distinct messages with one leaked capability: bounded by the per-capability quota
    let mut ok = 1;
    for _ in 0..CAP_QUOTA_ENVELOPES + 20 {
        if anon(&w, vec![(cap, rid(), 100)]).1 == ["queued"] {
            ok += 1;
        }
        w.clock.0.advance(1); // keep the per-capability token bucket out of the way; the QUEUE quota is what is under test
    }
    assert_eq!(ok, CAP_QUOTA_ENVELOPES);
    // other capabilities of the same recipient are unaffected
    let other = mint(&w, &bob, 1)[0];
    assert_eq!(anon(&w, vec![(other, rid(), 100)]).1, ["queued"]);
}

#[test]
fn guessing_capabilities_is_rate_limited_per_source_and_never_succeeds() {
    let w = World::new();
    let bob = new_client();
    w.register(&bob);
    let (mut limited, mut hits) = (0, 0);
    for _ in 0..700 {
        let (status, r) = anon(&w, vec![(rid(), rid(), 64)]);
        if status == 429 {
            limited += 1;
        } else if r == ["queued"] {
            hits += 1;
        }
    }
    assert_eq!(hits, 0);
    assert!(limited > 0, "the per-source bucket must engage");
}

#[test]
fn strangers_flooding_from_many_accounts_cannot_starve_capability_holders() {
    let w = World::new();
    let victim = new_client();
    w.register(&victim);
    let friend_cap = mint(&w, &victim, 1)[0];
    let attackers: Vec<_> = (0..8).map(|_| new_client()).collect();
    for a in &attackers {
        w.register(a);
    }
    let (mut ok, mut full) = (0, 0);
    for a in &attackers {
        for _ in 0..40 {
            match w.api(a).send_message(victim.device_id(), rid(), vec![1; 64], None) {
                Ok(_) => ok += 1,
                Err(_) => full += 1,
            }
        }
    }
    assert_eq!(ok, OPEN_LANE_ENVELOPES, "strangers share one small OPEN lane, however many accounts they have");
    assert_eq!(full, 8 * 40 - OPEN_LANE_ENVELOPES);
    // the victim's contact still gets through, repeatedly
    for _ in 0..50 {
        assert_eq!(anon(&w, vec![(friend_cap, rid(), 200)]).1, ["queued"]);
        w.clock.0.advance(1);
    }
    assert_eq!(queued(&w, &victim.device_id()), (OPEN_LANE_ENVELOPES + 50) as i64);
    // and draining the open lane restores it
    let f = w.api(&victim).fetch_messages().unwrap();
    w.api(&victim).ack(f.envelopes.iter().map(|e| e.message_id).collect()).unwrap();
}

#[test]
fn live_capabilities_per_device_are_bounded() {
    let w = World::new();
    let bob = new_client();
    w.register(&bob);
    for _ in 0..MAX_CAPS_PER_DEVICE / MAX_CAPS_PER_MINT {
        mint(&w, &bob, MAX_CAPS_PER_MINT);
        w.clock.0.advance(3600); // the mint rate limit is separate; this test is about the cap on live capabilities
    }
    assert_eq!(authed_post(&w, &bob, "/v1/caps", &MintCapsRequest { caps: vec![rid()], intro: false }), 429, "bounded");
}

#[test]
fn strangers_flooding_the_commit_lane_with_fake_groups_cannot_starve_capability_holders() {
    let w = World::new();
    let victim = new_client();
    w.register(&victim);
    let friend_cap = mint(&w, &victim, 1)[0];
    let attackers: Vec<_> = (0..8).map(|_| new_client()).collect();
    for a in &attackers {
        w.register(a);
    }
    let st = w.state.store.clone();
    let now = w.clock.0.unix_secs();
    let keys = cipher_relay::ratelimit::KeyHasher::new([7; 32]);
    let (mut ok, mut full) = (0, 0);
    for a in &attackers {
        let sender = cipher_relay::store::Sender { device: a.device_id(), keys: &keys };
        for _ in 0..60 {
            // a fresh, never-seen routing tag each time: creates a group row and "commits" to the victim
            let d = Delivery { recipient_device: victim.device_id(), message_id: rid(), ciphertext: vec![9; 200] };
            match w.rt.block_on(st.group_commit(&rid(), 0, None, &[d], now, Some(&sender))) {
                Ok(_) => ok += 1,
                Err(_) => full += 1,
            }
        }
    }
    assert!(ok <= COMMIT_LANE_ENVELOPES && ok > 0 && full > 0, "commit lane is bounded for everyone together: ok={ok} full={full}");
    for _ in 0..50 {
        assert_eq!(anon(&w, vec![(friend_cap, rid(), 200)]).1, ["queued"], "a contact still gets through");
        w.clock.0.advance(1);
    }
}
