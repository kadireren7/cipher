#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Private invitations (docs/INVITATIONS.md §5) on the real relay router + PostgreSQL: authorisation of every endpoint, atomic use slots, expiry,
//! revocation, indistinguishable failures, bounded inputs, and no identifier or request bytes in the logs.
mod harness;
use cipher_core::clock::Clock as _;
use cipher_wire::invite::*;
use cipher_wire::Id16;
use harness::*;

const DAY_MS: u64 = 24 * 3_600_000;

fn signed(w: &World, who: &cipher_core::mls::MlsClient, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let h = sign(who, AUDIENCE, method, path, w.clock.0.unix_secs(), cipher_core::rng::array::<16>().unwrap(), body);
    w.raw(method, path, Some(h), body.to_vec())
}

fn create(w: &World, who: &cipher_core::mls::MlsClient, id: Id16, preview: Vec<u8>, lifetime_ms: u64, max_uses: u32) -> u16 {
    let body = serde_json::to_vec(&CreateInviteRequest { id, preview, lifetime_ms, max_uses }).unwrap();
    signed(w, who, "POST", "/v1/invites", &body).0
}

fn lookup(w: &World, id: Id16) -> (u16, Vec<u8>) {
    w.raw("POST", "/v1/invites/lookup", None, serde_json::to_vec(&InviteIdRequest { id }).unwrap())
}

fn submit(w: &World, id: Id16, body: Vec<u8>) -> (u16, Vec<u8>) {
    w.raw("POST", "/v1/invites/request", None, serde_json::to_vec(&InviteSubmitRequest { id, body }).unwrap())
}

fn pending(w: &World, who: &cipher_core::mls::MlsClient) -> Vec<InvitePending> {
    let (st, body) = signed(w, who, "GET", "/v1/invites/pending", b"");
    assert_eq!(st, 200);
    serde_json::from_slice::<InvitePollResponse>(&body).unwrap().requests
}

fn resolve(w: &World, who: &cipher_core::mls::MlsClient, request_id: Id16, approved: bool) -> u16 {
    signed(w, who, "POST", "/v1/invites/resolve", &serde_json::to_vec(&InviteResolveRequest { request_id, approved }).unwrap()).0
}

fn revoke(w: &World, who: &cipher_core::mls::MlsClient, id: Id16) -> u16 {
    signed(w, who, "POST", "/v1/invites/revoke", &serde_json::to_vec(&InviteIdRequest { id }).unwrap()).0
}

fn issuer(w: &World) -> cipher_core::mls::MlsClient {
    let c = new_client();
    w.register(&c);
    c
}

fn preview() -> Vec<u8> {
    vec![0x5A; 64]
}

#[test]
fn a_live_invitation_returns_its_opaque_preview_to_anyone_with_the_identifier() {
    let w = World::new();
    let admin = issuer(&w);
    let id = rid();
    assert_eq!(create(&w, &admin, id, preview(), DAY_MS, 1), 204);
    let (st, body) = lookup(&w, id);
    assert_eq!(st, 200);
    assert_eq!(
        serde_json::from_slice::<InviteLookupResponse>(&body).unwrap().preview,
        preview(),
        "returned verbatim: the relay never interprets it"
    );
}

#[test]
fn unknown_expired_revoked_and_used_up_invitations_are_one_indistinguishable_not_found() {
    let w = World::new();
    let admin = issuer(&w);
    let unknown = lookup(&w, rid());
    assert_eq!(unknown.0, 404);

    let expiring = rid();
    assert_eq!(create(&w, &admin, expiring, preview(), 2 * 3_600_000, 1), 204);
    let revoked = rid();
    assert_eq!(create(&w, &admin, revoked, preview(), DAY_MS, 1), 204);
    assert_eq!(revoke(&w, &admin, revoked), 204);
    let used = rid();
    assert_eq!(create(&w, &admin, used, preview(), DAY_MS, 1), 204);
    assert_eq!(submit(&w, used, vec![1; 100]).0, 200);

    w.clock.0.advance(3 * 3600);
    for id in [expiring, revoked, used] {
        assert_eq!(lookup(&w, id), unknown, "same status and same body as an identifier that never existed");
        assert_eq!(submit(&w, id, vec![1; 100]), submit(&w, rid(), vec![1; 100]), "a request fails the same way");
    }
}

#[test]
fn a_use_slot_is_taken_once_and_a_rejection_returns_it() {
    let w = World::new();
    let admin = issuer(&w);
    let id = rid();
    assert_eq!(create(&w, &admin, id, preview(), DAY_MS, 1), 204);
    assert_eq!(submit(&w, id, vec![1; 100]).0, 200);
    assert_eq!(submit(&w, id, vec![2; 100]).0, 404, "the single use is taken");

    let p = pending(&w, &admin);
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].body, vec![1; 100]);
    assert_eq!(
        p[0].id_hash,
        cipher_wire::b64::encode(&id_hash(&id.0)),
        "the issuer finds its invitation by the hash, never by the identifier"
    );

    assert_eq!(resolve(&w, &admin, p[0].request_id, false), 204, "reject");
    assert!(pending(&w, &admin).is_empty());
    assert_eq!(resolve(&w, &admin, p[0].request_id, false), 404, "a request can be resolved only once");
    assert_eq!(submit(&w, id, vec![3; 100]).0, 200, "the rejected slot is available again");

    let p = pending(&w, &admin);
    assert_eq!(resolve(&w, &admin, p[0].request_id, true), 204, "approve consumes the slot for good");
    assert_eq!(submit(&w, id, vec![4; 100]).0, 404);
    assert_eq!(lookup(&w, id).0, 404, "a used-up invitation is no longer previewed");
}

#[test]
fn only_the_issuing_device_can_poll_resolve_or_revoke_and_nothing_unauthenticated_can() {
    let w = World::new();
    let admin = issuer(&w);
    let eve = issuer(&w);
    let id = rid();
    assert_eq!(create(&w, &admin, id, preview(), DAY_MS, 3), 204);
    assert_eq!(submit(&w, id, vec![1; 100]).0, 200);
    let p = pending(&w, &admin);
    assert_eq!(p.len(), 1);

    assert!(pending(&w, &eve).is_empty(), "another account never sees the request");
    assert_eq!(resolve(&w, &eve, p[0].request_id, true), 404, "and cannot resolve it (same answer as an unknown request)");
    assert_eq!(resolve(&w, &eve, rid(), true), 404);
    assert_eq!(revoke(&w, &eve, id), 404, "and cannot revoke the invitation");
    assert_eq!(lookup(&w, id).0, 200, "still alive");
    assert_eq!(pending(&w, &admin).len(), 1, "still pending");

    // no credentials at all
    let none = |method: &str, path: &str, body: Vec<u8>| w.raw(method, path, None, body).0;
    assert_eq!(none("GET", "/v1/invites/pending", vec![]), 401);
    assert_eq!(
        none(
            "POST",
            "/v1/invites",
            serde_json::to_vec(&CreateInviteRequest { id: rid(), preview: preview(), lifetime_ms: DAY_MS, max_uses: 1 }).unwrap()
        ),
        401
    );
    assert_eq!(
        none(
            "POST",
            "/v1/invites/resolve",
            serde_json::to_vec(&InviteResolveRequest { request_id: p[0].request_id, approved: true }).unwrap()
        ),
        401
    );
    assert_eq!(none("POST", "/v1/invites/revoke", serde_json::to_vec(&InviteIdRequest { id }).unwrap()), 401);
}

#[test]
fn concurrent_requests_can_never_take_more_slots_than_the_invitation_has() {
    let w = World::new();
    let admin = issuer(&w);
    let id = rid();
    assert_eq!(create(&w, &admin, id, preview(), DAY_MS, 3), 204);
    let ok = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|s| {
        for i in 0..12u8 {
            let (w, ok) = (&w, &ok);
            s.spawn(move || {
                if submit(w, id, vec![i + 1; 100]).0 == 200 {
                    ok.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            });
        }
    });
    assert_eq!(ok.load(std::sync::atomic::Ordering::SeqCst), 3, "exactly max_uses requests win");
    assert_eq!(pending(&w, &admin).len(), 3);
}

#[test]
fn expiry_and_revocation_end_an_invitation_and_hide_its_pending_requests() {
    let w = World::new();
    let admin = issuer(&w);
    let (a, b) = (rid(), rid());
    assert_eq!(create(&w, &admin, a, preview(), 2 * 3_600_000, 5), 204);
    assert_eq!(create(&w, &admin, b, preview(), DAY_MS, 5), 204);
    assert_eq!(submit(&w, a, vec![1; 100]).0, 200);
    assert_eq!(submit(&w, b, vec![2; 100]).0, 200);
    assert_eq!(pending(&w, &admin).len(), 2);

    assert_eq!(revoke(&w, &admin, b), 204);
    assert_eq!(submit(&w, b, vec![3; 100]).0, 404, "no new request after revocation");
    let p = pending(&w, &admin);
    assert_eq!(p.len(), 1, "revocation drops the still-pending request");
    assert_eq!(p[0].id_hash, cipher_wire::b64::encode(&id_hash(&a.0)));

    w.clock.0.advance(3 * 3600);
    assert!(pending(&w, &admin).is_empty(), "an expired invitation's requests are no longer offered");
    assert_eq!(lookup(&w, a).0, 404);
}

#[test]
fn creation_is_bounded_and_validated() {
    let w = World::new();
    let admin = issuer(&w);
    let c = |lifetime_ms, max_uses, preview: Vec<u8>| create(&w, &admin, rid(), preview, lifetime_ms, max_uses);
    assert_eq!(c(DAY_MS, 1, preview()), 204);
    assert_eq!(c(MIN_LIFETIME_MS - 1, 1, preview()), 400);
    assert_eq!(c(MAX_LIFETIME_MS + 1, 1, preview()), 400);
    assert_eq!(c(DAY_MS, 0, preview()), 400);
    assert_eq!(c(DAY_MS, MAX_USES + 1, preview()), 400);
    assert_eq!(c(DAY_MS, 1, vec![]), 400);
    assert_eq!(c(DAY_MS, 1, vec![0; MAX_PREVIEW_BLOB + 1]), 400);
    // an identifier cannot be created twice
    let dup = rid();
    assert_eq!(create(&w, &admin, dup, preview(), DAY_MS, 1), 204);
    assert_eq!(create(&w, &admin, dup, preview(), DAY_MS, 1), 409);
    // unknown fields are refused, and a request body is bounded
    let (st, _) = signed(
        &w,
        &admin,
        "POST",
        "/v1/invites",
        br#"{"id":"00000000000000000000000000000001","preview":"AAAA","lifetime_ms":86400000,"max_uses":1,"extra":1}"#,
    );
    assert_eq!(st, 400);
    let id = rid();
    assert_eq!(create(&w, &admin, id, preview(), DAY_MS, 5), 204);
    assert_eq!(submit(&w, id, vec![]).0, 400);
    assert_eq!(submit(&w, id, vec![0; MAX_REQUEST_BLOB + 1]).0, 400);
    assert_eq!(submit(&w, id, vec![0; MAX_REQUEST_BLOB]).0, 200);
}

#[test]
fn one_device_can_keep_only_a_bounded_number_of_live_invitations() {
    let w = World::new();
    let admin = issuer(&w);
    for _ in 0..MAX_LIVE_INVITES_PER_DEVICE {
        assert_eq!(create(&w, &admin, rid(), preview(), DAY_MS, 1), 204);
    }
    assert_eq!(create(&w, &admin, rid(), preview(), DAY_MS, 1), 429);
    w.clock.0.advance(2 * 24 * 3600);
    assert_eq!(create(&w, &admin, rid(), preview(), DAY_MS, 1), 204, "expired invitations free their place");
}

#[test]
fn unauthenticated_calls_are_rate_limited_per_invitation_and_the_limit_is_no_oracle() {
    let w = World::new();
    let admin = issuer(&w);
    let live = rid();
    assert_eq!(create(&w, &admin, live, preview(), DAY_MS, 1), 204);
    let never = rid();
    let first_limit = |id: Id16| (0..60).position(|_| lookup(&w, id).0 == 429);
    let a = first_limit(live);
    // The source-address bucket is shared by both measurements: let it refill, so only the per-invitation bucket is being compared.
    w.clock.0.advance(3600);
    let b = first_limit(never);
    assert!(a.is_some() && b.is_some(), "a flood is throttled");
    assert_eq!(a, b, "a live and a non-existent invitation are throttled at exactly the same point");
}

#[test]
fn the_logs_never_contain_the_identifier_the_preview_or_a_request() {
    let w = World::new();
    let admin = issuer(&w);
    let id = rid();
    let marker_preview = vec![0xC3; 80];
    let marker_request = vec![0xE7; 90];
    assert_eq!(create(&w, &admin, id, marker_preview.clone(), DAY_MS, 2), 204);
    assert_eq!(lookup(&w, id).0, 200);
    assert_eq!(submit(&w, id, marker_request.clone()).0, 200);
    assert_eq!(lookup(&w, rid()).0, 404);
    let p = pending(&w, &admin);
    assert_eq!(resolve(&w, &admin, p[0].request_id, true), 204);
    assert_eq!(revoke(&w, &admin, id), 204);

    let logs = w.logs.0.lock().unwrap().clone();
    for (what, needle) in [
        ("identifier (hex)", id.to_hex().into_bytes()),
        ("identifier (base64url)", cipher_wire::b64::encode(&id.0).into_bytes()),
        ("identifier hash", cipher_wire::b64::encode(&id_hash(&id.0)).into_bytes()),
        ("preview (base64url)", cipher_wire::b64::encode(&marker_preview).into_bytes()),
        ("request (base64url)", cipher_wire::b64::encode(&marker_request).into_bytes()),
        ("request id", p[0].request_id.to_hex().into_bytes()),
    ] {
        assert!(!contains(&logs, &needle), "the {what} must not appear in the relay's logs");
    }
}
