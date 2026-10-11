//! Availability: a peer that stalls mid-upload (dead mobile link, abandoned Tor circuit, or an attacker) must not hold one of the few
//! upload slots until the overall request deadline. Regression for the slot-exhaustion defect found in the Tor reliability pass.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod harness;
use axum::body::Body;
use axum::http::Request;
use bytes::Bytes;
use cipher_core::clock::Clock as _;
use harness::*;
use std::time::{Duration, Instant};
use tower::ServiceExt as _;

fn valid_blob() -> Vec<u8> {
    [b"CATT".as_slice(), &[0u8; 60]].concat()
}

/// A body that sends `first` bytes and then never sends anything again (the connection stays open).
fn stalling_body(first: Vec<u8>) -> Body {
    let s = futures_util::stream::once(async move { Ok::<_, std::io::Error>(Bytes::from(first)) }).chain(futures_util::stream::pending());
    Body::from_stream(s)
}
use futures_util::StreamExt as _;

#[test]
fn stalled_authenticated_upload_is_cut_off_and_frees_its_slot() {
    let w = World::new();
    let alice = new_client();
    w.register(&alice);
    let app = w.instance_with_body_idle(1);
    let blob = valid_blob();
    let auth = |b: &[u8]| {
        sign_announced(&alice, AUDIENCE, "POST", "/v1/blobs", w.clock.0.unix_secs(), cipher_core::rng::array::<16>().unwrap(), b)
    };
    // Announce the full length, deliver only part of it, then stall.
    let req = Request::builder()
        .method("POST")
        .uri("/v1/blobs")
        .header("content-length", blob.len().to_string())
        .header("authorization", auth(&blob))
        .body(stalling_body(blob[..10].to_vec()))
        .unwrap();
    let t = Instant::now();
    let status = w.rt.block_on(app.clone().oneshot(req)).unwrap().status().as_u16();
    assert_eq!(status, 408, "a stalled body is answered with a timeout");
    assert!(t.elapsed() < Duration::from_secs(10), "cut off by the idle deadline, not by the overall request deadline");
    // The slot is free again: eight more stalls in a row would have exhausted it if each had been held.
    let ok = Request::builder()
        .method("POST")
        .uri("/v1/blobs")
        .header("content-length", blob.len().to_string())
        .header("authorization", auth(&blob))
        .body(Body::from(blob.clone()))
        .unwrap();
    assert_eq!(w.rt.block_on(app.clone().oneshot(ok)).unwrap().status().as_u16(), 201);
}

#[test]
fn many_stalled_uploads_do_not_starve_a_good_one() {
    let w = World::new();
    let alice = new_client();
    w.register(&alice);
    let app = w.instance_with_body_idle(1);
    let blob = valid_blob();
    let mk = |body: Body| {
        let h =
            sign_announced(&alice, AUDIENCE, "POST", "/v1/blobs", w.clock.0.unix_secs(), cipher_core::rng::array::<16>().unwrap(), &blob);
        Request::builder()
            .method("POST")
            .uri("/v1/blobs")
            .header("content-length", blob.len().to_string())
            .header("authorization", h)
            .body(body)
            .unwrap()
    };
    // 12 stalled uploads at once (more than the 8 slots), then a good one right behind them.
    let stalled: Vec<_> = (0..12).map(|_| mk(stalling_body(blob[..4].to_vec()))).collect();
    let good = mk(Body::from(blob.clone()));
    let (statuses, good_status) = w.rt.block_on(async {
        let handles: Vec<_> = stalled.into_iter().map(|r| tokio::spawn(app.clone().oneshot(r))).collect();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let g = app.clone().oneshot(good).await.unwrap().status().as_u16();
        let mut v = Vec::new();
        for h in handles {
            v.push(h.await.unwrap().unwrap().status().as_u16());
        }
        (v, g)
    });
    assert!(
        statuses.iter().all(|s| *s == 408 || *s == 503),
        "stalled uploads end in 408 (or 503 when they could not even queue): {statuses:?}"
    );
    assert_eq!(good_status, 201, "the good upload waited for a slot instead of failing at once");
}
