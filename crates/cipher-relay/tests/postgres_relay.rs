#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! PostgreSQL-specific relay behaviour: migrations, transactional bounds, the group epoch sequencer under real
//! concurrency, and state shared across relay instances (rate limits, replay protection).
mod harness;
use cipher_core::clock::Clock as _;
use cipher_relay::store::{Enqueue, GroupOutcome};
use cipher_wire::limits::*;
use cipher_wire::messages::*;
use cipher_wire::Id16;
use futures_util::future::join_all;
use harness::*;

fn delivery(to: Id16, n: u8) -> Delivery {
    Delivery { recipient_device: to, message_id: rid(), ciphertext: vec![n; 40] }
}

fn queue_len(w: &World, dev: &Id16) -> i64 {
    w.rt.block_on(async {
        let c = w.pool.get().await.unwrap();
        c.query_one("SELECT count(*) FROM queue WHERE recipient=$1", &[&dev.0.as_slice()]).await.unwrap().get(0)
    })
}

// ------------------------------------------------------------------------------------------- migrations

#[test]
fn migrations_are_idempotent_checksummed_and_refuse_a_newer_schema() {
    let w = World::new();
    let pool = w.pool.clone();
    w.rt.block_on(cipher_relay::migrations::run(&pool)).expect("re-running is a no-op");
    // Someone edits an already-applied migration's recorded checksum (or the file changed): fail closed.
    w.exec("UPDATE schema_migrations SET checksum = '\\x00' WHERE version = 1", &[]);
    assert!(w.rt.block_on(cipher_relay::migrations::run(&pool)).is_err(), "checksum drift must stop startup");
    let good = cipher_relay::migrations::MIGRATIONS[0].2;
    use sha2::{Digest, Sha256};
    let sum = Sha256::digest(good.as_bytes()).to_vec();
    w.exec("UPDATE schema_migrations SET checksum = $1 WHERE version = 1", &[&sum]);
    w.rt.block_on(cipher_relay::migrations::run(&pool)).unwrap();
    // Database is AHEAD of this binary (downgrade): refuse.
    w.exec("INSERT INTO schema_migrations (version, name, checksum) VALUES (999, 'future', '\\x00')", &[]);
    assert!(w.rt.block_on(cipher_relay::migrations::run(&pool)).is_err(), "schema newer than binary must stop startup");
}

#[test]
fn concurrent_migration_runs_do_not_race() {
    // Fresh empty database, 6 instances migrating at once under the advisory lock.
    let w = World::new();
    w.exec("DROP SCHEMA public CASCADE", &[]);
    w.exec("CREATE SCHEMA public", &[]);
    let pool = w.pool.clone();
    let results = w.rt.block_on(join_all((0..6).map(|_| {
        let p = pool.clone();
        async move { cipher_relay::migrations::run(&p).await }
    })));
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    let n: i64 =
        w.rt.block_on(async { pool.get().await.unwrap().query_one("SELECT count(*) FROM schema_migrations", &[]).await.unwrap().get(0) });
    assert_eq!(n as usize, cipher_relay::migrations::MIGRATIONS.len());
}

#[test]
fn database_connection_security_is_mandatory_off_loopback() {
    use cipher_relay::db::build_pool;
    assert!(build_pool("postgres://u:p@db.example.com/x", 1, None).is_err(), "no sslmode on a remote host");
    assert!(build_pool("postgres://u:p@db.example.com/x?sslmode=disable", 1, None).is_err());
    assert!(build_pool("postgres://u:p@db.example.com/x?sslmode=prefer", 1, None).is_err(), "prefer can silently downgrade");
    assert!(build_pool("postgres://u:p@db.example.com/x?sslmode=require", 1, None).is_ok());
    assert!(build_pool("postgres://u:p@127.0.0.1/x", 1, None).is_ok(), "loopback is allowed for dev/CI");
    assert!(build_pool("not a url", 1, None).is_err());
}

// --------------------------------------------------------------------------------- group epoch sequencer

#[test]
fn group_commit_is_compare_and_swap_with_deterministic_ordering() {
    let w = World::new();
    let (alice, bob) = (new_client(), new_client());
    w.register(&alice);
    w.register(&bob);
    let st = w.state.store.clone();
    let tag = rid();
    let now = w.clock.unix_secs();
    let d = |n| vec![delivery(bob.device_id(), n)];
    let r = |e, dl: Vec<Delivery>| w.rt.block_on(st.group_commit(&tag, e, None, &dl, now, None)).unwrap();
    assert_eq!(r(0, d(1)), GroupOutcome::Accepted(1));
    assert_eq!(r(0, d(2)), GroupOutcome::Stale(1), "second committer on the same epoch loses");
    assert_eq!(r(5, d(3)), GroupOutcome::Stale(1), "future epoch is also refused");
    assert_eq!(r(1, d(4)), GroupOutcome::Accepted(2), "the loser rebases onto the winner and succeeds");
    assert_eq!(queue_len(&w, &bob.device_id()), 2, "only accepted commits are delivered");
    // unknown tag with a non-zero epoch cannot create state
    assert_eq!(w.rt.block_on(st.group_commit(&rid(), 3, None, &d(9), now, None)).unwrap(), GroupOutcome::Stale(0));
}

#[test]
fn concurrent_commits_have_exactly_one_winner_and_no_partial_delivery() {
    let w = World::new();
    let (alice, bob) = (new_client(), new_client());
    w.register(&alice);
    w.register(&bob);
    let st = w.state.store.clone();
    let tag = rid();
    let now = w.clock.unix_secs();
    let outcomes = w.rt.block_on(join_all((0..12u8).map(|i| {
        let (st, bob) = (st.clone(), bob.device_id());
        async move { st.group_commit(&tag, 0, None, &[delivery(bob, i)], now, None).await.unwrap() }
    })));
    let wins = outcomes.iter().filter(|o| matches!(o, GroupOutcome::Accepted(_))).count();
    assert_eq!(wins, 1, "{outcomes:?}");
    assert!(outcomes.iter().all(|o| matches!(o, GroupOutcome::Accepted(1) | GroupOutcome::Stale(1))));
    assert_eq!(queue_len(&w, &bob.device_id()), 1, "losers' ciphertext was never enqueued");
}

#[test]
fn removal_rotates_the_routing_tag_so_removed_members_cannot_brick_the_group() {
    let w = World::new();
    let (alice, bob) = (new_client(), new_client());
    w.register(&alice);
    w.register(&bob);
    let st = w.state.store.clone();
    let (old, new) = (rid(), rid());
    let now = w.clock.unix_secs();
    let run = |t: &Id16, e: u64, nt: Option<&Id16>| w.rt.block_on(st.group_commit(t, e, nt, &[delivery(bob.device_id(), 1)], now, None));
    assert_eq!(run(&old, 0, None).unwrap(), GroupOutcome::Accepted(1));
    assert_eq!(run(&old, 1, Some(&new)).unwrap(), GroupOutcome::Accepted(2), "removal commit rotates the tag");
    // The removed member only knows the old tag: it is retired and cannot be advanced or revived.
    assert_eq!(run(&old, 2, None).unwrap(), GroupOutcome::Gone);
    assert_eq!(run(&old, 1, None).unwrap(), GroupOutcome::Gone);
    assert_eq!(w.rt.block_on(st.group_epoch(&new)).unwrap(), Some((2, false)));
    assert_eq!(run(&new, 2, None).unwrap(), GroupOutcome::Accepted(3));
    // A tag that already exists cannot be claimed as a rotation target.
    let other = rid();
    assert_eq!(run(&other, 0, None).unwrap(), GroupOutcome::Accepted(1));
    assert!(matches!(run(&new, 3, Some(&other)), Err(cipher_relay::error::ApiError::Conflict)));
}

#[test]
fn group_commit_is_atomic_when_any_delivery_cannot_be_queued() {
    let w = World::new();
    let (alice, bob) = (new_client(), new_client());
    w.register(&alice);
    w.register(&bob);
    let st = w.state.store.clone();
    let tag = rid();
    let now = w.clock.unix_secs();
    let ghost = rid(); // unregistered device
    let r = w.rt.block_on(st.group_commit(&tag, 0, None, &[delivery(bob.device_id(), 1), delivery(ghost, 2)], now, None));
    assert!(matches!(r, Err(cipher_relay::error::ApiError::NotFound)));
    assert_eq!(queue_len(&w, &bob.device_id()), 0, "no partial fan-out");
    assert_eq!(w.rt.block_on(st.group_epoch(&tag)).unwrap(), None, "epoch (and group row) unchanged");
}

#[test]
fn group_endpoints_over_http_are_authenticated_validated_and_report_stale_epochs() {
    let w = World::new();
    let (alice, bob) = (new_client(), new_client());
    w.register(&alice);
    w.register(&bob);
    let tag = rid();
    let n = || cipher_core::rng::array::<16>().unwrap();
    let call = |m: &str, path: &str, c: &cipher_core::mls::MlsClient, body: Vec<u8>| {
        let h = sign(c, AUDIENCE, m, path, w.clock.unix_secs(), n(), &body);
        w.raw(m, path, Some(h), body)
    };
    let commit = |e: u64, nt: Option<Id16>| {
        serde_json::to_vec(&GroupCommitRequest { expected_epoch: e, new_tag: nt, deliveries: vec![delivery(bob.device_id(), 7)] }).unwrap()
    };
    let path = format!("/v1/groups/{tag}/commit");
    assert_eq!(w.raw("POST", &path, None, commit(0, None)).0, 401, "unauthenticated");
    assert_eq!(call("POST", &path, &alice, commit(0, None)).0, 200);
    let (st, body) = call("POST", &path, &alice, commit(0, None));
    assert_eq!(st, 409);
    let stale: GroupStaleResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(stale.current_epoch, 1);
    let (st, body) = call("GET", &format!("/v1/groups/{tag}"), &bob, vec![]);
    assert_eq!(st, 200);
    assert_eq!(serde_json::from_slice::<GroupStateResponse>(&body).unwrap().epoch, 1);
    assert_eq!(call("GET", &format!("/v1/groups/{}", rid()), &bob, vec![]).0, 404);
    assert_eq!(call("POST", "/v1/groups/not-a-tag/commit", &alice, commit(0, None)).0, 400);
    // empty / oversize deliveries rejected
    let empty = serde_json::to_vec(&GroupCommitRequest { expected_epoch: 1, new_tag: None, deliveries: vec![] }).unwrap();
    assert_eq!(call("POST", &path, &alice, empty).0, 400);
    let many: Vec<Delivery> = (0..MAX_BATCH_DELIVERIES + 1).map(|i| delivery(bob.device_id(), i as u8)).collect();
    let big = serde_json::to_vec(&GroupCommitRequest { expected_epoch: 1, new_tag: None, deliveries: many }).unwrap();
    assert_eq!(call("POST", &path, &alice, big).0, 400);
    // rotation: old tag is then 410 Gone
    let nt = rid();
    assert_eq!(call("POST", &path, &alice, commit(1, Some(nt))).0, 200);
    assert_eq!(call("POST", &path, &alice, commit(2, None)).0, 410);
    assert_eq!(call("GET", &format!("/v1/groups/{tag}"), &bob, vec![]).0, 410);
}

#[test]
fn batch_send_reports_per_recipient_results_and_is_idempotent() {
    let w = World::new();
    let (alice, bob, carol) = (new_client(), new_client(), new_client());
    for c in [&alice, &bob, &carol] {
        w.register(c);
    }
    let n = || cipher_core::rng::array::<16>().unwrap();
    let ghost = rid();
    let reuse = rid();
    let mk = |ds: Vec<Delivery>| serde_json::to_vec(&BatchSendRequest { deliveries: ds, ttl_secs: None }).unwrap();
    let d1 = Delivery { recipient_device: bob.device_id(), message_id: reuse, ciphertext: vec![1; 30] };
    let body = mk(vec![d1, delivery(carol.device_id(), 2), delivery(ghost, 3)]);
    let h = sign(&alice, AUDIENCE, "POST", "/v1/messages/batch", w.clock.unix_secs(), n(), &body);
    let (st, resp) = w.raw("POST", "/v1/messages/batch", Some(h), body);
    assert_eq!(st, 200);
    let r: BatchSendResponse = serde_json::from_slice(&resp).unwrap();
    assert_eq!(r.results, ["queued", "queued", "not_found"]);
    let body = mk(vec![Delivery { recipient_device: bob.device_id(), message_id: reuse, ciphertext: vec![1; 30] }]);
    let h = sign(&alice, AUDIENCE, "POST", "/v1/messages/batch", w.clock.unix_secs(), n(), &body);
    let r: BatchSendResponse = serde_json::from_slice(&w.raw("POST", "/v1/messages/batch", Some(h), body).1).unwrap();
    assert_eq!(r.results, ["duplicate"]);
}

// ------------------------------------------------------------------------ shared state across instances

#[test]
fn rate_limits_are_shared_across_relay_instances() {
    let limits = cipher_relay::api::Limits { device_burst: 6, device_refill_per_sec: 0.0, ..generous_limits() };
    let w = World::with_limits(limits);
    let alice = new_client();
    w.register(&alice); // consumes no device tokens (unauthenticated)
    let app2 = w.instance(limits);
    let mut ok = 0;
    for i in 0..12 {
        let h = sign(&alice, AUDIENCE, "GET", "/v1/messages", w.clock.unix_secs(), cipher_core::rng::array::<16>().unwrap(), b"");
        let status = if i % 2 == 0 {
            w.raw("GET", "/v1/messages", Some(h), vec![]).0
        } else {
            w.raw_on(&app2, "GET", "/v1/messages", Some(h), vec![])
        };
        if status == 200 {
            ok += 1;
        }
    }
    assert_eq!(ok, 6, "one shared budget, not 6 per instance");
}

#[test]
fn replay_protection_is_shared_across_relay_instances() {
    let w = World::new();
    let alice = new_client();
    w.register(&alice);
    let app2 = w.instance(generous_limits());
    let ts = w.clock.unix_secs();
    let hdr = sign(&alice, AUDIENCE, "GET", "/v1/messages", ts, [5u8; 16], b"");
    assert_eq!(w.raw("GET", "/v1/messages", Some(hdr.clone()), vec![]).0, 200);
    assert_eq!(w.raw_on(&app2, "GET", "/v1/messages", Some(hdr), vec![]), 401, "replayed against a different instance");
}

#[test]
fn rate_limit_keys_do_not_expose_ips_or_device_ids() {
    let w = World::new();
    let alice = new_client();
    w.register(&alice);
    w.api(&alice).fetch_messages().unwrap();
    let keys = w.query_bytes("SELECT key FROM rate_buckets");
    assert!(!keys.is_empty());
    for k in &keys {
        assert_eq!(k.len(), 16);
        assert_ne!(k.as_slice(), alice.device_id().0.as_slice(), "device id must be peppered/hashed");
        assert_ne!(&k[..4], &[0u8, 0, 0, 0][..]);
    }
    let (text, _) = w.db_dump();
    assert!(!text.contains("0.0.0.0") && !text.contains("127.0.0.1"));
}

// -------------------------------------------------------------------------------- transactional bounds

#[test]
fn queue_counters_stay_exact_through_enqueue_ack_expiry_and_duplicates() {
    let w = World::new();
    let (alice, bob) = (new_client(), new_client());
    w.register(&alice);
    w.register(&bob);
    let st = w.state.store.clone();
    let now = w.clock.unix_secs();
    let ids: Vec<Id16> = (0..5).map(|_| rid()).collect();
    for (i, id) in ids.iter().enumerate() {
        let r = w.rt.block_on(st.enqueue(&bob.device_id(), id, &vec![1u8; 100 + i], MIN_TTL_SECS, now, None)).unwrap();
        assert_eq!(r, Enqueue::Queued);
    }
    assert_eq!(w.rt.block_on(st.enqueue(&bob.device_id(), &ids[0], &[9u8; 50], MIN_TTL_SECS, now, None)).unwrap(), Enqueue::Duplicate);
    let counters = || -> (i32, i64, i64, i64) {
        w.rt.block_on(async {
            let c = w.pool.get().await.unwrap();
            let r = c.query_one("SELECT queued_count, queued_bytes, (SELECT count(*) FROM queue), (SELECT COALESCE(sum(octet_length(ct)),0)::bigint FROM queue) FROM devices WHERE device_id=$1", &[&bob.device_id().0.as_slice()]).await.unwrap();
            (r.get(0), r.get(1), r.get(2), r.get(3))
        })
    };
    let (c, b, rc, rb) = counters();
    assert_eq!((c as i64, b), (rc, rb));
    assert_eq!(c, 5);
    w.rt.block_on(st.ack(&bob.device_id(), &ids[..2])).unwrap();
    let (c, b, rc, rb) = counters();
    assert_eq!((c as i64, b, c), (rc, rb, 3));
    // expiry through the background purge
    w.clock.0.advance(MIN_TTL_SECS + 700);
    w.rt.block_on(st.purge(w.clock.unix_secs())).unwrap();
    let (c, b, rc, rb) = counters();
    assert_eq!((c, b, rc, rb), (0, 0, 0, 0), "purge must keep the counters consistent");
}

#[test]
fn concurrent_senders_can_never_exceed_the_per_device_queue_bound() {
    let w = World::new();
    let (alice, bob) = (new_client(), new_client());
    w.register(&alice);
    w.register(&bob);
    let st = w.state.store.clone();
    let now = w.clock.unix_secs();
    // (1) the OPEN lane (authenticated, no capability) is bounded exactly under concurrency
    let results = w.rt.block_on(join_all((0..OPEN_LANE_ENVELOPES + 60).map(|_| {
        let (st, bob) = (st.clone(), bob.device_id());
        async move { st.enqueue(&bob, &rid(), &[1u8; 16], DEFAULT_TTL_SECS, now, None).await }
    })));
    let queued = results.iter().filter(|r| matches!(r, Ok(Enqueue::Queued))).count();
    assert_eq!(queued, OPEN_LANE_ENVELOPES, "the open lane bound is exact even under concurrency");
    assert!(results.iter().filter(|r| r.is_err()).all(|r| matches!(r, Err(cipher_relay::error::ApiError::QueueFull))));
    // (2) the DEVICE bound is exact under concurrency across capabilities (6 capabilities x 250 would be 1500 > 1000)
    let caps: Vec<Id16> = (0..6).map(|_| rid()).collect();
    w.rt.block_on(st.mint_caps(&bob.device_id(), &caps, false, now)).unwrap();
    let remaining = MAX_QUEUED_ENVELOPES_PER_DEVICE - OPEN_LANE_ENVELOPES;
    let results = w.rt.block_on(join_all((0..remaining + 150).map(|i| {
        let (st, cap) = (st.clone(), caps[i % caps.len()]);
        async move { st.enqueue_anon(&cap, &rid(), &[1u8; 16], DEFAULT_TTL_SECS, now).await }
    })));
    let queued2 = results.iter().filter(|r| matches!(r, Ok((_, Enqueue::Queued)))).count();
    assert_eq!(queued + queued2, MAX_QUEUED_ENVELOPES_PER_DEVICE, "the per-device bound is exact even under concurrency");
    assert!(results.iter().filter(|r| r.is_err()).all(|r| matches!(r, Err(cipher_relay::error::ApiError::QueueFull))));
    assert_eq!(queue_len(&w, &bob.device_id()), MAX_QUEUED_ENVELOPES_PER_DEVICE as i64);
}

// ------------------------------------------------------------------------ load shedding / connection cap

fn slow_body(rx: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, std::io::Error>>) -> axum::body::Body {
    axum::body::Body::from_stream(tokio_stream_from(rx))
}

fn tokio_stream_from(
    mut rx: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, std::io::Error>>,
) -> impl futures_util::Stream<Item = Result<bytes::Bytes, std::io::Error>> {
    futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
}

#[test]
fn overload_is_shed_with_503_instead_of_queueing_without_bound() {
    use axum::http::Request;
    use tower::ServiceExt;
    let w = World::build(generous_limits(), 1, 30);
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let hold = Request::builder().method("POST").uri("/v1/accounts").body(slow_body(rx)).unwrap();
    let quick = Request::builder().method("GET").uri("/v1/messages").body(axum::body::Body::empty()).unwrap();
    let app = w.app.clone();
    let (a, b) = w.rt.block_on(async {
        let first = tokio::spawn({
            let app = app.clone();
            async move { app.oneshot(hold).await.unwrap().status().as_u16() }
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await; // first request now holds the only permit
        let shed = app.clone().oneshot(quick).await.unwrap().status().as_u16();
        tx.send(Ok(bytes::Bytes::from_static(b"{}"))).await.unwrap();
        drop(tx);
        (first.await.unwrap(), shed)
    });
    assert_eq!(b, 503, "second request must be shed immediately");
    assert_eq!(a, 400, "the first request completes normally once its body ends (invalid JSON -> 400)");
}

#[test]
fn slow_requests_are_cut_off_by_the_request_deadline() {
    use axum::http::Request;
    use tower::ServiceExt;
    let w = World::build(generous_limits(), 64, 1);
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let slow = Request::builder().method("POST").uri("/v1/accounts").body(slow_body(rx)).unwrap();
    let started = std::time::Instant::now();
    let status = w.rt.block_on(async { w.app.clone().oneshot(slow).await.unwrap().status().as_u16() });
    assert_eq!(status, 408);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn connection_cap_drops_excess_connections_before_any_work() {
    use axum_server::accept::Accept;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acc = cipher_relay::conn_limit::LimitAcceptor::new(2);
        let mut held = Vec::new();
        for _ in 0..2 {
            let _c = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (s, _) = listener.accept().await.unwrap();
            held.push(acc.accept(s, ()).await.expect("under the cap"));
        }
        let _c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (s, _) = listener.accept().await.unwrap();
        assert!(acc.accept(s, ()).await.is_err(), "third connection exceeds the cap");
        drop(held.pop()); // closing one frees a permit
        let _c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (s, _) = listener.accept().await.unwrap();
        assert!(acc.accept(s, ()).await.is_ok());
    });
}
