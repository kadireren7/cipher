#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The home-relay commit log of cross-relay groups (docs/CROSS_RELAY_GROUPS.md §7) on the real router + PostgreSQL: ordering, authentication by
//! epoch credentials, read limits for stale and removed members, idempotency, bounds. The relay only ever sees ciphertext and public keys.
mod harness;
use cipher_wire::home::*;
use cipher_wire::Id16;
use ed25519_dalek::{Signer as _, SigningKey};
use harness::*;

/// Stand-ins for the exporter-derived credentials of one epoch.
struct Epoch {
    n: u64,
    commit: SigningKey,
    read: SigningKey,
}

fn epoch(group: u8, n: u64) -> Epoch {
    let k = |label: u8| {
        let mut s = [0u8; 32];
        s[0] = group;
        s[1] = label;
        s[2..10].copy_from_slice(&n.to_be_bytes());
        SigningKey::from_bytes(&s)
    };
    Epoch { n, commit: k(1), read: k(2) }
}

impl Epoch {
    fn commit_pub(&self) -> Vec<u8> {
        self.commit.verifying_key().to_bytes().to_vec()
    }
    fn read_pub(&self) -> Vec<u8> {
        self.read.verifying_key().to_bytes().to_vec()
    }
}

fn signed(w: &World, key: &SigningKey, epoch: u64, method: &str, path: &str, body: Vec<u8>) -> (u16, Vec<u8>) {
    let sig = key.sign(&request_message(epoch, method, path, &body)).to_bytes();
    w.raw(method, path, Some(auth_value(epoch, &sig)), body)
}

fn req(expected: u64, id: u8, next: &Epoch) -> HomeCommitRequest {
    HomeCommitRequest {
        expected_seq: expected,
        commit_id: Id16([id; 16]),
        commit: format!("commit-{expected}-{id}").into_bytes(),
        next_commit_pub: next.commit_pub(),
        next_read_pub: next.read_pub(),
    }
}

/// Submit as a holder of `signer`'s epoch (creation is signed by the NEW key).
fn commit(w: &World, tag: &Id16, signer: &Epoch, r: &HomeCommitRequest) -> (u16, Vec<u8>) {
    let (key, ep) = if r.expected_seq == 0 { (None, 1) } else { (Some(&signer.commit), r.expected_seq) };
    let body = serde_json::to_vec(r).unwrap();
    let path = format!("/v1/home/{}/commit", tag.to_hex());
    match key {
        Some(k) => signed(w, k, ep, "POST", &path, body),
        None => {
            // creation: signed with the announced (new) commit key, which `signer` is expected to be
            signed(w, &signer.commit, 1, "POST", &path, body)
        }
    }
}

fn read_log(w: &World, tag: &Id16, who: &Epoch, after: u64) -> (u16, Option<HomeLogResponse>) {
    let path = format!("/v1/home/{}/log?after={after}", tag.to_hex());
    let (st, body) = signed(w, &who.read, who.n, "GET", &path, vec![]);
    (st, if st == 200 { Some(serde_json::from_slice(&body).unwrap()) } else { None })
}

fn chain_of(tag: &Id16, entries: &[(u64, &HomeCommitRequest, &Epoch)]) -> Vec<[u8; 32]> {
    let mut prev = chain_genesis(tag);
    let mut out = vec![];
    for (seq, r, next) in entries {
        prev =
            chain_next(&prev, *seq, &r.commit_id, &r.commit, &next.commit_pub().try_into().unwrap(), &next.read_pub().try_into().unwrap());
        out.push(prev);
    }
    out
}

fn tag_of(n: u8) -> Id16 {
    home_tag(&[n; 16])
}

#[test]
fn creation_then_ordered_appends_form_a_hash_chain_every_member_can_recompute() {
    let w = World::new();
    let tag = tag_of(1);
    let (e1, e2, e3) = (epoch(1, 1), epoch(1, 2), epoch(1, 3));
    let (r1, r2) = (req(0, 1, &e1), req(1, 2, &e2));
    let (st, body) = commit(&w, &tag, &e1, &r1);
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let resp1: HomeCommitResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp1.seq, 1);
    let (st, body) = commit(&w, &tag, &e1, &r2);
    assert_eq!(st, 200);
    let resp2: HomeCommitResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp2.seq, 2);
    let expected = chain_of(&tag, &[(1, &r1, &e1), (2, &r2, &e2)]);
    assert_eq!(resp1.chain, expected[0]);
    assert_eq!(resp2.chain, expected[1]);
    // a member at epoch 2 reads entry 3 only once it exists; the head is reported to head-epoch holders
    let (st, log) = read_log(&w, &tag, &e2, 0);
    assert_eq!(st, 200);
    let log = log.unwrap();
    assert_eq!(
        log.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
        [1, 2],
        "an epoch-2 key reads up to entry 3 (which does not exist yet)"
    );
    assert_eq!(log.head, Some(HomeHead { seq: 2, chain: expected[1].to_vec() }));
    let _ = e3;
}

#[test]
fn concurrent_commits_one_wins_the_loser_learns_the_head_and_a_lost_response_retry_is_idempotent() {
    let w = World::new();
    let tag = tag_of(2);
    let (e1, e2, e2b) = (epoch(2, 1), epoch(2, 2), epoch(2, 99));
    assert_eq!(commit(&w, &tag, &e1, &req(0, 1, &e1)).0, 200);
    let winner = req(1, 10, &e2);
    let loser = req(1, 11, &e2b);
    let (st, body) = commit(&w, &tag, &e1, &winner);
    assert_eq!(st, 200);
    let won: HomeCommitResponse = serde_json::from_slice(&body).unwrap();
    // the loser holds the same epoch-1 key and built a DIFFERENT commit for the same slot
    let (st, body) = commit(&w, &tag, &e1, &loser);
    assert_eq!(st, 409);
    let stale: HomeStaleResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!((stale.head_seq, stale.head_chain), (2, won.chain.clone()));
    // the winner lost its response and retries: same answer, nothing appended twice
    let (st, body) = commit(&w, &tag, &e1, &winner);
    assert_eq!(st, 200);
    assert_eq!(serde_json::from_slice::<HomeCommitResponse>(&body).unwrap(), won);
    let (_, log) = read_log(&w, &tag, &e2, 0);
    assert_eq!(log.unwrap().entries.len(), 2);
}

#[test]
fn requests_are_authenticated_by_epoch_credentials_and_every_failure_looks_the_same() {
    let w = World::new();
    let tag = tag_of(3);
    let (e1, e2, intruder) = (epoch(3, 1), epoch(3, 2), epoch(77, 1));
    assert_eq!(commit(&w, &tag, &e1, &req(0, 1, &e1)).0, 200);
    let r = req(1, 2, &e2);
    let body = serde_json::to_vec(&r).unwrap();
    let path = format!("/v1/home/{}/commit", tag.to_hex());
    let sig = |k: &SigningKey, ep: u64, m: &str, p: &str, b: &[u8]| auth_value(ep, &k.sign(&request_message(ep, m, p, b)).to_bytes());
    let hdr = |_ep: u64, s: String| Some(s);
    let cases = [
        ("wrong key", w.raw("POST", &path, hdr(1, sig(&intruder.commit, 1, "POST", &path, &body)), body.clone())),
        ("the READ key of the right epoch", w.raw("POST", &path, hdr(1, sig(&e1.read, 1, "POST", &path, &body)), body.clone())),
        ("signature over another body", w.raw("POST", &path, hdr(1, sig(&e1.commit, 1, "POST", &path, b"other")), body.clone())),
        (
            "signature over another path",
            w.raw("POST", &path, hdr(1, sig(&e1.commit, 1, "POST", "/v1/home/00/commit", &body)), body.clone()),
        ),
        ("epoch header differs from the slot", w.raw("POST", &path, hdr(2, sig(&e1.commit, 2, "POST", &path, &body)), body.clone())),
        ("no credential headers", w.raw("POST", &path, None, body.clone())),
        ("garbage signature", w.raw("POST", &path, hdr(1, "Home 1.AAAA".into()), body.clone())),
    ];
    for (name, (st, b)) in &cases {
        assert_eq!(*st, 401, "{name}");
        assert_eq!(b, &cases[0].1 .1, "{name}: identical body, no oracle");
    }
    // unknown tag looks the same as a wrong signature
    let other = format!("/v1/home/{}/commit", tag_of(99).to_hex());
    let (st, b) = w.raw("POST", &other, hdr(1, sig(&e1.commit, 1, "POST", &other, &body)), body.clone());
    assert_eq!((st, &b), (401, &cases[0].1 .1));
    // nothing was appended by any of it
    let (_, log) = read_log(&w, &tag, &e1, 0);
    assert_eq!(log.unwrap().entries.len(), 1);
    // and the legitimate request still works
    assert_eq!(commit(&w, &tag, &e1, &r).0, 200);
}

#[test]
fn a_key_reads_only_up_to_the_next_entry_so_a_removed_member_cannot_follow_the_group() {
    let w = World::new();
    let tag = tag_of(4);
    let eps: Vec<Epoch> = (1..=6).map(|n| epoch(4, n)).collect();
    assert_eq!(commit(&w, &tag, &eps[0], &req(0, 1, &eps[0])).0, 200);
    for n in 1..5u64 {
        assert_eq!(commit(&w, &tag, &eps[(n - 1) as usize], &req(n, (n + 1) as u8, &eps[n as usize])).0, 200);
    }
    // head = 5. A member that fell behind at epoch 2 reads entries 3 only (its next step), then, with the key that entry yields, the next one.
    let (_, l) = read_log(&w, &tag, &eps[1], 2);
    let l = l.unwrap();
    assert_eq!(l.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [3], "an epoch-2 key must not see entries 4 and 5");
    assert!(l.head.is_none(), "only head-epoch holders are told the head");
    let (_, l) = read_log(&w, &tag, &eps[2], 3);
    assert_eq!(l.unwrap().entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [4]);
    // a member removed by entry 3 holds epoch 2's keys: it can read its removal commit and nothing after it
    let (_, l) = read_log(&w, &tag, &eps[1], 0);
    assert_eq!(l.unwrap().entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [1, 2, 3]);
    // ... and cannot append: it is stale, learns nothing but "stale" (the head), and the group is unharmed
    let (st, _) = commit(&w, &tag, &eps[1], &req(2, 50, &eps[5]));
    assert_eq!(st, 409);
    let (_, l) = read_log(&w, &tag, &eps[4], 4);
    assert_eq!(l.unwrap().entries.len(), 1);
    // a future epoch's key does not exist yet: nothing to read with it
    assert_eq!(read_log(&w, &tag, &eps[5], 0).0, 401);
}

#[test]
fn the_first_writer_owns_a_tag_and_creation_cannot_be_replayed_or_hijacked() {
    let w = World::new();
    let tag = tag_of(5);
    let (e1, evil) = (epoch(5, 1), epoch(66, 1));
    assert_eq!(commit(&w, &tag, &e1, &req(0, 1, &e1)).0, 200);
    // another self-signed creation for the same tag: refused as stale, the owner's keys are untouched
    let (st, _) = commit(&w, &tag, &evil, &req(0, 9, &evil));
    assert_eq!(st, 409);
    assert_eq!(read_log(&w, &tag, &evil, 0).0, 401);
    assert_eq!(read_log(&w, &tag, &e1, 0).0, 200);
    // replaying the original creation request is idempotent (same commit id)
    assert_eq!(commit(&w, &tag, &e1, &req(0, 1, &e1)).0, 200);
}

#[test]
fn bounds_oversized_commits_malformed_bodies_and_a_per_relay_group_budget() {
    let w = World::new();
    let e1 = epoch(6, 1);
    let tag = tag_of(6);
    // oversized commit
    let mut big = req(0, 1, &e1);
    big.commit = vec![0; MAX_HOME_COMMIT_BYTES + 1];
    assert_eq!(commit(&w, &tag, &e1, &big).0, 400);
    // malformed JSON / unknown fields / short keys
    let path = format!("/v1/home/{}/commit", tag.to_hex());
    let body = br#"{"expected_seq":0,"unknown":1}"#.to_vec();
    assert_eq!(signed(&w, &e1.commit, 1, "POST", &path, body).0, 400);
    let mut short = req(0, 1, &e1);
    short.next_read_pub = vec![1; 5];
    assert_eq!(commit(&w, &tag, &e1, &short).0, 400);
    // the relay serves only `home_max_groups` (3 in the harness) groups; the 4th creation is refused, existing groups keep working
    for n in 10..13u8 {
        let e = epoch(n, 1);
        w.clock.0.advance(3600); // creation is rate limited per source address
        assert_eq!(commit(&w, &tag_of(n), &e, &req(0, 1, &e)).0, 200);
    }
    w.clock.0.advance(3600);
    let e = epoch(20, 1);
    assert_eq!(commit(&w, &tag_of(20), &e, &req(0, 1, &e)).0, 429);
    let e10 = epoch(10, 1);
    assert_eq!(read_log(&w, &tag_of(10), &e10, 0).0, 200);
}

#[test]
fn a_group_budget_caps_the_bytes_one_log_may_hold() {
    let w = World::new();
    let tag = tag_of(7);
    let eps: Vec<Epoch> = (1..=40).map(|n| epoch(7, n)).collect();
    assert_eq!(commit(&w, &tag, &eps[0], &req(0, 1, &eps[0])).0, 200);
    let mut refused = None;
    for n in 1..40u64 {
        let mut r = req(n, 2, &eps[n as usize]);
        r.commit = vec![n as u8; 250 * 1024];
        let (st, _) = commit(&w, &tag, &eps[(n - 1) as usize], &r);
        if st != 200 {
            refused = Some((n, st));
            break;
        }
        w.clock.0.advance(600); // the per-tag commit rate limit
    }
    let (n, st) = refused.expect("an 8 MiB budget must stop 250 KiB commits");
    assert_eq!(st, 429);
    assert!((30..=34).contains(&n), "refused at {n}");
}

#[test]
fn the_log_survives_a_relay_restart_and_a_second_instance_serves_the_same_history() {
    let w = World::new();
    let tag = tag_of(8);
    let (e1, e2) = (epoch(8, 1), epoch(8, 2));
    assert_eq!(commit(&w, &tag, &e1, &req(0, 1, &e1)).0, 200);
    assert_eq!(commit(&w, &tag, &e1, &req(1, 2, &e2)).0, 200);
    let other = w.instance(generous_limits());
    let path = format!("/v1/home/{}/log?after=0", tag.to_hex());
    let auth = auth_value(2, &e2.read.sign(&request_message(2, "GET", &path, &[])).to_bytes());
    let req =
        axum::http::Request::builder().method("GET").uri(&path).header("authorization", auth).body(axum::body::Body::empty()).unwrap();
    use tower::ServiceExt as _;
    let resp = w.rt.block_on(other.oneshot(req)).unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

#[test]
fn the_database_holds_no_account_device_or_member_identifier_for_a_home_group() {
    let w = World::new();
    let tag = tag_of(9);
    let (e1, e2) = (epoch(9, 1), epoch(9, 2));
    assert_eq!(commit(&w, &tag, &e1, &req(0, 1, &e1)).0, 200);
    assert_eq!(commit(&w, &tag, &e1, &req(1, 2, &e2)).0, 200);
    // only these columns exist: nothing links a request to a device or account
    let cols = w.query_bytes(
        "SELECT convert_to(column_name,'UTF8') FROM information_schema.columns WHERE table_name IN ('home_groups','home_log') ORDER BY 1",
    );
    let names: Vec<String> = cols.iter().map(|c| String::from_utf8_lossy(c).into_owned()).collect();
    for n in ["tag", "head_seq", "bytes", "touched_day", "seq", "commit_id", "commit", "chain", "commit_pub", "read_pub"] {
        assert!(names.iter().any(|x| x.contains(n)), "{n} in {names:?}");
    }
    assert_eq!(names.len(), 10 + 1, "unexpected extra column: {names:?}"); // 'tag' appears in both tables
}

/// Regression: a group's log was purged 180 days after its last COMMIT, although members polled it every day (application messages never touch
/// the home relay, so a quiet-but-alive group has no commits for months). The commit channel then vanished silently and membership changes were
/// impossible for ever. A successful authenticated read now counts as activity.
#[test]
fn a_group_that_is_still_polled_keeps_its_log_even_without_commits_for_over_six_months() {
    let w = World::new();
    let (alive, dead) = (tag_of(20), tag_of(21));
    let (a1, d1) = (epoch(20, 1), epoch(21, 1));
    assert_eq!(commit(&w, &alive, &a1, &req(0, 1, &a1)).0, 200);
    assert_eq!(commit(&w, &dead, &d1, &req(0, 1, &d1)).0, 200);
    let store = &w.state.store;
    for _ in 0..4 {
        w.clock.0.advance(60 * 86_400); // 240 days in total, polled every 60 days
        assert_eq!(read_log(&w, &alive, &a1, 0).0, 200, "members keep polling");
        w.rt.block_on(store.purge(cipher_core::clock::Clock::unix_secs(&w.clock.0))).unwrap();
    }
    assert_eq!(read_log(&w, &alive, &a1, 0).0, 200, "a polled group is not purged");
    assert_eq!(read_log(&w, &dead, &d1, 0).0, 401, "a group nobody touches for the idle period is still purged");
}
