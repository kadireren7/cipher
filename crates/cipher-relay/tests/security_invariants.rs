#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Security-invariant tests for client + relay working together. A failure here
//! is a security regression and must fail CI. Test names carry the invariant id.
mod harness;
use cipher_core::clock::testing::ManualClock;
use cipher_core::clock::Clock as _;
use cipher_core::events::SecurityEvent;
use cipher_core::keystore::testing::InMemoryKeyStore;
use cipher_core::keystore::ProtectionLevel;
use cipher_core::mls::MlsClient;
use cipher_core::protocol::{CommitValidator, ExpectedPeer, GroupProtocol, GroupRef, Processed};
use cipher_core::relay_client::{HttpRequest, HttpResponse};
use cipher_core::vault::{Vault, VaultConfig};
use cipher_core::verification::IdentityPins;
use cipher_wire::messages::*;
use cipher_wire::Id16;
use harness::*;
use std::sync::Arc;

const PT: &[u8] = b"PLAINTEXT-FIXTURE-secret-meeting-notes-4417";
const FILE_FIXTURE: &[u8] = b"PLAINTEXT-FIXTURE-attachment-body-8832-PLAINTEXT-FIXTURE-attachment-body";

struct AllowAll;
impl CommitValidator for AllowAll {
    fn approve_add(&self, _: &Id16, _: &Id16, _: &[u8]) -> bool {
        true
    }
}

fn vault() -> Vault {
    let mut v = Vault::open(
        None,
        Arc::new(InMemoryKeyStore::new(ProtectionLevel::HardwareBacked)),
        Arc::new(ManualClock::new(1)),
        VaultConfig::default(),
    )
    .unwrap();
    v.provision().unwrap();
    v
}

/// Trusted `ExpectedPeer` for `peer` according to pins fed by the relay directory.
fn trusted_peer(w: &World, me: &MlsClient, peer_account: &Id16, peer_device: &Id16, v: &mut Vault) -> ExpectedPeer {
    let dir = w.api(me).directory(peer_account).unwrap();
    let trust = v.with_store(|s| IdentityPins::new(s).evaluate_directory(peer_account, &dir.devices)).unwrap();
    let rec = trust.trusted.iter().find(|r| &r.device_id == peer_device).expect("peer device must be trusted");
    ExpectedPeer { account_id: *peer_account, device_id: *peer_device, identity_key: rec.identity_key.clone().try_into().unwrap() }
}

fn establish(w: &World, alice: &mut MlsClient, bob: &mut MlsClient, av: &mut Vault) -> GroupRef {
    w.register(alice);
    w.register(bob);
    let kps = bob.generate_key_packages(3).unwrap();
    w.api(bob).upload_key_packages(kps).unwrap();
    let expected = trusted_peer(w, alice, &bob.account_id(), &bob.device_id(), av);
    let kp = w.api(alice).consume_key_package(&bob.device_id()).unwrap();
    let g = alice.create_group().unwrap();
    let out = alice.add_member(&g, &kp, &expected).unwrap();
    alice.merge_pending_commit(&g).unwrap();
    w.api(alice).send_message(bob.device_id(), rid(), out.welcome.unwrap(), None).unwrap();
    let fetched = w.api(bob).fetch_messages().unwrap();
    let gb = bob.join_from_welcome(&fetched.envelopes[0].ciphertext).unwrap();
    w.api(bob).ack(vec![fetched.envelopes[0].message_id]).unwrap();
    assert_eq!(gb, g);
    g
}

fn send_app(w: &World, from: &mut MlsClient, to: &Id16, g: &GroupRef, pt: &[u8]) -> Id16 {
    let ct = from.encrypt(g, pt).unwrap();
    let id = rid();
    w.api(from).send_message(*to, id, ct, None).unwrap();
    id
}

fn recv_all(w: &World, me: &mut MlsClient, g: &GroupRef) -> Vec<Processed> {
    let f = w.api(me).fetch_messages().unwrap();
    let mut out = Vec::new();
    let mut acks = Vec::new();
    for e in f.envelopes {
        out.push(me.process(g, &e.ciphertext, &AllowAll).unwrap());
        acks.push(e.message_id);
    }
    if !acks.is_empty() {
        w.api(me).ack(acks).unwrap();
    }
    out
}

fn queue_ciphertexts(w: &World) -> Vec<Vec<u8>> {
    w.query_bytes("SELECT ct FROM queue")
}

// ---------------------------------------------------------------------------------------------
// SEC-001 / SEC-002 / SEC-003 / SEC-005 / SEC-010
// ---------------------------------------------------------------------------------------------

#[test]
fn sec_001_005_010_relay_wire_db_and_logs_contain_no_plaintext_or_private_keys() {
    let w = World::new();
    let (mut alice, mut bob) = (new_client(), new_client());
    let mut av = vault();
    let g = establish(&w, &mut alice, &mut bob, &mut av);
    w.api(&bob).register_push_token("push-token-abc123").unwrap();
    send_app(&w, &mut alice, &bob.device_id(), &g, PT);
    assert_eq!(recv_all(&w, &mut bob, &g), vec![Processed::Application(PT.to_vec())]);

    // Attachment through the same relay (SEC-004 also checked in its own test).
    let (blob, desc) = cipher_core::attachment::encrypt_attachment(
        &[b"%PDF-1.7 ", FILE_FIXTURE].concat(),
        "application/pdf",
        "PLAINTEXT-FIXTURE-name.pdf",
    )
    .unwrap();
    w.api(&alice).upload_blob(blob).unwrap();
    let _ = desc;

    // Honest traffic only: everything the network observer / relay saw so far.
    let honest_wire = w.all_wire_bytes();

    // Provoke error paths with plaintext-bearing garbage; they must not be echoed or logged.
    let (st, resp) = w.raw("POST", "/v1/messages", None, PT.to_vec());
    assert_eq!(st, 401);
    assert!(!contains(&resp, PT));
    let (st, resp) = w.raw("POST", "/v1/accounts", None, [b"{\"x\":\"", PT, b"\"}"].concat());
    assert!(st == 400 || st == 429, "status {st}"); // rejected, never 5xx
    assert!(!contains(&resp, PT));

    let wire = honest_wire;
    let db = w.db_bytes();
    let logs = w.log_text();
    for (name, hay) in [("wire", &wire), ("db", &db), ("logs", &logs)] {
        assert!(!contains(hay, b"PLAINTEXT-FIXTURE"), "plaintext fixture leaked into {name}");
        assert!(!contains(hay, PT), "plaintext leaked into {name}");
    }
    // SEC-002: no private key material crosses the wire or is stored/logged by the relay.
    for client in [&alice, &bob] {
        for secret in client.secret_material_for_tests() {
            assert!(secret.len() >= 32);
            assert!(!contains(&wire, &secret), "private key on the wire");
            assert!(!contains(&db, &secret), "private key in relay DB");
            assert!(!contains(&logs, &secret), "private key in logs");
        }
    }
    // Logs are not empty (we really captured something) and carry no ids/tokens/ciphertext.
    assert!(!logs.is_empty());
    let log_s = String::from_utf8_lossy(&logs).to_string();
    for id in [alice.device_id().to_hex(), bob.device_id().to_hex(), bob.account_id().to_hex(), "push-token-abc123".to_owned()] {
        assert!(!log_s.contains(&id), "identifier {id} appeared in logs");
    }
    for ct in queue_ciphertexts(&w) {
        assert!(!contains(&logs, cipher_wire::b64::encode(&ct).as_bytes()));
    }
}

#[test]
fn sec_003_full_database_dump_is_insufficient_to_decrypt_history() {
    let w = World::new();
    let (mut alice, mut bob) = (new_client(), new_client());
    let mut av = vault();
    let g = establish(&w, &mut alice, &mut bob, &mut av);
    send_app(&w, &mut alice, &bob.device_id(), &g, PT);
    // The attacker owns the ENTIRE relay database: every queued ciphertext, every public key,
    // every KeyPackage, every directory record.
    let cts = queue_ciphertexts(&w);
    assert!(!cts.is_empty());
    let mut attacker = new_client();
    let mut other_group_peer = new_client();
    let ga = build_unrelated_group(&mut attacker, &mut other_group_peer);
    for ct in &cts {
        assert!(!contains(ct, PT));
        assert!(attacker.process(&g, ct, &AllowAll).is_err(), "unknown group");
        assert!(attacker.process(&ga, ct, &AllowAll).is_err(), "wrong group/keys");
    }
    // The relay crate itself has no decryption capability (SEC-002) — see sec_002 test.
}

fn build_unrelated_group(a: &mut MlsClient, b: &mut MlsClient) -> GroupRef {
    let g = a.create_group().unwrap();
    let kp = b.generate_key_packages(1).unwrap().remove(0);
    let exp = ExpectedPeer { account_id: b.account_id(), device_id: b.device_id(), identity_key: b.identity_public() };
    let out = a.add_member(&g, &kp, &exp).unwrap();
    a.merge_pending_commit(&g).unwrap();
    b.join_from_welcome(&out.welcome.unwrap()).unwrap();
    g
}

#[test]
fn sec_002_relay_crate_has_no_client_crypto_dependencies() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    let deps: String = manifest
        .split("[dev-dependencies]")
        .next()
        .unwrap()
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in ["openmls", "cipher-core", "chacha20poly1305", "aes-gcm", "argon2", "hkdf", "x25519", "hpke"] {
        assert!(!deps.contains(forbidden), "relay [dependencies] must not include `{forbidden}`");
    }
}

// ---------------------------------------------------------------------------------------------
// SEC-004 attachments
// ---------------------------------------------------------------------------------------------

#[test]
fn sec_004_object_storage_receives_only_ciphertext_and_tampering_fails_closed() {
    let w = World::new();
    let (mut alice, mut bob) = (new_client(), new_client());
    let mut av = vault();
    let g = establish(&w, &mut alice, &mut bob, &mut av);
    let file = [b"%PDF-1.7 ".as_slice(), FILE_FIXTURE].concat();
    let (blob, desc) = cipher_core::attachment::encrypt_attachment(&file, "application/pdf", "PLAINTEXT-FIXTURE-name.pdf").unwrap();
    let blob_id = w.api(&alice).upload_blob(blob.clone()).unwrap();
    // The descriptor (with key) travels only inside the E2EE message.
    let desc_bytes = desc.to_bytes().unwrap();
    let mut msg = b"ATT:".to_vec();
    msg.extend_from_slice(blob_id.to_hex().as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(&desc_bytes);
    send_app(&w, &mut alice, &bob.device_id(), &g, &msg);

    // What the storage provider holds is exactly the ciphertext.
    let stored: Vec<u8> = w.query_bytes("SELECT data FROM blobs").remove(0);
    assert_eq!(stored, blob);
    assert!(!contains(&stored, b"PLAINTEXT-FIXTURE"));
    assert!(!contains(&w.all_wire_bytes(), b"PLAINTEXT-FIXTURE"));
    assert!(!contains(&w.db_bytes(), desc_bytes.as_slice()), "attachment key must not be stored by relay");

    // Bob decrypts via the E2EE message.
    let Processed::Application(m) = recv_all(&w, &mut bob, &g).remove(0) else { panic!() };
    let sep = m.iter().position(|b| *b == b'|').unwrap();
    let id = Id16::parse(std::str::from_utf8(&m[4..sep]).unwrap()).unwrap();
    let d2 = cipher_core::attachment::AttachmentDescriptor::from_bytes(&m[sep + 1..]).unwrap();
    let dl = w.api(&bob).download_blob(&id).unwrap();
    assert_eq!(cipher_core::attachment::decrypt_attachment(&dl, &d2).unwrap().as_slice(), file.as_slice());

    // Corrupted storage object: Bob's client must fail closed.
    {
        let mut bad = stored.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x55;
        w.exec("UPDATE blobs SET data=$1", &[&bad]);
    }
    let dl = w.api(&bob).download_blob(&id).unwrap();
    assert!(cipher_core::attachment::decrypt_attachment(&dl, &d2).is_err());
}

#[test]
fn blob_endpoint_enforces_container_header_and_size_limits() {
    let w = World::new();
    let alice = new_client();
    w.register(&alice);
    let post = |body: Vec<u8>| {
        let h =
            sign_announced(&alice, AUDIENCE, "POST", "/v1/blobs", w.clock.0.unix_secs(), cipher_core::rng::array::<16>().unwrap(), &body);
        w.raw("POST", "/v1/blobs", Some(h), body).0
    };
    assert_eq!(post(b"not-an-attachment-container-at-all-0123456789".to_vec()), 400);
    assert_eq!(post(b"CATT".to_vec()), 400);
    assert_eq!(post([b"CATT".as_slice(), &[0u8; 60]].concat()), 201);
    let mut oversize = b"CATT".to_vec();
    oversize.resize(cipher_wire::limits::MAX_BLOB_BYTES + 1, 0);
    assert_eq!(post(oversize), 413);
}

// ---------------------------------------------------------------------------------------------
// SEC-006 group removal across the relay
// ---------------------------------------------------------------------------------------------

#[test]
fn sec_006_removed_member_cannot_decrypt_post_removal_even_if_relay_forwards_it() {
    let w = World::new();
    let (mut a, mut b, mut c) = (new_client(), new_client(), new_client());
    let mut av = vault();
    for x in [&a, &b, &c] {
        w.register(x);
    }
    for x in [&mut b, &mut c] {
        let kps = x.generate_key_packages(2).unwrap();
        w.api(x).upload_key_packages(kps).unwrap();
    }
    let g = a.create_group().unwrap();
    let mut joined_b = false;
    for peer_idx in 0..2 {
        let (peer_acc, peer_dev) = if peer_idx == 0 { (b.account_id(), b.device_id()) } else { (c.account_id(), c.device_id()) };
        let exp = trusted_peer(&w, &a, &peer_acc, &peer_dev, &mut av);
        let kp = w.api(&a).consume_key_package(&peer_dev).unwrap();
        let out = a.add_member(&g, &kp, &exp).unwrap();
        a.merge_pending_commit(&g).unwrap();
        if joined_b {
            // existing member Bob processes the commit
            w.api(&a).send_message(b.device_id(), rid(), out.commit.clone(), None).unwrap();
            assert!(matches!(recv_all(&w, &mut b, &g)[0], Processed::Commit { .. }));
        }
        w.api(&a).send_message(peer_dev, rid(), out.welcome.unwrap(), None).unwrap();
        let who = if peer_idx == 0 { &mut b } else { &mut c };
        let f = w.api(who).fetch_messages().unwrap();
        who.join_from_welcome(&f.envelopes[0].ciphertext).unwrap();
        w.api(who).ack(vec![f.envelopes[0].message_id]).unwrap();
        joined_b = true;
    }
    // Carol legitimately reads pre-removal traffic.
    send_app(&w, &mut a, &c.device_id(), &g, b"before");
    assert_eq!(recv_all(&w, &mut c, &g), vec![Processed::Application(b"before".to_vec())]);

    // Remove Carol: commit goes to Bob (and Carol, who learns she is out).
    let out = a.remove_member(&g, &c.device_id()).unwrap();
    a.merge_pending_commit(&g).unwrap();
    w.api(&a).send_message(b.device_id(), rid(), out.commit.clone(), None).unwrap();
    w.api(&a).send_message(c.device_id(), rid(), out.commit, None).unwrap();
    assert!(matches!(&recv_all(&w, &mut b, &g)[0], Processed::Commit { self_removed: false, .. }));
    assert!(matches!(&recv_all(&w, &mut c, &g)[0], Processed::Commit { self_removed: true, .. }));

    // Post-removal message. Even a malicious relay that forwards it to Carol gains her nothing.
    let post = a.encrypt(&g, PT).unwrap();
    w.api(&a).send_message(b.device_id(), rid(), post.clone(), None).unwrap();
    w.api(&a).send_message(c.device_id(), rid(), post, None).unwrap(); // simulates relay misrouting
    assert_eq!(recv_all(&w, &mut b, &g), vec![Processed::Application(PT.to_vec())]);
    let fc = w.api(&c).fetch_messages().unwrap();
    assert_eq!(fc.envelopes.len(), 1);
    assert!(c.process(&g, &fc.envelopes[0].ciphertext, &AllowAll).is_err());
    assert!(c.encrypt(&g, b"x").is_err());
}

// ---------------------------------------------------------------------------------------------
// SEC-011 server key substitution is detectable
// ---------------------------------------------------------------------------------------------

#[test]
fn sec_011_malicious_relay_swapping_directory_key_is_detected_by_pins() {
    let w = World::new();
    let (alice, bob) = (new_client(), new_client());
    w.register(&alice);
    w.register(&bob);
    let mut av = vault();
    // First contact through the honest relay pins Bob.
    let dir = w.api(&alice).directory(&bob.account_id()).unwrap();
    av.with_store(|s| IdentityPins::new(s).evaluate_directory(&bob.account_id(), &dir.devices)).unwrap();

    // Now the relay is compromised: it serves Bob's device id with the attacker's (validly self-bound) keys.
    let mallory = MlsClient::generate(bob.account_id(), bob.device_id()).unwrap();
    let forged = mallory.device_record(None).unwrap();
    let mitm = Mitm {
        inner: &w,
        rewrite: Box::new(move |req: &HttpRequest, resp: HttpResponse| {
            if req.path_and_query.ends_with("/devices") && req.method == "GET" {
                let body = serde_json::to_vec(&DirectoryResponse {
                    account_id: forged.device_id, /* irrelevant */
                    devices: vec![forged.clone()],
                })
                .unwrap();
                return HttpResponse { status: resp.status, body };
            }
            resp
        }),
    };
    let api = cipher_core::relay_client::RelayApi { transport: &mitm, endpoint: &w.endpoint, client: &alice, clock: &*w.clock };
    let swapped = api.directory(&bob.account_id()).unwrap();
    let trust = av.with_store(|s| IdentityPins::new(s).evaluate_directory(&bob.account_id(), &swapped.devices)).unwrap();
    assert!(trust.trusted.is_empty(), "substituted key must not be trusted");
    assert!(trust.events.iter().any(|e| matches!(e, SecurityEvent::IdentityChanged { .. })));
}

#[test]
fn sec_011_malicious_relay_swapping_key_package_is_refused_by_client() {
    let w = World::new();
    let (mut alice, mut bob) = (new_client(), new_client());
    let mut av = vault();
    w.register(&alice);
    w.register(&bob);
    let kps = bob.generate_key_packages(1).unwrap();
    w.api(&bob).upload_key_packages(kps).unwrap();
    let expected = trusted_peer(&w, &alice, &bob.account_id(), &bob.device_id(), &mut av);
    let mut mallory = new_client();
    let evil_kp = mallory.generate_key_packages(1).unwrap().remove(0);
    let mitm = Mitm {
        inner: &w,
        rewrite: Box::new(move |req: &HttpRequest, resp: HttpResponse| {
            if req.path_and_query.ends_with("/key-package") {
                let body = serde_json::to_vec(&KeyPackageResponse { key_package: evil_kp.clone() }).unwrap();
                return HttpResponse { status: resp.status, body };
            }
            resp
        }),
    };
    let api = cipher_core::relay_client::RelayApi { transport: &mitm, endpoint: &w.endpoint, client: &alice, clock: &*w.clock };
    let kp = api.consume_key_package(&bob.device_id()).unwrap();
    let g = alice.create_group().unwrap();
    assert!(alice.add_member(&g, &kp, &expected).is_err(), "client must refuse a substituted KeyPackage");
}

// ---------------------------------------------------------------------------------------------
// SEC-013 / SEC-014 authentication, replay, expiry, duplicates
// ---------------------------------------------------------------------------------------------

#[test]
fn sec_014_replayed_signed_request_is_rejected_and_causes_no_second_transition() {
    let w = World::new();
    let (alice, bob) = (new_client(), new_client());
    w.register(&alice);
    w.register(&bob);
    let body =
        serde_json::to_vec(&SendRequest { message_id: rid(), recipient_device: bob.device_id(), ciphertext: vec![7; 40], ttl_secs: None })
            .unwrap();
    let ts = w.clock.0.unix_secs();
    let nonce = [9u8; 16];
    let hdr = sign(&alice, AUDIENCE, "POST", "/v1/messages", ts, nonce, &body);
    assert_eq!(w.raw("POST", "/v1/messages", Some(hdr.clone()), body.clone()).0, 200);
    // Attacker (A12) replays the captured request verbatim.
    assert_eq!(w.raw("POST", "/v1/messages", Some(hdr), body).0, 401);
    assert_eq!(queue_ciphertexts(&w).len(), 1);
}

#[test]
fn sec_014_duplicate_message_ids_are_idempotent_even_after_ack() {
    let w = World::new();
    let (alice, bob) = (new_client(), new_client());
    w.register(&alice);
    w.register(&bob);
    let id = rid();
    use cipher_wire::messages::SendStatus::*;
    assert_eq!(w.api(&alice).send_message(bob.device_id(), id, vec![1; 30], None).unwrap(), Queued);
    assert_eq!(w.api(&alice).send_message(bob.device_id(), id, vec![1; 30], None).unwrap(), Duplicate, "safe retry");
    let f = w.api(&bob).fetch_messages().unwrap();
    assert_eq!(f.envelopes.len(), 1);
    w.api(&bob).ack(vec![id]).unwrap();
    assert_eq!(w.api(&alice).send_message(bob.device_id(), id, vec![1; 30], None).unwrap(), Duplicate, "tombstone survives ack");
    assert!(w.api(&bob).fetch_messages().unwrap().envelopes.is_empty());
}

#[test]
fn sec_013_authentication_failures_fail_closed() {
    let w = World::new();
    let (alice, bob, stranger) = (new_client(), new_client(), new_client());
    w.register(&alice);
    w.register(&bob);
    let path = "/v1/messages";
    let now = w.clock.0.unix_secs();
    let n = || cipher_core::rng::array::<16>().unwrap();
    let get = |hdr: Option<String>| w.raw("GET", path, hdr, Vec::new()).0;

    assert_eq!(get(None), 401, "no credentials");
    assert_eq!(get(Some(sign(&alice, AUDIENCE, "GET", path, now, n(), b""))), 200, "control");
    assert_eq!(get(Some(sign(&stranger, AUDIENCE, "GET", path, now, n(), b""))), 401, "unregistered device");
    assert_eq!(get(Some(sign(&alice, AUDIENCE, "GET", path, now - 61, n(), b""))), 401, "stale timestamp");
    assert_eq!(get(Some(sign(&alice, AUDIENCE, "GET", path, now + 61, n(), b""))), 401, "future timestamp");
    assert_eq!(get(Some(sign(&alice, "other-relay.test", "GET", path, now, n(), b""))), 401, "wrong audience");
    assert_eq!(get(Some(sign(&alice, AUDIENCE, "POST", path, now, n(), b""))), 401, "method confusion");
    assert_eq!(get(Some(sign(&alice, AUDIENCE, "GET", "/v1/messages?x=1", now, n(), b""))), 401, "path mismatch");
    // Bob's signature but Alice's device id in the header.
    let forged = sign(&bob, AUDIENCE, "GET", path, now, n(), b"").replace(&bob.device_id().to_hex(), &alice.device_id().to_hex());
    assert_eq!(get(Some(forged)), 401, "identity confusion");
    // Single flipped signature bit.
    let good = sign(&alice, AUDIENCE, "GET", path, now, n(), b"");
    let mut chars: Vec<char> = good.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    assert_eq!(get(Some(chars.into_iter().collect())), 401, "bit flip");
    // Body modified after signing.
    let body = serde_json::to_vec(&AckRequest { message_ids: vec![rid()] }).unwrap();
    let h = sign(&alice, AUDIENCE, "POST", "/v1/messages/ack", now, n(), &body);
    let mut tampered = body.clone();
    tampered[5] ^= 1;
    assert_eq!(w.raw("POST", "/v1/messages/ack", Some(h), tampered).0, 401, "tampered body");
    // Garbage headers.
    for g in ["", "Bearer abc", "CipherSig v2 x=1", "CipherSig v1 device=zz", &"A".repeat(1000)] {
        assert_eq!(get(Some(g.to_owned())), 401, "{g}");
    }
}

#[test]
fn account_credential_alone_cannot_add_a_device_a8() {
    let w = World::new();
    let alice = new_client();
    w.register(&alice);
    // Attacker knows the account registration token (server-account credential) but has no device.
    let attacker_dev = MlsClient::generate(alice.account_id(), rid()).unwrap();
    // 1) no endorsement
    let r = w.api(&attacker_dev).add_device(TOKEN, Endorsement { endorser_device: alice.device_id(), signature: vec![0; 64] });
    assert!(r.is_err());
    // 2) endorsement signed by the attacker's own (non-account) key
    let outsider = new_client();
    let e = outsider.endorse_device(&attacker_dev.device_id(), &attacker_dev.identity_public(), &attacker_dev.auth_public()).unwrap();
    let e = Endorsement { endorser_device: alice.device_id(), signature: e.signature };
    assert!(w.api(&attacker_dev).add_device(TOKEN, e).is_err());
    // 3) wrong token with a valid endorsement
    let good = alice.endorse_device(&attacker_dev.device_id(), &attacker_dev.identity_public(), &attacker_dev.auth_public()).unwrap();
    assert!(w.api(&attacker_dev).add_device("wrong-token-wrong-token-wrong-token-xx", good.clone()).is_err());
    assert_eq!(w.api(&alice).directory(&alice.account_id()).unwrap().devices.len(), 1);
    // 4) the legitimate flow works and is visible in the directory with its endorsement
    w.api(&attacker_dev).add_device(TOKEN, good).unwrap();
    let dir = w.api(&alice).directory(&alice.account_id()).unwrap();
    assert_eq!(dir.devices.len(), 2);
    assert!(dir.devices.iter().any(|d| d.endorsement.is_some()));
    // Registering an existing account id again is a conflict, not a takeover.
    let again = MlsClient::generate(alice.account_id(), rid()).unwrap();
    assert!(w.api(&again).register_account(TOKEN).is_err());
}

#[test]
fn registration_requires_token_and_proof_of_identity_key_possession() {
    let w = World::new();
    let c = new_client();
    assert!(w.api(&c).register_account("wrong-token-wrong-token-wrong-token-xx").is_err());
    // Valid token but a binding signature made by a different key (no proof of possession).
    let other = new_client();
    let mut rec = c.device_record(None).unwrap();
    rec.binding_sig = other.device_record(None).unwrap().binding_sig;
    let body = serde_json::to_vec(&RegisterRequest { account_id: c.account_id(), registration_token: TOKEN.into(), device: rec }).unwrap();
    assert_eq!(w.raw("POST", "/v1/accounts", None, body).0, 403);
}

#[test]
fn queued_ciphertext_expires_and_ttl_bounds_are_enforced() {
    let w = World::new();
    let (alice, bob) = (new_client(), new_client());
    w.register(&alice);
    w.register(&bob);
    w.api(&alice).send_message(bob.device_id(), rid(), vec![1; 30], Some(cipher_wire::limits::MIN_TTL_SECS)).unwrap();
    assert_eq!(w.api(&bob).fetch_messages().unwrap().envelopes.len(), 1);
    w.clock.0.advance(cipher_wire::limits::MIN_TTL_SECS + 700);
    assert!(w.api(&bob).fetch_messages().unwrap().envelopes.is_empty(), "expired ciphertext must not be delivered");
    assert!(w.api(&alice).send_message(bob.device_id(), rid(), vec![1; 30], Some(cipher_wire::limits::MAX_TTL_SECS + 1)).is_err());
    assert!(w.api(&alice).send_message(bob.device_id(), rid(), vec![1; 30], Some(1)).is_err());
}

#[test]
fn queues_are_bounded_by_count_and_bytes() {
    // Queues are bounded per DEVICE (1000 envelopes / 16 MiB) and, inside that, per lane and per capability (ST-031). To reach the device bound a
    // sender needs capabilities: strangers only get the small OPEN lane (see inbox_flooding.rs / delivery_caps.rs).
    use cipher_wire::messages::AnonDelivery;
    let w = World::new();
    let (bob, carol) = (new_client(), new_client());
    w.register(&bob);
    w.register(&carol);
    let caps = |who: &cipher_core::mls::MlsClient, n: usize| -> Vec<cipher_wire::Id16> {
        let cs: Vec<_> = (0..n).map(|_| rid()).collect();
        for chunk in cs.chunks(cipher_wire::limits::MAX_CAPS_PER_MINT) {
            w.clock.0.advance(3600);
            w.api(who).mint_caps(chunk.to_vec()).unwrap();
        }
        cs
    };
    let deliver = |cap: cipher_wire::Id16, n: usize| -> bool {
        // the unauthenticated endpoint; one capability's token bucket is refilled by advancing the clock
        w.clock.0.advance(1);
        let req = cipher_wire::messages::AnonDeliverRequest {
            deliveries: vec![AnonDelivery { cap, message_id: rid(), ciphertext: vec![1; n] }],
            ttl_secs: None,
        };
        let (_, body) = w.raw("POST", "/v1/deliver", None, serde_json::to_vec(&req).unwrap());
        serde_json::from_slice::<cipher_wire::messages::AnonDeliverResponse>(&body).is_ok_and(|r| r.results == ["queued"])
    };
    let per_cap = cipher_wire::limits::CAP_QUOTA_ENVELOPES;
    let bob_caps = caps(&bob, cipher_wire::limits::MAX_QUEUED_ENVELOPES_PER_DEVICE / per_cap + 1);
    let mut accepted = 0;
    'fill: for cap in &bob_caps {
        for _ in 0..per_cap {
            if deliver(*cap, 20) {
                accepted += 1;
            } else {
                continue 'fill;
            }
        }
    }
    assert_eq!(accepted, cipher_wire::limits::MAX_QUEUED_ENVELOPES_PER_DEVICE, "count bound is exact");
    assert!(!deliver(bob_caps[bob_caps.len() - 1], 20), "count bound");
    // Bytes bound on a fresh recipient.
    let carol_caps = caps(&carol, 8);
    let big = 250 * 1024;
    let mut accepted = 0usize;
    'bytes: loop {
        let mut progressed = false;
        for cap in &carol_caps {
            if deliver(*cap, big) {
                accepted += 1;
                progressed = true;
                assert!(accepted < 100);
            }
        }
        if !progressed {
            break 'bytes;
        }
    }
    assert!(accepted * big <= cipher_wire::limits::MAX_QUEUED_BYTES_PER_DEVICE);
    assert!(accepted >= 60);
    // Draining restores capacity (bounded queue, not a permanent block).
    let f = w.api(&carol).fetch_messages().unwrap();
    assert_eq!(f.envelopes.len(), cipher_wire::limits::MAX_FETCH_BATCH.min(accepted));
    w.api(&carol).ack(f.envelopes.iter().map(|e| e.message_id).collect()).unwrap();
    assert!(carol_caps.iter().any(|c| deliver(*c, big)));
}

#[test]
fn input_size_limits_and_strict_validation() {
    let w = World::new();
    let (alice, bob) = (new_client(), new_client());
    w.register(&alice);
    w.register(&bob);
    let ts = || w.clock.0.unix_secs();
    let n = || cipher_core::rng::array::<16>().unwrap();
    let post = |path: &str, body: Vec<u8>| {
        let h = sign(&alice, AUDIENCE, "POST", path, ts(), n(), &body);
        w.raw("POST", path, Some(h), body).0
    };
    let too_big_ct = serde_json::to_vec(&SendRequest {
        message_id: rid(),
        recipient_device: bob.device_id(),
        ciphertext: vec![0; cipher_wire::limits::MAX_MESSAGE_CIPHERTEXT_BYTES + 1],
        ttl_secs: None,
    })
    .unwrap();
    assert!(matches!(post("/v1/messages", too_big_ct), 400 | 413));
    assert_eq!(post("/v1/messages", vec![b' '; cipher_wire::limits::MAX_JSON_BODY_BYTES + 1]), 413);
    let empty_ct =
        serde_json::to_vec(&SendRequest { message_id: rid(), recipient_device: bob.device_id(), ciphertext: vec![], ttl_secs: None })
            .unwrap();
    assert_eq!(post("/v1/messages", empty_ct), 400);
    let unknown =
        format!(r#"{{"message_id":"{}","recipient_device":"{}","ciphertext":"AAAA","ttl_secs":null,"extra":1}}"#, rid(), bob.device_id());
    assert_eq!(post("/v1/messages", unknown.into_bytes()), 400, "unknown fields rejected");
    let bad_b64 = format!(r#"{{"message_id":"{}","recipient_device":"{}","ciphertext":"!!!!","ttl_secs":null}}"#, rid(), bob.device_id());
    assert_eq!(post("/v1/messages", bad_b64.into_bytes()), 400);
    let nobody =
        serde_json::to_vec(&SendRequest { message_id: rid(), recipient_device: rid(), ciphertext: vec![1; 20], ttl_secs: None }).unwrap();
    assert_eq!(post("/v1/messages", nobody), 404);
    assert_eq!(post("/v1/messages/ack", br#"{"message_ids":[]}"#.to_vec()), 400);
    let too_many: Vec<Id16> = (0..101).map(|_| rid()).collect();
    assert_eq!(post("/v1/messages/ack", serde_json::to_vec(&AckRequest { message_ids: too_many }).unwrap()), 400);
    assert_eq!(post("/v1/devices/not-an-id/key-package", vec![]), 400);
}

#[test]
fn hostile_input_never_causes_server_errors() {
    let w = World::new();
    let alice = new_client();
    w.register(&alice);
    let paths = [
        ("POST", "/v1/accounts"),
        ("POST", "/v1/devices"),
        ("PUT", "/v1/key-packages"),
        ("POST", "/v1/messages"),
        ("POST", "/v1/messages/ack"),
        ("PUT", "/v1/push-token"),
        ("POST", "/v1/blobs"),
        ("GET", "/v1/blobs/zzzz"),
        ("GET", "/v1/accounts/xx/devices"),
        ("POST", "/v1/devices/yy/key-package"),
    ];
    for i in 0..400u32 {
        let (m, p) = paths[(i as usize) % paths.len()];
        let len = (cipher_core::rng::array::<2>().unwrap()[0] as usize) * 4;
        let mut body = vec![0u8; len];
        cipher_core::rng::fill(&mut body).unwrap();
        if i % 3 == 0 {
            body = format!("{{\"ciphertext\":\"{}\",\"token\":\"{}\"}}", "A".repeat(len), "\u{0}".repeat(len % 7)).into_bytes();
        }
        let hdr = if i % 2 == 0 {
            Some(sign(&alice, AUDIENCE, m, p, w.clock.0.unix_secs(), cipher_core::rng::array::<16>().unwrap(), &body))
        } else {
            None
        };
        let (status, _) = w.raw(m, p, hdr, body);
        assert!(status < 500, "{m} {p} -> {status}");
    }
}

#[test]
fn devices_cannot_read_or_ack_each_others_queues() {
    let w = World::new();
    let (alice, bob, eve) = (new_client(), new_client(), new_client());
    for c in [&alice, &bob, &eve] {
        w.register(c);
    }
    let id = rid();
    w.api(&alice).send_message(bob.device_id(), id, vec![1; 30], None).unwrap();
    assert!(w.api(&eve).fetch_messages().unwrap().envelopes.is_empty());
    w.api(&eve).ack(vec![id]).unwrap(); // cannot delete Bob's message
    assert_eq!(w.api(&bob).fetch_messages().unwrap().envelopes.len(), 1);
}

#[test]
fn rate_limiting_throttles_a_flooding_device_and_failed_auth() {
    let w = World::with_limits(cipher_relay::api::Limits {
        device_burst: 5,
        device_refill_per_sec: 0.0,
        auth_fail_burst: 3,
        auth_fail_refill_per_sec: 0.0,
        ..generous_limits()
    });
    let alice = new_client();
    w.register(&alice);
    let mut limited = false;
    for _ in 0..20 {
        if w.api(&alice).fetch_messages().is_err() {
            limited = true;
            break;
        }
    }
    assert!(limited, "per-device rate limit must engage");
    // Repeated failed auth from one source gets throttled (and does not reveal why).
    let stranger = new_client();
    let mut codes = Vec::new();
    for _ in 0..10 {
        let h = sign(&stranger, AUDIENCE, "GET", "/v1/messages", w.clock.0.unix_secs(), cipher_core::rng::array::<16>().unwrap(), b"");
        codes.push(w.raw("GET", "/v1/messages", Some(h), vec![]).0);
    }
    assert!(codes.contains(&401) && codes.contains(&429), "{codes:?}");
}

// ---------------------------------------------------------------------------------------------
// Notification privacy
// ---------------------------------------------------------------------------------------------

#[test]
fn push_provider_receives_only_a_constant_content_free_wakeup() {
    let w = World::new();
    let (alice, bob) = (new_client(), new_client());
    w.register(&alice);
    w.register(&bob);
    w.api(&alice).send_message(bob.device_id(), rid(), vec![1; 30], None).unwrap();
    assert!(w.push.sent.lock().unwrap().is_empty(), "no token registered -> no push");
    w.api(&bob).register_push_token("TOKEN-xyz-0001").unwrap();
    let ct = vec![0x42u8; 64];
    w.api(&alice).send_message(bob.device_id(), rid(), ct.clone(), None).unwrap();
    let sent = w.push.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, "TOKEN-xyz-0001");
    assert_eq!(sent[0].1, cipher_relay::push::WAKE_PAYLOAD);
    assert_eq!(sent[0].1, "{\"v\":1}");
    assert!(w.api(&bob).register_push_token(&"x".repeat(600)).is_err());
    assert!(w.api(&bob).register_push_token("bad token with spaces").is_err());
}

#[test]
fn directory_and_key_package_flow_is_single_use() {
    let w = World::new();
    let (alice, bob) = (new_client(), new_client());
    w.register(&alice);
    w.register(&bob);
    let mut bobm = bob;
    let kps = bobm.generate_key_packages(2).unwrap();
    w.api(&bobm).upload_key_packages(kps).unwrap();
    let k1 = w.api(&alice).consume_key_package(&bobm.device_id()).unwrap();
    let k2 = w.api(&alice).consume_key_package(&bobm.device_id()).unwrap();
    assert_ne!(k1, k2);
    assert!(w.api(&alice).consume_key_package(&bobm.device_id()).is_err(), "single use; exhausted");
    assert!(w.api(&bobm).upload_key_packages(vec![]).is_err());
    assert!(w.api(&alice).directory(&rid()).is_err());
    let _ = &mut bobm;
}
