#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Relay administration (docs/RELAY_ADMIN.md) on the real router + PostgreSQL: who can reach it, what it can and cannot reveal, what it can change,
//! and that every change is recorded in a chain that notices tampering.
mod harness;
use axum::body::Body;
use axum::http::Request;
use axum::Router;
use cipher_relay::admin::{router, AdminConfig};
use harness::*;
use http_body_util::BodyExt;
use tower::ServiceExt;

const ADMIN_TOKEN: &str = "an-administrator-secret-that-is-long-enough-0123456789";

fn admin_router(w: &World) -> Router {
    let cfg = AdminConfig::build(ADMIN_TOKEN, "127.0.0.1:9444", &w.state.cfg.registration_token_hash, None).unwrap();
    router(w.state.clone(), &cfg)
}

fn call(w: &World, app: &Router, method: &str, path: &str, auth: Option<&str>, body: &str) -> (u16, String) {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("content-length", body.len().to_string());
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    let resp = w.rt.block_on(app.clone().oneshot(b.body(Body::from(body.to_owned())).unwrap())).unwrap();
    let status = resp.status().as_u16();
    let bytes = w.rt.block_on(resp.into_body().collect()).unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn bearer() -> String {
    format!("Bearer {ADMIN_TOKEN}")
}

const ROUTES: [(&str, &str); 3] = [("GET", "/admin/v1/stats"), ("GET", "/admin/v1/audit"), ("POST", "/admin/v1/registration")];

#[test]
fn nothing_but_the_administrator_secret_opens_any_route() {
    let w = World::new();
    let app = admin_router(&w);
    let device = new_client();
    w.register(&device);
    let signed = sign(&device, AUDIENCE, "GET", "/admin/v1/stats", 1_800_000_000, [1u8; 16], b"");
    let reg_token = format!("Bearer {TOKEN}");
    let wrong = "Bearer an-administrator-secret-that-is-long-enough-012345678X".to_owned();
    let first = call(&w, &app, "GET", "/admin/v1/stats", None, "");
    assert_eq!(first.0, 401);
    for (method, path) in ROUTES {
        for auth in
            [None, Some(""), Some("Bearer "), Some(wrong.as_str()), Some(reg_token.as_str()), Some(signed.as_str()), Some(ADMIN_TOKEN)]
        {
            let r = call(&w, &app, method, path, auth, r#"{"open":false}"#);
            assert_eq!(r, first, "{method} {path} with {auth:?}: the same refusal in every case");
        }
    }
    // the registration state did not change and nothing was recorded
    let ok = call(&w, &app, "GET", "/admin/v1/audit", Some(&bearer()), "");
    assert_eq!(ok.0, 200);
    assert!(ok.1.contains(r#""entries":[]"#), "{}", ok.1);
}

#[test]
fn registering_the_first_account_grants_no_administrative_power() {
    let w = World::new();
    let app = admin_router(&w);
    let first = new_client();
    w.register(&first); // the very first account on this relay
    let signed = sign(&first, AUDIENCE, "POST", "/admin/v1/registration", 1_800_000_000, [2u8; 16], br#"{"open":false}"#);
    assert_eq!(call(&w, &app, "POST", "/admin/v1/registration", Some(&signed), r#"{"open":false}"#).0, 401);
    // and the public router has no administrative routes at all
    for (method, path) in ROUTES {
        assert_eq!(w.raw(method, path, None, vec![]).0, 404, "{path} must not exist on the public listener");
    }
}

#[test]
fn the_stats_are_coarse_and_name_no_user_device_group_or_message() {
    let w = World::new();
    let app = admin_router(&w);
    let (a, b) = (new_client(), new_client());
    w.register(&a);
    w.register(&b);
    let (status, body) = call(&w, &app, "GET", "/admin/v1/stats", Some(&bearer()), "");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "accounts",
            "admin_auth_failures",
            "backup_age_secs",
            "blob_bytes",
            "blobs",
            "database_ready",
            "devices",
            "groups",
            "live_invitations",
            "pending_join_requests",
            "queued_bytes",
            "queued_messages",
            "registration_open",
            "schema_version",
            "uptime_secs",
            "version"
        ],
        "the answer has exactly these fields and no others"
    );
    assert_eq!(v["accounts"], "<10", "two accounts are reported as a coarse bucket, not as 2");
    assert_eq!(v["devices"], "<10");
    assert_eq!(v["registration_open"], true);
    assert_eq!(v["database_ready"], true);
    assert!(v["schema_version"].as_i64().unwrap() >= 12);
    // no identifier of any kind appears in the answer
    for id in [a.account_id().to_hex(), a.device_id().to_hex(), b.account_id().to_hex(), b.device_id().to_hex()] {
        assert!(!body.contains(&id), "an identifier leaked into the stats");
    }
    assert!(
        !body.chars().collect::<Vec<_>>().windows(32).any(|w| w.iter().all(char::is_ascii_hexdigit)),
        "no 32-character hex identifier at all"
    );
}

#[test]
fn closing_registration_stops_new_accounts_not_existing_ones_and_is_audited() {
    let w = World::new();
    let app = admin_router(&w);
    let existing = new_client();
    w.register(&existing);
    assert_eq!(call(&w, &app, "POST", "/admin/v1/registration", Some(&bearer()), r#"{"open":false}"#).0, 204);

    let newcomer = new_client();
    assert!(w.api(&newcomer).register_account(TOKEN).is_err(), "a correct registration token no longer creates an account");
    assert!(w.api(&existing).fetch_messages().is_ok(), "an existing account keeps working");
    let stats: serde_json::Value = serde_json::from_str(&call(&w, &app, "GET", "/admin/v1/stats", Some(&bearer()), "").1).unwrap();
    assert_eq!(stats["registration_open"], false);

    assert_eq!(call(&w, &app, "POST", "/admin/v1/registration", Some(&bearer()), r#"{"open":true}"#).0, 204);
    assert!(w.api(&newcomer).register_account(TOKEN).is_ok(), "reopened");

    let audit: serde_json::Value = serde_json::from_str(&call(&w, &app, "GET", "/admin/v1/audit", Some(&bearer()), "").1).unwrap();
    assert_eq!(audit["chain_ok"], true);
    let entries: Vec<(String, String)> = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["action"].as_str().unwrap().to_owned(), e["detail"].as_str().unwrap().to_owned()))
        .collect();
    assert_eq!(entries, [("registration".to_owned(), "closed".to_owned()), ("registration".to_owned(), "opened".to_owned())]);
    // paging by the last sequence number seen
    let seq = audit["entries"][0]["seq"].as_i64().unwrap();
    let rest: serde_json::Value =
        serde_json::from_str(&call(&w, &app, "GET", &format!("/admin/v1/audit?after={seq}"), Some(&bearer()), "").1).unwrap();
    assert_eq!(rest["entries"].as_array().unwrap().len(), 1);
}

#[test]
fn a_request_body_with_unknown_fields_is_refused_and_changes_nothing() {
    let w = World::new();
    let app = admin_router(&w);
    for body in [r#"{"open":false,"extra":1}"#, r#"{}"#, r#"{"open":"no"}"#, "not json"] {
        let s = call(&w, &app, "POST", "/admin/v1/registration", Some(&bearer()), body).0;
        assert!(s == 400 || s == 415 || s == 422, "{body}: {s}");
    }
    let audit: serde_json::Value = serde_json::from_str(&call(&w, &app, "GET", "/admin/v1/audit", Some(&bearer()), "").1).unwrap();
    assert!(audit["entries"].as_array().unwrap().is_empty());
}

#[test]
fn the_audit_log_cannot_be_rewritten_and_the_chain_notices_a_forged_entry() {
    let w = World::new();
    let app = admin_router(&w);
    call(&w, &app, "POST", "/admin/v1/registration", Some(&bearer()), r#"{"open":false}"#);
    call(&w, &app, "POST", "/admin/v1/registration", Some(&bearer()), r#"{"open":true}"#);
    // the database itself refuses to update or delete history
    let (update, delete) = w.rt.block_on(async {
        let c = w.pool.get().await.unwrap();
        (
            c.execute("UPDATE admin_audit SET detail = 'nothing happened'", &[]).await.is_err(),
            c.execute("DELETE FROM admin_audit", &[]).await.is_err(),
        )
    });
    assert!(update && delete, "admin_audit is append-only");
    // a forged entry that does not link to its predecessor is detected
    w.rt.block_on(async {
        let c = w.pool.get().await.unwrap();
        c.execute(
            "INSERT INTO admin_audit (at, action, detail, prev_hash, hash) VALUES (1, 'registration', 'forged', $1, $1)",
            &[&vec![9u8; 32]],
        )
        .await
        .unwrap();
    });
    let audit: serde_json::Value = serde_json::from_str(&call(&w, &app, "GET", "/admin/v1/audit", Some(&bearer()), "").1).unwrap();
    assert_eq!(audit["chain_ok"], false, "the chain no longer verifies");
}

#[test]
fn failed_attempts_are_counted_but_never_itemised_and_the_secret_is_never_logged() {
    let w = World::new();
    let app = admin_router(&w);
    for i in 0..3 {
        assert_eq!(call(&w, &app, "GET", "/admin/v1/stats", Some(&format!("Bearer wrong-{i}")), "").0, 401);
    }
    let stats: serde_json::Value = serde_json::from_str(&call(&w, &app, "GET", "/admin/v1/stats", Some(&bearer()), "").1).unwrap();
    assert_eq!(stats["admin_auth_failures"], 3);
    let audit: serde_json::Value = serde_json::from_str(&call(&w, &app, "GET", "/admin/v1/audit", Some(&bearer()), "").1).unwrap();
    assert!(audit["entries"].as_array().unwrap().is_empty(), "a failed login is not an administrative change");
    let logs = w.logs.0.lock().unwrap().clone();
    for needle in [ADMIN_TOKEN, "wrong-0", "Bearer"] {
        assert!(!contains(&logs, needle.as_bytes()), "{needle} must not be in the logs");
    }
}

#[test]
fn only_get_and_post_on_the_listed_routes_exist() {
    let w = World::new();
    let app = admin_router(&w);
    assert_eq!(call(&w, &app, "DELETE", "/admin/v1/audit", Some(&bearer()), "").0, 405);
    assert_eq!(call(&w, &app, "PUT", "/admin/v1/registration", Some(&bearer()), "{}").0, 405);
    assert_eq!(call(&w, &app, "GET", "/admin/v1/users", Some(&bearer()), "").0, 404, "there is no per-user endpoint to find");
    assert_eq!(call(&w, &app, "GET", "/admin/v1/messages", Some(&bearer()), "").0, 404);
    // answers are never cached
    let resp =
        w.rt.block_on(
            app.clone().oneshot(Request::builder().uri("/admin/v1/stats").header("authorization", bearer()).body(Body::empty()).unwrap()),
        )
        .unwrap();
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
}
