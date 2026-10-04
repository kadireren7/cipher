#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Static guards over the FFI surface: no key material may be exposed, and no hand-written `unsafe`.
use std::path::{Path, PathBuf};

fn rs(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn sources() -> Vec<(PathBuf, String)> {
    let mut v = Vec::new();
    rs(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut v);
    v.into_iter().map(|p| (p.clone(), std::fs::read_to_string(&p).unwrap())).collect()
}

fn code_lines(s: &str) -> Vec<(usize, &str)> {
    s.lines().enumerate().filter(|(_, l)| !l.trim_start().starts_with("//")).map(|(i, l)| (i + 1, l)).collect()
}

#[test]
fn guards_read_real_sources() {
    let s = sources();
    assert!(s.len() >= 6);
    assert!(s.iter().any(|(_, t)| t.contains("#[uniffi::export]")));
}

#[test]
fn hand_written_ffi_code_contains_no_unsafe() {
    for (p, t) in sources() {
        for (n, l) in code_lines(&t) {
            assert!(!l.contains("unsafe"), "{}:{n}: hand-written unsafe in the FFI crate", p.display());
        }
    }
}

/// Exported function names (inside `#[uniffi::export] impl` blocks and free `#[uniffi::export]` fns).
fn exported_fns() -> Vec<String> {
    let mut names = Vec::new();
    for (_, t) in sources() {
        let mut in_export_impl = false;
        let mut pending_export = false;
        for l in t.lines() {
            let l = l.trim();
            if l.starts_with("#[uniffi::export]") {
                pending_export = true;
                continue;
            }
            if pending_export && l.starts_with("impl ") {
                in_export_impl = true;
                pending_export = false;
                continue;
            }
            if l.starts_with("impl ") {
                in_export_impl = false;
            }
            if let Some(rest) = l.strip_prefix("pub fn ") {
                if in_export_impl || pending_export {
                    names.push(rest.split(['(', '<']).next().unwrap().to_owned());
                    pending_export = false;
                }
            }
        }
    }
    names
}

#[test]
fn no_exported_function_can_return_key_material() {
    let names = exported_fns();
    assert!(names.len() > 50, "found {} exported fns", names.len());
    let banned = ["secret", "snapshot", "private", "master", "dek", "seed", "identity_key", "signing", "export_state", "mls_state"];
    for n in &names {
        for b in banned {
            assert!(!n.contains(b), "exported fn `{n}` looks like it exposes key material (`{b}`)");
        }
    }
    // `refresh_keys` refreshes MLS leaf keys inside Rust; it returns nothing.
    assert!(names.contains(&"refresh_keys".to_owned()));
}

#[test]
fn only_attachment_decryption_returns_raw_bytes() {
    // Vec<u8> returns in the exported object API: exactly open_attachment (display data), nothing else.
    let t = sources().into_iter().find(|(p, _)| p.ends_with("engine_api.rs")).unwrap().1;
    let mut offenders = Vec::new();
    for chunk in t.split("pub fn ").skip(1) {
        let sig = chunk.split('{').next().unwrap_or("");
        if sig.contains("-> R<Vec<u8>>") {
            offenders.push(format!("pub fn {}", sig.split(['(', '<']).next().unwrap().trim()));
        }
    }
    assert_eq!(offenders, ["pub fn open_attachment"], "{offenders:?}");
}

#[test]
fn exported_records_have_no_key_like_fields() {
    let t = sources().into_iter().find(|(p, _)| p.ends_with("types.rs")).unwrap().1;
    let allowed = ["qr_payload", "fingerprint"]; // public identity QR + 30-digit fingerprint: public by design
    for (n, l) in code_lines(&t) {
        let l = l.trim();
        if let Some(field) = l.strip_prefix("pub ").and_then(|r| r.split(':').next()) {
            let f = field.trim();
            if allowed.contains(&f) {
                continue;
            }
            for b in ["key", "secret", "private", "seed", "master"] {
                assert!(!f.contains(b), "types.rs:{n}: record field `{f}` looks like key material");
            }
        }
    }
}

#[test]
fn errors_never_carry_free_text_from_inputs() {
    let t = sources().into_iter().find(|(p, _)| p.ends_with("error.rs")).unwrap().1;
    // CipherError text comes only from static &'static str categories (checked by the From impl using `to_owned()` of statics).
    assert!(t.contains("S::NotFound(w) => CipherError::NotFound { what: w.to_owned() }"));
    assert!(!t.contains("format!"), "no formatted free text in error mapping");
}
