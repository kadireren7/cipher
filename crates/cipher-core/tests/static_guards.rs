#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Static source guards for invariants that are easiest to enforce by scanning
//! (SEC-010, SEC-012, TLS downgrade). A hit means a regression, not a style nit.
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Production code only: everything before the first `#[cfg(test)]`, comments stripped.
fn production_lines(path: &Path) -> Vec<(usize, String)> {
    let src = std::fs::read_to_string(path).unwrap();
    let cut = src.find("#[cfg(test)]\nmod tests").unwrap_or(src.len());
    src[..cut].lines().enumerate().filter(|(_, l)| !l.trim_start().starts_with("//")).map(|(i, l)| (i + 1, l.to_owned())).collect()
}

fn workspace_sources() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for krate in ["cipher-core", "cipher-wire", "cipher-relay"] {
        rust_files(&root.join(krate).join("src"), &mut files);
    }
    files
}

fn violations(patterns: &[&str], allow_files: &[&str]) -> Vec<String> {
    let mut v = Vec::new();
    for f in workspace_sources() {
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        if allow_files.contains(&name.as_str()) {
            continue;
        }
        for (n, l) in production_lines(&f) {
            for p in patterns {
                if l.contains(p) {
                    v.push(format!("{}:{n}: `{p}`", f.display()));
                }
            }
        }
    }
    v
}

#[test]
fn sec_012_no_non_cryptographic_or_ad_hoc_randomness() {
    let v = violations(&["thread_rng", "rand::", "StdRng", "SmallRng", "from_entropy", "fastrand", "rand_core::OsRng"], &[]);
    assert!(v.is_empty(), "ad-hoc randomness: {v:?}");
}

#[test]
fn sec_012_direct_os_rng_calls_only_in_approved_places() {
    // rng.rs is the single client entry point; the relay needs 128 random bits for blob ids.
    let v = violations(&["getrandom::"], &["rng.rs", "api.rs"]);
    assert!(v.is_empty(), "getrandom outside crate::rng: {v:?}");
}

#[test]
fn sec_010_no_stdout_stderr_or_dbg_in_production_code() {
    let v = violations(&["println!", "eprintln!", "dbg!(", "print!(", "eprint!("], &[]);
    assert!(v.is_empty(), "stdout/stderr output in production code: {v:?}");
}

#[test]
fn sec_010_logging_calls_never_reference_bodies_or_secrets() {
    let mut bad = Vec::new();
    for f in workspace_sources() {
        for (n, l) in production_lines(&f) {
            let is_log =
                ["tracing::info!", "tracing::warn!", "tracing::error!", "tracing::debug!", "tracing::trace!"].iter().any(|m| l.contains(m));
            if is_log {
                for banned in
                    ["body", "ciphertext", "plaintext", "token", "secret", "key", "nonce", "device", "account", "authorization", "{:?}"]
                {
                    if l.to_lowercase().contains(banned) {
                        bad.push(format!("{}:{n}: log mentions `{banned}`", f.display()));
                    }
                }
            }
        }
    }
    assert!(bad.is_empty(), "{bad:?}");
}

#[test]
fn no_cleartext_http_or_tls_downgrade_in_production_code() {
    let v = violations(
        &["\"http://", "danger_accept_invalid", "dangerous()", "with_custom_certificate_verifier", "TLS12", "SslProtocol", "NoVerifier"],
        &[],
    );
    assert!(v.is_empty(), "TLS downgrade or cleartext: {v:?}");
}

#[test]
fn no_hardcoded_key_like_literals() {
    // 64 hex chars or long base64-looking literals in production code would indicate embedded keys.
    let mut bad = Vec::new();
    for f in workspace_sources() {
        for (n, l) in production_lines(&f) {
            for tok in l.split('"').skip(1).step_by(2) {
                let hex = tok.len() >= 64 && tok.chars().all(|c| c.is_ascii_hexdigit());
                if hex {
                    bad.push(format!("{}:{n}", f.display()));
                }
            }
        }
    }
    assert!(bad.is_empty(), "{bad:?}");
}

#[test]
fn guards_actually_scan_production_code() {
    // Vacuous-pass protection: the scanner must see many files and recognise known production lines.
    assert!(workspace_sources().len() >= 15);
    assert!(!violations(&["pub fn"], &[]).is_empty());
    assert!(!violations(&["tracing::info!"], &[]).is_empty(), "relay logging call must be visible to the logging guard");
    assert!(!violations(&["getrandom::fill"], &[]).is_empty());
}
