#![allow(clippy::print_stdout, clippy::unwrap_used, clippy::indexing_slicing)]
//! Argon2id benchmark used to choose and document mobile KDF parameters.
//! Run: `cargo run --release -p cipher-core --example kdf_bench`
//! These are HOST numbers. SECURITY TODO (ST-003): repeat on low-end Android hardware.
use cipher_core::kdf::{derive, KdfFloor, KdfParams};
use std::time::Instant;

fn main() {
    let salt = [7u8; 16];
    for (label, p) in [
        ("floor (OWASP minimum)", KdfParams { m_kib: 19 * 1024, t: 2, p: 1 }),
        ("MOBILE_DEFAULT", KdfParams::MOBILE_DEFAULT),
        ("high", KdfParams { m_kib: 128 * 1024, t: 3, p: 1 }),
    ] {
        let runs = 5;
        let mut times = Vec::new();
        for _ in 0..runs {
            let t = Instant::now();
            let _ = derive(b"493817", &salt, p, KdfFloor::Enforced).unwrap();
            times.push(t.elapsed().as_millis());
        }
        times.sort_unstable();
        println!(
            "{label:<24} m={} KiB t={} p={}  median={} ms  min={} ms  max={} ms",
            p.m_kib,
            p.t,
            p.p,
            times[runs / 2],
            times[0],
            times[runs - 1]
        );
    }
}
