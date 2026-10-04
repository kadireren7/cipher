#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::needless_range_loop
)]
//! Controlled traffic experiments with REAL engines against the real relay + PostgreSQL (docs/ISP_OBSERVABILITY_REPORT.md,
//! docs/PRIVACY_TRANSPORT_REVIEW.md §experiments). Simulated time: one clock step = one second. Run with `--nocapture` to see the tables.
//!
//! What is simulated: the observer's view (request times and sizes on the client link; delivery times at the relay). What is NOT: Tor itself —
//! its latency is modelled as uniform noise, which is generous to the defender for tiny sets and says nothing about real Tor's behaviour.
mod harness;
use cipher_core::app::netprofile::NetworkProfile;
use cipher_core::clock::Clock as _;
use cipher_wire::Id16;
use harness::engine::*;
use harness::*;

fn lcg(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *seed >> 33
}

fn is_send_shaped(e: &NetEvent) -> bool {
    e.method == "POST" && (e.path == "/v1/deliver" || e.path == "/v1/messages/batch" || e.path == "/v1/messages")
}

fn dm_to(w: &World, sender: &mut TestEngine, recv: &mut TestEngine, recv_pub: &cipher_core::app::PublicIdentity) -> Id16 {
    let conv = sender.start_dm(&recv_pub.account_id).unwrap();
    sender.send_text(&conv, "hello", None).unwrap();
    for _ in 0..2 {
        recv.sync().unwrap();
        sender.sync().unwrap();
    }
    let _ = w;
    conv
}

fn set_profile(e: &mut TestEngine, p: NetworkProfile) {
    let mut s = e.settings().unwrap();
    s.network_profile = p;
    e.set_settings(&s).unwrap();
}

/// ISP-style detector: from per-window uplink bytes alone, guess "the user sent a message in this window". The attacker picks the best threshold
/// ON THE SAME DATA (optimistic for the attacker). Returns (balanced accuracy, base rate of sending windows).
fn isp_detector(profile: NetworkProfile, seed0: u64) -> (f64, f64, usize) {
    let w = World::new();
    let (mut a, mut r) = (w.engine(), w.engine());
    let rp = r.public_identity().unwrap();
    let ia = a.public_identity().unwrap();
    a.add_contact_by_id(&rp.cipher_id, "R").unwrap();
    r.add_contact_by_id(&ia.cipher_id, "A").unwrap();
    let conv = dm_to(&w, &mut a, &mut r, &rp);
    set_profile(&mut a, profile);
    let mut seed = seed0;
    let (t_end, window) = (1800u64, 10u64);
    let mut next_due = 0u64;
    let mut sends_at = Vec::new();
    a.transport.log.lock().unwrap().clear();
    let t0 = w.clock.0.unix_secs();
    for t in 0..t_end {
        if lcg(&mut seed) % 60 == 0 {
            let _ = a.send_text(&conv, &format!("m{t}"), None);
            sends_at.push(t);
        }
        if t >= next_due {
            let tr = a.network_tick().unwrap();
            next_due = t + tr.next_delay_ms.div_ceil(1000);
        }
        w.clock.0.advance(1);
    }
    let log = a.transport.log.lock().unwrap().clone();
    let nwin = (t_end / window) as usize;
    let mut bytes = vec![0usize; nwin];
    for e in &log {
        let i = ((e.t_secs - t0) / window) as usize;
        if i < nwin {
            bytes[i] += e.req_bytes;
        }
    }
    let truth: Vec<bool> = (0..nwin).map(|i| sends_at.iter().any(|t| (t / window) as usize == i)).collect();
    let pos = truth.iter().filter(|x| **x).count();
    let neg = nwin - pos;
    let mut best = 0.0f64;
    let mut cands: Vec<usize> = bytes.clone();
    cands.sort_unstable();
    cands.dedup();
    for th in cands {
        let tp = (0..nwin).filter(|i| truth[*i] && bytes[*i] > th).count() as f64;
        let tn = (0..nwin).filter(|i| !truth[*i] && bytes[*i] <= th).count() as f64;
        let bal = (tp / pos.max(1) as f64 + tn / neg.max(1) as f64) / 2.0;
        best = best.max(bal);
    }
    (best, pos as f64 / nwin as f64, log.len())
}

#[test]
fn an_isp_that_sees_only_sizes_and_times_cannot_tell_when_the_user_sends_in_enhanced_but_can_in_standard() {
    let (std_acc, base, std_reqs) = isp_detector(NetworkProfile::Standard, 11);
    let (enh_acc, _, enh_reqs) = isp_detector(NetworkProfile::Enhanced, 11);
    println!("ISP detector (balanced accuracy, 0.5 = chance; best threshold chosen on the same data): STANDARD {std_acc:.3}  ENHANCED {enh_acc:.3}  (windows with a send: {base:.2})");
    println!("requests over 30 simulated minutes: STANDARD {std_reqs}  ENHANCED {enh_reqs}");
    assert!(std_acc > 0.9, "STANDARD leaks send times to a link observer: {std_acc}");
    assert!(enh_acc < 0.65, "ENHANCED should be close to chance: {enh_acc}");
}

/// End-to-end timing correlation with N senders messaging one receiver. The attacker sees (a) when each sender's link carries a send-shaped request and
/// (b) when the relay received a REAL delivery (plus Tor-like latency noise). For every real delivery: how many senders could have produced it?
fn correlation(profile: NetworkProfile, n: usize, seed0: u64) -> (f64, f64) {
    let w = World::new();
    let mut r = w.engine();
    let rp = r.public_identity().unwrap();
    let mut senders: Vec<TestEngine> = (0..n).map(|_| w.engine()).collect();
    let mut convs = Vec::new();
    for s in senders.iter_mut() {
        let sp = s.public_identity().unwrap();
        s.add_contact_by_id(&rp.cipher_id, "R").unwrap();
        r.add_contact_by_id(&sp.cipher_id, "S").unwrap();
        convs.push(dm_to(&w, s, &mut r, &rp));
    }
    for s in senders.iter_mut() {
        set_profile(s, profile);
        s.transport.log.lock().unwrap().clear();
    }
    let mut seed = seed0;
    let t0 = w.clock.0.unix_secs();
    let mut due: Vec<u64> = (0..n).map(|_| lcg(&mut seed) % 10).collect();
    for t in 0..1200u64 {
        for i in 0..n {
            if lcg(&mut seed) % 90 == 0 {
                let _ = senders[i].send_text(&convs[i], &format!("m{t}"), None);
            }
            if t >= due[i] {
                let tr = senders[i].network_tick().unwrap();
                due[i] = t + tr.next_delay_ms.div_ceil(1000);
            }
        }
        w.clock.0.advance(1);
    }
    // relay view: real deliveries (time at the relay = request time + latency noise in [0.2, 1.5] s); link view: every send-shaped request per sender
    let mut sets = Vec::new();
    for i in 0..n {
        let log = senders[i].transport.log.lock().unwrap().clone();
        for e in log.iter().filter(|e| is_send_shaped(e) && e.queued) {
            let lat = 0.2 + (lcg(&mut seed) % 1300) as f64 / 1000.0;
            let t_relay = (e.t_secs - t0) as f64 + lat;
            // candidates: senders with a send-shaped request on their link in [t_relay - 1.5 - 0.5, t_relay - 0.2 + 0.5] (the attacker allows for the latency range)
            let mut c = 0;
            for j in 0..n {
                let lj = senders[j].transport.log.lock().unwrap().clone();
                if lj.iter().any(|x| {
                    is_send_shaped(x) && ((x.t_secs - t0) as f64) <= t_relay - 0.2 + 0.5 && ((x.t_secs - t0) as f64) >= t_relay - 1.5 - 0.5
                }) {
                    c += 1;
                }
            }
            sets.push((c.max(1), i));
        }
    }
    let k = sets.iter().map(|(c, _)| *c as f64).sum::<f64>() / sets.len().max(1) as f64;
    let acc = sets.iter().map(|(c, _)| 1.0 / *c as f64).sum::<f64>() / sets.len().max(1) as f64;
    (k, acc)
}

#[test]
fn end_to_end_timing_correlation_is_not_defeated_but_the_candidate_set_grows_with_cover() {
    let n = 6;
    let (k_std, acc_std) = correlation(NetworkProfile::Standard, n, 5);
    let (k_enh, acc_enh) = correlation(NetworkProfile::Enhanced, n, 5);
    println!("correlation, {n} senders -> 1 receiver: STANDARD candidate set {k_std:.2} (top-1 accuracy {acc_std:.2});  ENHANCED candidate set {k_enh:.2} (top-1 accuracy {acc_enh:.2})");
    assert!(k_std < 1.3, "without cover the real sender is nearly uniquely identified by timing: {k_std}");
    assert!(k_enh > k_std, "cover must at least enlarge the candidate set");
    // honest bound: it is NOT defeated — an attacker with both views still narrows to a small set.
    assert!(acc_enh > 1.0 / (n as f64) - 1e-9);
}

/// Application-layer cost of an idle, foreground client (what the user pays in data; excludes TLS and Tor cell overhead).
#[test]
fn idle_foreground_cost_per_hour_by_profile() {
    for (p, max_kb) in [(NetworkProfile::Standard, 600.0), (NetworkProfile::Enhanced, 1500.0)] {
        let w = World::new();
        let mut a = w.engine();
        set_profile(&mut a, p);
        a.transport.log.lock().unwrap().clear();
        let mut next_due = 0u64;
        for t in 0..1800u64 {
            if t >= next_due {
                next_due = t + a.network_tick().unwrap().next_delay_ms.div_ceil(1000);
            }
            w.clock.0.advance(1);
        }
        let log = a.transport.log.lock().unwrap().clone();
        let (up, down): (usize, usize) = log.iter().fold((0, 0), |(u, d), e| (u + e.req_bytes, d + e.resp_bytes));
        let kb_per_hour = (up + down) as f64 * 2.0 / 1024.0;
        println!(
            "idle {p:?}: {} requests / 30 min, {kb_per_hour:.0} KB/hour application-layer (up {} B, down {} B per 30 min)",
            log.len(),
            up,
            down
        );
        assert!(kb_per_hour < max_kb, "{p:?} {kb_per_hour}");
    }
}
