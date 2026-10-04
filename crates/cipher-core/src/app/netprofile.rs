//! Network behaviour profiles (docs/PRIVACY_TRANSPORT_REVIEW.md): how often the client talks to the relay and when it sends.
//!
//! STANDARD: a poll every ~4 s while the app is in the foreground and sends leave immediately (lowest latency).
//! ENHANCED: a poll on a jittered ~10 s cadence; sends are held until the next tick and every tick carries exactly one send-shaped request
//! (a real delivery, or a bounded dummy of the same size class) so a link observer cannot see WHEN the user sends. It does NOT hide that the
//! user is online, and it does nothing against an observer who sees both ends (end-to-end timing correlation) — see the review's experiments.
//!
//! Cost (ENHANCED, foreground only): ~360 ticks/hour, each one GET plus one ~1.7 KB POST. Nothing runs in the background.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkProfile {
    #[default]
    Standard,
    Enhanced,
}

/// Ciphertext length of a minimal real message (frame bucket + MLS overhead). Dummy deliveries use the same length so both fall in one size class;
/// a unit test fails if the real size changes.
pub const COVER_CIPHERTEXT_BYTES: usize = 1214;

impl NetworkProfile {
    pub fn base_interval_ms(self) -> u64 {
        match self {
            NetworkProfile::Standard => 4_000,
            NetworkProfile::Enhanced => 10_000,
        }
    }

    /// ± this many per mille of the base interval.
    pub fn jitter_permille(self) -> u64 {
        match self {
            NetworkProfile::Standard => 100,
            NetworkProfile::Enhanced => 250,
        }
    }

    pub fn holds_sends_until_tick(self) -> bool {
        self == NetworkProfile::Enhanced
    }

    pub fn sends_cover(self) -> bool {
        self == NetworkProfile::Enhanced
    }

    /// Delay before the next tick; `entropy` is any uniformly random u32.
    pub fn next_delay_ms(self, entropy: u32) -> u64 {
        let base = self.base_interval_ms();
        let j = self.jitter_permille();
        let span = 2 * j + 1;
        let permille = 1000 - j + u64::from(entropy) % span;
        base * permille / 1000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delays_stay_inside_the_jitter_window_and_enhanced_is_slower() {
        for p in [NetworkProfile::Standard, NetworkProfile::Enhanced] {
            let (lo, hi) =
                (p.base_interval_ms() * (1000 - p.jitter_permille()) / 1000, p.base_interval_ms() * (1000 + p.jitter_permille()) / 1000);
            for e in [0u32, 1, 12345, u32::MAX / 2, u32::MAX] {
                let d = p.next_delay_ms(e);
                assert!(d >= lo && d <= hi, "{p:?} {d}");
            }
        }
        assert!(NetworkProfile::Enhanced.next_delay_ms(0) > NetworkProfile::Standard.next_delay_ms(u32::MAX));
    }
}
