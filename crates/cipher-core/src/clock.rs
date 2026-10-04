//! Injectable time source so lock/inactivity/rate-limit logic is testable.
use std::time::Instant;

pub trait Clock: Send + Sync {
    /// Wall-clock seconds (persisted lockouts). Can be changed by the user: see docs.
    fn unix_secs(&self) -> u64;
    /// Monotonic seconds (inactivity timeout). Not affected by wall-clock changes.
    fn monotonic_secs(&self) -> u64;
    /// Wall-clock milliseconds (message timestamps; display only, never a security input).
    fn unix_millis(&self) -> u64 {
        self.unix_secs().saturating_mul(1000)
    }
}

#[derive(Debug)]
pub struct SystemClock {
    start: Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self { start: Instant::now() }
    }
}

impl Clock for SystemClock {
    fn unix_secs(&self) -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }
    fn monotonic_secs(&self) -> u64 {
        self.start.elapsed().as_secs()
    }
}

#[cfg(any(test, feature = "insecure-test-support"))]
pub mod testing {
    use super::Clock;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug, Default)]
    pub struct ManualClock {
        unix: AtomicU64,
        mono: AtomicU64,
    }
    impl ManualClock {
        pub fn new(unix: u64) -> Self {
            Self { unix: AtomicU64::new(unix), mono: AtomicU64::new(0) }
        }
        pub fn advance(&self, secs: u64) {
            self.unix.fetch_add(secs, Ordering::SeqCst);
            self.mono.fetch_add(secs, Ordering::SeqCst);
        }
    }
    impl Clock for ManualClock {
        fn unix_secs(&self) -> u64 {
            self.unix.load(Ordering::SeqCst)
        }
        fn monotonic_secs(&self) -> u64 {
            self.mono.load(Ordering::SeqCst)
        }
    }
}
