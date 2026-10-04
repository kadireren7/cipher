//! Logging policy (SEC-010, PRIV-008): request/response bodies, ciphertext, device/account ids, capabilities, tokens and IP addresses are
//! never logged. Per-request lines are DEBUG (off by default) so the default log is not an activity record; whatever is logged carries a
//! timestamp rounded DOWN to a whole minute, so logs cannot be used to correlate individual requests. Structured JSON by default so
//! attacker-controlled text cannot confuse log pipelines.
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::EnvFilter;

/// UTC time rounded down to the minute (`2026-10-04T12:55:00Z`).
#[derive(Debug)]
pub struct CoarseTime;

impl FormatTime for CoarseTime {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        w.write_str(&format_minute(secs))
    }
}

/// `unix_secs` -> `YYYY-MM-DDTHH:MM:00Z` (civil-from-days, proleptic Gregorian).
pub fn format_minute(unix_secs: u64) -> String {
    let minutes = unix_secs / 60;
    let (days, mod_min) = (minutes / 1440, minutes % 1440);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:00Z", mod_min / 60, mod_min % 60)
}

pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false).with_target(false).with_timer(CoarseTime);
    if std::env::var("CIPHER_RELAY_LOG_FORMAT").is_ok_and(|v| v == "pretty") {
        let _ = builder.try_init();
    } else {
        let _ = builder.json().flatten_event(true).try_init();
    }
}

#[cfg(test)]
mod tests {
    use super::format_minute;

    #[test]
    fn timestamps_are_rounded_down_to_the_minute() {
        assert_eq!(format_minute(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_minute(86_399), "1970-01-01T23:59:00Z");
        assert_eq!(format_minute(1_791_118_743), "2026-10-04T12:59:00Z");
        assert_eq!(format_minute(1_791_118_759), format_minute(1_791_118_743), "seconds within a minute are indistinguishable");
        assert_eq!(format_minute(951_782_400), "2000-02-29T00:00:00Z");
    }
}
