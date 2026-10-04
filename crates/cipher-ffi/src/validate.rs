//! Hostile-input validation at the FFI edge.
use crate::error::CipherError;
use cipher_wire::Id16;

pub const MAX_TEXT_BYTES: usize = 48_000;
pub const MAX_NAME_BYTES: usize = 256;
pub const MAX_TOKEN_BYTES: usize = 512;
pub const MAX_PIN_BYTES: usize = 256;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_PAYLOAD_BYTES: usize = 4096;
pub const MAX_THUMB_BYTES: usize = 128 * 1024;
pub const MAX_LIST: usize = 200;

fn bad(what: &'static str) -> CipherError {
    CipherError::InvalidInput { what: what.to_owned() }
}

pub fn bounded<'a>(s: &'a str, max: usize, what: &'static str) -> Result<&'a str, CipherError> {
    if s.len() > max || s.contains('\0') {
        return Err(bad(what));
    }
    Ok(s)
}

pub fn id(s: &str, what: &'static str) -> Result<Id16, CipherError> {
    Id16::parse(s).map_err(|_| bad(what))
}

pub fn opt_id(s: &Option<String>, what: &'static str) -> Result<Option<Id16>, CipherError> {
    s.as_deref().map(|x| id(x, what)).transpose()
}

pub fn ids(v: &[String], what: &'static str) -> Result<Vec<Id16>, CipherError> {
    if v.len() > MAX_LIST {
        return Err(bad(what));
    }
    v.iter().map(|x| id(x, what)).collect()
}

/// Source files for attachments may only be file descriptors handed over by the app: `/proc/self/fd/<n>`.
/// (A hostile or buggy caller therefore cannot make the core read arbitrary files.) `extra_dir` exists for tests.
pub fn source_path<'a>(p: &'a str, extra_dir: Option<&str>) -> Result<&'a str, CipherError> {
    bounded(p, MAX_PATH_BYTES, "source path")?;
    if let Some(rest) = p.strip_prefix("/proc/self/fd/") {
        if !rest.is_empty() && rest.len() <= 6 && rest.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(p);
        }
        return Err(bad("source path"));
    }
    if let Some(dir) = extra_dir {
        let ok = p.starts_with(dir) && !p.contains("/../") && !p.ends_with("/..");
        if ok {
            return Ok(p);
        }
    }
    Err(bad("source path"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn id_parser_never_panics_and_only_accepts_canonical_hex(s in ".{0,60}") {
            if let Ok(i) = id(&s, "x") {
                prop_assert_eq!(i.to_hex(), s);
            }
        }
        #[test]
        fn source_paths_are_restricted(s in ".{0,80}") {
            if source_path(&s, None).is_ok() {
                prop_assert!(s.starts_with("/proc/self/fd/"));
                prop_assert!(s["/proc/self/fd/".len()..].bytes().all(|b| b.is_ascii_digit()));
            }
        }
    }

    #[test]
    fn explicit_cases() {
        assert!(source_path("/proc/self/fd/37", None).is_ok());
        for bad in [
            "/proc/self/fd/",
            "/proc/self/fd/../../etc/passwd",
            "/proc/self/fd/12a",
            "/etc/passwd",
            "relative",
            "/proc/self/fd/1234567",
            "/proc/self/fd/1\0",
        ] {
            assert!(source_path(bad, None).is_err(), "{bad}");
        }
        assert!(source_path("/data/x/../../etc/shadow", Some("/data/x")).is_err());
        assert!(bounded("a\0b", 10, "x").is_err() && bounded(&"a".repeat(11), 10, "x").is_err());
        assert!(id("A".repeat(32).as_str(), "x").is_err());
    }
}
