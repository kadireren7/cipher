//! Invitation link codec and policy limits (docs/INVITATIONS.md §3–§4).
//!
//! A link is `cipher-invite:v1:` + base64url(`version(1) | secret(16) | flags(1) | [pin(32)] | url_len(1) | url`). It carries the invitation SECRET and
//! the issuer's relay descriptor, nothing else: no group name, no member list, no key of any group. The secret is a bearer secret; everything derived
//! from it (lookup id, preview key, request MAC key) is derived in `cipher-core`. This module only encodes and strictly parses bytes: it performs no
//! cryptography, and it never prints the secret (`Debug` is redacted, so a stray `{:?}` cannot put it in a log).
use crate::relay_desc::{RelayDescError, RelayDescriptor};

pub const LINK_PREFIX: &str = "cipher-invite:v1:";
pub const VERSION: u8 = 1;
pub const SECRET_LEN: usize = 16;
/// A link is a QR code and a clipboard string: anything longer is not a link.
pub const MAX_LINK_LEN: usize = 512;

pub const MIN_LIFETIME_MS: u64 = 60_000;
pub const DEFAULT_LIFETIME_MS: u64 = 24 * 3_600_000;
pub const MAX_LIFETIME_MS: u64 = 7 * 24 * 3_600_000;
pub const MAX_USES: u32 = 100;
/// Automatic admission is a convenience with a higher risk (the first holders in are admitted), so it is capped hard.
pub const AUTO_MAX_USES: u32 = 10;
pub const AUTO_MAX_LIFETIME_MS: u64 = 24 * 3_600_000;

/// What a relay stores and looks up by: `SHA-256("cipher-inv-idhash-v1" || 0x00 || id)`. The relay never keeps `id` itself, so a database leak
/// does not hand out usable invitation identifiers (docs/INVITATIONS.md §3).
pub fn id_hash(id: &[u8; 16]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"cipher-inv-idhash-v1\0");
    h.update(id);
    h.finalize().into()
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InviteError {
    #[error("not a Cipher invitation link")]
    Prefix,
    #[error("invitation link is too long")]
    TooLong,
    #[error("invitation link is not canonical base64url")]
    Encoding,
    #[error("unsupported invitation version")]
    Version,
    #[error("invitation link is truncated")]
    Truncated,
    #[error("invitation link has trailing data")]
    Trailing,
    #[error("invalid relay in the invitation: {0}")]
    Relay(#[from] RelayDescError),
    #[error("invitation policy refused: {0}")]
    Policy(&'static str),
}

#[derive(Clone, PartialEq, Eq)]
pub struct InviteLink {
    secret: [u8; SECRET_LEN],
    relay: RelayDescriptor,
}

impl core::fmt::Debug for InviteLink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InviteLink").field("secret", &"<redacted>").field("relay", &self.relay).finish()
    }
}

impl InviteLink {
    pub fn new(secret: [u8; SECRET_LEN], relay: RelayDescriptor) -> Self {
        Self { secret, relay }
    }

    pub fn secret(&self) -> &[u8; SECRET_LEN] {
        &self.secret
    }

    pub fn relay(&self) -> &RelayDescriptor {
        &self.relay
    }

    /// The link text, as shown in a QR code or copied. Infallible: a `RelayDescriptor` is already validated and its URL is at most 255 bytes.
    pub fn encode(&self) -> String {
        let url = self.relay.url().as_bytes();
        let pin = self.relay.pin().ok().flatten();
        let mut b = Vec::with_capacity(2 + SECRET_LEN + 33 + url.len());
        b.push(VERSION);
        b.extend_from_slice(&self.secret);
        b.push(u8::from(pin.is_some()));
        if let Some(p) = pin {
            b.extend_from_slice(&p);
        }
        b.push(url.len() as u8); // <= 255 by RelayDescriptor::MAX_URL_LEN
        b.extend_from_slice(url);
        format!("{LINK_PREFIX}{}", crate::b64::encode(&b))
    }

    /// Strict parse. Surrounding ASCII whitespace (a paste artefact) is tolerated; everything else must be exact: prefix, canonical base64url,
    /// version, flags, lengths, a canonical relay descriptor, and no trailing bytes.
    pub fn parse(text: &str) -> Result<Self, InviteError> {
        let t = text.trim_matches(|c: char| c.is_ascii_whitespace());
        if t.len() > MAX_LINK_LEN {
            return Err(InviteError::TooLong);
        }
        let body = t.strip_prefix(LINK_PREFIX).ok_or(InviteError::Prefix)?;
        let raw = crate::b64::decode(body).ok_or(InviteError::Encoding)?;
        if crate::b64::encode(&raw) != body {
            return Err(InviteError::Encoding); // non-canonical alphabet or padding
        }
        let mut r = Reader(&raw);
        if r.byte()? != VERSION {
            return Err(InviteError::Version);
        }
        let secret: [u8; SECRET_LEN] = r.take(SECRET_LEN)?.try_into().map_err(|_| InviteError::Truncated)?;
        let pin = match r.byte()? {
            0 => None,
            1 => Some(<[u8; 32]>::try_from(r.take(32)?).map_err(|_| InviteError::Truncated)?),
            _ => return Err(InviteError::Encoding),
        };
        let url_len = usize::from(r.byte()?);
        let url = core::str::from_utf8(r.take(url_len)?).map_err(|_| InviteError::Encoding)?;
        if !r.0.is_empty() {
            return Err(InviteError::Trailing);
        }
        let relay = RelayDescriptor::new(url, pin)?;
        if relay.url() != url {
            return Err(InviteError::Relay(RelayDescError::Url)); // must already be canonical (no aliases for one relay)
        }
        Ok(Self { secret, relay })
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], InviteError> {
        if self.0.len() < n {
            return Err(InviteError::Truncated);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, InviteError> {
        self.take(1)?.first().copied().ok_or(InviteError::Truncated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinMode {
    /// An admin sees who is asking (and their safety number) and approves or rejects. The default.
    Approval,
    /// The issuing admin's device admits requesters itself, within the tight caps below.
    Auto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvitePolicy {
    pub lifetime_ms: u64,
    pub max_uses: u32,
    pub mode: JoinMode,
}

impl InvitePolicy {
    /// 24 hours, one use, approval by an admin.
    pub const fn default_single_use() -> Self {
        Self { lifetime_ms: DEFAULT_LIFETIME_MS, max_uses: 1, mode: JoinMode::Approval }
    }

    /// The one place the limits are decided; the relay and the client both call it.
    pub fn validate(&self) -> Result<(), InviteError> {
        if !(MIN_LIFETIME_MS..=MAX_LIFETIME_MS).contains(&self.lifetime_ms) {
            return Err(InviteError::Policy("lifetime must be between 1 minute and 7 days"));
        }
        if !(1..=MAX_USES).contains(&self.max_uses) {
            return Err(InviteError::Policy("uses must be between 1 and 100"));
        }
        if self.mode == JoinMode::Auto && (self.max_uses > AUTO_MAX_USES || self.lifetime_ms > AUTO_MAX_LIFETIME_MS) {
            return Err(InviteError::Policy("automatic admission is limited to 10 uses and 24 hours"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ONION: &str = "https://46qfvf5rr4gulgasuzud7la5izd4fjm555gvynfnuipkwtwhz7shbcad.onion";

    fn link(url: &str, pin: Option<[u8; 32]>) -> InviteLink {
        InviteLink::new([7u8; 16], RelayDescriptor::new(url, pin).unwrap())
    }

    #[test]
    fn a_link_round_trips_with_and_without_a_pin() {
        for l in
            [link("https://relay.example.org", None), link("https://relay.example.org:8443", Some([9u8; 32])), link(ONION, Some([3u8; 32]))]
        {
            let text = l.encode();
            assert!(text.starts_with(LINK_PREFIX));
            assert!(text.len() <= MAX_LINK_LEN);
            assert_eq!(InviteLink::parse(&text).unwrap(), l);
        }
    }

    #[test]
    fn surrounding_whitespace_from_a_paste_is_tolerated_but_nothing_else() {
        let text = link("https://relay.example.org", None).encode();
        assert!(InviteLink::parse(&format!("  {text}\n")).is_ok());
        assert_eq!(InviteLink::parse(&format!("{text} x")), Err(InviteError::Encoding));
        assert_eq!(InviteLink::parse(&format!("x{text}")), Err(InviteError::Prefix));
    }

    #[test]
    fn the_debug_output_never_contains_the_secret() {
        let l = InviteLink::new([0xAB; 16], RelayDescriptor::new("https://relay.example.org", None).unwrap());
        let shown = format!("{l:?}");
        assert!(shown.contains("<redacted>"));
        assert!(!shown.contains("171") && !shown.to_lowercase().contains("abab"), "{shown}");
        assert!(!shown.contains(&crate::b64::encode(l.secret())));
    }

    #[test]
    fn an_onion_relay_without_a_pin_is_refused_when_parsing() {
        // Hand-build a link whose relay is an onion host with no pin: the codec must not construct it even though the bytes are well formed.
        let mut b = vec![VERSION];
        b.extend_from_slice(&[1u8; 16]);
        b.push(0);
        b.push(ONION.len() as u8);
        b.extend_from_slice(ONION.as_bytes());
        let text = format!("{LINK_PREFIX}{}", crate::b64::encode(&b));
        assert_eq!(InviteLink::parse(&text), Err(InviteError::Relay(RelayDescError::OnionNeedsPin)));
    }

    #[test]
    fn malformed_links_are_refused() {
        let good = link("https://relay.example.org", Some([1u8; 32]));
        let text = good.encode();
        let raw = crate::b64::decode(text.strip_prefix(LINK_PREFIX).unwrap()).unwrap();
        let wrap = |bytes: &[u8]| format!("{LINK_PREFIX}{}", crate::b64::encode(bytes));
        // unknown version
        let mut v = raw.clone();
        v[0] = 2;
        assert_eq!(InviteLink::parse(&wrap(&v)), Err(InviteError::Version));
        // trailing byte
        let mut t = raw.clone();
        t.push(0);
        assert_eq!(InviteLink::parse(&wrap(&t)), Err(InviteError::Trailing));
        // every truncation
        for n in 0..raw.len() {
            assert!(InviteLink::parse(&wrap(&raw[..n])).is_err(), "truncated to {n}");
        }
        // a flags byte that is neither 0 nor 1
        let mut f = raw.clone();
        f[1 + SECRET_LEN] = 2;
        assert!(InviteLink::parse(&wrap(&f)).is_err());
        // padding / wrong alphabet is not canonical
        assert_eq!(InviteLink::parse(&format!("{text}=")), Err(InviteError::Encoding));
        // too long
        assert_eq!(InviteLink::parse(&format!("{LINK_PREFIX}{}", "A".repeat(MAX_LINK_LEN))), Err(InviteError::TooLong));
        // a relay URL that is not canonical (upper-case host) is refused: one relay, one spelling
        let mut u = vec![VERSION];
        u.extend_from_slice(&[1u8; 16]);
        u.push(0);
        let url = b"https://Relay.Example.org";
        u.push(url.len() as u8);
        u.extend_from_slice(url);
        assert_eq!(InviteLink::parse(&wrap(&u)), Err(InviteError::Relay(RelayDescError::Url)));
        assert_eq!(InviteLink::parse(""), Err(InviteError::Prefix));
    }

    #[test]
    fn the_stored_identifier_is_a_domain_separated_hash_of_the_id() {
        let a = id_hash(&[1u8; 16]);
        assert_eq!(a, id_hash(&[1u8; 16]));
        assert_ne!(a, id_hash(&[2u8; 16]));
        assert_ne!(a.as_slice(), [1u8; 16].as_slice());
        // not the plain hash of the id: the label separates it from every other use of SHA-256 over 16 bytes
        use sha2::{Digest, Sha256};
        assert_ne!(a.as_slice(), Sha256::digest([1u8; 16]).as_slice());
    }

    #[test]
    fn the_default_policy_is_valid_and_the_limits_are_enforced() {
        assert!(InvitePolicy::default_single_use().validate().is_ok());
        let ok = |lifetime_ms, max_uses, mode| InvitePolicy { lifetime_ms, max_uses, mode }.validate().is_ok();
        assert!(ok(MIN_LIFETIME_MS, 1, JoinMode::Approval));
        assert!(ok(MAX_LIFETIME_MS, MAX_USES, JoinMode::Approval));
        assert!(!ok(MIN_LIFETIME_MS - 1, 1, JoinMode::Approval));
        assert!(!ok(MAX_LIFETIME_MS + 1, 1, JoinMode::Approval));
        assert!(!ok(DEFAULT_LIFETIME_MS, 0, JoinMode::Approval));
        assert!(!ok(DEFAULT_LIFETIME_MS, MAX_USES + 1, JoinMode::Approval));
        // automatic admission: at most 10 uses and 24 hours, regardless of anything else
        assert!(ok(AUTO_MAX_LIFETIME_MS, AUTO_MAX_USES, JoinMode::Auto));
        assert!(!ok(AUTO_MAX_LIFETIME_MS, AUTO_MAX_USES + 1, JoinMode::Auto));
        assert!(!ok(AUTO_MAX_LIFETIME_MS + 1, 1, JoinMode::Auto));
        assert!(!ok(MAX_LIFETIME_MS, MAX_USES, JoinMode::Auto));
    }

    proptest! {
        #[test]
        fn encode_parse_is_the_identity(secret in any::<[u8; 16]>(), pin in proptest::option::of(any::<[u8; 32]>()), port in 1u16..=65535) {
            let l = InviteLink::new(secret, RelayDescriptor::new(&format!("https://relay.example.org:{port}"), pin).unwrap());
            prop_assert_eq!(InviteLink::parse(&l.encode()).unwrap(), l);
        }

        #[test]
        fn parsing_arbitrary_text_never_panics(s in ".{0,700}") {
            let _ = InviteLink::parse(&s);
        }

        #[test]
        fn parsing_arbitrary_bytes_behind_the_prefix_never_panics(b in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = InviteLink::parse(&format!("{LINK_PREFIX}{}", crate::b64::encode(&b)));
        }
    }
}
