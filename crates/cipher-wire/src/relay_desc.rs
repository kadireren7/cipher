//! Relay Descriptor (docs/MULTI_RELAY_PROTOCOL.md §2): the NAME of a relay, nothing more.
//!
//! A descriptor says where a mailbox lives and how to recognise the relay's TLS identity. It is NOT a user identity and carries no authority over
//! one: user keys are pinned separately and can never be replaced through a descriptor.
//!
//! * `https` only (no cleartext, no downgrade). Host is lowercased; userinfo, paths, queries and fragments are refused.
//! * A `.onion` host REQUIRES a pin: onion relays use a self-signed certificate that no CA vouches for, so the pin from the invitation is the only
//!   thing that authenticates it (the app never disables certificate or host-name validation to accommodate it).
//! * A pin is the SHA-256 of the certificate's SubjectPublicKeyInfo (the same value OkHttp's `CertificatePinner` and curl's `--pinnedpubkey` use).
use serde::{Deserialize, Serialize};

pub const MAX_URL_LEN: usize = 255;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelayDescError {
    #[error("relay url must be https://host[:port]")]
    Url,
    #[error("onion relays require a certificate pin")]
    OnionNeedsPin,
    #[error("pin must be 32 bytes of base64url")]
    Pin,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayDescriptor {
    url: String,
    #[serde(default)]
    pin: Option<String>,
}

fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && !h.starts_with(['.', '-'])
        && !h.ends_with(['.', '-'])
        && !h.contains("..")
        && h.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

impl RelayDescriptor {
    pub fn new(url: &str, pin: Option<[u8; 32]>) -> Result<Self, RelayDescError> {
        let rest = url.strip_prefix("https://").ok_or(RelayDescError::Url)?;
        if url.len() > MAX_URL_LEN || rest.is_empty() || rest.contains(['/', '@', '?', '#', ' ', '\\', '%']) {
            return Err(RelayDescError::Url);
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        };
        if let Some(p) = port {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u16>().ok().is_none_or(|n| n == 0) {
                return Err(RelayDescError::Url);
            }
        }
        let host = host.to_ascii_lowercase();
        if !valid_host(&host) {
            return Err(RelayDescError::Url);
        }
        if host.ends_with(".onion") && pin.is_none() {
            return Err(RelayDescError::OnionNeedsPin);
        }
        let url = match port {
            Some(p) => format!("https://{host}:{p}"),
            None => format!("https://{host}"),
        };
        Ok(Self { url, pin: pin.map(|p| crate::b64::encode(&p)) })
    }

    /// Re-validates everything (used after deserialisation: `deny_unknown_fields` alone does not check the contents).
    pub fn validated(self) -> Result<Self, RelayDescError> {
        let pin = self.pin()?;
        let canonical = Self::new(&self.url, pin)?;
        if canonical.url != self.url {
            return Err(RelayDescError::Url); // must already be in canonical form
        }
        Ok(canonical)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn pin(&self) -> Result<Option<[u8; 32]>, RelayDescError> {
        match &self.pin {
            None => Ok(None),
            Some(p) => crate::b64::decode(p).and_then(|b| b.try_into().ok()).map(Some).ok_or(RelayDescError::Pin),
        }
    }

    /// Host (with port if explicit), as the signed-request audience uses it.
    pub fn host(&self) -> &str {
        self.url.strip_prefix("https://").unwrap_or(&self.url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "https://46qfvf5rr4gulgasuzud7la5izd4fjm555gvynfnuipkwtwhz7shbcad.onion";

    #[test]
    fn accepts_canonical_https_and_lowercases_the_host() {
        let d = RelayDescriptor::new("https://Relay.Example.org:8443", None).unwrap();
        assert_eq!(d.url(), "https://relay.example.org:8443");
        assert_eq!(d.host(), "relay.example.org:8443");
    }

    #[test]
    fn refuses_everything_that_is_not_plain_https_host_port() {
        for bad in [
            "http://relay.example.org",
            "relay.example.org",
            "https://",
            "https://user@relay.example.org",
            "https://relay.example.org/path",
            "https://relay.example.org?x=1",
            "https://relay.example.org#f",
            "https://relay.example.org:0",
            "https://relay.example.org:99999",
            "https://relay.example.org:",
            "https://re lay.example.org",
            "https://relay..example.org",
            "https://-relay.example.org",
            "https://relay.example.org%2f",
            "https://rélay.example.org",
            "ftp://relay.example.org",
            "https://relay.example.org\\@evil.example",
        ] {
            assert!(RelayDescriptor::new(bad, None).is_err(), "must refuse {bad}");
        }
    }

    #[test]
    fn onion_relays_require_a_pin_and_clearnet_relays_may_have_one() {
        assert_eq!(RelayDescriptor::new(ONION, None), Err(RelayDescError::OnionNeedsPin));
        assert!(RelayDescriptor::new(ONION, Some([7; 32])).is_ok());
        assert!(RelayDescriptor::new("https://relay.example.org", Some([7; 32])).is_ok());
    }

    #[test]
    fn deserialisation_cannot_smuggle_a_noncanonical_or_pinless_onion_descriptor() {
        let ok: RelayDescriptor = serde_json::from_str(&format!("{{\"url\":\"{ONION}\",\"pin\":\"{}\"}}", crate::b64::encode(&[1; 32]))).unwrap();
        assert!(ok.validated().is_ok());
        for bad in [
            format!("{{\"url\":\"{ONION}\"}}"),
            format!("{{\"url\":\"{ONION}\",\"pin\":\"AAAA\"}}"),
            "{\"url\":\"https://Relay.Example.org\"}".to_owned(),
            "{\"url\":\"http://relay.example.org\"}".to_owned(),
            "{\"url\":\"https://relay.example.org\",\"extra\":1}".to_owned(),
        ] {
            let r = serde_json::from_str::<RelayDescriptor>(&bad).map(RelayDescriptor::validated);
            assert!(!matches!(r, Ok(Ok(_))), "must refuse {bad}");
        }
    }
}
