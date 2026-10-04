//! 128-bit random identifiers, generated client-side so the server is not
//! trusted to pick them. Strict lowercase-hex text form.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id16(pub [u8; 16]);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdError {
    #[error("identifier must be exactly 32 lowercase hex characters")]
    Malformed,
}

impl Id16 {
    pub fn parse(s: &str) -> Result<Self, IdError> {
        let b = s.as_bytes();
        if b.len() != 32 {
            return Err(IdError::Malformed);
        }
        let mut out = [0u8; 16];
        for (i, pair) in b.chunks_exact(2).enumerate() {
            let hi = nibble(pair.first().copied())?;
            let lo = nibble(pair.get(1).copied())?;
            if let Some(slot) = out.get_mut(i) {
                *slot = (hi << 4) | lo;
            }
        }
        Ok(Id16(out))
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(32);
        for byte in self.0 {
            for n in [byte >> 4, byte & 0x0f] {
                s.push(char::from_digit(u32::from(n), 16).unwrap_or('0'));
            }
        }
        s
    }
}

fn nibble(c: Option<u8>) -> Result<u8, IdError> {
    match c {
        Some(c @ b'0'..=b'9') => Ok(c - b'0'),
        Some(c @ b'a'..=b'f') => Ok(c - b'a' + 10),
        _ => Err(IdError::Malformed),
    }
}

impl fmt::Debug for Id16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id16({})", self.to_hex())
    }
}
impl fmt::Display for Id16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}
impl Serialize for Id16 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}
impl<'de> Deserialize<'de> for Id16 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Id16::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip(bytes in any::<[u8; 16]>()) {
            let id = Id16(bytes);
            prop_assert_eq!(Id16::parse(&id.to_hex()), Ok(id));
        }

        #[test]
        fn parser_never_panics(s in ".{0,80}") {
            let _ = Id16::parse(&s);
        }
    }

    #[test]
    fn rejects_uppercase_and_wrong_length() {
        assert!(Id16::parse(&"A".repeat(32)).is_err());
        assert!(Id16::parse("abcd").is_err());
        assert!(Id16::parse(&"g".repeat(32)).is_err());
    }
}
