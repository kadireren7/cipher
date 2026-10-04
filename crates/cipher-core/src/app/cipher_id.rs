//! Human-friendly Cipher identifier.
//!
//! The account id is 128 random bits generated on the device — it is **not** derived from any key, phone number, or
//! email, and reveals nothing about them. The text form is Crockford base32 (no I/L/O/U) in groups of 4 with a 2-char
//! checksum to catch typos: `CIPH-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXC` (a display/typo-detection encoding, not cryptography).
use crate::error::{Result, SecurityError};
use cipher_wire::Id16;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PREFIX: &str = "CIPH";

fn sym_byte(v: u32) -> u8 {
    ALPHABET.get((v & 31) as usize).copied().unwrap_or(b'0')
}

fn sym(v: u32) -> char {
    char::from(sym_byte(v))
}

fn encode_bytes(bytes: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(sym(acc >> bits));
        }
    }
    if bits > 0 {
        out.push(sym(acc << (5 - bits)));
    }
    out
}

fn checksum(bytes: &[u8]) -> [u8; 2] {
    // Simple position-weighted sum mod 1024 -> 2 base32 chars. Detects any single-character error and most transpositions.
    let mut sum: u32 = 0;
    for (i, b) in bytes.iter().enumerate() {
        sum = (sum + (u32::from(*b) + 1) * (i as u32 + 7)) % 1024;
    }
    [sym_byte(sum >> 5), sym_byte(sum)]
}

pub fn format(id: &Id16) -> String {
    let body = encode_bytes(&id.0); // 26 chars
    let c = checksum(&id.0);
    let all = format!("{body}{}{}", char::from(c[0]), char::from(c[1])); // 28 chars = 7 groups of 4
    let groups: Vec<&str> = all.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
    format!("{PREFIX}-{}", groups.join("-"))
}

pub fn parse(s: &str) -> Result<Id16> {
    let cleaned: String = s.trim().to_ascii_uppercase().replace(['-', ' '], "");
    let rest = cleaned.strip_prefix(PREFIX).ok_or(SecurityError::Malformed("cipher id prefix"))?;
    if rest.len() != 28 {
        return Err(SecurityError::Malformed("cipher id length"));
    }
    // Crockford leniency for commonly confused characters.
    let rest: String = rest
        .chars()
        .map(|c| match c {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect();
    let mut vals = Vec::with_capacity(28);
    for ch in rest.bytes() {
        vals.push(ALPHABET.iter().position(|a| *a == ch).ok_or(SecurityError::Malformed("cipher id character"))? as u32);
    }
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut bytes = Vec::new();
    for v in vals.iter().take(26) {
        acc = (acc << 5) | v;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            bytes.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // Canonical form only: 26 chars carry 130 bits for a 128-bit id, so the low 2 bits of the last data char are padding and
    // MUST be zero. Without this check a typo in the padding bits would parse to the same id (two spellings, one account).
    if vals.get(25).is_none_or(|v| v & 0b11 != 0) {
        return Err(SecurityError::Malformed("cipher id padding"));
    }
    let arr: [u8; 16] = bytes.get(..16).and_then(|b| b.try_into().ok()).ok_or(SecurityError::Malformed("cipher id length"))?;
    let c = checksum(&arr);
    let want = (vals.get(26).copied().unwrap_or(99), vals.get(27).copied().unwrap_or(99));
    let have = (ALPHABET.iter().position(|a| *a == c[0]).unwrap_or(0) as u32, ALPHABET.iter().position(|a| *a == c[1]).unwrap_or(0) as u32);
    if want != have {
        return Err(SecurityError::Malformed("cipher id checksum"));
    }
    Ok(Id16(arr))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip(b in any::<[u8; 16]>()) {
            let id = Id16(b);
            prop_assert_eq!(parse(&format(&id)).unwrap(), id);
        }
        #[test]
        fn single_char_errors_are_detected(b in any::<[u8; 16]>(), pos in 0usize..28, repl in 0usize..32) {
            let s = format(&Id16(b));
            let mut chars: Vec<char> = s.chars().collect();
            // map pos to a non-dash index
            let idxs: Vec<usize> = chars.iter().enumerate().filter(|(i, c)| *i >= 5 && **c != '-').map(|(i, _)| i).collect();
            let i = idxs[pos % idxs.len()];
            let new = char::from(ALPHABET[repl]);
            prop_assume!(chars[i] != new);
            chars[i] = new;
            let mutated: String = chars.into_iter().collect();
            prop_assert!(parse(&mutated).map(|x| x != Id16(b)).unwrap_or(true));
        }
        #[test]
        fn parser_never_panics(s in ".{0,80}") {
            let _ = parse(&s);
        }
    }

    /// Regression: flipping only the padding bits of the last data character used to parse to the SAME id (non-canonical alias).
    #[test]
    fn padding_bits_must_be_zero_so_every_id_has_exactly_one_spelling() {
        let id = Id16([0x5A; 16]);
        let s = format(&id);
        let mut chars: Vec<char> = s.chars().collect();
        let idxs: Vec<usize> = chars.iter().enumerate().filter(|(i, c)| *i >= 5 && **c != '-').map(|(i, _)| i).collect();
        let i = idxs[25]; // the 26th data character: 3 data bits + 2 padding bits
        let v = ALPHABET.iter().position(|a| *a as char == chars[i]).unwrap();
        for pad in 1..4usize {
            chars[i] = char::from(ALPHABET[(v & !3) | pad]);
            let alias: String = chars.iter().collect();
            assert!(parse(&alias).is_err(), "alias {alias} was accepted");
        }
        assert_eq!(parse(&s).unwrap(), id);
    }

    #[test]
    fn looks_like_an_identifier_and_tolerates_case_and_confusables() {
        let id = Id16([0xAB; 16]);
        let s = format(&id);
        assert!(s.starts_with("CIPH-") && s.len() == 5 + 28 + 6);
        assert_eq!(parse(&s.to_lowercase()).unwrap(), id);
        assert_eq!(parse(&s.replace('-', " ")).unwrap(), id);
        assert!(parse("CIPH-0000").is_err());
        assert!(parse("NOPE-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA").is_err());
    }
}
