//! Message frame codec: strict JSON + length-hiding padding buckets.
//!
//! Frame layout before MLS encryption: `0x01 || u32_be(len) || json || zero padding` padded to a bucket size.
//! Buckets (bytes): 1 KiB, 2 KiB, … 64 KiB, then multiples of 64 KiB. MLS adds its own 128-byte padding on top.
//! The relay therefore sees only coarse size classes, not exact message lengths. (It still sees *that* a message of a
//! class was sent, to whom, and when.)
use super::model::Frame;
use crate::error::{Result, SecurityError};

pub const FRAME_VERSION: u8 = 1;
pub const MIN_BUCKET: usize = 1024;
pub const MAX_FRAME_BYTES: usize = 128 * 1024;
pub const MAX_TEXT_CHARS: usize = 8_000;

pub fn bucket_for(len: usize) -> usize {
    if len <= MIN_BUCKET {
        return MIN_BUCKET;
    }
    if len <= 64 * 1024 {
        return len.next_power_of_two();
    }
    len.div_ceil(64 * 1024) * 64 * 1024
}

pub fn encode(frame: &Frame) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(frame).map_err(|_| SecurityError::Malformed("frame encode"))?;
    let total = 1 + 4 + json.len();
    if total > MAX_FRAME_BYTES {
        return Err(SecurityError::Malformed("frame too large"));
    }
    let bucket = bucket_for(total);
    let mut out = Vec::with_capacity(bucket);
    out.push(FRAME_VERSION);
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(&json);
    out.resize(bucket, 0);
    Ok(out)
}

/// Strict decoder: wrong version, inconsistent length, non-zero padding or unknown fields are all errors.
pub fn decode(bytes: &[u8]) -> Result<Frame> {
    if bytes.len() < 5 || bytes.len() > MAX_FRAME_BYTES * 2 {
        return Err(SecurityError::Malformed("frame length"));
    }
    if bytes.first() != Some(&FRAME_VERSION) {
        return Err(SecurityError::Malformed("frame version"));
    }
    let len = u32::from_be_bytes(bytes.get(1..5).and_then(|b| b.try_into().ok()).ok_or(SecurityError::Malformed("frame length"))?) as usize;
    let json = bytes.get(5..5 + len).ok_or(SecurityError::Malformed("frame length"))?;
    let pad = bytes.get(5 + len..).ok_or(SecurityError::Malformed("frame length"))?;
    if pad.iter().any(|b| *b != 0) || bytes.len() != bucket_for(5 + len) {
        return Err(SecurityError::Malformed("frame padding"));
    }
    let f: Frame = serde_json::from_slice(json).map_err(|_| SecurityError::Malformed("frame json"))?;
    if f.v != FRAME_VERSION {
        return Err(SecurityError::Malformed("frame version"));
    }
    Ok(f)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::app::model::Content;
    use cipher_wire::Id16;
    use proptest::prelude::*;

    fn text(n: usize) -> Frame {
        Frame { v: 1, id: Id16([1; 16]), ts_ms: 5, reply_to: None, content: Content::Text { body: "a".repeat(n) } }
    }

    #[test]
    fn buckets_hide_exact_length_and_roundtrip() {
        let sizes: std::collections::BTreeSet<usize> = (0..400).map(|n| encode(&text(n)).unwrap().len()).collect();
        assert!(sizes.len() <= 3, "400 distinct lengths collapse into few buckets: {sizes:?}");
        for n in [0, 1, 100, 300, 5000, 60_000] {
            let f = text(n);
            let b = encode(&f).unwrap();
            assert_eq!(decode(&b).unwrap(), f);
            assert!(b.len() == bucket_for(b.len()));
        }
        assert!(encode(&text(MAX_FRAME_BYTES)).is_err());
    }

    #[test]
    fn receipts_control_frames_and_short_texts_share_one_size_class() {
        let receipt =
            Frame { v: 1, id: Id16([2; 16]), ts_ms: 5, reply_to: None, content: Content::Receipt { ids: vec![Id16([3; 16]); 8] } };
        let cap = Frame { v: 1, id: Id16([4; 16]), ts_ms: 5, reply_to: None, content: Content::DeliveryCap { cap: Id16([5; 16]) } };
        let sizes: std::collections::BTreeSet<usize> = [
            encode(&receipt).unwrap().len(),
            encode(&cap).unwrap().len(),
            encode(&text(1)).unwrap().len(),
            encode(&text(500)).unwrap().len(),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            sizes.len(),
            1,
            "a link observer cannot tell a receipt, a capability announcement and a short text apart by size: {sizes:?}"
        );
        assert_eq!(*sizes.iter().next().unwrap(), MIN_BUCKET);
        assert_eq!(
            decode(&encode(&cap).unwrap()).unwrap(),
            cap,
            "padding is authenticated by MLS and rejected unless zero: semantics cannot change"
        );
    }

    #[test]
    fn strict_decoding() {
        let good = encode(&text(10)).unwrap();
        let mut bad = good.clone();
        *bad.last_mut().unwrap() = 1;
        assert!(decode(&bad).is_err(), "non-zero padding");
        let mut bad = good.clone();
        bad[0] = 2;
        assert!(decode(&bad).is_err(), "version");
        assert!(decode(&good[..good.len() - 1]).is_err(), "truncated (bucket mismatch)");
        let mut longer = good.clone();
        longer.extend_from_slice(&[0; 512]);
        assert!(decode(&longer).is_err(), "extra padding beyond the bucket");
        assert!(decode(&[]).is_err() && decode(&[1, 0, 0, 0, 9]).is_err());
        let mut j = good.clone();
        j[5] = b'[';
        assert!(decode(&j).is_err());
    }

    proptest! {
        #[test]
        fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1500)) {
            let _ = decode(&bytes);
        }
        #[test]
        fn bucket_is_monotone_and_bounded(n in 0usize..300_000) {
            let b = bucket_for(n);
            prop_assert!(b >= n && b >= MIN_BUCKET);
            prop_assert!(b <= n.max(MIN_BUCKET) * 2 + 65_536);
        }
    }
}
