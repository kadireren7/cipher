#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
use cipher_core::attachment::*;
use cipher_core::error::SecurityError;
use proptest::prelude::*;

fn png(n: usize) -> Vec<u8> {
    let mut v = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    v.extend((0..n).map(|i| (i % 251) as u8));
    v
}

#[test]
fn roundtrip_across_chunk_boundaries() {
    for extra in
        [0usize, 1, 100, CHUNK_PLAINTEXT_BYTES - 9, CHUNK_PLAINTEXT_BYTES - 8, CHUNK_PLAINTEXT_BYTES, 3 * CHUNK_PLAINTEXT_BYTES + 7]
    {
        let pt = png(extra);
        let (ct, d) = encrypt_attachment(&pt, "image/png", "a.png").unwrap();
        assert_eq!(ct.len() as u64, d.ciphertext_len);
        assert_eq!(ct.len() as u64, ciphertext_len_for(pt.len() as u64));
        assert_eq!(decrypt_attachment(&ct, &d).unwrap().as_slice(), pt.as_slice(), "len {}", pt.len());
    }
}

#[test]
fn storage_provider_sees_only_ciphertext() {
    let secret = b"PLAINTEXT-FIXTURE-attachment-bytes-5521".repeat(50);
    let mut pt = png(0);
    pt.extend(&secret);
    let (ct, _) = encrypt_attachment(&pt, "image/png", "holiday-photo.png").unwrap();
    assert!(!ct.windows(24).any(|w| w == &secret[..24]));
    assert!(!ct.windows(5).any(|w| w == b"photo"), "filename must not appear in the blob");
    assert!(!ct.windows(9).any(|w| w == b"image/png"), "mime must not appear in the blob");
}

#[test]
fn each_attachment_gets_fresh_key_and_nonce() {
    let pt = png(10);
    let (c1, d1) = encrypt_attachment(&pt, "image/png", "a").unwrap();
    let (c2, d2) = encrypt_attachment(&pt, "image/png", "a").unwrap();
    assert_ne!(c1, c2);
    assert_ne!(d1.to_bytes().unwrap().as_slice(), d2.to_bytes().unwrap().as_slice());
    // Decrypting with the other attachment's key fails.
    assert!(decrypt_attachment(&c1, &d2).is_err());
}

#[test]
fn modified_ciphertext_is_rejected_everywhere() {
    let pt = png(2 * CHUNK_PLAINTEXT_BYTES + 5);
    let (ct, d) = encrypt_attachment(&pt, "image/png", "a").unwrap();
    let step = ct.len() / 64;
    for i in (0..ct.len()).step_by(step) {
        let mut bad = ct.clone();
        bad[i] ^= 1;
        assert!(decrypt_attachment(&bad, &d).is_err(), "byte {i}");
    }
}

#[test]
fn truncation_extension_and_reordering_detected_even_if_hash_is_recomputed() {
    // Attacker controls storage AND rewrites the descriptor hash? They cannot: descriptor is E2EE.
    // But the AEAD stream layer must independently catch structural attacks, so bypass the hash check
    // by building descriptors that match the manipulated bytes.
    use sha2::{Digest, Sha256};
    let pt = png(3 * CHUNK_PLAINTEXT_BYTES);
    let (ct, d) = encrypt_attachment(&pt, "image/png", "a").unwrap();
    let step = CHUNK_PLAINTEXT_BYTES + 16;
    let header = 13;
    let rewrap = |bytes: Vec<u8>| {
        let mut j: serde_json::Value = serde_json::from_slice(&d.to_bytes().unwrap()).unwrap();
        j["ciphertext_sha256"] = serde_json::Value::String(cipher_wire::b64::encode(&Sha256::digest(&bytes)));
        j["ciphertext_len"] = serde_json::Value::from(bytes.len() as u64);
        (bytes, serde_json::to_vec(&j).unwrap())
    };
    // Reorder first two chunks.
    let mut re = ct.clone();
    let (a, b) = (ct[header..header + step].to_vec(), ct[header + step..header + 2 * step].to_vec());
    re[header..header + step].copy_from_slice(&b);
    re[header + step..header + 2 * step].copy_from_slice(&a);
    let (bytes, dj) = rewrap(re);
    let dd: AttachmentDescriptor = serde_json::from_slice(&dj).unwrap();
    assert!(decrypt_attachment_unchecked_len(&bytes, &dd).is_err(), "reordering must be detected by the AEAD stream");
    // Drop the final chunk (truncate at chunk boundary).
    let tr = ct[..ct.len() - step].to_vec();
    let (bytes, dj) = rewrap(tr);
    let dd: AttachmentDescriptor = serde_json::from_slice(&dj).unwrap();
    assert!(decrypt_attachment_unchecked_len(&bytes, &dd).is_err(), "truncation at a chunk boundary must be detected");
}

/// Helper: the public API checks `ciphertext_len` against plaintext_len first; for this structural test we
/// need to reach the AEAD layer, so also fix plaintext_len up to match.
fn decrypt_attachment_unchecked_len(ct: &[u8], d: &AttachmentDescriptor) -> Result<(), SecurityError> {
    let mut j: serde_json::Value = serde_json::from_slice(&d.to_bytes().unwrap()).unwrap();
    // Choose the plaintext_len whose canonical ciphertext length equals ct.len(), if one exists.
    let target = ct.len() as u64;
    let pl = (0..=3 * CHUNK_PLAINTEXT_BYTES as u64 + 1).rev().find(|p| ciphertext_len_for(*p) == target);
    match pl {
        Some(p) => {
            j["plaintext_len"] = serde_json::Value::from(p);
            let dd: AttachmentDescriptor = serde_json::from_slice(&serde_json::to_vec(&j).unwrap()).unwrap();
            decrypt_attachment(ct, &dd).map(|_| ())
        }
        None => decrypt_attachment(ct, d).map(|_| ()),
    }
}

#[test]
fn truncated_garbage_and_wrong_sizes_rejected() {
    let (ct, d) = encrypt_attachment(&png(100), "image/png", "a").unwrap();
    for bad in [vec![], ct[..10].to_vec(), ct[..ct.len() - 1].to_vec(), [ct.clone(), vec![0]].concat()] {
        assert!(decrypt_attachment(&bad, &d).is_err());
    }
}

#[test]
fn size_limit_enforced() {
    let big = vec![0u8; MAX_ATTACHMENT_PLAINTEXT_BYTES as usize + 1];
    assert!(matches!(encrypt_attachment(&big, "application/octet-stream", "x"), Err(SecurityError::Attachment(_))));
}

#[test]
fn mime_allowlist_and_magic_bytes() {
    assert!(encrypt_attachment(b"x", "text/html", "x.html").is_err());
    assert!(encrypt_attachment(b"x", "image/png; charset=utf-8", "x").is_err());
    assert!(encrypt_attachment(b"x", "IMAGE/PNG", "x").is_err());
    assert!(encrypt_attachment(b"<html>", "image/png", "x.png").is_err(), "content must match declared type");
    assert!(encrypt_attachment(b"%PDF-1.7", "image/jpeg", "x.jpg").is_err());
    assert!(encrypt_attachment(&[0xff, 0xfe, 0xfd], "text/plain", "x.txt").is_err(), "invalid UTF-8 text");
    assert!(encrypt_attachment(b"%PDF-1.7 ...", "application/pdf", "x.pdf").is_ok());
    assert!(encrypt_attachment(b"anything", "application/octet-stream", "blob").is_ok());
}

#[test]
fn filename_sanitisation() {
    assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
    assert_eq!(sanitize_filename("C:\\Windows\\system32\\evil.exe"), "evil.exe");
    assert_eq!(sanitize_filename(".hidden"), "hidden");
    assert_eq!(sanitize_filename(""), "file");
    assert_eq!(sanitize_filename("///"), "file");
    assert_eq!(sanitize_filename("a\u{0000}b\nc.txt"), "abc.txt");
    assert_eq!(sanitize_filename("photo\u{202E}gnp.exe"), "photognp.exe", "bidi override stripped");
    assert!(sanitize_filename(&"é".repeat(500)).len() <= MAX_FILENAME_BYTES);
    assert_eq!(sanitize_filename("e\u{0301}.txt"), "\u{e9}.txt", "NFC normalised");
    assert_eq!(sanitize_filename("a:b*c?.txt"), "abc.txt");
}

#[test]
fn descriptor_validation_rejects_inconsistent_or_hostile_input() {
    let (_, d) = encrypt_attachment(&png(10), "image/png", "a.png").unwrap();
    let good = d.to_bytes().unwrap();
    assert!(AttachmentDescriptor::from_bytes(&good).is_ok());
    let mut j: serde_json::Value = serde_json::from_slice(&good).unwrap();
    j["mime"] = "text/html".into();
    assert!(AttachmentDescriptor::from_bytes(&serde_json::to_vec(&j).unwrap()).is_err());
    let mut j: serde_json::Value = serde_json::from_slice(&good).unwrap();
    j["filename"] = "../x".into();
    assert!(AttachmentDescriptor::from_bytes(&serde_json::to_vec(&j).unwrap()).is_err());
    let mut j: serde_json::Value = serde_json::from_slice(&good).unwrap();
    j["plaintext_len"] = (MAX_ATTACHMENT_PLAINTEXT_BYTES + 1).into();
    assert!(AttachmentDescriptor::from_bytes(&serde_json::to_vec(&j).unwrap()).is_err());
    assert!(AttachmentDescriptor::from_bytes(&vec![b'{'; 5000]).is_err());
    assert!(AttachmentDescriptor::from_bytes(b"not json").is_err());
    assert!(!format!("{d:?}").contains("key\":"));
}

#[test]
fn filename_regressions_found_by_fuzzing() {
    // libFuzzer crash `. .*.4`: interleaved dots/whitespace/stripped chars left a leading-dot name.
    assert_eq!(sanitize_filename(". .*.4"), "4");
    assert_eq!(sanitize_filename(". .."), "file");
    assert_eq!(sanitize_filename(". . ."), "file");
    // Removing a char between a base letter and a combining mark must not make a second pass differ.
    let s = sanitize_filename("e*\u{0301}");
    assert_eq!(sanitize_filename(&s), s);
    assert_eq!(s, "\u{e9}");
    // Truncation must not leave trailing whitespace that a second pass would remove.
    let long = format!("{} x", "a".repeat(MAX_FILENAME_BYTES - 1));
    let s = sanitize_filename(&long);
    assert_eq!(sanitize_filename(&s), s);
    assert!(!s.ends_with(' '));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]
    #[test]
    fn sanitize_filename_invariants(raw in ".{0,300}") {
        let f = sanitize_filename(&raw);
        prop_assert!(!f.is_empty() && f.len() <= MAX_FILENAME_BYTES);
        prop_assert!(!f.contains('/') && !f.contains('\\') && !f.starts_with('.'));
        prop_assert!(!f.chars().any(|c| c.is_control()));
        prop_assert!(f == f.trim());
        prop_assert_eq!(sanitize_filename(&f), f);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn roundtrip_property(body in proptest::collection::vec(any::<u8>(), 0..200_000)) {
        let (ct, d) = encrypt_attachment(&body, "application/octet-stream", "f").unwrap();
        let out = decrypt_attachment(&ct, &d).unwrap();
        prop_assert_eq!(out.as_slice(), body.as_slice());
    }

    #[test]
    fn decrypt_never_panics_on_arbitrary_bytes(junk in proptest::collection::vec(any::<u8>(), 0..2000)) {
        let (_, d) = encrypt_attachment(b"hello", "application/octet-stream", "f").unwrap();
        let _ = decrypt_attachment(&junk, &d);
    }
}

// ------------------------------------------------------------------------------------------ streaming + padding

mod streaming {
    use super::*;
    use std::io::Cursor;

    fn enc(data: &[u8], mime: &str, pad: bool) -> (Vec<u8>, AttachmentDescriptor) {
        let mut out = Vec::new();
        let d = encrypt_stream(Cursor::new(data), &mut out, mime, "f", pad, &mut |_| true).unwrap();
        (out, d)
    }
    fn dec(ct: &[u8], d: &AttachmentDescriptor) -> Result<Vec<u8>, SecurityError> {
        decrypt_stream(Cursor::new(ct), d, &mut |_| true).map(|z| z.to_vec())
    }

    #[test]
    fn padme_matches_the_published_properties() {
        assert_eq!((padme(0), padme(1), padme(2), padme(3)), (0, 1, 2, 3));
        for l in [5u64, 100, 1000, 65_537, 1_000_000, 123_456_789] {
            let p = padme(l);
            assert!(p >= l);
            assert!((p - l) as f64 / l as f64 <= 0.125 + 1e-9, "overhead for {l}: {p}");
            assert_eq!(padme(p), p, "idempotent");
        }
        let classes: std::collections::BTreeSet<u64> = (1_000_000u64..1_100_000).step_by(997).map(padme).collect();
        assert!(classes.len() < 12, "100 distinct sizes collapse into few classes: {}", classes.len());
    }

    #[test]
    fn roundtrip_with_and_without_padding_across_chunk_boundaries() {
        for n in
            [0usize, 1, 100, CHUNK_PLAINTEXT_BYTES - 1, CHUNK_PLAINTEXT_BYTES, CHUNK_PLAINTEXT_BYTES + 1, 3 * CHUNK_PLAINTEXT_BYTES + 5]
        {
            for pad in [false, true] {
                let pt = png(n);
                let (ct, d) = enc(&pt, "image/png", pad);
                assert_eq!(ct.len() as u64, d.ciphertext_len);
                assert_eq!(dec(&ct, &d).unwrap(), pt, "n={n} pad={pad}");
                let d2 = AttachmentDescriptor::from_bytes(&d.to_bytes().unwrap()).unwrap();
                assert_eq!(dec(&ct, &d2).unwrap(), pt);
                if pad {
                    assert_eq!(d.padded_len, padme(pt.len() as u64));
                }
            }
        }
    }

    #[test]
    fn streamed_and_in_memory_formats_interoperate() {
        let pt = png(200_000);
        let (ct_mem, d_mem) = encrypt_attachment(&pt, "image/png", "a").unwrap();
        assert_eq!(dec(&ct_mem, &d_mem).unwrap(), pt);
        let (ct, d) = enc(&pt, "image/png", false);
        assert_eq!(decrypt_attachment(&ct, &d).unwrap().as_slice(), pt.as_slice());
    }

    #[test]
    fn ciphertext_sizes_leak_only_a_coarse_class() {
        let sizes: std::collections::BTreeSet<usize> =
            (2_000_000usize..2_040_000).step_by(1999).map(|n| enc(&png(n), "image/png", true).0.len()).collect();
        assert!(sizes.len() <= 3, "{sizes:?}");
    }

    #[test]
    fn cancel_stops_work_and_returns_an_error_without_a_descriptor() {
        let pt = png(5 * CHUNK_PLAINTEXT_BYTES);
        let mut out = Vec::new();
        let mut calls = 0;
        let r = encrypt_stream(Cursor::new(&pt), &mut out, "image/png", "f", true, &mut |_| {
            calls += 1;
            calls < 3
        });
        assert!(matches!(r, Err(SecurityError::Attachment("cancelled"))));
        assert!(out.len() < pt.len(), "stopped early");
        let (ct, d) = enc(&pt, "image/png", false);
        let mut n = 0;
        assert!(decrypt_stream(Cursor::new(&ct), &d, &mut |_| {
            n += 1;
            n < 2
        })
        .is_err());
    }

    #[test]
    fn any_tampering_truncation_or_extension_is_rejected_and_nothing_is_returned() {
        let pt = png(3 * CHUNK_PLAINTEXT_BYTES + 77);
        let (ct, d) = enc(&pt, "image/png", true);
        let step = ct.len() / 50;
        for i in (0..ct.len()).step_by(step) {
            let mut bad = ct.clone();
            bad[i] ^= 1;
            assert!(dec(&bad, &d).is_err(), "byte {i}");
        }
        assert!(dec(&ct[..ct.len() - 1], &d).is_err());
        assert!(dec(&[ct.clone(), vec![0]].concat(), &d).is_err(), "trailing byte");
        assert!(dec(&ct[..20], &d).is_err());
        // a different valid blob of the same size cannot be substituted: hash + key bind the object
        let (other, _) = enc(&pt, "image/png", true);
        assert!(dec(&other, &d).is_err());
    }

    #[test]
    fn declared_mime_must_match_content_and_oversize_is_refused() {
        let mut out = Vec::new();
        assert!(encrypt_stream(Cursor::new(b"<html>".as_slice()), &mut out, "image/png", "f", false, &mut |_| true).is_err());
        assert!(encrypt_stream(Cursor::new(b"x".as_slice()), &mut out, "text/html", "f", false, &mut |_| true).is_err());
        use std::io::Read as _;
        let huge = std::io::repeat(0).take(MAX_ATTACHMENT_PLAINTEXT_BYTES + 1);
        assert!(encrypt_stream(huge, std::io::sink(), "application/octet-stream", "f", false, &mut |_| true).is_err());
    }

    #[test]
    fn descriptor_padding_must_be_canonical() {
        let (_, d) = enc(&png(5000), "image/png", true);
        let mut j: serde_json::Value = serde_json::from_slice(&d.to_bytes().unwrap()).unwrap();
        j["padded_len"] = (d.padded_len + 1).into();
        assert!(AttachmentDescriptor::from_bytes(&serde_json::to_vec(&j).unwrap()).is_err());
    }
}
