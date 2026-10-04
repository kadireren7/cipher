#![no_main]
use cipher_core::attachment::*;
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};

// Reach the AEAD stream layer directly: fix up the descriptor (hash + length) to match the fuzzed bytes,
// so the fuzzer explores chunk parsing and authentication rather than stopping at the hash check.
fuzz_target!(|data: &[u8]| {
    let Ok((_, d)) = encrypt_attachment(b"seed", "application/octet-stream", "f") else { return };
    let Ok(raw) = d.to_bytes() else { return };
    let Ok(mut j) = serde_json::from_slice::<serde_json::Value>(&raw) else { return };
    // Invert ciphertext_len_for analytically: ct = header(13) + plain + 16 * chunks.
    let plain_len = (1u64..=8).find_map(|chunks| {
        let p = (data.len() as u64).checked_sub(13 + 16 * chunks)?;
        (ciphertext_len_for(p) == data.len() as u64).then_some(p)
    });
    let Some(p) = plain_len else {
        // Length cannot match any plaintext length: must be rejected cleanly.
        let _ = decrypt_attachment(data, &d);
        return;
    };
    j["plaintext_len"] = p.into();
    j["ciphertext_len"] = (data.len() as u64).into();
    j["ciphertext_sha256"] = cipher_wire::b64::encode(&Sha256::digest(data)).into();
    if let Ok(d2) = serde_json::from_slice::<AttachmentDescriptor>(&serde_json::to_vec(&j).unwrap_or_default()) {
        let _ = decrypt_attachment(data, &d2);
    }
});
