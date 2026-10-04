//! Client-side attachment encryption (SEC-004).
//!
//! * Fresh 256-bit key per attachment from the OS CSPRNG; never derived from or
//!   shared with message keys. The key travels only inside the E2EE message that
//!   carries the `AttachmentDescriptor`.
//! * Chunked AEAD using the STREAM construction (Hoang/Reyhanitabar/Rogaway/Vizár)
//!   as implemented by RustCrypto's `aead::stream` with ChaCha20-Poly1305. Reordering,
//!   truncation and chunk modification are detected. Nothing is invented here.
//! * Declared MIME type must be allow-listed and consistent with the content's magic
//!   bytes; filenames are sanitised. File name and MIME live only in the encrypted
//!   descriptor, never in the storage provider's view.
use crate::error::{Result, SecurityError};
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::Payload;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub const MAX_ATTACHMENT_PLAINTEXT_BYTES: u64 = 100 * 1024 * 1024;
pub const CHUNK_PLAINTEXT_BYTES: usize = 64 * 1024;
const TAG_BYTES: usize = 16;
const MAGIC: &[u8; 4] = cipher_wire::limits::ATTACHMENT_MAGIC;
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 1 + 7;
const CHUNK_LOG2: u8 = 16;
pub const MAX_FILENAME_BYTES: usize = 128;

pub const ALLOWED_MIME: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "application/pdf",
    "video/mp4",
    "audio/mp4",
    "audio/ogg",
    "audio/aac",
    "text/plain",
    // Opaque download-only bytes: must never be rendered or opened inline.
    "application/octet-stream",
];

/// Padmé padding (Nikitin et al., PETS 2019): rounds a length up so that the *size class* leaks only O(log log n) bits,
/// with at most ~12% overhead. A published scheme, not ours.
pub fn padme(l: u64) -> u64 {
    if l < 2 {
        return l;
    }
    let e = 63 - l.leading_zeros() as u64; // floor(log2 l)
    let s = 64 - e.leading_zeros() as u64; // floor(log2 e) + 1
    let last_bits = e.saturating_sub(s);
    let mask = (1u64 << last_bits) - 1;
    l.saturating_add(mask) & !mask
}

pub fn ciphertext_len_for(plain_len: u64) -> u64 {
    // An empty file still has one (empty) final chunk; otherwise ceil(len / chunk).
    let chunks = plain_len.div_ceil(CHUNK_PLAINTEXT_BYTES as u64).max(1);
    HEADER_LEN as u64 + plain_len + chunks * TAG_BYTES as u64
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AttachmentDescriptor {
    #[serde(with = "cipher_wire::b64")]
    key: Vec<u8>,
    pub plaintext_len: u64,
    /// Length after Padmé padding (0 = unpadded, i.e. equal to `plaintext_len`).
    #[serde(default)]
    pub padded_len: u64,
    pub ciphertext_len: u64,
    #[serde(with = "cipher_wire::b64")]
    pub ciphertext_sha256: Vec<u8>,
    pub mime: String,
    pub filename: String,
}

impl std::fmt::Debug for AttachmentDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentDescriptor")
            .field("plaintext_len", &self.plaintext_len)
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Drop for AttachmentDescriptor {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

impl AttachmentDescriptor {
    fn effective_len(&self) -> u64 {
        if self.padded_len == 0 {
            self.plaintext_len
        } else {
            self.padded_len
        }
    }

    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        serde_json::to_vec(self).map(Zeroizing::new).map_err(|_| SecurityError::Attachment("descriptor encode"))
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() > 4096 {
            return Err(SecurityError::Attachment("descriptor too large"));
        }
        let d: Self = serde_json::from_slice(b).map_err(|_| SecurityError::Attachment("descriptor malformed"))?;
        if d.key.len() != 32 || d.ciphertext_sha256.len() != 32 {
            return Err(SecurityError::Attachment("descriptor field length"));
        }
        if d.padded_len != 0 && d.padded_len != padme(d.plaintext_len) {
            return Err(SecurityError::Attachment("descriptor padding inconsistent"));
        }
        if d.plaintext_len > MAX_ATTACHMENT_PLAINTEXT_BYTES || d.ciphertext_len != ciphertext_len_for(d.effective_len()) {
            return Err(SecurityError::Attachment("descriptor size inconsistent"));
        }
        validate_mime(&d.mime)?;
        if sanitize_filename(&d.filename) != d.filename {
            return Err(SecurityError::Attachment("descriptor filename not sanitised"));
        }
        Ok(d)
    }
}

fn validate_mime(mime: &str) -> Result<()> {
    if ALLOWED_MIME.contains(&mime) {
        Ok(())
    } else {
        Err(SecurityError::Attachment("mime type not allowed"))
    }
}

fn check_magic(mime: &str, data: &[u8]) -> Result<()> {
    let ok = match mime {
        "image/jpeg" => data.starts_with(&[0xFF, 0xD8, 0xFF]),
        "image/png" => data.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]),
        "image/gif" => data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a"),
        "image/webp" => data.len() >= 12 && data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP"),
        "application/pdf" => data.starts_with(b"%PDF-"),
        "video/mp4" | "audio/mp4" => data.len() >= 12 && data.get(4..8) == Some(b"ftyp"),
        "audio/ogg" => data.starts_with(b"OggS"),
        // ADTS frame sync: 12 set bits.
        "audio/aac" => data.len() >= 2 && data.first() == Some(&0xFF) && data.get(1).is_some_and(|b| b & 0xF0 == 0xF0),
        "text/plain" => std::str::from_utf8(data).is_ok(),
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(SecurityError::Attachment("content does not match declared mime type"))
    }
}

/// One sanitisation pass. Not idempotent on its own: removing characters can enable new
/// Unicode compositions or expose new leading dots/whitespace, so `sanitize_filename` iterates it.
fn sanitize_pass(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let filtered: String = base
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(*c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        })
        .collect();
    let normalised: String = filtered.nfc().collect();
    // Leading dots/whitespace in ANY interleaving ("`. .x`") must go, otherwise ".." or hidden names survive.
    let trimmed = normalised.trim_start_matches(|c: char| c == '.' || c.is_whitespace());
    let mut out = String::new();
    for c in trimmed.chars() {
        if out.len() + c.len_utf8() > MAX_FILENAME_BYTES {
            break;
        }
        out.push(c);
    }
    out.trim_end().to_owned()
}

/// Strip path components, control/format/bidi characters, reserved punctuation, leading dots and
/// whitespace; NFC; length-cap. Guarantees (fuzzed + property-tested): non-empty, <= 128 bytes, no path
/// separators, no leading dot, no control characters, and idempotent (`f(f(x)) == f(x)`), which descriptor
/// validation relies on.
pub fn sanitize_filename(name: &str) -> String {
    let mut cur = sanitize_pass(name);
    for _ in 0..8 {
        let next = sanitize_pass(&cur);
        if next == cur {
            return if cur.is_empty() { "file".to_owned() } else { cur };
        }
        cur = next;
    }
    "file".to_owned() // did not converge: fail closed to a constant name
}

pub struct AttachmentEncryptor {
    enc: Option<EncryptorBE32<ChaCha20Poly1305>>,
    header: [u8; HEADER_LEN],
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for AttachmentEncryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttachmentEncryptor(<redacted>)")
    }
}

impl AttachmentEncryptor {
    pub fn new() -> Result<Self> {
        let key = crate::rng::secret32()?;
        let prefix = crate::rng::array::<7>()?;
        let mut header = [0u8; HEADER_LEN];
        header[..4].copy_from_slice(MAGIC);
        header[4] = VERSION;
        header[5] = CHUNK_LOG2;
        header[6..].copy_from_slice(&prefix);
        let enc = EncryptorBE32::from_aead(ChaCha20Poly1305::new(Key::from_slice(key.as_slice())), prefix.as_slice().into());
        Ok(Self { enc: Some(enc), header, key })
    }
    pub fn header(&self) -> &[u8] {
        &self.header
    }
    /// Encrypt a full (CHUNK_PLAINTEXT_BYTES) non-final chunk.
    pub fn encrypt_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        if chunk.len() != CHUNK_PLAINTEXT_BYTES {
            return Err(SecurityError::Attachment("non-final chunk must be full size"));
        }
        let enc = self.enc.as_mut().ok_or(SecurityError::InvalidState)?;
        enc.encrypt_next(Payload { msg: chunk, aad: &self.header }).map_err(|_| SecurityError::CryptoAuthFailed)
    }
    /// Encrypt the final chunk (0..=CHUNK_PLAINTEXT_BYTES bytes). Consumes the stream.
    pub fn encrypt_last(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        if chunk.len() > CHUNK_PLAINTEXT_BYTES {
            return Err(SecurityError::Attachment("final chunk too large"));
        }
        let enc = self.enc.take().ok_or(SecurityError::InvalidState)?;
        enc.encrypt_last(Payload { msg: chunk, aad: &self.header }).map_err(|_| SecurityError::CryptoAuthFailed)
    }
    fn key_bytes(&self) -> Vec<u8> {
        self.key.to_vec()
    }
}

/// Encrypt an in-memory file. Returns (ciphertext for object storage, descriptor for the E2EE message).
pub fn encrypt_attachment(plaintext: &[u8], mime: &str, filename: &str) -> Result<(Vec<u8>, AttachmentDescriptor)> {
    if plaintext.len() as u64 > MAX_ATTACHMENT_PLAINTEXT_BYTES {
        return Err(SecurityError::Attachment("file too large"));
    }
    validate_mime(mime)?;
    check_magic(mime, plaintext)?;
    let mut e = AttachmentEncryptor::new()?;
    let mut out = Vec::with_capacity(ciphertext_len_for(plaintext.len() as u64) as usize);
    out.extend_from_slice(e.header());
    let mut chunks = plaintext.chunks(CHUNK_PLAINTEXT_BYTES).peekable();
    let mut wrote_last = false;
    while let Some(c) = chunks.next() {
        if chunks.peek().is_none() {
            out.extend_from_slice(&e.encrypt_last(c)?);
            wrote_last = true;
        } else {
            out.extend_from_slice(&e.encrypt_chunk(c)?);
        }
    }
    if !wrote_last {
        out.extend_from_slice(&e.encrypt_last(&[])?);
    }
    let desc = AttachmentDescriptor {
        key: e.key_bytes(),
        plaintext_len: plaintext.len() as u64,
        padded_len: 0,
        ciphertext_len: out.len() as u64,
        ciphertext_sha256: Sha256::digest(&out).to_vec(),
        mime: mime.to_owned(),
        filename: sanitize_filename(filename),
    };
    Ok((out, desc))
}

/// Decrypt and fully authenticate. Any modification, truncation or extension fails closed.
pub fn decrypt_attachment(ciphertext: &[u8], desc: &AttachmentDescriptor) -> Result<Zeroizing<Vec<u8>>> {
    if desc.plaintext_len > MAX_ATTACHMENT_PLAINTEXT_BYTES
        || ciphertext.len() as u64 != desc.ciphertext_len
        || desc.ciphertext_len != ciphertext_len_for(desc.effective_len())
    {
        return Err(SecurityError::Attachment("size mismatch"));
    }
    let digest = Sha256::digest(ciphertext);
    if !bool::from(digest.as_slice().ct_eq(&desc.ciphertext_sha256)) {
        return Err(SecurityError::CryptoAuthFailed);
    }
    let header = ciphertext.get(..HEADER_LEN).ok_or(SecurityError::Attachment("truncated"))?;
    if header.get(..4) != Some(MAGIC.as_slice()) || header.get(4) != Some(&VERSION) || header.get(5) != Some(&CHUNK_LOG2) {
        return Err(SecurityError::Attachment("bad header"));
    }
    let prefix = header.get(6..HEADER_LEN).ok_or(SecurityError::Attachment("bad header"))?;
    let mut dec = DecryptorBE32::from_aead(ChaCha20Poly1305::new(Key::from_slice(&desc.key)), prefix.into());
    let body = ciphertext.get(HEADER_LEN..).ok_or(SecurityError::Attachment("truncated"))?;
    let step = CHUNK_PLAINTEXT_BYTES + TAG_BYTES;
    let mut out = Zeroizing::new(Vec::with_capacity(desc.effective_len() as usize));
    let mut rest = body;
    loop {
        if rest.len() > step {
            let (c, r) = rest.split_at(step);
            let pt = dec.decrypt_next(Payload { msg: c, aad: header }).map_err(|_| SecurityError::CryptoAuthFailed)?;
            out.extend_from_slice(&pt);
            rest = r;
        } else {
            let pt = dec.decrypt_last(Payload { msg: rest, aad: header }).map_err(|_| SecurityError::CryptoAuthFailed)?;
            out.extend_from_slice(&pt);
            break;
        }
    }
    if out.len() as u64 != desc.effective_len() {
        return Err(SecurityError::Attachment("length mismatch"));
    }
    out.truncate(desc.plaintext_len as usize); // drop Padmé padding
    check_magic(&desc.mime, &out)?;
    Ok(out)
}

// ------------------------------------------------------------------------------------------------------------
// Streaming (file-to-file) encryption/decryption. Plaintext never touches disk: the source is read through a
// file descriptor / reader and only CIPHERTEXT is written. Progress callbacks return `false` to cancel.
// ------------------------------------------------------------------------------------------------------------

/// Pulls `want` bytes at a time from `reader`, then (optionally) a run of zero bytes up to the Padmé length.
struct PaddedSource<R: std::io::Read> {
    reader: R,
    read_total: u64,
    reader_done: bool,
    pad: bool,
    pad_left: u64,
}

impl<R: std::io::Read> PaddedSource<R> {
    fn next_chunk(&mut self, want: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; want];
        let mut filled = 0usize;
        while filled < want && !self.reader_done {
            let n = self.reader.read(buf.get_mut(filled..).unwrap_or(&mut [])).map_err(|_| SecurityError::Attachment("read failed"))?;
            if n == 0 {
                self.reader_done = true;
                if self.pad {
                    self.pad_left = padme(self.read_total).saturating_sub(self.read_total);
                }
            } else {
                filled += n;
                self.read_total += n as u64;
                if self.read_total > MAX_ATTACHMENT_PLAINTEXT_BYTES {
                    return Err(SecurityError::Attachment("file too large"));
                }
            }
        }
        if self.reader_done && filled < want && self.pad_left > 0 {
            let z = (want - filled).min(self.pad_left as usize);
            self.pad_left -= z as u64;
            filled += z; // buf is already zero-filled
        }
        buf.truncate(filled);
        Ok(buf)
    }
}

/// Encrypt everything from `reader` into `writer` (header + STREAM chunks). Returns the descriptor for the E2EE message.
pub fn encrypt_stream<R: std::io::Read, W: std::io::Write>(
    reader: R,
    mut writer: W,
    mime: &str,
    filename: &str,
    pad: bool,
    progress: &mut dyn FnMut(u64) -> bool,
) -> Result<AttachmentDescriptor> {
    validate_mime(mime)?;
    let mut e = AttachmentEncryptor::new()?;
    let mut src = PaddedSource { reader, read_total: 0, reader_done: false, pad, pad_left: 0 };
    let mut hash = Sha256::new();
    let mut ct_len: u64 = 0;
    let mut emit = |bytes: &[u8], w: &mut W| -> Result<()> {
        w.write_all(bytes).map_err(|_| SecurityError::Attachment("write failed"))?;
        hash.update(bytes);
        ct_len += bytes.len() as u64;
        Ok(())
    };
    emit(e.header(), &mut writer)?;
    let mut cur = src.next_chunk(CHUNK_PLAINTEXT_BYTES)?;
    let mut first_chunk_checked = false;
    let mut plain_done: u64 = 0;
    loop {
        if !first_chunk_checked {
            check_magic(mime, &cur)?; // declared type must match the content's magic bytes
            first_chunk_checked = true;
        }
        let next = if cur.len() == CHUNK_PLAINTEXT_BYTES { src.next_chunk(CHUNK_PLAINTEXT_BYTES)? } else { Vec::new() };
        plain_done += cur.len() as u64;
        if !progress(plain_done) {
            return Err(SecurityError::Attachment("cancelled"));
        }
        if next.is_empty() {
            emit(&e.encrypt_last(&cur)?, &mut writer)?;
            break;
        }
        emit(&e.encrypt_chunk(&cur)?, &mut writer)?;
        cur = next;
    }
    writer.flush().map_err(|_| SecurityError::Attachment("write failed"))?;
    let plaintext_len = src.read_total;
    let padded = if pad { padme(plaintext_len) } else { 0 };
    let eff = if pad { padded } else { plaintext_len };
    if ct_len != ciphertext_len_for(eff) {
        return Err(SecurityError::Attachment("internal length mismatch"));
    }
    Ok(AttachmentDescriptor {
        key: e.key_bytes(),
        plaintext_len,
        padded_len: padded,
        ciphertext_len: ct_len,
        ciphertext_sha256: hash.finalize().to_vec(),
        mime: mime.to_owned(),
        filename: sanitize_filename(filename),
    })
}

/// Decrypt a ciphertext stream into memory. Nothing is returned unless EVERY chunk authenticated, the length matches,
/// and the whole-ciphertext hash from the descriptor matches. `max_plain` bounds memory use.
pub fn decrypt_stream<R: std::io::Read>(
    mut reader: R,
    desc: &AttachmentDescriptor,
    progress: &mut dyn FnMut(u64) -> bool,
) -> Result<Zeroizing<Vec<u8>>> {
    if desc.plaintext_len > MAX_ATTACHMENT_PLAINTEXT_BYTES || desc.ciphertext_len != ciphertext_len_for(desc.effective_len()) {
        return Err(SecurityError::Attachment("size mismatch"));
    }
    let mut hash = Sha256::new();
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).map_err(|_| SecurityError::Attachment("truncated"))?;
    hash.update(header);
    if header.get(..4) != Some(MAGIC.as_slice()) || header.get(4) != Some(&VERSION) || header.get(5) != Some(&CHUNK_LOG2) {
        return Err(SecurityError::Attachment("bad header"));
    }
    let prefix = header.get(6..HEADER_LEN).ok_or(SecurityError::Attachment("bad header"))?;
    let mut dec = Some(DecryptorBE32::from_aead(ChaCha20Poly1305::new(Key::from_slice(&desc.key)), prefix.into()));
    let step = CHUNK_PLAINTEXT_BYTES + TAG_BYTES;
    let mut out = Zeroizing::new(Vec::with_capacity(desc.effective_len().min(MAX_ATTACHMENT_PLAINTEXT_BYTES) as usize));
    let mut remaining = desc.ciphertext_len - HEADER_LEN as u64;
    let mut buf = vec![0u8; step];
    while remaining > 0 {
        let take = (remaining as usize).min(step);
        let slice = buf.get_mut(..take).ok_or(SecurityError::Attachment("internal"))?;
        reader.read_exact(slice).map_err(|_| SecurityError::Attachment("truncated"))?;
        hash.update(&*slice);
        remaining -= take as u64;
        let pt = if remaining == 0 {
            dec.take()
                .ok_or(SecurityError::InvalidState)?
                .decrypt_last(Payload { msg: slice, aad: &header })
                .map_err(|_| SecurityError::CryptoAuthFailed)?
        } else {
            if take != step {
                return Err(SecurityError::Attachment("malformed chunking"));
            }
            dec.as_mut()
                .ok_or(SecurityError::InvalidState)?
                .decrypt_next(Payload { msg: slice, aad: &header })
                .map_err(|_| SecurityError::CryptoAuthFailed)?
        };
        out.extend_from_slice(&pt);
        if !progress(out.len() as u64) {
            return Err(SecurityError::Attachment("cancelled"));
        }
        // dec is consumed by decrypt_last; loop ends because remaining == 0
        if remaining == 0 {
            break;
        }
    }
    // Any trailing byte means the stored object is longer than the descriptor says.
    let mut extra = [0u8; 1];
    if reader.read(&mut extra).map_err(|_| SecurityError::Attachment("read failed"))? != 0 {
        return Err(SecurityError::Attachment("trailing data"));
    }
    if !bool::from(hash.finalize().as_slice().ct_eq(&desc.ciphertext_sha256)) {
        return Err(SecurityError::CryptoAuthFailed);
    }
    if out.len() as u64 != desc.effective_len() {
        return Err(SecurityError::Attachment("length mismatch"));
    }
    out.truncate(desc.plaintext_len as usize);
    check_magic(&desc.mime, &out)?;
    Ok(out)
}
