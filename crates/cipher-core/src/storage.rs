//! Encrypted local record store (SEC-009).
//!
//! Every record is sealed with XChaCha20-Poly1305 under a key derived (HKDF) from
//! the vault data-encryption key, with the namespace and id bound as AAD so rows
//! cannot be swapped between locations. SQLite only ever holds ciphertext, row
//! locations and sizes. Corruption or tampering is an error, never partial data.
//!
//! Known limits (documented in docs/LOCAL_STORAGE_SECURITY.md): an attacker with
//! file-write access can roll a record back to an older valid ciphertext or delete
//! rows; row count, namespaces, ids and approximate sizes are visible.
//! SECURITY TODO (ST-004): production Android builds should additionally place this file
//! under SQLCipher / OS file protection (Android
//! file-based encryption) as defence in depth.
use crate::error::{Result, SecurityError};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;
use std::path::Path;
use zeroize::Zeroizing;

const RECORD_INFO: &[u8] = b"cipher/storage/record-key/v1";
const FORMAT: u8 = 1;
const CHECK_NS: &str = "__vault__";
const CHECK_ID: &str = "check";
const CHECK_PLAINTEXT: &[u8] = b"cipher-store-check-v1";
pub const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;

pub struct EncryptedStore {
    conn: Connection,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for EncryptedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncryptedStore(<redacted>)")
    }
}

pub(crate) fn open_conn(path: Option<&Path>) -> Result<Connection> {
    let conn = match path {
        Some(p) => Connection::open(p),
        None => Connection::open_in_memory(),
    }
    .map_err(|_| SecurityError::StorageCorrupt)?;
    conn.execute_batch(
        "PRAGMA secure_delete=ON;
         CREATE TABLE IF NOT EXISTS vault_meta(k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
         CREATE TABLE IF NOT EXISTS records(ns TEXT NOT NULL, id TEXT NOT NULL, ct BLOB NOT NULL, PRIMARY KEY(ns,id)) WITHOUT ROWID;",
    )
    .map_err(|_| SecurityError::StorageCorrupt)?;
    Ok(conn)
}

fn record_key(dek: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(None, dek);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(RECORD_INFO, out.as_mut_slice()).map_err(|_| SecurityError::CryptoAuthFailed)?;
    Ok(out)
}

fn aad(ns: &str, id: &str) -> Vec<u8> {
    let mut a = vec![FORMAT];
    a.extend_from_slice(&(ns.len() as u32).to_be_bytes());
    a.extend_from_slice(ns.as_bytes());
    a.extend_from_slice(id.as_bytes());
    a
}

impl EncryptedStore {
    /// Open with the data-encryption key. `create` initialises the key-check record.
    pub(crate) fn open(conn: Connection, dek: &[u8; 32], create: bool) -> Result<Self> {
        let mut s = Self { conn, key: record_key(dek)? };
        if create {
            s.put(CHECK_NS, CHECK_ID, CHECK_PLAINTEXT)?;
        }
        match s.get(CHECK_NS, CHECK_ID) {
            Ok(Some(v)) if v.as_slice() == CHECK_PLAINTEXT => Ok(s),
            Ok(_) => Err(SecurityError::StorageCorrupt),
            Err(SecurityError::CryptoAuthFailed) => Err(SecurityError::StorageWrongKey),
            Err(e) => Err(e),
        }
    }

    /// Open on an existing connection, returning the connection on failure so the
    /// caller can stay `Locked` without losing the database handle.
    pub(crate) fn open_keep_conn(conn: Connection, dek: &[u8; 32]) -> std::result::Result<Self, Box<(Connection, SecurityError)>> {
        let key = match record_key(dek) {
            Ok(k) => k,
            Err(e) => return Err(Box::new((conn, e))),
        };
        let s = Self { conn, key };
        let res = match s.get(CHECK_NS, CHECK_ID) {
            Ok(Some(v)) if v.as_slice() == CHECK_PLAINTEXT => Ok(()),
            Ok(_) => Err(SecurityError::StorageCorrupt),
            Err(SecurityError::CryptoAuthFailed) => Err(SecurityError::StorageWrongKey),
            Err(e) => Err(e),
        };
        match res {
            Ok(()) => Ok(s),
            Err(e) => Err(Box::new((s.into_conn(), e))),
        }
    }

    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Consume the store, dropping (and zeroizing) the record key.
    pub(crate) fn into_conn(self) -> Connection {
        self.conn
    }

    pub fn put(&mut self, ns: &str, id: &str, plaintext: &[u8]) -> Result<()> {
        if plaintext.len() > MAX_RECORD_BYTES {
            return Err(SecurityError::Malformed("record too large"));
        }
        let nonce = crate::rng::array::<24>()?;
        let c = XChaCha20Poly1305::new(Key::from_slice(self.key.as_slice()));
        let ct = c
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad(ns, id) })
            .map_err(|_| SecurityError::CryptoAuthFailed)?;
        let mut blob = Vec::with_capacity(24 + ct.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        self.conn
            .execute("INSERT OR REPLACE INTO records(ns,id,ct) VALUES(?1,?2,?3)", params![ns, id, blob])
            .map_err(|_| SecurityError::StorageCorrupt)?;
        Ok(())
    }

    pub fn get(&self, ns: &str, id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let row: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT ct FROM records WHERE ns=?1 AND id=?2", params![ns, id], |r| r.get(0))
            .optional()
            .map_err(|_| SecurityError::StorageCorrupt)?;
        let Some(blob) = row else { return Ok(None) };
        if blob.len() < 24 + 16 {
            return Err(SecurityError::CryptoAuthFailed);
        }
        let (nonce, ct) = blob.split_at(24);
        let c = XChaCha20Poly1305::new(Key::from_slice(self.key.as_slice()));
        let pt =
            c.decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad(ns, id) }).map_err(|_| SecurityError::CryptoAuthFailed)?;
        Ok(Some(Zeroizing::new(pt)))
    }

    pub fn delete(&mut self, ns: &str, id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM records WHERE ns=?1 AND id=?2", params![ns, id]).map_err(|_| SecurityError::StorageCorrupt)?;
        Ok(())
    }

    /// Newest-first page of record ids (ids sort lexicographically): efficient keyset pagination, never loads the whole namespace.
    pub fn list_ids_page(&self, ns: &str, before: Option<&str>, limit: usize) -> Result<Vec<String>> {
        let limit = limit.clamp(1, 500) as i64;
        let mut st = self
            .conn
            .prepare("SELECT id FROM records WHERE ns=?1 AND (?2 IS NULL OR id < ?2) ORDER BY id DESC LIMIT ?3")
            .map_err(|_| SecurityError::StorageCorrupt)?;
        let rows = st.query_map(params![ns, before, limit], |r| r.get::<_, String>(0)).map_err(|_| SecurityError::StorageCorrupt)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(|_| SecurityError::StorageCorrupt)
    }

    pub fn count(&self, ns: &str) -> Result<u64> {
        self.conn
            .query_row("SELECT count(*) FROM records WHERE ns=?1", params![ns], |r| r.get::<_, i64>(0))
            .map(|n| n as u64)
            .map_err(|_| SecurityError::StorageCorrupt)
    }

    /// Run `f` atomically: either every `put`/`delete` inside it is applied, or none (crash/err => rollback).
    pub fn atomic<R>(&mut self, f: impl FnOnce(&mut Self) -> Result<R>) -> Result<R> {
        self.conn.execute_batch("BEGIN IMMEDIATE").map_err(|_| SecurityError::StorageCorrupt)?;
        match f(self) {
            Ok(v) => {
                self.conn.execute_batch("COMMIT").map_err(|_| SecurityError::StorageCorrupt)?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    pub fn list_ids(&self, ns: &str) -> Result<Vec<String>> {
        let mut st = self.conn.prepare("SELECT id FROM records WHERE ns=?1 ORDER BY id").map_err(|_| SecurityError::StorageCorrupt)?;
        let rows = st.query_map(params![ns], |r| r.get::<_, String>(0)).map_err(|_| SecurityError::StorageCorrupt)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(|_| SecurityError::StorageCorrupt)
    }
}
