//! Foreign (Kotlin) services the core needs: the Android Keystore and the HTTP stack.
//! The core only ever sees opaque wrapped blobs from the Keystore and ciphertext/signed requests on HTTP.
use cipher_core::app::transport::{HttpError, HttpOut, HttpTransport};
use cipher_core::keystore::{Capabilities, KeyPolicy, KeyStoreError, Platform, ProtectionLevel, SecureKeyStore};
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum KeyLevel {
    /// Dedicated secure element (StrongBox).
    Strongbox,
    /// Trusted execution environment (hardware-backed Keystore).
    Tee,
    /// Software-backed or not provably hardware-backed. Never reported as hardware.
    SoftwareOrUnknown,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum KeystoreFault {
    #[error("missing")]
    Missing,
    #[error("invalidated")]
    Invalidated,
    #[error("auth required")]
    AuthRequired,
    #[error("auth cancelled")]
    AuthCancelled,
    #[error("corrupt")]
    Corrupt,
    #[error("unavailable")]
    Unavailable,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for KeystoreFault {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        KeystoreFault::Unavailable
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct KeystoreCaps {
    pub best_level: KeyLevel,
    pub user_auth_supported: bool,
    pub biometric_supported: bool,
}

/// Implemented in Kotlin on top of Android Keystore. `wrap`/`unwrap` operate with NON-EXPORTABLE hardware keys; the Rust core
/// never learns key material of the Keystore keys, only the blobs they produce.
/// Receives a secret from the platform and keeps it in Rust memory only (zeroized on drop). Implemented in Rust; Kotlin only calls `put`.
#[uniffi::export(with_foreign)]
pub trait SecretSink: Send + Sync {
    fn put(&self, data: Vec<u8>);
}

#[derive(Default)]
pub(crate) struct Capture(std::sync::Mutex<Option<Zeroizing<Vec<u8>>>>);

impl Capture {
    pub(crate) fn take(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

impl SecretSink for Capture {
    fn put(&self, data: Vec<u8>) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(Zeroizing::new(data));
    }
}

#[uniffi::export(foreign)]
pub trait KeystoreCallbacks: Send + Sync {
    fn capabilities(&self) -> Result<KeystoreCaps, KeystoreFault>;
    fn create_key(
        &self,
        alias: String,
        require_user_auth: bool,
        invalidate_on_biometric_change: bool,
        prefer_strongbox: bool,
    ) -> Result<KeyLevel, KeystoreFault>;
    fn key_protection(&self, alias: String) -> Result<KeyLevel, KeystoreFault>;
    /// The implementation MUST zero `plaintext` (the vault key) as soon as the key operation is done.
    fn wrap(&self, alias: String, plaintext: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, KeystoreFault>;
    /// Decrypts `blob` and hands the plaintext to `sink` instead of RETURNING it, so the Kotlin side can zero its own copy right after
    /// `sink.put(..)` returns (a return value would stay reachable until the generated glue and the GC are done with it; ST-027).
    fn unwrap_into(&self, alias: String, blob: Vec<u8>, aad: Vec<u8>, sink: Arc<dyn SecretSink>) -> Result<(), KeystoreFault>;
    fn delete_key(&self, alias: String) -> Result<(), KeystoreFault>;
    /// Monotonic generation counter stored by the platform OUTSIDE the app's data directory (0 if none). Rollback detection.
    fn counter_read(&self) -> Result<u64, KeystoreFault>;
    /// Raises the counter to `to`; must never lower it.
    fn counter_advance(&self, to: u64) -> Result<(), KeystoreFault>;
}

fn level(l: KeyLevel) -> ProtectionLevel {
    match l {
        KeyLevel::Strongbox => ProtectionLevel::SecureElement,
        KeyLevel::Tee => ProtectionLevel::HardwareBacked,
        KeyLevel::SoftwareOrUnknown => ProtectionLevel::OsSoftware,
    }
}

fn fault(f: KeystoreFault) -> KeyStoreError {
    match f {
        KeystoreFault::Missing => KeyStoreError::Missing,
        KeystoreFault::Invalidated => KeyStoreError::Invalidated,
        KeystoreFault::AuthRequired => KeyStoreError::AuthRequired,
        KeystoreFault::AuthCancelled => KeyStoreError::AuthCancelled,
        KeystoreFault::Corrupt => KeyStoreError::Corrupt,
        KeystoreFault::Unavailable => KeyStoreError::Unavailable("platform keystore"),
    }
}

pub(crate) struct KeystoreAdapter(pub Arc<dyn KeystoreCallbacks>);

impl std::fmt::Debug for KeystoreAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeystoreAdapter")
    }
}

impl SecureKeyStore for KeystoreAdapter {
    fn capabilities(&self) -> Capabilities {
        match self.0.capabilities() {
            Ok(c) => Capabilities {
                platform: Platform::Android,
                best_level: level(c.best_level),
                user_auth_supported: c.user_auth_supported,
                biometric_supported: c.biometric_supported,
            },
            // Fail closed: if the platform cannot say what it offers, report the weakest level.
            Err(_) => Capabilities {
                platform: Platform::Android,
                best_level: ProtectionLevel::Insecure,
                user_auth_supported: false,
                biometric_supported: false,
            },
        }
    }
    fn create_key(&self, alias: &str, p: &KeyPolicy) -> Result<ProtectionLevel, KeyStoreError> {
        self.0
            .create_key(alias.to_owned(), p.require_user_auth, p.invalidate_on_biometric_change, p.prefer_secure_element)
            .map(level)
            .map_err(fault)
    }
    fn key_protection(&self, alias: &str) -> Result<ProtectionLevel, KeyStoreError> {
        self.0.key_protection(alias.to_owned()).map(level).map_err(fault)
    }
    fn wrap(&self, alias: &str, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        self.0.wrap(alias.to_owned(), plaintext.to_vec(), aad.to_vec()).map_err(fault)
    }
    fn unwrap(&self, alias: &str, blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
        let capture = Arc::new(Capture::default());
        let sink: Arc<dyn SecretSink> = capture.clone();
        self.0.unwrap_into(alias.to_owned(), blob.to_vec(), aad.to_vec(), sink).map_err(fault)?;
        capture.take().ok_or(KeyStoreError::Corrupt)
    }
    fn delete_key(&self, alias: &str) -> Result<(), KeyStoreError> {
        self.0.delete_key(alias.to_owned()).map_err(fault)
    }
    fn counter_read(&self) -> Result<u64, KeyStoreError> {
        self.0.counter_read().map_err(fault)
    }
    fn counter_advance(&self, to: u64) -> Result<(), KeyStoreError> {
        self.0.counter_advance(to).map_err(fault)
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum HttpFault {
    #[error("network")]
    Network,
    #[error("tls")]
    Tls,
    #[error("timeout")]
    Timeout,
    #[error("io")]
    Io,
    /// The privacy route (e.g. the local SOCKS endpoint) is not available. Treated like a network failure by the engine — the encrypted message
    /// stays queued — and NEVER retried over any other route.
    #[error("privacy route unavailable")]
    RouteUnavailable,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for HttpFault {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        HttpFault::Io
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct HttpReply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Implemented in Kotlin with OkHttp: TLS 1.3 only, system trust anchors, no certificate-verification overrides.
#[uniffi::export(foreign)]
pub trait HttpCallbacks: Send + Sync {
    fn execute(
        &self,
        base_url: String,
        method: String,
        path_and_query: String,
        authorization: Option<String>,
        body: Vec<u8>,
    ) -> Result<HttpReply, HttpFault>;
    fn upload_file(
        &self,
        base_url: String,
        path_and_query: String,
        authorization: Option<String>,
        file_path: String,
    ) -> Result<HttpReply, HttpFault>;
    fn download_file(
        &self,
        base_url: String,
        path_and_query: String,
        authorization: Option<String>,
        dest_path: String,
        max_bytes: u64,
    ) -> Result<u16, HttpFault>;
    /// From now on, for `base_url`, accept ONLY a server certificate whose SubjectPublicKeyInfo SHA-256 equals `spki_sha256_b64` (unpadded base64url),
    /// and do not validate a CA chain for that host. Must fail (return an error) if this cannot be enforced: the request is then refused.
    fn pin_relay(&self, base_url: String, spki_sha256_b64: String) -> Result<(), HttpFault>;
}

#[uniffi::export(foreign)]
pub trait ProgressCallback: Send + Sync {
    /// Return `false` to cancel.
    fn on_progress(&self, done: u64, total: u64) -> bool;
}

fn http_err(f: HttpFault) -> HttpError {
    match f {
        HttpFault::Network => HttpError::Network,
        HttpFault::Tls => HttpError::Tls,
        HttpFault::Timeout => HttpError::Timeout,
        HttpFault::Io => HttpError::Io,
        HttpFault::RouteUnavailable => HttpError::RouteUnavailable,
    }
}

pub(crate) struct HttpAdapter {
    pub inner: Arc<dyn HttpCallbacks>,
    /// Set by `CipherEngine::request_lock`: every new request fails immediately (the platform transport is cancelled by the shell).
    pub abort: Arc<std::sync::atomic::AtomicBool>,
}

impl HttpAdapter {
    fn check(&self) -> Result<(), HttpError> {
        if self.abort.load(std::sync::atomic::Ordering::SeqCst) {
            Err(HttpError::Network)
        } else {
            Ok(())
        }
    }
}

impl HttpTransport for HttpAdapter {
    fn execute(&self, base_url: &str, method: &str, path: &str, auth: Option<&str>, body: &[u8]) -> Result<HttpOut, HttpError> {
        self.check()?;
        self.inner
            .execute(base_url.to_owned(), method.to_owned(), path.to_owned(), auth.map(str::to_owned), body.to_vec())
            .map(|r| HttpOut { status: r.status, body: r.body })
            .map_err(http_err)
    }
    fn upload_file(&self, base_url: &str, path: &str, auth: Option<&str>, file: &str) -> Result<HttpOut, HttpError> {
        self.check()?;
        self.inner
            .upload_file(base_url.to_owned(), path.to_owned(), auth.map(str::to_owned), file.to_owned())
            .map(|r| HttpOut { status: r.status, body: r.body })
            .map_err(http_err)
    }
    fn download_file(&self, base_url: &str, path: &str, auth: Option<&str>, dest: &str, max_bytes: u64) -> Result<u16, HttpError> {
        self.check()?;
        self.inner
            .download_file(base_url.to_owned(), path.to_owned(), auth.map(str::to_owned), dest.to_owned(), max_bytes)
            .map_err(http_err)
    }
    fn pin_relay(&self, base_url: &str, spki_sha256: &[u8; 32]) -> Result<(), HttpError> {
        self.check()?;
        self.inner.pin_relay(base_url.to_owned(), cipher_wire::b64::encode(spki_sha256)).map_err(http_err)
    }
}

#[cfg(test)]
mod abort_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Counting(AtomicU32);
    impl HttpCallbacks for Counting {
        fn execute(&self, _: String, _: String, _: String, _: Option<String>, _: Vec<u8>) -> Result<HttpReply, HttpFault> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(HttpReply { status: 200, body: vec![] })
        }
        fn upload_file(&self, _: String, _: String, _: Option<String>, _: String) -> Result<HttpReply, HttpFault> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(HttpReply { status: 200, body: vec![] })
        }
        fn download_file(&self, _: String, _: String, _: Option<String>, _: String, _: u64) -> Result<u16, HttpFault> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(200)
        }
        fn pin_relay(&self, _: String, _: String) -> Result<(), HttpFault> {
            Err(HttpFault::Tls)
        }
    }

    #[test]
    fn once_a_lock_is_requested_no_new_network_call_reaches_the_platform() {
        let inner = Arc::new(Counting(AtomicU32::new(0)));
        let abort = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let a = HttpAdapter { inner: inner.clone(), abort: abort.clone() };
        assert!(a.execute("https://r", "GET", "/x", None, &[]).is_ok());
        abort.store(true, Ordering::SeqCst);
        assert!(a.execute("https://r", "GET", "/x", None, &[]).is_err());
        assert!(a.upload_file("https://r", "/x", None, "/proc/self/fd/3").is_err());
        assert!(a.download_file("https://r", "/x", None, "/dev/null", 10).is_err());
        assert_eq!(inner.0.load(Ordering::SeqCst), 1, "only the call made before the lock request got through");
    }
}
