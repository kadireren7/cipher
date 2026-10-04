#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout, clippy::print_stderr, clippy::indexing_slicing)]
//! DEVELOPMENT TOOL ONLY — a headless peer for end-to-end verification against a real relay binary.
//!
//! It drives exactly the same `CipherEngine` surface the Android app uses (so the FFI boundary is exercised), with
//! * an in-memory fake Keystore (the process IS the "device"; nothing is persisted outside the vault directory), and
//! * `curl` as the HTTP transport (TLS 1.3 only, explicit test CA, `--connect-to` so the signed audience matches the relay's).
//!
//! It is not shipped, not part of any release artifact, and trusts only the throwaway test CA given on the command line.
//!
//! Usage: `e2e_peer <data_dir> <host:port> <ca.pem> <connect_ip>` then commands on stdin (one per line, results on stdout).
use cipher_core::keystore::testing::InMemoryKeyStore;
use cipher_core::keystore::{KeyPolicy, KeyStoreError, ProtectionLevel, SecureKeyStore};
use cipher_ffi::*;
use std::io::{BufRead, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;

struct Ks(InMemoryKeyStore);
fn fault(e: KeyStoreError) -> KeystoreFault {
    match e {
        KeyStoreError::Missing => KeystoreFault::Missing,
        KeyStoreError::Invalidated => KeystoreFault::Invalidated,
        KeyStoreError::AuthRequired => KeystoreFault::AuthRequired,
        KeyStoreError::AuthCancelled => KeystoreFault::AuthCancelled,
        KeyStoreError::Corrupt => KeystoreFault::Corrupt,
        KeyStoreError::Unavailable(_) => KeystoreFault::Unavailable,
    }
}
impl KeystoreCallbacks for Ks {
    fn capabilities(&self) -> Result<KeystoreCaps, KeystoreFault> {
        Ok(KeystoreCaps { best_level: KeyLevel::SoftwareOrUnknown, user_auth_supported: false, biometric_supported: false })
    }
    fn create_key(&self, alias: String, auth: bool, inv: bool, sb: bool) -> Result<KeyLevel, KeystoreFault> {
        self.0
            .create_key(&alias, &KeyPolicy { require_user_auth: auth, invalidate_on_biometric_change: inv, prefer_secure_element: sb })
            .map_err(fault)?;
        Ok(KeyLevel::SoftwareOrUnknown)
    }
    fn key_protection(&self, alias: String) -> Result<KeyLevel, KeystoreFault> {
        self.0.key_protection(&alias).map_err(fault)?;
        Ok(KeyLevel::SoftwareOrUnknown)
    }
    fn wrap(&self, alias: String, p: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, KeystoreFault> {
        self.0.wrap(&alias, &p, &aad).map_err(fault)
    }
    fn unwrap_into(&self, alias: String, b: Vec<u8>, aad: Vec<u8>, sink: Arc<dyn SecretSink>) -> Result<(), KeystoreFault> {
        let plain = self.0.unwrap(&alias, &b, &aad).map_err(fault)?;
        sink.put(plain.to_vec());
        Ok(())
    }
    fn delete_key(&self, alias: String) -> Result<(), KeystoreFault> {
        self.0.delete_key(&alias).map_err(fault)
    }
    fn counter_read(&self) -> Result<u64, KeystoreFault> {
        self.0.counter_read().map_err(fault)
    }
    fn counter_advance(&self, to: u64) -> Result<(), KeystoreFault> {
        self.0.counter_advance(to).map_err(fault)
    }
}

struct Curl {
    ca: String,
    resolve: String,
}
impl Curl {
    #[allow(clippy::too_many_arguments)]
    fn run(
        &self,
        base: &str,
        method: &str,
        path: &str,
        auth: Option<&str>,
        stdin_file: Option<&str>,
        body: &[u8],
        out: Option<&str>,
    ) -> Result<(u16, Vec<u8>), HttpFault> {
        let mut c = Command::new("curl");
        c.args(["-sS", "--tlsv1.3", "--proto", "=https", "--max-time", "120", "--cacert", &self.ca, "--connect-to", &self.resolve]);
        c.args(["-X", method, "-w", "\n%{http_code}"]);
        if let Some(a) = auth {
            c.args(["-H", &format!("Authorization: {a}")]);
        }
        if let Some(f) = stdin_file {
            c.args(["-H", "Content-Type: application/octet-stream", "--data-binary", &format!("@{f}")]);
        } else if method != "GET" {
            c.args(["-H", "Content-Type: application/octet-stream", "--data-binary", "@-"]);
        }
        if let Some(o) = out {
            c.args(["-o", o]);
        }
        c.arg(format!("{base}{path}"));
        c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = c.spawn().map_err(|_| HttpFault::Io)?;
        {
            let mut si = child.stdin.take().ok_or(HttpFault::Io)?;
            if stdin_file.is_none() && method != "GET" {
                si.write_all(body).map_err(|_| HttpFault::Io)?;
            }
        }
        let o = child.wait_with_output().map_err(|_| HttpFault::Io)?;
        if !o.status.success() {
            return Err(HttpFault::Network);
        }
        let s = &o.stdout;
        let nl = s.iter().rposition(|b| *b == b'\n').ok_or(HttpFault::Io)?;
        let code: u16 = std::str::from_utf8(&s[nl + 1..]).ok().and_then(|t| t.trim().parse().ok()).ok_or(HttpFault::Io)?;
        Ok((code, s[..nl].to_vec()))
    }
}
impl HttpCallbacks for Curl {
    fn execute(&self, base: String, method: String, path: String, auth: Option<String>, body: Vec<u8>) -> Result<HttpReply, HttpFault> {
        let (status, body) = self.run(&base, &method, &path, auth.as_deref(), None, &body, None)?;
        Ok(HttpReply { status, body })
    }
    fn upload_file(&self, base: String, path: String, auth: Option<String>, file: String) -> Result<HttpReply, HttpFault> {
        let (status, body) = self.run(&base, "POST", &path, auth.as_deref(), Some(&file), &[], None)?;
        Ok(HttpReply { status, body })
    }
    fn download_file(&self, base: String, path: String, auth: Option<String>, dest: String, _max: u64) -> Result<u16, HttpFault> {
        let (status, _) = self.run(&base, "GET", &path, auth.as_deref(), None, &[], Some(&dest))?;
        Ok(status)
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (dir, host, ca, ip) = (&a[1], &a[2], &a[3], &a[4]);
    let port = host.rsplit(':').next().unwrap();
    let http = Arc::new(Curl { ca: ca.clone(), resolve: format!("{host}:{ip}:{port}") });
    let ks = Arc::new(Ks(InMemoryKeyStore::new(ProtectionLevel::OsSoftware)));
    let eng = CipherEngine::new(
        EngineSettings {
            data_dir: dir.clone(),
            relay_url: format!("https://{host}"),
            allow_software_keystore: true,
            inactivity_timeout_secs: 3600,
            require_user_auth: false,
            extra_source_dir: Some(dir.clone()),
        },
        ks,
        http,
    )
    .unwrap();
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let p: Vec<&str> = line.splitn(4, ' ').collect();
        let out: String = match p[0] {
            "provision" => format!("{:?}", eng.provision_vault_pin_only("739104".into())),
            "register" => format!("{:?}", eng.create_identity(p[1].into())),
            "id" => format!("{:?}", eng.get_public_identity()),
            "add" => format!("{:?}", eng.add_contact_by_cipher_id(p[1].into(), p[2].into())),
            "contacts" => format!("{:?}", eng.list_contacts()),
            "dm" => format!("{:?}", eng.create_conversation(p[1].into())),
            "convs" => format!("{:?}", eng.list_conversations()),
            "accept" => format!("{:?}", eng.accept_conversation(p[1].into())),
            "send" => format!("{:?}", eng.send_text(p[1].into(), line.splitn(3, ' ').nth(2).unwrap().into(), None)),
            "sync" => format!("{:?}", eng.sync()),
            "flush" => format!("{:?}", eng.flush_outbox()),
            "history" => format!("{:?}", eng.get_history(p[1].into(), None, 50)),
            "group" => format!("{:?}", eng.create_group(p[1].into(), p[2..].iter().flat_map(|s| s.split(' ')).map(String::from).collect())),
            "remove" => format!("{:?}", eng.remove_group_member(p[1].into(), p[2].into())),
            "add_member" => format!("{:?}", eng.add_group_member(p[1].into(), p[2].into())),
            "promote" => format!("{:?}", eng.promote_admin(p[1].into(), p[2].into())),
            "refresh" => format!("{:?}", eng.refresh_keys(p[1].into())),
            "leave" => format!("{:?}", eng.leave_group(p[1].into())),
            "verify" => format!("{:?}", eng.verify_identity(p[1].into())),
            "safety" => format!("{:?}", eng.get_safety_number(p[1].into())),
            "members" => format!("{:?}", eng.get_members(p[1].into())),
            "file" => {
                let f = std::fs::File::open(p[2]).unwrap();
                let _keep = &f;
                let mime = p[3];
                let name = std::path::Path::new(p[2]).file_name().unwrap().to_string_lossy().into_owned();
                let kind = if mime.starts_with("image/") {
                    AttachmentKindFfi::Image
                } else if mime == "application/pdf" {
                    AttachmentKindFfi::Pdf
                } else {
                    AttachmentKindFfi::File
                };
                // /proc/self/fd/N is the interface the app uses: no plaintext copy is made by the core.
                use std::os::fd::AsRawFd;
                let path = format!("/proc/self/fd/{}", f.as_raw_fd());
                format!("{:?}", eng.send_attachment(p[1].into(), path, mime.into(), name, kind, String::new(), None, None, None, None))
            }
            "voice" => format!("{:?}", eng.send_voice_note(p[1].into(), std::fs::read(p[2]).unwrap(), 1500, None)),
            "open" => match eng.open_attachment(p[1].into(), p[2].into(), false, None) {
                Ok(b) => {
                    std::fs::write(p[3], &b).unwrap();
                    format!("Ok({} bytes -> {})", b.len(), p[3])
                }
                Err(e) => format!("Err({e:?})"),
            },
            "quit" => break,
            _ => "unknown".into(),
        };
        println!("{out}");
        std::io::stdout().flush().unwrap();
    }
}
