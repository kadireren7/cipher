//! Typed relay client. The platform networking layer implements `RelayTransport`
//! (TLS 1.2+/1.3 enforced by the OS stack and pinned config); this module enforces
//! what it can on the core side: https-only endpoints (no silent downgrade),
//! signed requests, and strict status handling.
//!
//! TLS IS NOT THE E2EE SECURITY BOUNDARY: everything sent through here that
//! carries message content is already protocol ciphertext.
use crate::clock::Clock;
use crate::error::{Result, SecurityError};
use crate::mls::MlsClient;
use cipher_wire::messages::*;
use cipher_wire::signing::{canonical_string, format_auth_header, AuthHeader, CanonicalParts};
use cipher_wire::Id16;
use sha2::Digest as _;

#[derive(Clone, Debug)]
pub struct RelayEndpoint {
    base: String,
    audience: String,
    pin: Option<[u8; 32]>,
}

impl RelayEndpoint {
    /// Only `https://host[:port]` is accepted. Anything else is an error, never a fallback.
    pub fn new(url: &str) -> Result<Self> {
        let rest = url.strip_prefix("https://").ok_or(SecurityError::Transport("https required"))?;
        let host = rest.trim_end_matches('/');
        if host.is_empty() || host.contains(['/', '@', '?', '#', ' ']) {
            return Err(SecurityError::Transport("invalid relay url"));
        }
        Ok(Self { base: format!("https://{host}"), audience: host.to_ascii_lowercase(), pin: None })
    }

    /// Test-only: in-process transports have no real URL.
    #[cfg(any(test, feature = "insecure-test-support"))]
    pub fn for_tests(audience: &str) -> Self {
        Self { base: format!("test://{audience}"), audience: audience.to_owned(), pin: None }
    }

    /// Endpoint for a relay named by a descriptor (validated). The pin, if any, is available to the transport through `pin()`.
    pub fn from_descriptor(d: &cipher_wire::RelayDescriptor) -> Result<Self> {
        let d = d.clone().validated().map_err(|_| SecurityError::Transport("invalid relay descriptor"))?;
        let pin = d.pin().map_err(|_| SecurityError::Transport("invalid relay descriptor"))?;
        let mut e = Self::new(d.url())?;
        e.pin = pin;
        Ok(e)
    }

    /// SHA-256 of the relay certificate's SubjectPublicKeyInfo that the transport must require (instead of a CA chain), if the descriptor carried one.
    pub fn pin(&self) -> Option<[u8; 32]> {
        self.pin
    }

    pub fn base(&self) -> &str {
        &self.base
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum GroupCommitResult {
    Accepted(u64),
    Stale(u64),
    Gone,
}

#[derive(Debug)]
pub struct HttpRequest {
    pub method: &'static str,
    pub path_and_query: String,
    pub authorization: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub trait RelayTransport {
    fn execute(&self, endpoint: &RelayEndpoint, req: HttpRequest) -> Result<HttpResponse>;

    /// Upload the file at `path` as the request body (streamed; never fully in memory). `req.body` is empty.
    fn upload_file(&self, _endpoint: &RelayEndpoint, _req: HttpRequest, _path: &str) -> Result<HttpResponse> {
        Err(SecurityError::Transport("file upload unsupported"))
    }

    /// Stream the response body to `dest` (at most `max_bytes`). Returns the HTTP status.
    fn download_file(&self, _endpoint: &RelayEndpoint, _req: HttpRequest, _dest: &str, _max_bytes: u64) -> Result<u16> {
        Err(SecurityError::Transport("file download unsupported"))
    }
}

pub struct RelayApi<'a> {
    pub transport: &'a dyn RelayTransport,
    pub endpoint: &'a RelayEndpoint,
    pub client: &'a MlsClient,
    pub clock: &'a dyn Clock,
}

impl std::fmt::Debug for RelayApi<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RelayApi")
    }
}

fn check(resp: HttpResponse) -> Result<HttpResponse> {
    match resp.status {
        200..=299 => Ok(resp),
        401 | 403 => Err(SecurityError::Transport("unauthorized")),
        404 => Err(SecurityError::Transport("not found")),
        409 => Err(SecurityError::Transport("conflict")),
        413 => Err(SecurityError::Transport("payload too large")),
        429 => Err(SecurityError::Transport("rate limited")),
        500..=599 => Err(SecurityError::Transport("server error")),
        _ => Err(SecurityError::Transport("request rejected")),
    }
}

fn json<T: serde::de::DeserializeOwned>(resp: &HttpResponse) -> Result<T> {
    serde_json::from_slice(&resp.body).map_err(|_| SecurityError::Transport("malformed response"))
}

fn enc<T: serde::Serialize>(v: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|_| SecurityError::Malformed("encode"))
}

impl RelayApi<'_> {
    fn send_unauth(&self, method: &'static str, path: &str, body: Vec<u8>) -> Result<HttpResponse> {
        check(self.transport.execute(self.endpoint, HttpRequest { method, path_and_query: path.to_owned(), authorization: None, body })?)
    }

    fn signed_header_for_hash(&self, method: &'static str, path: &str, body_hash: &[u8; 32]) -> Result<String> {
        let nonce = crate::rng::array::<16>()?;
        let ts = self.clock.unix_secs();
        let device = self.client.device_id();
        let canonical = cipher_wire::signing::canonical_string_with_hash(
            &CanonicalParts {
                audience: self.endpoint.audience(),
                method,
                path_and_query: path,
                timestamp: ts,
                nonce: &nonce,
                body: &[],
                device: &device,
            },
            body_hash,
        );
        let signature = self.client.sign_transport(&canonical);
        Ok(format_auth_header(&AuthHeader { device, timestamp: ts, nonce, signature, body_hash: Some(*body_hash) }))
    }

    fn send_signed_raw(&self, method: &'static str, path: &str, body: Vec<u8>) -> Result<HttpResponse> {
        self.send_signed_raw_inner(method, path, body, false)
    }

    /// `announce_hash`: also put the body hash into the header (`bh=`) so the relay can authenticate BEFORE it reads a large body.
    fn send_signed_raw_inner(&self, method: &'static str, path: &str, body: Vec<u8>, announce_hash: bool) -> Result<HttpResponse> {
        let nonce = crate::rng::array::<16>()?;
        let ts = self.clock.unix_secs();
        let device = self.client.device_id();
        let canonical = canonical_string(&CanonicalParts {
            audience: self.endpoint.audience(),
            method,
            path_and_query: path,
            timestamp: ts,
            nonce: &nonce,
            body: &body,
            device: &device,
        });
        let signature = self.client.sign_transport(&canonical);
        let body_hash = announce_hash.then(|| -> [u8; 32] { sha2::Sha256::digest(&body).into() });
        let authorization = format_auth_header(&AuthHeader { device, timestamp: ts, nonce, signature, body_hash });
        self.transport
            .execute(self.endpoint, HttpRequest { method, path_and_query: path.to_owned(), authorization: Some(authorization), body })
    }

    fn send_signed(&self, method: &'static str, path: &str, body: Vec<u8>) -> Result<HttpResponse> {
        check(self.send_signed_raw(method, path, body)?)
    }

    pub fn register_account(&self, registration_token: &str) -> Result<()> {
        let body = enc(&RegisterRequest {
            account_id: self.client.account_id(),
            registration_token: registration_token.to_owned(),
            device: self.client.device_record(None)?,
        })?;
        self.send_unauth("POST", "/v1/accounts", body).map(|_| ())
    }

    pub fn add_device(&self, registration_token: &str, endorsement: Endorsement) -> Result<()> {
        let body = enc(&AddDeviceRequest {
            account_id: self.client.account_id(),
            registration_token: registration_token.to_owned(),
            device: self.client.device_record(Some(endorsement))?,
        })?;
        self.send_unauth("POST", "/v1/devices", body).map(|_| ())
    }

    pub fn directory(&self, account: &Id16) -> Result<DirectoryResponse> {
        json(&self.send_signed("GET", &format!("/v1/accounts/{account}/devices"), Vec::new())?)
    }

    pub fn upload_key_packages(&self, kps: Vec<Vec<u8>>) -> Result<()> {
        let up = UploadKeyPackages { key_packages: kps };
        up.validate().map_err(|_| SecurityError::Malformed("key packages"))?;
        self.send_signed("PUT", "/v1/key-packages", enc(&up)?).map(|_| ())
    }

    pub fn consume_key_package(&self, device: &Id16) -> Result<Vec<u8>> {
        let r: KeyPackageResponse = json(&self.send_signed("POST", &format!("/v1/devices/{device}/key-package"), Vec::new())?)?;
        Ok(r.key_package)
    }

    pub fn send_message(&self, recipient: Id16, message_id: Id16, ciphertext: Vec<u8>, ttl_secs: Option<u64>) -> Result<SendStatus> {
        let req = SendRequest { message_id, recipient_device: recipient, ciphertext, ttl_secs };
        req.validate().map_err(|_| SecurityError::Malformed("send request"))?;
        let r: SendResponse = json(&self.send_signed("POST", "/v1/messages", enc(&req)?)?)?;
        Ok(r.status)
    }

    /// Registers capabilities (chosen by us) that let contacts deliver to this device without authenticating.
    pub fn mint_caps(&self, caps: Vec<Id16>) -> Result<()> {
        self.mint_caps_inner(caps, false)
    }

    /// Registers an INTRO capability for a contact card (docs/MULTI_RELAY_PROTOCOL.md §4).
    pub fn mint_intro_cap(&self, cap: Id16) -> Result<()> {
        self.mint_caps_inner(vec![cap], true)
    }

    fn mint_caps_inner(&self, caps: Vec<Id16>, intro: bool) -> Result<()> {
        let req = MintCapsRequest { caps, intro };
        req.validate().map_err(|_| SecurityError::Malformed("mint caps"))?;
        self.send_signed("POST", "/v1/caps", enc(&req)?).map(|_| ())
    }

    /// UNAUTHENTICATED (card holder → the card issuer's relay, i.e. `self.endpoint`): the issuer's device records. They are self-authenticating, so
    /// the caller MUST evaluate them against the pinned root key from the card; this call alone proves nothing.
    pub fn intro_directory(&self, cap: &Id16) -> Result<DirectoryResponse> {
        json(&self.send_unauth("POST", "/v1/intro/directory", enc(&IntroRequest { cap: *cap, device: None })?)?)
    }

    /// UNAUTHENTICATED: consume one KeyPackage of one of the issuer's devices.
    pub fn intro_key_package(&self, cap: &Id16, device: &Id16) -> Result<Vec<u8>> {
        let r: KeyPackageResponse =
            json(&self.send_unauth("POST", "/v1/intro/key-package", enc(&IntroRequest { cap: *cap, device: Some(*device) })?)?)?;
        Ok(r.key_package)
    }

    pub fn revoke_caps(&self, caps: Vec<Id16>, grace_secs: Option<u64>) -> Result<()> {
        let req = RevokeCapsRequest { caps, grace_secs };
        req.validate().map_err(|_| SecurityError::Malformed("revoke caps"))?;
        self.send_signed("POST", "/v1/caps/revoke", enc(&req)?).map(|_| ())
    }

    /// UNAUTHENTICATED delivery with recipients' capabilities: the relay learns neither who we are nor the recipients' stable ids.
    pub fn anon_deliver(&self, deliveries: Vec<AnonDelivery>, ttl_secs: Option<u64>) -> Result<Vec<String>> {
        let req = AnonDeliverRequest { deliveries, ttl_secs };
        req.validate().map_err(|_| SecurityError::Malformed("anon deliver"))?;
        let r: AnonDeliverResponse = json(&self.send_unauth("POST", "/v1/deliver", enc(&req)?)?)?;
        Ok(r.results)
    }

    pub fn fetch_messages(&self) -> Result<FetchResponse> {
        json(&self.send_signed("GET", "/v1/messages", Vec::new())?)
    }

    pub fn ack(&self, ids: Vec<Id16>) -> Result<()> {
        let a = AckRequest { message_ids: ids };
        a.validate().map_err(|_| SecurityError::Malformed("ack"))?;
        self.send_signed("POST", "/v1/messages/ack", enc(&a)?).map(|_| ())
    }

    pub fn register_push_token(&self, token: &str) -> Result<()> {
        self.send_signed("PUT", "/v1/push-token", enc(&PushTokenRequest { token: token.to_owned() })?).map(|_| ())
    }

    pub fn upload_blob(&self, ciphertext: Vec<u8>) -> Result<Id16> {
        let r: BlobCreated = json(&check(self.send_signed_raw_inner("POST", "/v1/blobs", ciphertext, true)?)?)?;
        Ok(r.blob_id)
    }

    /// Upload an already-encrypted blob file; the body hash is computed by streaming (the file is not loaded into memory).
    pub fn upload_blob_file(&self, path: &str) -> Result<Id16> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let mut f = std::fs::File::open(path).map_err(|_| SecurityError::Transport("cannot read upload file"))?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf).map_err(|_| SecurityError::Transport("cannot read upload file"))?;
            if n == 0 {
                break;
            }
            h.update(buf.get(..n).unwrap_or(&[]));
        }
        let hash: [u8; 32] = h.finalize().into();
        let authorization = self.signed_header_for_hash("POST", "/v1/blobs", &hash)?;
        let resp = check(self.transport.upload_file(
            self.endpoint,
            HttpRequest { method: "POST", path_and_query: "/v1/blobs".to_owned(), authorization: Some(authorization), body: Vec::new() },
            path,
        )?)?;
        let r: BlobCreated = json(&resp)?;
        Ok(r.blob_id)
    }

    pub fn download_blob_file(&self, id: &Id16, dest: &str, max_bytes: u64) -> Result<()> {
        use sha2::{Digest, Sha256};
        let path = format!("/v1/blobs/{id}");
        let hash: [u8; 32] = Sha256::digest(b"").into();
        let authorization = self.signed_header_for_hash("GET", &path, &hash)?;
        let status = self.transport.download_file(
            self.endpoint,
            HttpRequest { method: "GET", path_and_query: path, authorization: Some(authorization), body: Vec::new() },
            dest,
            max_bytes,
        )?;
        check(HttpResponse { status, body: Vec::new() }).map(|_| ())
    }

    pub fn send_batch(&self, deliveries: Vec<Delivery>, ttl_secs: Option<u64>) -> Result<Vec<String>> {
        let req = BatchSendRequest { deliveries, ttl_secs };
        req.validate().map_err(|_| SecurityError::Malformed("batch"))?;
        let r: BatchSendResponse = json(&self.send_signed("POST", "/v1/messages/batch", enc(&req)?)?)?;
        Ok(r.results)
    }

    /// Group commit through the sequencer. `Stale(current)` means another commit won: process the inbox, rebase, retry.
    pub fn group_commit(
        &self,
        tag: &Id16,
        expected_epoch: u64,
        new_tag: Option<Id16>,
        deliveries: Vec<Delivery>,
    ) -> Result<GroupCommitResult> {
        let req = GroupCommitRequest { expected_epoch, new_tag, deliveries };
        req.validate().map_err(|_| SecurityError::Malformed("group commit"))?;
        let resp = self.send_signed_raw("POST", &format!("/v1/groups/{tag}/commit"), enc(&req)?)?;
        match resp.status {
            200..=299 => Ok(GroupCommitResult::Accepted(json::<GroupCommitResponse>(&resp)?.epoch)),
            409 => Ok(GroupCommitResult::Stale(json::<GroupStaleResponse>(&resp)?.current_epoch)),
            410 => Ok(GroupCommitResult::Gone),
            _ => check(resp).map(|_| GroupCommitResult::Gone),
        }
    }

    pub fn download_blob(&self, id: &Id16) -> Result<Vec<u8>> {
        Ok(self.send_signed("GET", &format!("/v1/blobs/{id}"), Vec::new())?.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_and_odd_urls_are_rejected() {
        for bad in
            ["http://relay.example", "ws://x", "relay.example", "https://", "https://user@relay.example", "https://relay.example/path"]
        {
            assert!(RelayEndpoint::new(bad).is_err(), "{bad}");
        }
        assert!(RelayEndpoint::new("https://relay.example:8443/").is_ok());
    }
}
