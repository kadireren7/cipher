# Threat model

Scope: the Android app (Kotlin/Compose UI, `cipher-ffi` bridge, Android Keystore wrapper), the Rust core (`cipher-core`, `cipher-wire`) and the
relay (`cipher-relay` + PostgreSQL). Every security property below is stated *against a named adversary and explicit
assumptions*. Nothing here claims the system is unbreakable or anonymous. **Passing tests does not prove Cipher secure**: claims are labelled with
what was actually exercised (see `SECURITY_TESTING.md`).

Legend: **Implemented** = exists and is tested here. **Designed** = interface/decision exists, not built.
**Not addressed** = explicitly out of scope for this phase. Invariant IDs refer to `SECURITY_INVARIANTS.md`.

> **Final review:** the complete list of attack surfaces mapped to these adversaries is in `ATTACK_SURFACE.md`; what was found, fixed and left open is in `FINAL_SECURITY_REVIEW.md`. Adversaries A17–A18 below were added by that review.

## 1. Assets

| # | Asset | Where it lives | Protected by | Who may access |
| --- | --- | --- | --- | --- |
| 1 | Message plaintext | Authorized participant devices only (in memory while displayed; encrypted at rest in the vault) | MLS (RFC 9420) E2EE in transit; vault AEAD at rest; lock lifecycle | Unlocked participant devices |
| 2 | Attachment plaintext | Participant devices; never at relay/storage | Per-file random key, chunked AEAD, client-side only | Participants who received the descriptor |
| 3 | Conversation history | Local vault records | Vault AEAD under hardware-wrapped DEK | Unlocked device |
| 4 | Identity keys (Ed25519 signature key per device) | Inside MLS state snapshot in the vault | Vault; never leaves device; not in plain storage (SEC-008) | Device only |
| 5 | Session/group key material (MLS epoch secrets, ratchets, HPKE keys) | Vault (snapshot) / process memory while unlocked | Vault; MLS forward secrecy | Device only |
| 6 | Local database | `vault.db` | Record-level AEAD, location-bound; DEK wrapped by keystore (+ optional PIN) | Unlocked device |
| 7 | Authentication credentials | (a) device transport-auth key (in vault), (b) server account credential (registration token; future per-user credential) | (a) vault; separate from identity key; (b) hashed in relay config | (a) device (b) account holder |
| 8 | Device identity | Device id + identity key + auth key + binding signature + endorsements | Identity-key signatures; client-side pinning | Public (directory); private halves on device |
| 9 | Contact / group relationships | Local vault; at relay only *implicitly* (device ids in send requests, queue rows) | Not stored as an explicit graph at relay; see `METADATA_MODEL.md` | Device; relay sees fragments (A2) |
| 10 | Metadata | Relay DB/logs, TLS terminator, push provider, ISP | Minimisation; no sender stored; constant push payload; see `METADATA_MODEL.md` | Not protected from relay/network (documented) |
| 11 | Notification contents | Push provider, OS notification centre, lock screen | Constant wake payload; generic local text; lock-screen "secret" visibility | OS/provider see *that* a wake happened |

## 2. Trust assumptions (apply to every adversary unless stated)

* The cryptographic libraries (OpenMLS 0.9.0 + RustCrypto/dalek via `openmls_rust_crypto`, `chacha20poly1305`,
  `argon2`, `hkdf`, `sha2`, `ed25519-dalek`, `rustls`+`ring`) are correct. **We have not independently audited them**; see
  `CRYPTOGRAPHIC_DESIGN.md` for what is known and unknown.
* The OS CSPRNG is sound; the Android Keystore (StrongBox/TEE) behaves as documented — **never verified on real hardware here**.
* The user's device is not already compromised, except where an adversary row says otherwise (A13).
* Clients are not modified by the adversary (a modified client can leak anything it can read).

## 3. Adversaries

For each: **Observes**, **Modifies**, **Must stay confidential**, **Cannot realistically be protected**,
**Assumptions**, **Where addressed**.

### A1 — Passive ISP / mobile-network observer
* **Observes:** TLS 1.3 ciphertext between device and relay and between device and push provider; relay IP, timing, volume,
  packet sizes; TLS SNI (Encrypted Client Hello is not implemented).
* **Modifies:** nothing (passive).
* **Must stay confidential:** all message and attachment plaintext, all keys.
* **Cannot protect:** the fact that a device uses the service, when it is active, rough message sizes and timing (traffic
  analysis). MLS padding (128-byte granularity) blurs sizes only slightly.
* **Assumptions:** TLS 1.3 is sound; E2EE does not rely on it (SEC-005).
* **Addressed:** SEC-005 (wire capture, TLS 1.3-only server config, TLS 1.2/untrusted-cert refusal tests). Metadata: `METADATA_MODEL.md`.

### A2 — Malicious or compromised application server (relay)
* **Observes:** everything the relay process handles: ciphertext, recipient device ids, sender device id *transiently*
  (to verify the send signature), source IPs at the TLS terminator, public keys, KeyPackages, push tokens, queue timing,
  directory lookups, the random per-group routing tag and commit sequence, and **which requests are group commits** (it sequences them). If it parses MLS framing it also sees `group_id`, `epoch`
  and `content_type` (all in the clear in an MLS `PrivateMessage`; the relay in this repo does not parse them, a malicious one can).
* **Modifies:** drop, delay, reorder, duplicate, inject, misroute ciphertext; serve forged/swapped directory records and
  KeyPackages; present different views to different users (split view); refuse service.
* **Must stay confidential:** message/attachment plaintext, private keys, local history.
* **Final-review result for a fully controlled relay + PostgreSQL** (tests in `relay_compromise.rs`): ciphertext tampering, redirection to the wrong device, duplication, old-commit replay, fake acknowledgements, routing-tag retirement and relay counter resets are **prevented** or fail closed; a group **partition** is **detected** only as undecryptable traffic and heals only if the relay cooperates; **message dropping/delay is undetectable** (ST-032); denial of service is always possible.
* **Cannot protect:** availability and censorship; metadata listed above; **first-contact key substitution** unless users
  compare safety numbers/QR out-of-band (TOFU), because key transparency is not deployed (an experimental verifier exists, `KEY_TRANSPARENCY.md`); commit ordering between
  a **partition of a group** by showing different commit orders to different members (detectable as undecryptable traffic, not preventable; `GROUP_SECURITY.md` §4).
* **Assumptions:** clients pin identity keys and verify endorsements (implemented); users verify safety numbers when warned.
* **Addressed:** SEC-001, SEC-002, SEC-011, SEC-013, SEC-014. Tests: relay invariants, `sec_011_*`.

### A3 — Complete production database leak
* **Observes:** queued ciphertext (bounded by TTL), directory rows (account→device mapping, public keys, endorsement
  graph = device lists), KeyPackages, push tokens, message-id tombstones, encrypted attachment blobs.
* **Modifies:** n/a (read-only leak); if the attacker can also write, treat as A2.
* **Must stay confidential:** all content and keys. The DB holds no private key and no decryption capability.
* **Cannot protect:** social-graph fragments (recipient device ids with queue rows at dump time), device/account linkage,
  push tokens (device identifiers known to the push provider), blob sizes and counts.
* **Assumptions:** relay secrets (TLS key, registration token) are not stored in the DB (they are env/config).
* **Addressed:** SEC-003 (`sec_003_full_database_dump_is_insufficient_to_decrypt_history`), SEC-002.

### A4 — Compromised object-storage / CDN provider
* **Observes:** blob ciphertext, exact ciphertext size, upload/download times, requester IPs, blob ids.
* **Modifies:** corrupt, truncate, swap, replay or delete blobs.
* **Must stay confidential:** file contents, file name, MIME type, attachment key (all inside the E2EE descriptor).
* **Cannot protect:** file-size leakage, access patterns, availability (deletion).
* **Assumptions:** descriptor travels only inside the E2EE message. Today blobs are stored by the relay itself; the
  `BlobStore` abstraction for a separate provider is **Designed, not built** (SECURITY TODO ST-011).
* **Addressed:** SEC-004, SEC-015 (tamper/truncate/reorder detected; descriptor carries the ciphertext hash).

### A5 — Active network MITM
* **Observes/Modifies:** can block or alter traffic; can present a rogue certificate only if a trusted CA is subverted
  or a user-installed CA were trusted — the network-security config trusts system anchors only (the throwaway test CA exists only in debug builds).
* **Must stay confidential:** message content even if TLS is fully broken (E2EE). Request authenticity: requests are
  signed per device with audience binding, timestamp and single-use nonce, so captured requests cannot be replayed or
  re-targeted (SEC-014).
* **Cannot protect:** metadata exposure and denial of service if TLS is broken; key substitution on first contact (see A2).
* **Assumptions:** clients refuse non-https endpoints (implemented) and use the platform TLS stack with certificate
  validation. **Certificate pinning is a SECURITY TODO (ST-002)** (needs a rotation plan).
* **Addressed:** SEC-005, SEC-013, SEC-014, SEC-016.

### A6 — Attacker holding a locked, powered-on phone (after first unlock)
* **Observes:** lock-screen content (notifications are generic: "New message"; the default mode never shows sender or text), app presence, encrypted files on flash if
  they can extract them.
* **Modifies:** attempts PIN/biometric guesses, may try to dump process memory or files with forensic tooling.
* **Must stay confidential:** vault contents and identity keys. While the app is locked/backgrounded the DEK is dropped
  from memory and the keystore key is auth-gated (`setUnlockedDeviceRequired`, user-auth per use) — *designed, only the wrapper's non-biometric behaviour was tested, on an emulator*.
* **Cannot protect:** an OS-level exploit on an after-first-unlock device can reach whatever the OS itself can decrypt;
  our extra layer is that the DEK additionally requires an auth-gated hardware key operation. Anything the app held in
  memory *while unlocked* at seizure time is exposed (that is A13).
* **Assumptions:** strong device passcode; platform patched; hardware throttling of auth attempts works; the Keystore
  wrapper behaves as designed (**never executed on a physical device**).
* **Addressed:** SEC-009, vault lifecycle tests, PIN limiter tests. PIN guesses additionally require the hardware-bound
  secret `S` (a stolen database copy cannot be attacked offline: `pin_unlock_requires_the_hardware_bound_secret`).

### A7 — Attacker holding a powered-off phone
* **Observes:** encrypted storage only.
* **Must stay confidential:** everything at rest. Keys are rooted in hardware that is unusable without the device
  passcode; our vault adds a second layer (keystore-wrapped DEK, optional PIN).
* **Cannot protect:** a weak device passcode; hardware/firmware vulnerabilities; a tampered device later returned to the
  user (evil maid).
* **Assumptions:** hardware key protection is not bypassed; reports of the *actual* protection level are honest
  (the core refuses to run below the configured minimum — SEC-016).
* **Addressed:** SEC-008, SEC-009, SEC-016.

### A8 — Knows the user's server account credentials, does not hold the device
* **Observes/Modifies:** can authenticate as the account to the *server*, attempt to register devices.
* **Must stay confidential:** all messages and history (the credential grants no key material).
* **Cannot protect:** nuisance/DoS at the account level; a future account-recovery flow is the real risk surface and is
  **not designed yet**.
* **Assumptions:** device keys are separate from the account credential (they are: device transport-auth key ≠ identity
  key ≠ account token). A new device must be **endorsed by an existing device's identity key**; the relay checks it and
  peers re-check it, raising `UnendorsedDevice`/`DeviceListChanged` events.
* **Addressed:** SEC-018 (`account_credential_alone_cannot_add_a_device_a8`), SEC-011.

### A9 — Removed group member
* **Knows:** everything up to the removal epoch: plaintext they received, old epoch secrets, member list at that time.
* **Must stay confidential:** all messages created in later epochs; and (since the history-revocation layer, `HISTORY_REVOCATION.md`) the **Cipher-retained** pre-removal history on their device once their compliant client observes the removal (REV-001..REV-010).
* **Cannot protect:** plaintext they copied/screenshotted/exported before removal, anything a modified client kept, what they saw (metadata); a relay that withholds the removal commit delays revocation on their device (tested, documented).
* **Assumptions:** removal commit is processed by remaining members; the removed member cannot obtain future
  key material (MLS tree-based key schedule).
* **Addressed:** SEC-006 (three tests incl. stolen pre-removal snapshot and a relay that misroutes ciphertext to the
  removed member); the routing tag rotates on removal so the removed member cannot keep submitting commits. Also exercised on the **real relay binary with the Android app as a member** (`SECURITY_TESTING.md` §6).

### A10 — Malicious current group member
* **Observes:** all group plaintext (by definition).
* **Modifies:** can send spam and attempt commits; cannot forge another member's authenticated messages.
* **Must stay confidential:** other groups, other members' private keys, history from before they joined (a new
  member does not receive past epoch secrets).
* **Cannot protect:** leaks by the member; abuse within their role.
* **Authorisation (ST-007, resolved):** roles OWNER/ADMIN/MEMBER live in an MLS-authenticated GroupContext extension and **every receiver** runs the same pure `authorize_commit` before merging a commit; a
  member's forged add/remove/rename/role change is rejected by everyone and does not brick the group. The relay is not trusted for any of this.
* **Addressed:** SEC-010, `group_policy.rs` (7), `engine_groups.rs` (8). Details and residuals: `GROUP_SECURITY.md`.

### A11 — Compromised dependency / build pipeline
* **Can:** ship a malicious crate/Maven release, tamper with CI, poison caches.
* **Mitigations (implemented):** exact version pins for security-critical crates, committed lockfiles, `--locked` builds,
  Gradle dependency pinning via a version catalogue, `cargo deny` (sources, bans, licences, advisories), `cargo audit`, no OpenSSL/native-tls,
  minimal dependency set, SHA-pinned GitHub Actions, least-privilege CI token, `unsafe` forbidden in our code.
* **Cannot protect:** a malicious release of an audited-by-reputation crate that also passes review; no reproducible
  builds, no SBOM, no signed provenance, no vendoring yet (SECURITY TODO ST-014).
* **Assumptions:** crates.io / Maven Central / Google Maven integrity and the lockfile checksums.

### A12 — Replay attacker
* **Can:** resend captured HTTP requests, protocol ciphertext, commits, welcomes.
* **Mitigations (implemented):** signed requests with timestamp window ± 60 s, single-use nonce (only valid signatures
  occupy the cache), audience binding, body hash; relay dedup on `(recipient, message_id)` that survives acknowledgement
  until TTL; client replay cache plus MLS secret-tree consumption; commits cannot advance the epoch twice.
* **Cannot protect:** replay after the relay's TTL window re-enqueues a message id (the client cache and MLS then reject
  it); the client replay cache is bounded (8192).
* **Addressed:** SEC-014 (four tests).

### A13 — Compromised endpoint while the user is actively using the app
* **Observes:** *everything the authorised device can see*: plaintext on screen, decrypted history, keys in memory, the
  vault while unlocked.
* **Cannot protect:** **application-layer cryptography cannot provide confidentiality on a fully compromised
  authorised device.** Screen recording, accessibility abuse, hooking, a rooted/jailbroken device with malware, and
  physical shoulder-surfing defeat any E2EE design.
* **What we do to shrink the window:** keys are dropped on background/inactivity/screen lock; `FLAG_SECURE` on every window (screenshots, recording, Recents) —
  which does **not** stop another camera pointed at the screen; generic notifications; MLS forward secrecy limits what a *later* compromise reveals about *earlier*
  traffic that is no longer stored; post-compromise security lets a healed device regain secrecy once it issues an
  update commit and the attacker loses access (tested: `sec_007_post_compromise_security_*`). Local history stored in
  the vault is *not* ratcheted and is exposed if the vault is open.

### A17 — Attacker who can replace the app's files with an older copy (rollback)
* **Can:** restore an old `vault.db` (backup restore, a rooted/forensic tool, a malicious app with storage access on a rooted device, `adb` on a debuggable build), delete rows.
* **Why it matters:** besides resurrecting deleted data, a restored MLS state makes the device **reuse ratchet keys and nonces** for new messages.
* **Mitigation:** encrypted generation record + monotonic counter held in the platform keystore (outside the data directory); a vault older than the counter is refused and invalidated. **Not covered:** same-session snapshots, deletion of the counter entries (needs code execution as the app/root), per-record rollback, hardware-protected counters (Android offers none to apps). See `LOCAL_STORAGE_SECURITY.md` §8.

### A18 — Hostile contact or group member sending malicious media / abusive traffic
* **Can:** send images with decompression-bomb headers, malformed audio/video/PDF, oversized descriptors, floods; drain a victim's KeyPackages; fill a victim's relay inbox.
* **Mitigation:** bounded, `Throwable`-safe decoding and guarded players (`SafeDecode`), size/MIME/filename limits before exposure, per-target KeyPackage limits. **Not covered:** inbox flooding (ST-031), platform codec/renderer vulnerabilities (ST-034).

### A14 — Another app on the same Android device
* **Can:** read world-readable files and the clipboard, listen for exported components/intents, draw overlays (if permitted), request accessibility.
* **Mitigations:** app-private storage in `noBackupFilesDir`; no exported component except the launcher; no deep links, providers or services; no external storage; clipboard use is opt-in, flagged sensitive and cleared after 60 s;
  `FLAG_SECURE` hides content from screen capture APIs. **Cannot protect:** a user-granted accessibility service or a rooted device reads the screen/process.
* **Evidence:** manifest/installed-package tests (TESTED); no cross-app attack was attempted (NOT TESTED).

### A15 — Hostile or compromised Kotlin/UI layer
* **Can:** call the FFI with arbitrary arguments, call it in the wrong order, make callbacks fail or panic, and observe everything the UI is entitled to see.
* **Mitigations:** every FFI input is validated and bounded; lifecycle misuse returns `Locked`/`InvalidState`; panics are contained and lock the vault; no key, MLS state or attachment key is returned by any function.
  **Cannot protect:** code injected into the app process while the vault is unlocked can ask the engine for plaintext exactly as the UI does, and can observe the 32-byte vault key during a Keystore unwrap (ST-027).
* **Evidence:** `boundary_behaviour.rs` (12), `boundary_guards.rs` (6), instrumented lifecycle/malformed-id tests.

### A16 — Attacker with adb / a debuggable build
* **Can:** `run-as`, backup, attach debuggers to debuggable builds. **Mitigations:** release is non-debuggable, `allowBackup=false`; the debug-only no-auth marker file is honoured only when `BuildConfig.DEBUG`
  (guarded; absent in release). **Cannot protect:** a debug build installed by the user; a rooted device.

## 4. Explicit non-goals of this phase

Anonymity / metadata-resistant transport (interfaces only); resistance to traffic analysis; compelled disclosure
(rubber-hose); deniability (MLS signatures are not deniable); contact-discovery privacy; spam/abuse policy beyond rate
limits; post-quantum protection (the chosen ciphersuite is classical); hardware attacks; malicious OS/baseband; physical-device
validation of the Keystore (still open, ST-001); independent cryptographic review (ST-005).
