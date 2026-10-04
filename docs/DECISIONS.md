# Architecture decision log

Each entry: decision, alternatives, rationale, consequences. Newest decisions are appended.

**ADR-001 Rust core + native shell.** *Alternatives:* fully native Kotlin crypto; React Native with JS crypto. *(Updated: the shell is now Kotlin/Compose on Android only — ADR-019.)*
*Why:* one memory-safe, testable implementation of the security logic for both platforms; JS cannot hold or wipe secrets reliably; native
crypto twice doubles audit surface. *Consequence:* needs an FFI layer (UniFFI, built — ADR-020); platform code stays minimal (keystore, biometrics, lifecycle).

**ADR-002 MLS (RFC 9420) via OpenMLS for 1:1 and groups; not Signal/libsignal, not Olm/Megolm.** *Why:* standards-track, tree-based groups with real
removal semantics, FS + PCS, one protocol (no unsafe composition), permissive licence and crates.io distribution (libsignal is AGPL-3.0 and distributed via git).
*Consequence:* needs KeyPackages and a commit-ordering story (open item); OpenMLS audit status must be verified before production.

**ADR-003 Protocol behind `GroupProtocol`.** *Why:* replaceable and independently auditable implementation; storage/transport/UI never see protocol internals.

**ADR-004 Relay in Rust with no crypto dependencies beyond signature verification + TLS.** *Why:* "untrusted relay" is enforced structurally (CI graph check), not by promise.

**ADR-005 Keystore as a wrapping oracle, not a key exporter.** *Why:* non-exportable hardware keys; the core never handles keystore key bytes; a uniform contract for the Android Keystore (AES-256-GCM, AAD-bound). *Consequence:* the Keystore returns the unwrapped 32-byte vault key to the app process, so it transits JVM memory (documented residual, ST-027).

**ADR-006 Vault key hierarchy: DEK wrapped by hardware key; optional PIN envelope requiring a hardware-bound secret.** *Why:* an offline attacker with the database cannot brute-force a PIN
without the device's keystore; biometric and PIN paths are independent. *Consequence:* a new device cannot unlock a copied database (by design).

**ADR-007 Argon2id 64 MiB/t=3/p=1 with a floor of 19 MiB/t=2 enforced on load.** *Why:* RFC 9106/OWASP; stored-parameter downgrade fails closed. *Consequence:* needs on-device benchmarking (ST-003).

**ADR-008 Record-level AEAD (XChaCha20-Poly1305, location-bound AAD) over SQLite now; SQLCipher as a later defence-in-depth layer.** *Why:* builds/tests on a plain toolchain, no custom crypto, AEAD
failures are explicit. *Consequence:* table names/ids/sizes visible at rest (documented).

**ADR-009 Separate transport-auth key and per-request signatures instead of bearer tokens.** *Why:* nothing replayable is ever transmitted; identity key never signs HTTP; account credential ≠ device credential.
*Consequence:* needs clocks within ±60 s; nonce cache must be shared in multi-instance deployments (ST-012).

**ADR-010 TLS 1.3 only, on the relay and in the app.** *Why:* "modern TLS", smaller attack surface; OkHttp is restricted to a TLS 1.3 `ConnectionSpec`. *Consequence:* minSdk is 30 (Android 11); TLS is not the E2EE boundary regardless.

**ADR-011 Do not store or forward the sender.** *Why:* MLS authenticates the sender inside the ciphertext; the relay does not need it. *Consequence:* the relay can't offer sender-based abuse controls.

**ADR-012 STREAM (chunked AEAD) for attachments with per-file random keys.** *Why:* standard construction in RustCrypto; truncation/reorder detection; bounded memory per chunk.

**ADR-013 TOFU pins + device endorsements + safety numbers/QR.** *Why:* detectable key substitution without needing key transparency yet. *Consequence:* first-contact lie undetectable without out-of-band
verification (documented; KT is future work).

**ADR-014 No destructive wipe, no silent downgrade, no analytics.** *Why:* accidental/malicious wipe is a safety hazard; downgrades defeat guarantees; third-party SDKs leak metadata.

**ADR-015 Test-only code behind `insecure-test-support` and asserted absent from the production dependency graph.** *Why:* fakes (in-memory keystore, weak KDF params, manual clock) must not be
shippable. `KdfFloor::DisabledForTests` and `ProtectionLevel::Insecure` exist only in that configuration/tests.

**ADR-016 Pure-ciphertext MLS wire format (SUPERSEDED in its rationale).** The commit body and sender data are encrypted, but `PrivateMessage` still exposes `group_id`, `epoch` and `content_type`, and the relay sequences commits, so it *can* tell commits from messages. The original claim was wrong and is withdrawn (`CRYPTOGRAPHIC_DESIGN.md` §2). The wire format itself is unchanged.

**ADR-017 `unsafe` forbidden (except UniFFI scaffolding in `cipher-ffi`, guarded); clippy `unwrap/panic/indexing` denied in production code; `panic = abort` except the `android-release` profile (`unwind`, ADR-020); overflow checks on in release.** *Why:* memory-safety and no panic-driven DoS in parsers.

**ADR-018 Pin CI actions by commit SHA; install audit tools by exact version; `--locked` everywhere.** *Why:* A11 build-pipeline compromise.

**ADR-019 Android only; remove React Native, the TypeScript layer and all iOS code.** *Why:* one platform lets the security model, UI and tests be exact instead of lowest-common-denominator; a JS layer cannot hold or wipe secrets and doubled the audit surface.
*Process:* the TS policy logic (log redaction, notification privacy, protection-level rules, https-only checks) was **ported first** — notification privacy and protection reporting to Rust, logging to `SafeLog`, https/TLS rules to the OkHttp transport and Rust validation — and its tests were re-expressed as Rust/Kotlin tests before `mobile/` was deleted.
*Consequence:* no iOS; the invariant registry now maps to Rust and Kotlin tests only.

**ADR-020 Narrow UniFFI bridge with a panic guard.** *Why:* the bridge is the trust boundary between a UI that handles text and a core that handles keys. Every exported function is high level (no key, no raw MLS state in any return type — enforced by `boundary_guards.rs`), validates every input, and runs under `catch_unwind`.
*Consequence:* the library is built with the `android-release` profile (`panic = unwind`, thin LTO, stripped) because `panic = abort` would turn a panic into a process kill that cannot be contained; a panic locks the vault and returns `Internal`. Kotlin bindings are generated from the compiled library on every build so they cannot drift.

**ADR-021 Keystore callbacks run on the engine thread; the Kotlin shell owns no secrets.** *Why:* `BiometricPrompt` must be shown on the UI thread while the key operation blocks the caller; a single `cipher-engine` executor serialises all engine calls and lifecycle events and keeps the prompt flow off the main thread.

**ADR-022 PIN-only vault mode.** *Why:* devices without a secure lock screen (and users who prefer it) need a path that does not depend on per-use Keystore authentication. *Consequence:* no biometric option exists for such a vault; the PIN envelope (Argon2id + hardware-bound secret `S`) is the only unlock. A debug-only marker file also lets emulators skip per-use auth for testing; it is gated by `BuildConfig.DEBUG` and guarded by a test.

**ADR-023 Group policy lives in the MLS GroupContext and is enforced by receivers.** *Alternatives:* trust the relay to check roles; a separate signed ACL. *Why:* anything the relay enforces, a malicious relay can skip; the GroupContext extension is covered by MLS's own authentication. *Consequence:* policy is ours (a pure function, easy to test and review) but unreviewed externally (ST-005). See `GROUP_SECURITY.md`.

**ADR-024 The relay is an ordering authority, not a trust anchor.** Per-tag compare-and-swap sequencer with atomic fan-out; clients rebase on conflict. *Consequence:* honest concurrency converges deterministically; a malicious relay can still partition or delay (detectable, documented).

**ADR-025 PostgreSQL for the relay; shared limiter, nonces and sequencer live in the database.** *Why:* horizontal scaling with correct rate limiting and replay protection needs shared state (ST-012). Forward-only checksummed migrations under an advisory lock; TLS to the database is mandatory off loopback; rate-limit keys are peppered hashes.

**ADR-026 Notification privacy is decided in Rust from privacy mode and vault state.** Default `NO_CONTENT`; a locked vault can only ever produce the generic text. *Consequence:* no content while locked, and (because the transport key lives in the vault) a locked app cannot even fetch to build better text.

**ADR-027 Key transparency stays experimental and feature-gated.** `ct-merkle` (RFC 6962/9162 proofs) is used by a verifier with signed tree heads and gossip split-view detection, but it is not wired to anything and cannot produce a "verified" state; manual QR/safety numbers remain independent. *Why:* shipping a verifier without a log, monitors or gossip would add attack surface and false assurance. See `KEY_TRANSPARENCY.md`.

**ADR-028 Honest platform reporting over convenient defaults.** The emulator Keystore is reported as `SOFTWARE_OR_UNKNOWN`; debug builds may opt in, release builds refuse it (verified on an emulator with a throwaway-signed release build). No claim of StrongBox/TEE is made unless `KeyInfo` says so.

**ADR-029 Authenticate before reading large bodies (`bh=` in the signed header).** *Why:* the signature covers the body hash, so the relay used to buffer up to 101 MiB per connection before it could reject an unauthenticated peer (FR-10). The client announces the SHA-256 in the `Authorization` header; the relay verifies the signature against it, caps concurrent uploads (8), then reads and re-hashes the body. *Consequence:* blob uploads require `Content-Length`; other endpoints are unchanged (small bodies, still verified by recomputed hash).

**ADR-030 Local rollback detection with a keystore-held generation counter.** *Alternatives:* a counter inside the vault only (an attacker restores the whole file); a server-side counter (leaks activity, needs trust); StrongBox/RPMB counters (not exposed to apps). *Why:* the only monotonic state Android lets an app keep outside its data directory is the system keystore; encoding the number in key alias names needs no new primitive. *Consequence:* detects restored files, not a root attacker (FR-05, `LOCAL_STORAGE_SECURITY.md` §8).

**ADR-031 `unwrap_into(sink)` instead of returning the vault key; zero every JVM copy.** *Why:* narrowest exposure achievable with the Android Keystore wrapping pattern (ST-027). Not a fix: the key still exists in the JVM during the Keystore operation.

**ADR-032 Lock requests bypass the engine mutex (`request_lock`) and cancel the network.** *Why:* a single engine mutex serialises everything, so a long transfer used to delay "lock on background" (FR-11). The flag is set without taking the mutex; the ordered lock still follows.

**ADR-033 The device binding signature covers the account id (v2).** *Why:* v1 covered `device ‖ auth_key` only, allowing a valid record to be replayed under another account id (FR-09). Pre-release, so no migration was needed; any deployed v1 record would be rejected.

**ADR-034 Persist MLS state after every sync that processed something, before acknowledging, and before locking.** *Why:* forward secrecy requires consumed ratchet keys to be gone from DISK, not only from memory (FR-12). *Cost:* one snapshot write per busy sync.

**ADR-035 No certificate pinning is shipped.** *Why:* pins are only safe with an operator-owned rotation plan and a backup pin; users may point the app at any self-hosted relay, so a baked pin is impossible, and a trust-on-first-use pin would turn every certificate renewal or provider migration into a lock-out with no account recovery. *Consequence:* a subverted public CA can intercept the **metadata** channel (never content). The transport already supports SPKI pins; an operator build can enable them. Revisit when a managed relay exists.

**ADR-037 History revocation by per-epoch exporter-derived keys.** *Why:* new members must derive the current key from MLS state alone, removed members must not be able to derive later keys, and nothing may be a long-lived master key. Per-message keys by HKDF avoid storing thousands of keys. *Rejected:* a server-held kill switch (relay stays untrusted), a single history generation key (permanent secret), forward chains (let removed members derive future keys), plaintext-column hiding (UI-only). *Consequence:* revocation takes effect when the removed compliant client observes the removal; voluntary leave keeps history.

**ADR-038 No per-message group tag.** *Why:* it would let the relay (or a DB leak) link every group message to a group and so purge/measure groups — a metadata regression. *Consequence:* the relay cannot purge a removed member's pending group application messages; client cryptography does not depend on it (they are undecryptable after revocation).

**ADR-039 Idempotent group commit.** *Why:* a committer whose response is lost used to diverge from its own group. The relay keeps the first delivery id + consumed epoch of the latest commit per group; the client persists the in-flight commit with the MLS pending commit and re-sends it until answered.

**ADR-040 Per-sender share of a recipient's queue (ST-031, partial).** *Why:* one account must not starve a victim's inbox. A keyed pair hash (pepper, never the device id) is stored with the envelope only. *Residual:* N registered accounts still fill the queue; the real fix (recipient-issued send capabilities) is a protocol design decision, not built.

**ADR-041 No cryptographic account recovery.** *Why:* every recovery scheme short of a user-held secret (email/SMS reset, security questions, server-held keys) gives someone other than the device the ability to impersonate or decrypt. No user-held-secret scheme was designed/reviewed. *Result:* "No cryptographic recovery available." A lost phone loses the identity (documented in onboarding).

**ADR-036 Message dropping stays undetectable for now (ST-032).** *Why:* exposing per-sender sequence numbers needs a frame-format change and UI for gaps/reordering; doing it half-way would create false alarms. Documented rather than hidden.


**ADR-042 Privacy transport = Tor through a local SOCKS5 endpoint; no home-grown anonymity protocol.** See `ADR-PRIVACY-TRANSPORT.md`. *Consequences:* the relay name never resolves on the device; fail closed with no direct fallback; the direct route exists only in debug builds; Tor itself is unverified here.

**ADR-043 Delivery capabilities instead of authenticated, device-addressed sends for contacts.** See `DELIVERY_CAPABILITIES.md`. *Why:* removes the sender from the relay's view and gives recipients a revocable, rotating, quota-bounded inbox address; fixes ST-031's stranger case. *Cost:* a new unauthenticated endpoint, per-conversation state, rotation logic; the relay can still resolve capability → recipient.

**ADR-044 Queue lanes (open / capability / commit).** *Why:* a single shared per-device bound let strangers (open lane) or fake group tags (commit lane) starve contacts. *Consequence:* a stranger without a capability gets only a small allowance and is refused when it is full.

**ADR-045 Frame minimum 1 KiB.** *Why:* receipts, capability announcements and short texts become one size class (measured entropy 0.45 → 0.03 bits on a synthetic mix) for ≈ +0.5 KB per message. Pre-release, so the frame format was changed.

**ADR-046 ENHANCED profile with bounded cover, foreground only; relay request logs off by default with minute-rounded timestamps.** *Why:* measured: link-level send-time detector 0.981 → 0.596 (emulator trace). *Not claimed:* resistance to end-to-end correlation or a global observer (candidate set only 1.2 → 2.1 for 6 senders).
