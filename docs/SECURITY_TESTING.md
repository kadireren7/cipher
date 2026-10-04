# Security testing

**Passing tests does not prove Cipher secure.** This document says what exists, how to run it, what it found, and — most importantly — what is **not** established.
Every claim in the docs carries one of four labels:

* **TESTED** — an automated test or a recorded run exercised it (and the scope is stated).
* **ARCHITECTURALLY EXPECTED** — follows from the design or documented platform behaviour; not exercised here.
* **NOT TESTED** — no evidence either way.
* **REQUIRES EXTERNAL REVIEW** — needs a party other than the author (reviewing our own code does not count; ST-005).

**No physical Android device was used at any point.** All Android runs were on one emulator (AVD `cipher34`, API 34, google_apis x86_64, software Keystore).

## 1. Automated inventory (clean run on the dev host, Rust 1.99, JDK 17, Android SDK 36 / NDK 27.2)

| Layer | Location | Tests | What it covers |
| --- | --- | --- | --- |
| Wire / core units | `cipher-wire`, `cipher-core/src` | 9 + 34 | Strict ids, header parser, canonical string; KDF floor, endpoint https-only, safety number, Cipher ID (round trip, typo detection, **canonical-padding regression**), codec, group metadata, notification policy |
| MLS protocol | `cipher-core/tests/mls_protocol.rs` | 14 | Round trip, bit flips, malformed/truncated, wrong keys, replay, removed member, forward secrecy, **PCS after self-update**, unapproved device, KeyPackage substitution, snapshot corruption |
| Group policy | `group_policy.rs` | 7 | Roles/permissions, malicious metadata commits, forks detected not merged, reordered/stale commits, sender from the authenticated tree |
| Vault / local storage | `vault_security.rs`, `store_paging.rs` | 19 + 2 | No plaintext/keys in DB, lifecycle, PIN-only vault, rate limit, KDF downgrade, corruption, row swapping, atomic batches, bounded paging |
| Attachments | `attachments.rs` | 22 | STREAM round trips, tamper/truncate/reorder, limits, MIME/magic, filename sanitisation, Padmé |
| Verification / parsers | `verification.rs`, `parsers_property.rs`, `static_guards.rs` | 8 + 7 + 7 | Pins, substitution, endorsements; random bytes into every parser; static guards that read real files |
| **Experimental KT** | `transparency_attacks.rs` (feature `transparency-experimental`) | 13 | Forged/tampered heads, rollback, fork evidence, history rewrite, key substitution, malformed proofs, gossip, structural independence, 2 property tests |
| **FFI boundary** | `cipher-ffi/tests/boundary_behaviour.rs`, `boundary_guards.rs`, unit | 12 + 6 + 3 | Hostile inputs, panics in calls and callbacks, lifecycle misuse, concurrency, honest protection reporting, no key material in any export, no hand-written `unsafe` |
| **Android static guards** | `android_guards.rs` | 13 | Manifest, FLAG_SECURE, dialogs, banned APIs, single logger, release strictness + debug-bypass gating, NSC, TLS 1.3-only transport, backup rules, R8 log stripping, dependencies, no secrets in tree. **Mutation-checked** (planted violations are caught) |
| Relay unit + invariants | `cipher-relay/src`, `security_invariants.rs`, `tls.rs` | 2 + 21 + 2 | Wire/DB/log scans, DB-dump attacker, key swapping, replay, auth failures, bounded queues, hostile input, rate limits, push payload, real TLS handshakes |
| **Relay on PostgreSQL** | `postgres_relay.rs` | 17 | Migrations (checksums, newer-schema refusal, concurrent runs), CAS commit sequencer (one winner, atomic), tag rotation, shared limiter/replay across **two relay instances**, peppered keys, exact queue counters, load shedding |
| **Engine end-to-end through the relay** | `engine_dm.rs`, `engine_groups.rs`, `engine_attachments.rs` | 13 + 8 + 5 | DMs (order, dedupe, retry, offline, receipts, pagination, restart, bucketed sizes), groups (roles, removal, forged commit, concurrency, withheld commit, key refresh), all attachment kinds, cancel, tamper |
| **Final-review suites** | `relay_compromise.rs` (15 + 1 measurement), `group_attacks.rs` (2), vault rollback (+5), FFI (+3 incl. stress), name policy (+2), binding v2 (+3), Android guards (+7) | 38 | Compromised relay/DB, pre-authentication limits, KeyPackage draining, forward-secrecy durability, rollback, lock ordering, hostile Welcome |
| **Rust total** | | **280** passed, 0 failed, 1 ignored (a measurement) (`cargo test --workspace --all-features`) | clean build, 24 test binaries |
| **Kotlin JVM unit** | `android/app/src/test` | 6 | Formatting helpers, `humanize` never leaks details, `SafeDecode` size policy |
| **Android instrumented** (emulator) | `android/app/src/androidTest` | 39 | Keystore wrapper incl. zeroing and the rollback counter (11), hardening incl. overlay/autofill flags (8), engine lifecycle incl. a real-stack rollback (9), hostile media (3), **network attacks** against adversarial TLS servers (7), a live-relay attachment upload (1, needs arguments; run manually) — 38 passed in the automated run, the live test passed when given a relay |
| Fuzzing | `fuzz/` (libFuzzer, nightly) | 8 targets | New `app_parsers` target (Cipher ID, frame codec, group metadata, wake payload): 13.4 M executions in 90 s, no crash. Short smoke runs, **not a campaign** |
| Registry | `security/invariants.json` | 38 invariants (each with a threat mapping) → 190+ mapped tests | `scripts/check_invariants.py` fails CI if a mapped Rust or Kotlin test disappears |

Commands: `cargo test --workspace --all-features --locked` (needs PostgreSQL via `CIPHER_TEST_DATABASE_URL`) · `(cd android && ./gradlew :app:testDebugUnitTest :app:ktlintCheck :app:lintDebug :app:connectedDebugAndroidTest)` ·
`scripts/verify-all.sh` · `scripts/ci-emulator-tests.sh`.

## 2. Static analysis

`cargo clippy --workspace --all-targets --all-features -- -D warnings` clean · `cargo fmt --check` clean · ktlint clean · Android lint clean (one false positive on UniFFI's generated `Cleaner` use is suppressed **for the generated directory only**; the generated code guards it with `Class.forName` and falls back to JNA on API 30–32 — the fallback itself was not run on an API 30–32 device) ·
`cargo deny check` (advisories, bans, licences, sources) ok · `cargo audit --deny warnings` ok · `scripts/secret_scan.py` ok (179 files) · `scripts/check-relay-deps.sh` ok.
Clippy found real defects in new code this phase (indexing in the ID codec, `expect` in test-support code that must stay out of shipped builds); all fixed or explicitly scoped to test-support.

## 3. Bugs found by testing in this phase (each has a regression test or gate)

| Found by | Bug | Fix / regression |
| --- | --- | --- |
| Real emulator onboarding | **UI hang forever** when provisioning or identity creation threw: the completion callback was never invoked | `launchReporting` always reports the outcome; an error state is shown |
| Emulator + real relay | Relay audience configured as a URL gave `401` on every signed request after registration | Documented: audience is the dialled host[:port]; `.env.example` already used that form |
| Property test (persisted regression) | **Cipher ID non-canonical aliases**: flipping the 2 padding bits of the last data character parsed to the same account | Parser rejects non-zero padding; `padding_bits_must_be_zero_so_every_id_has_exactly_one_spelling`; failing seed kept in `proptest-regressions/` |
| Release APK inspection | Merged manifest contained a **library-exported receiver** (`ProfileInstallReceiver`) invisible to the source-level guard | Removed with `tools:node="remove"`; guard + `scripts/check-release-apk.sh` now check the **merged** manifest; instrumented test checks every installed component |
| Group E2E | Group header member count stayed stale after a removal | `ChatViewModel.refresh()` re-reads the roster and role |
| Android lint | UniFFI `Cleaner` flagged for API 33 vs minSdk 30 | Verified guarded; scoped suppression |
| Documentation audit | Docs claimed the relay "cannot distinguish commits from messages" — MLS `PrivateMessage` exposes `content_type` and the relay sequences commits | Claim withdrawn everywhere; metadata model corrected |
| Doc/test audit | Earlier test mutation checks showed guards fail when a property is broken (WebView planted, `allowBackup=true`, R8 rule removed) | Guards restored; evidence in §5 |

## 4. End-to-end verification on an emulator against the real relay (TESTED, not automated)

Setup: the **release-built relay binary** over TLS 1.3 (throwaway test CA) on PostgreSQL 16 (docker), the **real debug APK** on the emulator, and a headless Rust peer (`cipher-ffi/examples/e2e_peer.rs`, same `CipherEngine` API, curl-based TLS 1.3 transport). Recorded observations:

* Onboarding through the UI: welcome → server + invite → PIN-only → PIN → identity (random Cipher ID, fingerprint shown). Relay: account `201`, 20 KeyPackages `204`.
* **DM both ways**: the peer's message arrived as a **message request showing nothing until accepted**; after accepting, the text decrypted; the app's reply decrypted on the peer.
* **Attachments** (peer → app): image (PNG), PDF, voice note delivered; each opened in the viewer without a crash; `cache/viewer` stayed **empty** (no plaintext temp file). Rendering correctness was **not** checked visually because FLAG_SECURE blocks screenshots.
* **Group** (peer creates TeamBeta with the app and a second peer): app joined by Welcome ("3 members"), sent a message that the peer read; the creator **removed** the second peer, then posted; the app received it; the **removed peer's sync returned nothing new, its history held only pre-removal text, and `send` was refused**.
* **Inactivity lock** after 60 s observed in the UI; PIN unlock worked.
* **Plaintext audit** after the session (all fixtures start with `…-MARKER-…`, plus file names and contact names): the whole app data directory (raw + `strings`), `/sdcard` and `/data/local/tmp`, `logcat`, the relay log (333 lines: only `method, route template, status`) and a full `pg_dump` — **0 hits**. The only app files were `vault.db` and four non-secret config files.
* **Relay DB inspection**: schema and rows reviewed for `METADATA_MODEL.md` (no sender column, no IPs, no push tokens populated, peppered rate keys).
* **FLAG_SECURE**: `dumpsys window` shows `SECURE`; `screencap` of the foreground app returns 0 bytes while the launcher returns 1.37 MB.

Not covered by this run: app-side attachment *sending* through the system picker, camera/QR scanning, voice recording via the microphone, notifications (none posted in this session), screen-off locking, the Android-side group management screens, and anything on a physical device.

## 5. Guard-the-guards (mutation checks performed)

Planted `WebView` in a Kotlin file, set `allowBackup="true"`, and removed a `Log.w` R8 rule → 3 Android guards failed → files restored → all 13 pass. Earlier phases: secret in scratch file, renamed mapped test, extra relay dependency — each failed the corresponding gate.

## 6. Release build verification

`assembleRelease` (minified, resource-shrunk, `isDebuggable=false`, no test CA, no software Keystore, no default relay): **unsigned** `app-release-unsigned.apk`. `scripts/check-release-apk.sh` (merged manifest via `aapt2`): not debuggable, `allowBackup=false`, `usesCleartextTraffic=false`, only the launcher activity exported, no test CA packaged — passes.
Runtime check on the emulator (signed with a **throwaway** debug key; not a distributable): server field empty (nothing baked in) and **PIN-only provisioning is refused** ("Couldn't set up secure storage on this device") because the emulator Keystore is software-backed — i.e. the release policy rejects it. A release build also does not trust the test CA (system roots only) — **not exercised** separately because provisioning is refused first.

## 7. What is NOT tested

* **Physical devices of any kind**: StrongBox/TEE, per-use biometric prompts, `setUnlockedDeviceRequired`, invalidation on enrolment change or lock-screen removal, OEM behaviour, Android 11–13 (the `Cleaner` fallback), low-memory Argon2id behaviour.
* Certificate pinning; a hostile CA / MITM against the app; TLS behaviour in OEM stacks.
* Push notifications, notification history retention, Doze, background fetch, app killed while locked.
* Actual backup / device-transfer attempts; cross-app attacks; accessibility-service abuse; rooted-device extraction; heap dumps while unlocked; swap.
* Multi-hour fuzz campaigns, sanitizers, mutation testing of the crypto adapter, formal verification, side channels beyond using `subtle`.
* Load and DoS at scale; HA PostgreSQL; a TLS-terminating proxy in front of the relay; database encryption at rest.
* Interoperability with other MLS implementations; cross-version OpenMLS state migration.
* Usability of security UX (safety-number comparison, identity-change warnings) with real users; accessibility audits (TalkBack) — the UI uses content descriptions but was not audited.
* **The GitHub Actions pipeline has never run** (no remote exists). Each gate was run locally; the emulator-in-CI job is untested.

## 8. REQUIRES EXTERNAL REVIEW

OpenMLS 0.9.0 and the RustCrypto provider build; our compositions (`CRYPTOGRAPHIC_DESIGN.md` §6, including group policy, commit sequencer, framing/padding, KT glue); the Android Keystore wrapper on hardware; `ct-merkle`; the relay under adversarial load; penetration testing of the whole system.

## 9. Final review additions (see `FINAL_SECURITY_REVIEW.md`)

* **New adversarial suites:** a compromised relay/PostgreSQL (`relay_compromise.rs`), hostile Welcome (`group_attacks.rs`), local rollback (core + real Keystore), lock/unlock races (FFI stress), unauthenticated uploads (a body that records whether it was read), KeyPackage draining by several accounts, forward-secrecy durability across a restart, hostile media on the real decoders, TLS attacks from the emulator.
* **Regression discipline:** every finding FR-05…FR-13 has a test that fails on the old behaviour (FR-12, FR-07 and the pre-auth test were observed failing before the fix).
* **Fuzzing:** 10 libFuzzer targets (new: `app_parsers`, `ffi_validate`, `vault_file`). Final campaign: 3 parallel streams on this host, 7 minutes per target — see the table in `FINAL_SECURITY_REVIEW.md` §18 for executions per target. No crash, panic, OOM or hang in any run. **Not** a multi-day campaign, no sanitizers.
* **Release artifact checks:** merged-manifest gate, APK content analysis with a positive control (the debug APK fails it), reproducibility (identical SHA-256 across consecutive clean builds, including one from a completely clean Rust target directory).
* **End-to-end on the emulator against the real relay binary + PostgreSQL:** onboarding through the UI; DM and group in both directions (peers = headless Rust engines over TLS 1.3); image, PDF and voice note received and opened; a 3 MiB attachment **sent by the real app stack** and decrypted byte-exact by the peer; process kill → relaunch → locked → PIN unlock → data intact; **rollback attack on the real app** (restore an older `vault.db` after further use) → refused with a specific message, nothing decrypted; release build refuses the software Keystore and is non-debuggable at runtime.
* **Plaintext hunt** (canary fixtures `FINAL-CANARY-…`, `LIVE-CANARY-…`, names and file names) after those sessions: app data directory (raw bytes and `strings`), `/sdcard`, `/data/local/tmp`, `/storage/emulated`, logcat, relay log, a full `pg_dump`, the release APK → **0 hits**. One hit was a *test-tooling artifact*: `/sdcard/ui.xml`, written by the UI-automation dump, which contains whatever the screen showed (removed). Searches that were **impossible** without root: other apps' memory, kernel page cache/swap, the system keystore database, notification history, the IME dictionary. A zero-hit result is evidence for this run only.

## 10. History revocation pass (see `HISTORY_REVOCATION.md`, `FINAL_SECURITY_REVIEW.md` addendum)

TESTED (engine + real relay + PostgreSQL): normal/admin/owner removal, unauthorised removal, offline removed member (stale send, forced commit), old vault snapshot, replayed Welcome and legitimate re-add, withheld and reordered removal commits, concurrent send/attachment with removal, rapid successive removals, restart and process death after revocation, committer lost response (± restart). Flooding: `inbox_flooding.rs`. NOT TESTED: physical devices; multi-device accounts (none exist); the new UI strings on screen.


## 11. Network-privacy pass
TESTED: privacy-route behaviour against hostile/dead SOCKS test doubles (JVM + emulator), remote name resolution, fail-closed with a directly reachable relay, the TLS attack suite through the route, capability lifecycle/flooding on the real relay + PostgreSQL, ENHANCED cadence and cover, DB/log social-graph and IP hunts, link-observer send-time detector (emulator trace + in-process model), correlation experiment. NOT TESTED: real Tor, Orbot, physical devices, packet capture, battery/Doze, real carrier networks, DNS capture on a device, long fuzz campaigns.
