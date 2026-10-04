# Consolidated SECURITY TODO list

Every item is an unresolved security gap or a decision deferred on purpose. IDs are stable; code comments say `SECURITY TODO` and refer here.
**Nothing is closed without evidence.** Status words: **OPEN**; **PARTIAL** (progress with evidence, not closed); **CLOSED** (evidence listed, residuals moved to a new or existing item).
Severity (H/M/L) is a rough prioritisation. Evidence labels as in `SECURITY_TESTING.md`.

| ID | Sev | Item | Status | Evidence / what remains |
| --- | --- | --- | --- | --- |
| ST-001 | H | Device-test the Android Keystore module (StrongBox, TEE, biometric prompt, enrolment change, lock-screen removal, FLAG_SECURE, backup exclusion); independent review | **PARTIAL — not closed** | Module compiled; wrapper behaviour TESTED on an **emulator** (software Keystore): 9 instrumented tests, honest level read-back, AAD binding, tamper, restart, deletion, key-loss-fails-closed-without-wipe; FLAG_SECURE observed live (0-byte screencap vs 1.3 MB launcher). **Not done:** any physical device, StrongBox, TEE, per-use biometric, `setUnlockedDeviceRequired`, enrolment-change invalidation, independent review. Cannot be closed until a physical-device matrix has run |
| ST-002 | H | Certificate pinning with a rotation/backup-pin plan | OPEN | Transport supports SPKI pins (`OkHttpCallbacks(pins)`); none shipped because pins and a backup/rotation plan are the operator's decision |
| ST-003 | M | Benchmark Argon2id on low-end Android; tune; check peak memory | OPEN | Host numbers only (`LOCAL_STORAGE_SECURITY.md` §3); emulator onboarding with 64 MiB completed on a memory-starved guest but that is not a benchmark |
| ST-004 | M | SQLCipher and/or OS file-protection as defence in depth; verify on device | OPEN | Record-level AEAD only; vault excluded from backup; file-system metadata visible |
| ST-005 | H | **Independent** cryptographic review (compositions in `CRYPTOGRAPHIC_DESIGN.md` §6, group policy, OpenMLS 0.9.0 / provider audit status) | **OPEN — REQUIRES EXTERNAL REVIEW** | Reviewing our own code cannot close this. New compositions since phase 1: group metadata/policy, commit sequencer, frame/Padmé padding, KT glue |
| ST-006 | M | Key transparency / auditable key directory | **PARTIAL (experimental, NOT PRODUCTION READY)** | Feature-gated verifier + design + 13 attack tests (`KEY_TRANSPARENCY.md`). No log, monitor, gossip transport or deployment; independent of QR/safety numbers by construction |
| ST-007 | H | MLS commit ordering & fork resolution; group authorisation policy; stale-epoch handling | **CLOSED (with documented residuals)** | Roles in an MLS-authenticated GroupContext extension; every receiver enforces `authorize_commit` (`group_policy.rs` 7, `engine_groups.rs` 8); relay CAS sequencer with atomic fan-out and deterministic rebase (`postgres_relay.rs`); held out-of-order messages; `max_past_epochs = 2`; tag rotation on removal; verified on the real relay with the Android app as a member. **Residuals:** relay can partition/withhold (detectable, no healing) → tracked under ST-009/ST-029; policy unreviewed → ST-005 |
| ST-008 | M | Automatic PCS scheduling; KeyPackage replenishment and last-resort KeyPackage | **PARTIAL** | PCS scheduler (≥ 24 h with activity or every 100 messages, ≥ 1 h apart) and +10 KeyPackages/day implemented and tested. **Open:** last-resort KeyPackage |
| ST-009 | M | Hide MLS `group_id`/`epoch`/`content_type` and the sender from the relay (outer routing / sealed sender) | **PARTIAL (sender hidden for capability deliveries; MLS framing, recipient and commit authorship still visible)** | Routing tag is random and rotates on removal, but framing fields and the sending device remain visible (`METADATA_MODEL.md`) |
| ST-010 | H | Account authentication and **recovery** design (per-user credentials, recovery secret, lost-device flow, device revocation); no automatic wipe | **OPEN** | A shared invite/registration token stands in. No recovery exists **by design** (onboarding says so). Key loss keeps the vault and requires an explicit user reset (tested: no wipe). Real design still needed |
| ST-011 | M | Separate `BlobStore` abstraction + object-storage provider with short-lived capabilities | OPEN | Blobs are still stored by the relay in PostgreSQL (padded, ciphertext only) |
| ST-012 | M | Shared rate limiter and nonce cache for multi-instance relay; production database | **CLOSED (with residuals)** | PostgreSQL: shared `take_tokens` limiter, `request_nonces`, checksummed migrations under advisory lock, bounded queues, TTL purge, load shedding (`postgres_relay.rs` 17 tests incl. two relay instances on one DB; real relay binary run against Postgres). **Residuals:** no load test, no HA topology, DB encryption-at-rest/backup policy is operator-owned |
| ST-013 | H | FFI crate (UniFFI) and bridge; async authentication prompt flow; zeroisation across the boundary; no secrets in the UI | **CLOSED for the Android bridge (with residuals)** | `cipher-ffi`: no key/MLS state in any return type (`boundary_guards.rs`), every input validated, panics contained, lifecycle misuse safe (`boundary_behaviour.rs` 12); BiometricPrompt flow on the engine thread. **Residuals:** 32-byte vault key transits JVM memory → **ST-027**; Kotlin `String`/`ByteArray` copies cannot be reliably wiped |
| ST-014 | M | SBOM, provenance attestations, reproducible builds, `cargo vet`/vendoring, signed releases | OPEN | `cargo deny`/`audit` run; no SBOM, no reproducible/signed release |
| ST-015 | M | Secure memory (`mlock`, guard pages, madvise); upstream zeroizing of OpenMLS storage | OPEN | |
| ST-016 | M | Rollback/deletion detection for the local DB | **PARTIAL** | Whole-vault rollback detected via a keystore-held generation counter + encrypted generation record (`LOCAL_STORAGE_SECURITY.md` §8; T + E). **Open:** hardware-protected counter (not available to apps), same-session snapshots, per-record rollback, row deletion |
| ST-017 | M | Push integration with the content-free payload; behaviour while locked | **OPEN** | Only the constant-wake interface and notification modes exist; no FCM/UnifiedPush; a locked app cannot authenticate to the relay, so only "New message" is possible; foreground polling every few seconds is the only delivery path |
| ST-018 | L | `proc-macro-error2` (RUSTSEC-2026-0173) transitive unmaintained dependency; re-evaluate on every OpenMLS bump | OPEN (exception recorded) | `deny.toml`, `.cargo/audit.toml` |
| ST-019 | L | TLS Encrypted Client Hello; SNI exposure | OPEN | |
| ST-020 | M | Multi-device message/state sync design | OPEN | |
| ST-021 | M | Android build + instrumented tests in CI; dependency policy | **PARTIAL — not closed** | Workflow rewritten (Rust + PostgreSQL service, FFI generation check, Android unit/ktlint/lint/debug+release build + release-manifest gate, emulator job, fuzz matrix). **The pipeline has never run on GitHub** (no remote). Every step was executed locally except the emulator-in-CI job (written, KVM-dependent, untested there). Actions are pinned by SHA except where no pin was verifiable offline (Postgres image tag) |
| ST-022 | M | Abuse resistance: spam, contact-discovery privacy, KeyPackage draining, per-target throttles | OPEN | Per-device/IP limits exist; no per-target throttles or last-resort KeyPackage |
| ST-023 | L | Design (do not default-enable) any destructive wipe feature | OPEN | No automatic wipe exists; reset is explicit and user-initiated only |
| ST-024 | L | Incremental vault-backed MLS `StorageProvider`; atomic multi-record commits | **PARTIAL** | Atomic multi-record transactions exist for identity creation and commit state; snapshots are still whole-state |
| ST-025 | L | Client clock-skew handling and relay time signalling | OPEN | Signed-request window ±60 s |
| ST-026 | L | Disappearing messages / retention and secure deletion on the client | OPEN | Local deletion exists (`secure_delete`); flash wear-levelling not assessed |
| ST-027 | M | **New.** Vault key transits JVM memory during Keystore wrap/unwrap | **OPEN — mitigated** | `unwrapInto` sink + immediate zeroing of both JVM copies; a keystore that delivers nothing fails closed (`ANDROID_SECURITY.md` §4). The key still exists in the JVM for the duration of the Keystore operation |
| ST-028 | H | **New.** Physical-device validation matrix (StrongBox device, TEE-only device, no-biometrics device, enrolment change, lock-screen removal, OEM variants, Android 11–16) | OPEN | Everything so far ran on one API 34 x86_64 emulator |
| ST-029 | M | **New.** Group partition detection/healing and relay-equivocation evidence | OPEN | Detectable as undecryptable traffic only |
| ST-030 | L | **New.** Last-resort KeyPackage and KeyPackage-exhaustion DoS handling | **PARTIAL** | Per-target (12/h) and per-pair (4/h) claim limits and hourly refill (FR-08). **Open:** last-resort KeyPackage |
| ST-031 | M | Inbox flooding: any authenticated device can fill a victim's relay queue | **PARTIAL — not closed** | Lanes: strangers share one OPEN lane (100 envelopes / 2 MiB per recipient); capability holders get 250 / 4 MiB **per capability**; per-sender share on the open/commit lanes; guessing/replay/expiry/revocation/multi-account tests (`delivery_caps.rs`, `engine_caps.rs`, `inbox_flooding.rs`). **Commit lane** (group commits/Welcomes) is bounded separately at 200 envelopes / 8 MiB per recipient so fake groups cannot crowd out capability holders (`strangers_flooding_the_commit_lane…`). **Residual:** leaked capabilities allow junk up to quota until rotation; strangers can keep the commit lane full and so delay legitimate commits/Welcomes to a victim (not capability deliveries); a stranger without a capability is refused while the open lane is full |
| ST-032 | M | **New (final review).** Message dropping/delay by the relay is undetectable (no exposed per-sender sequence numbers) | OPEN (DESIGN DECISION) | Safety property holds (later messages still decrypt); a gap-detection design (sender counters inside the E2EE frame + UI warning) is needed |
| ST-033 | L | **New.** Device revocation and multi-device do not exist; a lost phone's device record stays in the directory | OPEN | Part of ST-010; user-facing consequence: lose the phone = start a new identity |
| ST-034 | L | **New.** Hostile audio/video/PDF files are only handled defensively (guarded setup); platform codec bugs and malformed-sample fuzzing are not covered | OPEN | `SECURITY_TESTING.md` |
| ST-035 | M | **New (history revocation).** Revocation on the removed member's device requires that device's compliant client to *observe* the removal; a relay that withholds the commit keeps their old access (never new content) | OPEN — documented, tested | `withheld_removal_blocks_new_content_and_ends_old_access_when_it_arrives`; possible mitigations (relay purge of tagged commit rows — not implemented; partition detection ST-029) would not remove the client-side dependency |
| ST-036 | L | **New.** Account-level removal of a *second device* is untested (no multi-device exists); commit idempotency covers only the latest commit per group | OPEN | `REV-008` partial; becomes an engine-level test when ST-020 ships |
| ST-037 | L | **New.** Relay cannot purge a removed member's pending group application messages (no per-message group tag, by decision ADR-038) | INTENTIONALLY DEFERRED | Cryptographically moot after revocation; metadata cost of a tag judged worse |
| ST-038 | H | **New (privacy).** The privacy route was only exercised against a local SOCKS5 test double; the Tor network, Orbot integration, circuit behaviour, Android DNS behaviour for the proxy and real latency/battery were never tested | OPEN — REQUIRES REAL INFRASTRUCTURE / PHYSICAL DEVICE | `ADR-PRIVACY-TRANSPORT.md`, `PRIVACY_TRANSPORT_REVIEW.md`; procedure in `DEVICE_TEST_CHECKLIST.md` §H |
| ST-039 | M | **New.** The relay can still map a delivery capability to its recipient device, sees recipient + time of every delivery, the online state, and the committer/tag of every group commit and first contact | OPEN — DESIGN DECISION | needs sealed-sender/mailbox designs; `DELIVERY_CAPABILITIES.md` residual |
| ST-040 | L | **New.** ENHANCED cover is distinguishable from real traffic by the relay (invalid capability / unknown device) and does not defeat end-to-end timing correlation (candidate set 1.2 → 2.1 for 6 senders) | OPEN — documented | `PRIVACY_TRANSPORT_REVIEW.md` |
| ST-041 | M | **New.** Relay as an onion service (no exit) needs TLS for an onion name or an explicit relaxation of "no cleartext" | OPEN — DESIGN DECISION | `ADR-PRIVACY-TRANSPORT.md` |
| ST-042 | M | **New.** No background delivery without push; privacy mode relies on foreground polling | OPEN — REQUIRES PHYSICAL DEVICE / REAL INFRASTRUCTURE | `PUSH_DESIGN.md` addendum |
| ST-043 | L | **New.** "Uses Tor" is visible to the ISP; no bridge/pluggable-transport support | OPEN — INTENTIONALLY DEFERRED | `ISP_OBSERVABILITY_REPORT.md` |

## Classification of every open item (this pass)

CAN COMPLETE NOW = done in this environment (see status column above). REQUIRES PHYSICAL DEVICE / EXTERNAL REVIEW / REAL INFRASTRUCTURE / DESIGN DECISION / INTENTIONALLY DEFERRED = cannot honestly be closed here.

| ID | Class | Note |
| --- | --- | --- |
| ST-001 | REQUIRES PHYSICAL DEVICE | `DEVICE_TEST_CHECKLIST.md` |
| ST-002 | DESIGN DECISION (operator) | pins need an operator-owned rotation plan |
| ST-003 | REQUIRES PHYSICAL DEVICE | low-end benchmarks |
| ST-004 | DESIGN DECISION | SQLCipher adds a dependency and a second key hierarchy; not clearly better than record AEAD |
| ST-005 | **REQUIRES EXTERNAL REVIEW — OPEN** | `EXTERNAL_REVIEW_SCOPE.md`; never closed by self-review |
| ST-006 | REQUIRES REAL INFRASTRUCTURE | needs a log operator |
| ST-007 | CLOSED earlier | residuals tracked as ST-009/029/035 |
| ST-008 / ST-030 | CAN COMPLETE (not done) | last-resort KeyPackage — next engineering pass |
| ST-009 | DESIGN DECISION | sealed sender is a protocol redesign |
| ST-010 | DESIGN DECISION | recovery: **No cryptographic recovery available** (`RECOVERY_AND_DEVICES.md`, ADR-041) |
| ST-011 | REQUIRES REAL INFRASTRUCTURE | object storage provider |
| ST-012 | CLOSED earlier | |
| ST-013 | CLOSED earlier | |
| ST-014 | CAN COMPLETE (partly) / REAL INFRASTRUCTURE | SBOM/signing need a release pipeline; hashes + dependency verification exist |
| ST-015 | CAN COMPLETE (not done) | mlock/guard pages; upstream OpenMLS storage not zeroizing |
| ST-016 | REQUIRES PHYSICAL DEVICE (hardware counter) / PARTIAL | |
| ST-017 | REQUIRES REAL INFRASTRUCTURE | real FCM/UnifiedPush account; no fake provider was built; the opaque-payload abstraction is documented in `PUSH_DESIGN.md` |
| ST-018 | INTENTIONALLY DEFERRED | upstream |
| ST-019 | INTENTIONALLY DEFERRED | ECH not supported by the stack |
| ST-020 | DESIGN DECISION | multi-device sync |
| ST-021 | REQUIRES REAL INFRASTRUCTURE | needs a GitHub remote |
| ST-022 | PARTIAL (see ST-031) | |
| ST-023 / ST-026 | DESIGN DECISION | |
| ST-024 / ST-025 | INTENTIONALLY DEFERRED | |
| ST-027 | INTENTIONALLY DEFERRED (platform limit) | |
| ST-028 | REQUIRES PHYSICAL DEVICE | |
| ST-029 | DESIGN DECISION | |
| ST-031 | PARTIAL (improved: lanes + capabilities); remainder DESIGN DECISION | commit lane still shares only a per-sender share |
| ST-038..043 | see rows above | privacy pass |
| ST-032 | DESIGN DECISION | `DELIVERY_SEMANTICS.md` |
| ST-033 | DESIGN DECISION (needs ST-020) | |
| ST-034 | REQUIRES PHYSICAL DEVICE / EXTERNAL | platform codecs |

## Next phase (recommended scope)

1. **ST-028 / ST-001:** run the instrumented suite and a scripted manual matrix on physical devices (StrongBox, TEE-only, no biometrics); add biometric-enrolment/invalidation tests; fix what breaks. Do not call the Keystore verified before this.
2. **ST-005:** commission an independent review of the compositions and group policy; fix findings; re-run fuzzing as a campaign (hours, corpus kept, sanitizers).
3. **ST-017 / ST-009:** push (UnifiedPush or FCM with the constant payload) and a first metadata-reduction step (sealed-sender-style delivery tokens), with the threat model updated first.
4. **ST-010:** account authentication + recovery/device-revocation design (users will lose phones).
5. **ST-002 / ST-014:** pinning strategy with the relay operator; SBOM, reproducible and signed release builds; get CI running on a real GitHub remote and fix whatever it finds.
6. **ST-006:** only if a log operator exists — wire the experimental verifier as an additive warning with gossip; otherwise leave it gated.
