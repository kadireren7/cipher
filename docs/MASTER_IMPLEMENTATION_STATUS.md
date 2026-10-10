# Master implementation status — branch `feat/self-hosted-multi-relay`

Dated 2026-10-10. Evidence labels: **TESTED** = automated test or script run in this session (name given); **TESTED-LIVE** = against the real Tor network / real Docker;
**NOT TESTED**; **BLOCKED** (reason). Nothing is called complete unless it says so. Base: `main` @ `ca45fd3`.

## Baseline (before changes)
`cargo test --workspace` with PostgreSQL up: all suites green (first run showed 21 relay-test failures only because the `cipher-pg` container was stopped — an environment fact, now noted in SELF_HOSTING/CI).

## Phase 1 — Stabilise: **mostly done, exit gate met for the matrix that exists**
| Item | Result |
| --- | --- |
| Load-sensitive FFI lock/unlock test | Fixed (readers must observe each state; 3/3 under 4 CPU hogs). Cause: a coverage assertion that depended on thread scheduling. |
| **Message LOSS after offline period** (new finding) | 25 messages queued offline → 16 silently lost: outbox flushed in random-id order, MLS keeps 5 skipped generations. Fixed with strict per-conversation FIFO + head-of-line blocking. Test `many_messages_queued_offline_all_arrive_after_reconnecting`. |
| Lost acknowledgment (new finding) | Receipts for messages that arrived as a message request were discarded → sender stuck at `Sent`. Fixed. Test `a_message_that_arrived_as_a_request_becomes_delivered_once_the_recipient_accepts`. |
| Ordering | Outgoing timestamps strictly increasing and persisted across restarts. Test `messages_sent_within_one_clock_tick_keep_their_order`. |
| Deterministic fault matrix | `delivery_matrix.rs`: 8 single-relay + 6 cross-relay seeds × 70 steps; injects network flaps, lost responses (relay executed, answer lost), device restarts, relay restarts, clock jumps. Invariant: every message exactly once at the recipient, in order, ends `Delivered`. **Passes** (MR-010). |
| Cancel/FAILED semantics | A FAILED head holds successors until retried or deleted; deleting an undelivered message now cancels its send; conversation deletion purges its outbox. |
| Not done | PostgreSQL restart inside the matrix (covered by `test-deploy.py` instead); group epoch transitions under faults; attachment resume (ST-046); multi-device. |

## Phase 2 — Self-hosting: **done for one Linux host; Profile A relay side TESTED-LIVE**
* `deploy/` Compose stack, Dockerfiles, `cipherctl.sh`, `docs/SELF_HOSTING.md`. Health checks, secrets as files, internal-only DB network, TLS 1.3 to PostgreSQL with a local CA, hardened containers.
* `scripts/test-deploy.py` **17/17** on the final relay: fresh install, relay restart, PostgreSQL restart, backup → volume wipe → restore, no-downgrade guard.
* `scripts/test-upgrade.py` **10/10**: previous `main` relay + previous client binary → this relay on the same database (migrations 7–8 applied, checksums intact, old client works, old relay refuses the upgraded DB).
* Onion (Profile A): Tor bootstrapped to 100 %, relay reachable through a **separate Tor client over the live network**; pinned cert accepted, wrong pin and missing pin refused. Found and fixed: the 10 s TLS handshake deadline made the onion relay unreachable (6–18 s measured) — now configurable (60 s in the overlay).
* Not tested: multi-host, real Let's Encrypt issuance, load, rootless Docker, disk-full, the weekly workflow `deploy-test.yml` (never run on GitHub).

## Phase 3 — Multi-relay: **1:1 messaging done and tested; groups BLOCKED**
`MULTI_RELAY_PROTOCOL.md` is the design. Implemented: relay descriptor, signed Contact Card v1, intro capabilities (migration 0007 + two unauthenticated endpoints), engine support (remote contacts, capability+relay storage, per-relay outbox routing, no authenticated fallback for remote peers, Welcome-before-messages gate), vault-persisted own relay.
Exit gate (Alice on A, Bob on B, separate databases, offline either side): **met** in `multi_relay.rs` (12 tests, MR-001…006). In-process transport — not two processes over TLS.
BLOCKED / not built: cross-relay **groups** and **key-update commits** (no sequencer: ST-044), relay migration (ST-047), Android UI (ST-048).

## Phase 4 — Cross-relay files: **done for single-blob files up to the relay limit**
Image, PDF, video, voice, arbitrary file + thumbnail cross relays (`text_image_pdf_video_voice_and_arbitrary_files_cross_relays…`); ciphertext only on both relays; tamper/truncate/swap/missing fail closed; capability needed, per-capability and global quota; interrupted transfer leaves no message and no files. Not done: resumable/chunked upload (ST-046), group-removal behaviour (no cross-relay groups), real large-file (100 MiB) soak.

## Phase 5 — Metadata: **measured; modest, honest improvement**
`metadata_measurement.rs`: against the mailbox relay, first contact via card exposes 0 signed requests / 0 Alice→Bob links / 0 stored mentions of Alice (vs 8 / 6 / 73 on the same-relay flow). PIR/mixnet/sealed-sender **not built** (design-only, `MAILBOX_PRIVACY.md` §5). Traffic analysis is unchanged.

## Phase 6 — Tor: relay side TESTED-LIVE; **Android app stack TESTED over real Tor in CI (emulator)**
See `NETWORK_ADVERSARY_MODEL.md` and *Session 3* below. Still not tested: Orbot, a physical device, IPv6, network handover, airplane mode, backgrounding, the app's own Tor integration (the Tor client runs on the host and the app is its SOCKS client).

## Phase 7 — Device/account security: **no new work** (needs a physical device; ST-001/028 unchanged). Cards are issued only by the root device; no recovery was added (explicit no-recovery policy kept).

## Phase 8 — Reliability: foreground retry/backoff/ordering/receipts are covered by the matrix. Background delivery, FCM/UnifiedPush and battery work are **not done** (ST-017/042).

## Phase 9 — Adversarial: added hostile-relay key substitution, withheld/replayed/reordered delivery (matrix + existing tests), capability guessing/revocation, quota flooding, tampered blobs; fuzz target `multi_relay_wire` (90 s smoke: 5.5 M executions, no crash; its first crash was a bug in my own assertion; no campaign, no sanitizers beyond libFuzzer's defaults), and two previously missing targets added to the CI fuzz matrix. Not done: sanitizer runs, long fuzz campaigns, TLS-downgrade tests of the app.

## Phase 10 — Release engineering: SBOM generator (`scripts/gen_sbom.py`, 972 components, reproducible), `cargo deny` pass, `cargo audit` pass **with a reviewed exception** (ST-045), CI updated. No signed release, no reproducible-build claim, no APK produced. See `RELEASE_READINESS.md`.

## Security findings in this pass
1. HIGH (pre-existing): message loss after offline queueing (fixed). 2. MEDIUM: lost receipts for message requests (fixed). 3. MEDIUM: onion handshake deadline (fixed). 4. LOW: `own_relay` memory-only would have mis-addressed cross-relay capabilities after restart (found by design review before release; fixed, persisted). 5. LOW: CI fuzz matrix omitted two targets (fixed). 6. INFO: `libcrux-kem` advisories (not in build graph; exception recorded). Everything is **self-reviewed**; ST-005 (independent review) stays open.

## Commands and results (this machine)
`cargo test --workspace` (PostgreSQL on 127.0.0.1:55432) — last full run: 39 suites; the one failure (a static guard flagging my negative-test URL literals) was fixed and re-run green; `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` clean; `scripts/check_invariants.py` 75 invariants; `scripts/test-deploy.py localhost:18443` 17/17; `scripts/test-upgrade.py` 10/10; `scripts/public_release_scan.py` 0 findings.

## Session 2 (Android UI, pinning, CI) — evidence as of HEAD after `84448b1`
| Item | Result |
| --- | --- |
| Android UI: contact card create/QR/paste, QR-scan routing, relay URL + onion pin settings, onboarding pin field | **Written; compiled and ktlint/lint/unit tests green in GitHub CI** (`android` job) and exercised by the emulator E2E. Never viewed on a physical device. |
| Kotlin TLS pinning (`PinnedTls`, `RelayAddress`) | **TESTED**: JVM tests incl. real TLS 1.3 handshakes (right pin accepted, wrong pin/expired refused); static guard against accept-all trust managers. Not run against a real onion relay from the app. |
| Complete Rust suite | **TESTED locally**: `cargo test --workspace --no-fail-fast`, PostgreSQL up, exit 0, 40 suites `ok`, 0 failed. (A first attempt failed 8 relay tests only because I exported an empty `CIPHER_TEST_DATABASE_URL`: harness error, not product.) Also green in CI (`build / lint / tests`). |
| CI on GitHub (run on `84448b1`) | Green: rust, dependency audit, secret scan, invariants, android unit/ktlint/lint/build, **self-hosting acceptance (deploy-test + upgrade)**. Earlier failures (upgrade step ref, history secret scan) fixed. |
| CI `android-instrumented` (emulator job) | **GREEN on GitHub (run 38077466094; also 38071782971)**: 46 instrumented tests on an API 34 x86_64 emulator, 0 failed, 2 skipped (the skipped ones were not individually identified; the multi-relay phase test is skipped there by design and covered by the job below). It had never run before and failed three times for real reasons, all fixed: truncated system-image download hidden by the script (now retried and verified on disk), unbounded waits (now bounded + 60 min timeout), missing Gradle checksum for `junit-bom-5.9.2.module` (added after matching Maven Central's published SHA-256). |
| Emulator E2E, two independent relays (`android-e2e-multirelay` CI job, `scripts/android-e2e-multirelay.py`) | **14/14 PASS on GitHub (run 38077466094, the commit "build the relay binary and the e2e peer example separately")**. Real app stack (native core, Android Keystore, OkHttp/TLS 1.3, `PinnedTls`) on an emulator against relay A (CA-signed) and a self-signed, pinned relay B, headless peer on B, separate PostgreSQL databases: card exchange across relays, message app→B, 3 offline texts + 900 KB file B→app while the app is offline, replies + attachment back (byte-for-byte), end-to-end receipts, each relay holds only its own user, no sender hash on B. The first CI attempt failed only because my script built `--example` without the relay binary (script bug). Earlier local emulator runs peaked at 10/14 (driver bugs, since fixed). Scope: emulator, software-backed Keystore, direct route (no Tor), one run — not a physical device, not a soak. |
| Cross-relay groups (ST-044) | Design **reviewed and found not yet defensible** (`CROSS_RELAY_GROUPS.md` §5a: commit-cap liveness attack, removal window, read-cap linkage, undefined equivocation detection, welcome ordering). Not implemented; engine still refuses. |
| Real Tor from the Android app | Done in Session 3 (below). |

## Session 3 — repeated E2E, resilience, Android over real Tor (evidence from GitHub Actions)
All results are from GitHub-hosted runners (KVM emulator, API 34, software-backed Keystore); nothing ran on a physical device.

**1. Repetition of the two-relay E2E (workflow `e2e-repeat`, run 38082672542, 5 independent jobs, no retries):** 5/5 green, each log 14 PASS / 0 FAIL; job wall time 11 to 16 minutes (including build).

**2. Resilience phases added to the E2E driver** (offline burst of 10 after an app restart; app's relay stopped and restarted on the same database; peer's relay down while the app sends a text and a 300 KB attachment; recovery with exactly-once and byte-for-byte checks; all messages DELIVERED, none FAILED). Final result on commit 731b1c5: **`ci` run 38090565452 all 7 jobs green, direct-route E2E 21/21; instrumented suite 49 tests, 0 failed.**
Failures found on the way (all in my driver, none in product code): ktlint violations in new androidTest sources (3 CI runs); at ad15f54 the direct E2E scored 18/21 (run 38087638441) because failed sends retry on an exponential backoff (10 s, 20 s, 40 s ... `backoff_ms`, FAILED after 8 attempts) and my driver stopped syncing the peer before the app's retry was due, so no receipt came back. Fixed by keeping the peer syncing while the app recovers; assertions unchanged.

**3. Android over real Tor (workflow `android-tor`; own Tor client on the runner, two relays as hidden services with self-signed certificates and SPKI pins, app uses its SOCKS privacy route, peer uses `curl --socks5-hostname`; 3 repetitions per push):**
| Run | Commit | Result |
| --- | --- | --- |
| 38082923137 | 7d54dc1 | 1 rep, 16/16 (baseline, no resilience phases yet) |
| 38083099330 | 47493e0 | **FAIL** 9/22: first connection from the app to the other onion service timed out at the 60 s connect limit (`addContactByCard` Offline) |
| 38084578602 | d121b53 | 3/3 green |
| 38084625647 | 5bc9edf | 2 green, **1 FAIL** 19/23: `sendAttachment` Offline (circuit timeout during upload; no message left behind) |
| 38087515662 | cc8c21d | 3/3 green |
| 38087638416 | ad15f54 | 2 green, **1 FAIL** 18/23: the peer's 900 KB upload through Tor returned Offline |
| 38090565453 | 731b1c5 | 3/3 green, each 23/23 (no peer-upload retry needed) |
Total 17 repetitions: **14 green, 3 failed**. All three failures were Tor circuit timeouts surfacing as "offline"; none was a TLS, pin or data-integrity failure. The code under test changed between rows (harness retries were added after the failures), so this is not a clean flake rate; with the bounded retries the last commit was 3/3. Retries are limited to "offline" (never to a TLS refusal) and are printed/recorded.
The Android-level assertions that held in every run that reached them (class `OnionRelayInstrumentedTest`): correct pin accepted and route `PROTECTED`; wrong pin refused with a TLS fault; a self-signed onion certificate without any pin refused (platform CA validation). The same app-stack flow as the direct E2E (cards across relays, offline messages and attachments, receipts, metadata checks) ran over Tor.
Product changes made for this: the privacy route's connect timeout is 60 s (was 10 s; circuit building routinely exceeds 10 s). Invariants MR-011 and MR-012 added (status `partial`).

**4. The skipped instrumented tests:** Gradle prints "2 skipped"; the result XML lists 8 `assumeTrue`-gated cases (PrivacyRoute x5, PrivacyTraffic, LiveRelay, MultiRelay phase) plus the 3 new onion tests that need arguments. They are skipped because they need arguments or servers that only a driver provides (a SOCKS endpoint, a live relay URL, a phase name). The multi-relay and onion tests are executed by the E2E and Tor jobs. I did not reconcile Gradle's count of 2 with the XML.

**5. ST-044 (cross-relay groups):** `CROSS_RELAY_GROUPS.md` §7 is a revised design (epoch-derived authentication switched atomically with the commit, hash-chained log with fork/rollback detection, write-ahead Welcome, stated limits for a hostile member and for permanent partitions). It is **design only, unreviewed, with an open feasibility check (§7.1)**; the engine still refuses cross-relay groups.

**Not covered by any of this:** mid-stream network cuts during an upload at the E2E level (only a refused connection; the mid-transfer case is a Rust test), database outage, multi-device, physical devices, Orbot, battery/background behaviour, independent review.

## Resume checkpoint
Next actions in dependency order: (1) A mid-stream upload cut (TCP-cutting proxy) and airplane-mode/handover phases; Orbot on a physical device; (2) run `multi_relay_wire` fuzz and a longer campaign; (3) chunked/resumable upload (ST-046); (4) cross-relay commit design (ST-044) before any group work; (5) physical-device + Orbot matrix (ST-028/038/049); (6) independent crypto review (ST-005).
