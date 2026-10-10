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

## Phase 6 — Tor: relay side TESTED-LIVE; **client side NOT TESTED**
See `NETWORK_ADVERSARY_MODEL.md`. Not tested: Orbot, the Android `PinnedTls` against an onion relay, IPv6, handover, airplane mode, process death, backgrounding. Real-Tor evidence used `curl`, not the app.

## Phase 7 — Device/account security: **no new work** (needs a physical device; ST-001/028 unchanged). Cards are issued only by the root device; no recovery was added (explicit no-recovery policy kept).

## Phase 8 — Reliability: foreground retry/backoff/ordering/receipts are covered by the matrix. Background delivery, FCM/UnifiedPush and battery work are **not done** (ST-017/042).

## Phase 9 — Adversarial: added hostile-relay key substitution, withheld/replayed/reordered delivery (matrix + existing tests), capability guessing/revocation, quota flooding, tampered blobs; fuzz target `multi_relay_wire` (90 s smoke: 5.5 M executions, no crash; its first crash was a bug in my own assertion; no campaign, no sanitizers beyond libFuzzer's defaults), and two previously missing targets added to the CI fuzz matrix. Not done: sanitizer runs, long fuzz campaigns, TLS-downgrade tests of the app.

## Phase 10 — Release engineering: SBOM generator (`scripts/gen_sbom.py`, 972 components, reproducible), `cargo deny` pass, `cargo audit` pass **with a reviewed exception** (ST-045), CI updated. No signed release, no reproducible-build claim, no APK produced. See `RELEASE_READINESS.md`.

## Security findings in this pass
1. HIGH (pre-existing): message loss after offline queueing (fixed). 2. MEDIUM: lost receipts for message requests (fixed). 3. MEDIUM: onion handshake deadline (fixed). 4. LOW: `own_relay` memory-only would have mis-addressed cross-relay capabilities after restart (found by design review before release; fixed, persisted). 5. LOW: CI fuzz matrix omitted two targets (fixed). 6. INFO: `libcrux-kem` advisories (not in build graph; exception recorded). Everything is **self-reviewed**; ST-005 (independent review) stays open.

## Commands and results (this machine)
`cargo test --workspace` (PostgreSQL on 127.0.0.1:55432) — last full run: 39 suites; the one failure (a static guard flagging my negative-test URL literals) was fixed and re-run green; `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` clean; `scripts/check_invariants.py` 75 invariants; `scripts/test-deploy.py localhost:18443` 17/17; `scripts/test-upgrade.py` 10/10; `scripts/public_release_scan.py` 0 findings.

## Resume checkpoint
Next actions in dependency order: (1) Kotlin: UI for card create/scan + relay/pin settings, call `set_own_relay` after unlock, build and run JVM tests for `PinnedTls` (ST-048); (2) run `multi_relay_wire` fuzz and a longer campaign; (3) chunked/resumable upload (ST-046); (4) cross-relay commit design (ST-044) before any group work; (5) physical-device + Orbot matrix (ST-028/038/049); (6) independent crypto review (ST-005).
