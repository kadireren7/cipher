# Final security review (engineering pass)

**Scope and honesty.** This is an adversarial engineering review performed by the author of the code, with the goal of finding where Cipher is *not* secure. It is **not** the independent review required by ST-005 and must not be cited as one. No physical Android device was available at any point; nothing here is a hardware claim. A green test run is evidence for the tested scope only. Evidence labels: **TESTED** (automated), **EXERCISED** (observed on the emulator, not automated), **REVIEWED** (read, not run), **NOT TESTED**.

## 1. Baseline state (before this pass)

Rust workspace: 244 tests green (`cargo test --workspace --all-features`), clippy `-D warnings`, `cargo deny`, `cargo audit` clean; 4 JVM unit tests; 24 instrumented tests on one API 34 x86_64 emulator; 27 invariants → 139 mapped tests; the entire work of the previous prompts is **uncommitted** (no git commits exist), so a tarball snapshot was taken before any change (`~/cipher-baseline-<date>.tgz`). `adb devices` listed **no physical device**.

## 2. Attack surfaces reviewed

24 surfaces (UI, saved state, lifecycle, UniFFI, FFI callbacks, core engine, OpenMLS integration, local DB, Keystore, PIN/biometric, attachments, temp files, notifications, groups, relay API, PostgreSQL, TLS, account/device auth, rate limits, key verification, experimental KT, build pipeline, dependencies, APK) — see `ATTACK_SURFACE.md` for the mapping to adversaries, controls, evidence and findings. The threat model gained A17 (rollback) and A18 (hostile contact/media/abuse) and a per-attack result list for a fully controlled relay.

## 3. Findings

Severity scale: **CRITICAL** (remote compromise of confidentiality/integrity of many users), **HIGH** (serious exploitable weakness or unauthenticated remote DoS), **MEDIUM**, **LOW**, **INFO**. No CRITICAL finding was made. Absence of findings is not evidence of absence.

| ID | Sev | Finding | Status | Regression test |
| --- | --- | --- | --- | --- |
| FR-10 | **HIGH** | **Pre-authentication memory exhaustion.** `POST /v1/blobs` buffered up to 101 MiB of body *before* authenticating (the signature covers the body hash), so an unauthenticated peer could hold ~100 MiB per connection (up to `max_inflight` of them). | **Fixed** (signed `bh=` hash, authenticate first, upload-slot semaphore, re-hash after read) | `unauthenticated_or_badly_signed_uploads_are_refused_without_reading_the_body` (a body that records whether it was polled), `a_valid_signature_over_a_different_body_is_rejected_after_reading` |
| FR-06 | MEDIUM | **Message-triggered crash loop.** A contact's 128 KB thumbnail declaring a huge image was decoded at full size on every conversation open → `OutOfMemoryError`. Same class: unguarded `MediaPlayer`/`PdfRenderer` setup, unbounded PDF page sizes. | **Fixed** (`SafeDecode`, guarded players, PDF caps) | JVM `SafeDecodeTest`, instrumented bomb/garbage tests, source guard |
| FR-12 | MEDIUM | **Forward secrecy not durable.** On *group* receive the ratchet advance was only in memory; the on-disk MLS state could still re-derive consumed message keys (until the next send/commit, never on lock). A relay that kept ciphertext could read it after a later vault compromise. | **Fixed** (persist after every processing sync, before ack, before lock) | `consumed_group_message_keys_are_gone_from_the_state_on_disk_after_a_restart` (failed before the fix) |
| FR-07 | MEDIUM | **Relay counter reset bricks commits forever.** After a relay restore/reset every member's stored `relay_seq` stayed ahead; no member could rename/add/remove or **refresh keys (PCS)** again. | **Fixed** (adopt a lower `Stale` value) | `a_reset_relay_group_counter_does_not_permanently_brick_commits` (failed before) |
| FR-08 | MEDIUM | **KeyPackage draining.** Any account could take a victim's entire supply (100) in seconds (limit was ~8000/h per requester) → victim unreachable for new contacts. | **Fixed** (per-target 12/h and per-pair 4/h, hourly refill) | `key_package_draining_is_throttled_per_target_even_across_many_attackers` |
| FR-11 | MEDIUM | **Lock delayed behind running work.** The single engine mutex serialises everything, so "lock on background" waited for an in-flight upload/download while keys stayed in memory. | **Fixed** (`request_lock` + network cancellation on the calling thread, abort-aware adapters) | FFI abort tests, ordering guard, stress test |
| FR-05 | MEDIUM | **Local rollback.** Restoring an older `vault.db` was undetectable and would make the device reuse ratchet keys/nonces. | **Mitigated** (detection of whole-vault rollback; residuals below, ST-016) | 5 core tests + 2 instrumented |
| FR-09 | LOW | **Device binding did not cover the account id** (directory unknown-key-share; MLS credential checks kept it from becoming impersonation). | **Fixed** (binding v2 signs account‖device‖auth key) | `a_device_record_transplanted_to_another_account_fails_binding_verification`, `a_device_record_cannot_be_registered_under_a_different_account_id` |
| FR-04 | LOW | No tapjacking/overlay/accessibility-service defences. | **Fixed (best effort, API-gated)** | guards + instrumented flag test |
| FR-02 | LOW | Typed text could reach keyboard learning and autofill. | **Mitigated (best effort)** | guard `every_text_field_goes_through_private_text_field` |
| FR-13 | LOW | Names/previews accepted Unicode format characters (bidi overrides, zero-width) → display disguise; a malicious group committer could install such a name. | **Fixed** (shared policy; receivers reject; names/previews stripped) | 2 unit tests |
| FR-01 | INFO | *Hypothesis refuted*: a Welcome carrying an existing group's id does **not** overwrite its state (OpenMLS refuses); an explicit check was added as defence in depth. | Closed | `welcome_with_the_group_id_of_an_existing_group_cannot_overwrite_it` + control |
| FR-03 | INFO | Saved state held no secrets; a guard now keeps it that way. | Closed | guard |
| ST-027 | MEDIUM | Vault key passes through JVM memory. | **Mitigated, OPEN** (§6) | instrumented zeroing test |

## 4. Unresolved vulnerabilities and gaps (nothing hidden)

| ID | Sev | Issue | Exploit prerequisites | Impact | Mitigation / next step |
| --- | --- | --- | --- | --- | --- |
| ST-001 / ST-028 | **HIGH for readiness** | Keystore, StrongBox/TEE, biometrics, enrolment change, FLAG_SECURE on real devices **never tested** | n/a (unknown) | Hardware claims unverified | Physical-device matrix |
| ST-005 | **HIGH for readiness** | No independent cryptographic/security review | n/a | Unknown flaws in compositions (group policy, sequencer, framing, KT glue) and in OpenMLS usage | External review |
| ST-031 | MEDIUM | **Inbox flooding**: any authenticated device can fill a victim's relay queue (1000 envelopes / 16 MiB) | An account (invite token) and the victim's Cipher ID | Victim's other contacts get 429 until the victim syncs | Contact-based capabilities / blind tokens (needs design) |
| ST-032 | MEDIUM | **Message drop/delay by the relay is undetectable** | Control of the relay | Silent censorship of single messages | Sender sequence numbers inside the frame + UI |
| ST-016 | MEDIUM | Rollback residuals: same-session snapshot; deletion of keystore counter entries; per-record rollback; root | Code execution as the app / root, or snapshot+restore inside one unlocked session | Old state accepted | Hardware-attested counter if Android ever exposes one |
| ST-027 | MEDIUM | Vault key exists in the JVM for the duration of the Keystore operation | Memory read of the app process during an unlock (debugger on a debuggable build, root/Frida, heap dump) | Offline decryption of `vault.db` | Cannot be removed with the Keystore wrapping pattern |
| ST-010 / ST-033 | MEDIUM | No recovery, **no device revocation**, shared invite token | Lost/stolen phone | Identity is lost; a stolen unlocked device cannot be revoked remotely | Design needed; do not ship insecure recovery |
| ST-002 | LOW–MED | No certificate pinning (decision, ADR-035) | A subverted public CA + network position | Interception of **metadata** (content stays E2EE) | Operator-owned pin + rotation plan |
| ST-017 | MEDIUM | No push; foreground polling only; locked app cannot fetch | n/a | Delivery while closed depends on a future push design | `PUSH_DESIGN.md` |
| ST-034 | LOW–MED | Platform codecs/renderers (MediaPlayer, PdfRenderer) parse hostile files | A contact + a platform bug | App crash or worse | Fuzz with malformed samples; consider isolating decoding |
| ST-009 | MEDIUM | Relay sees the sending device, recipient sets, commit vs message, group id/epoch if it parses MLS framing | Relay/operator or anyone who can read request metadata | Social-graph and timing leakage | Sealed sender / outer routing layer |
| ST-006 | — | Key transparency is experimental and unwired | n/a | First-contact TOFU gap remains | Needs a log operator |

## 5. FFI findings (phase 4)

Every export is validated and bounded; a panic inside a call or callback is contained and locks the vault; poisoned locks lock; hostile ids/paths/enums/PINs are refused before any work; no handle outlives a lock (the API returns plain data). Added: a keystore that "succeeds" without delivering a secret cannot unlock (fail closed); the abort flag cannot get stuck; a stress test races rapid lock/unlock/background against plaintext calls from three threads (no panic, no stale success after a completed lock). Fuzzing: `ffi_validate` (validators accept only canonical ids / `/proc/self/fd/N`), `app_parsers`, `vault_file`. **No FFI vulnerability was found**; the lock-delay (FR-11) and the key transit (ST-027) were architectural weaknesses behind the FFI, not input-handling bugs.

## 6. ST-027 status (phase 5)

Reduced, **not eliminated, still OPEN**. Where the key exists: (1) Rust → Kotlin argument at `wrap` (provisioning/PIN enable only; zeroed right after the Keystore used it); (2) inside `Cipher.doFinal` at unwrap — JCA/Keystore-internal buffers cannot be controlled; (3) Kotlin → Rust at unwrap through a Rust-implemented `SecretSink`, after which Kotlin zeroes its copy immediately — the key is no longer *returned* (a return value stays reachable through generated glue until GC). The UniFFI buffer in native memory is not zeroed on free. Attacker capability required: reading this process's memory during an unlock (debugger on a debuggable build, root/Frida, a heap dump) — the same capability that can call the engine directly while unlocked, so the marginal gain for the attacker is persistence of the key after lock, which the zeroing removes in the common path. Android offers no Keystore operation whose output stays in the secure world for this wrapping pattern. Guards: `keystore_wrapper_never_returns_the_vault_key_and_zeroes_its_copies`, instrumented `theJvmCopyOfTheKeyIsZeroedAfterUnwrapAndWrap`, Rust `a_keystore_that_never_delivers_the_secret_cannot_unlock_the_vault`.

## 7. OpenMLS integration and cryptographic review findings (phases 2–3)

Reviewed adversarially (not the independent review): ciphersuite and extension use, KeyPackage and Welcome handling, epoch handling, commit authorisation, replay, persistence, attachment encryption, vault hierarchy, request signing, binding/endorsement messages, safety numbers, KDF/AAD/nonce/domain separation. Results:

* **Found and fixed:** binding without account id (FR-09); non-durable forward secrecy on group receive (FR-12); relay sequence value that could never be lowered (FR-07).
* **Hypotheses tested and refuted:** Welcome-collision state overwrite (FR-01); nonce reuse in the vault (random 24-byte XChaCha nonces, location-bound AAD); cross-protocol key reuse (the identity key signs MLS structures and our binding/endorsement messages, but with distinct, versioned context prefixes; MLS signing content is length-prefixed with `MLS 1.0 …` labels); epoch confusion (stale commits dropped, future ones held, bounded); malformed-message state corruption (parsers never panic and leave state unchanged — fuzzed and property-tested).
* **Remaining design caveats (need external eyes):** the identity key is used for both MLS and our own signatures; `max_past_epochs = 2` keeps two old epochs' decryption material longer; group policy and the sequencer are our constructions; the first-contact lie is only addressed by manual verification.
* **1:1 over MLS:** a DM is a two-member MLS group. This adds KeyPackage logistics, commit handling and welcome flows compared with a pairwise ratchet, but gives one state machine and one audit surface; no concrete security reason to change the architecture was found, and no migration was attempted.
* **Dependencies:** `cargo tree`, `cargo deny` (advisories, bans, licences, sources), `cargo audit --deny warnings`: clean. The single advisory exception (RUSTSEC-2026-0173, `proc-macro-error2`) was **re-evaluated and retained**: it is a compile-time proc-macro of `hax-lib-macros`, pulled in through libcrux/`hpke-rs`/OpenMLS (visible with `cargo tree -i proc-macro-error2 --target all -e all`), not linked into runtime logic; removal needs an OpenMLS/hpke-rs update. Two narrow policy additions were made in `deny.toml` earlier (CDLA-Permissive-2.0 for CA root data; `fastrand` allowed only as `tempfile`'s dependency inside the UniFFI code generator). `ct-merkle` and `sha2 0.11` exist only behind a feature and are **absent from the shipped graph** (CI-asserted). No JavaScript/npm exists anywhere in the runtime or build.

## 8. Android storage and locked-device findings (phases 6, 22)

* Searched after realistic sessions (DM, group, image, PDF, voice, lock/unlock, restart): see §24. Result: 0 fixture hits wherever a search was possible.
* The **MLS snapshot not being persisted on receive** was the one storage-consistency defect (FR-12).
* Process death: the receive path stores messages atomically, persists the MLS state **before** acknowledging, so a crash re-delivers rather than loses; lock persists first. A kill inside one sync batch keeps the pre-batch state (documented residual in SEC-033).
* Whole-vault rollback detection added (FR-05). Not covered: root, same-session snapshot, per-record rollback.
* WAL/SHM: the vault uses a rollback journal; no `-wal`/`-shm` files were observed. `secure_delete` is on; flash wear-levelling is not assessed.
* **Not searchable without root:** other apps' memory, the system keystore database, kernel page cache/swap, the notification service's history, the IME's dictionary. The search covered the app's own data directory, `/sdcard`, `/data/local/tmp`, logcat, the relay log and a PostgreSQL dump.

## 9. Keystore findings (phase 21 and §6)

Emulator only (software Keystore): creation, honest level read-back, non-exportable keys, AAD binding, tamper detection, restart, deletion, the new counter, the release build refusing software keys — all TESTED/EXERCISED. **StrongBox, TEE, biometric prompts, `setUnlockedDeviceRequired`, enrolment-change invalidation, device reboot behaviour, screen recording, notification behaviour on real devices: NOT TESTED** (ST-001, ST-028). `adb devices` showed no physical device.

## 10. Compromised relay and PostgreSQL (phase 8)

Tests drive the relay's tables directly like a malicious operator (`relay_compromise.rs`, real PostgreSQL):

| Attack | Result |
| --- | --- |
| Bit-flip queued ciphertext | **Prevented** (dropped, never decrypted, queue not wedged) |
| Redirect ciphertext to the wrong device | **Prevented** (nothing readable, no conversation appears) |
| Duplicate under a new message id | **Prevented** (shown once) |
| Replay an old commit (epoch rollback) | **Prevented** (epoch and title unchanged) |
| Fake acknowledgement / swallow messages | **Prevented** from forging delivery (receipts are E2EE); messages are lost → see drop |
| Retire the routing tag | **Prevented** from corrupting state (commit fails cleanly, chat continues) |
| Reset the group counter | **Fixed** (was a permanent brick, FR-07) |
| Substitute a device key / KeyPackage | **Detected** (pins, KeyPackage identity check; earlier tests) |
| Withhold a commit from one member (partition) | **Detected** only as undecryptable traffic; heals when delivered |
| **Drop or delay a message** | **UNDETECTABLE** (ST-032) |
| Read content with total DB access | **Prevented** (dump after all attacks: no fixture) |

## 11. PostgreSQL dump results

A full dump of the E2E database after the final session and after the attack suites contains no plaintext fixture, no sender column, no raw IPs or device ids in rate-limit keys, and no populated push tokens (§24).

## 12. Group attack results (phase 11)

Receiver-side policy covers a malicious MEMBER/ADMIN (role matrix), forged commits, concurrent/reordered/duplicate commits, stale devices, a removed member (cannot read future epochs, cannot commit — tag rotated), no pre-join history, and member removal during a send. A malicious OWNER can do anything an owner may (by definition), including removing members and renaming; ownership transfer is explicit. The relay cannot rewrite authorisation (roles are in the MLS GroupContext). Remaining: partition/withholding (detectable only as undecryptable traffic) and the owner's absolute power.

## 13. Attachment attack results (phase 12)

Existing suites cover tampering, truncation, reordering, extension, chunk duplication, MIME/extension spoofing, filename traversal, size limits and fail-closed behaviour (authentication precedes any plaintext). Added: hostile image headers and malformed media on the receiving side (FR-06), PDF page/size caps. **Not tested:** real malformed audio/video/PDF samples against the platform decoders (ST-034). Viewer plaintext is held in memory and zero-filled on dispose; PDFs go through an unlinked anonymous temp file that is overwritten on close (flash wear-levelling may retain blocks).

## 14. Network attack results (phase 9)

From the emulator, against adversarial TLS servers (`scripts/adversarial-tls-servers.py`): TLS 1.3 negotiated even when the server also offers 1.2; **TLS 1.2-only server refused; expired certificate refused; wrong-hostname certificate refused; untrusted-CA certificate (what a MITM proxy presents) refused; redirect to `http://` not followed (the plain server received zero connections); `http://` URLs refused before any connection.** All TESTED (7 instrumented tests, skipped automatically when the servers are not running). Proxy interception beyond a CA the device trusts, DNS manipulation, and OEM TLS stacks: NOT TESTED. **Pinning (decision):** not shipped (ADR-035): a baked pin is impossible because users choose their relay, and trust-on-first-use pinning plus certificate renewal with no account recovery creates a lock-out risk worse than the threat it addresses (a subverted CA reads only metadata). Revisit with an operator-managed relay and a backup-pin plan.

## 15. Metadata remaining (phase 10)

See `METADATA_MODEL.md` §4a for measurements. Passive observer: relay IP, SNI, connection and request timing, message-size class (powers of two up to 8 KB; attachments +0.4–5.3 % via Padmé), bursts, recipient-set sizes of group sends, polling cadence (foreground app polls every few seconds). Relay: additionally recipient devices, the sending device at request time, which requests are commits, routing tags and commit sequence, KeyPackage claims. **No ISP-invisibility or anonymity claim.** Routing-tag rotation beyond removal was evaluated and not changed (the recipient device set links a group anyway).

## 16. Release APK analysis (phase 14)

`scripts/analyze-release-apk.sh` unpacks the release APK and searches dex, native libraries and resources: **no** private-key markers, test fixtures, `debug_no_user_auth`, `insecure-test-support`, relay environment names, test CA, `10.0.2.2`/localhost, developer machine paths or cleartext URLs; seven benign `https://` strings (library constants and the two relay-address hint examples `https://relay.example.org[:8443]` shown in the UI). The same script run on the **debug** APK fails (positive control: it flags the debug bypass, the test CA and `10.0.2.2`). The merged-manifest gate passes: not debuggable, backup off, cleartext off, only the launcher activity exported. R8 did not break security logic: the minified release build refused the emulator's software Keystore at runtime (§19). Dex was inspected statically only (no full decompilation review).

## 17. Supply chain (phase 19)

* Cargo: `Cargo.lock` committed; `--locked` everywhere; deny/audit clean.
* Gradle: **dependency verification metadata** (SHA-256 of 570+ artifacts) generated and enforced; versions are fixed by the catalogue.
* CI: all third-party actions pinned by commit SHA; `permissions: contents: read`; no `pull_request_target`; the Postgres service image is pinned by digest; workflow YAML parses; **CI has never run on GitHub**.
* Release signing: architecture and scripts only (`RELEASE_SIGNING.md`, `sign-release.sh`); no signing material exists in the repo; the release APK is **unsigned**.
* **Reproducibility:** two consecutive **clean** release builds on this machine produced **bit-identical APKs** (same SHA-256) after adding `--remap-path-prefix` to the Rust build; APK timestamps are normalised by AGP. **Not demonstrated:** a different machine, different absolute checkout path, or different JDK/SDK/NDK/Rust versions. Final-source hashes are in §26.
* SBOM/provenance attestations: not produced (ST-014 open).

## 18. Fuzzing (phase 15)

Final campaign (this host, 3 parallel streams, `cargo +nightly fuzz run <target> -- -max_total_time=420 -rss_limit_mb=700`, existing corpus + discovered units kept in `fuzz/corpus`, ~135 MB):

| Target | Executions | Seconds | Crashes/OOM/timeouts |
| --- | ---: | ---: | ---: |
| app_parsers (Cipher ID, frame codec, group metadata, wake payload) | 42,820,196 | 421 | 0 |
| attachment_decrypt | 4,713,144 | 421 | 0 |
| attachment_descriptor | 44,487,264 | 421 | 0 |
| auth_header | 103,527,113 | 421 | 0 |
| ffi_validate (FFI boundary validators) | 60,786,842 | 421 | 0 |
| filename_and_endpoint | 8,395,927 | 421 | 0 |
| mls_snapshot_restore | 16,484,638 | 421 | 0 |
| mls_welcome_and_keypackage | 235,074 | 421 | 0 |
| vault_file (arbitrary bytes as `vault.db`) | 1,277,084 | 421 | 0 |
| wire_json | 14,531,838 | 421 | 0 |
| **Total (10 targets)** | **297,259,120** | **4,210** | **0** |

Earlier in this pass the same targets ran for ~10-minute slots each (e.g. `auth_header` 52.9 M, `wire_json` 16.7 M, `app_parsers` 52.8 M executions; `mls_snapshot_restore` is slow at ~100 exec/s because restoring MLS state is expensive). Findings from fuzzing in this pass: **none**. (The earlier phase-1 finding in `filename_and_endpoint`, a 6-byte input, still replays clean and has its regression test.) These are single-host runs of minutes, **not** a multi-day campaign, **without sanitizers**, and `mls_welcome_and_keypackage` is deep but slow (558 exec/s), so its coverage of OpenMLS parsing is thin. The MLS wire parsers are also property-tested (`parsers_property.rs`).

## 19. Physical-device and emulator testing actually performed

Physical device: **none**. Emulator (API 34, x86_64, google_apis, software Keystore): the instrumented suite, UI-driven onboarding/DM/group/attachments against the real relay and PostgreSQL, release-build refusal of software Keystore, network attack tests, plaintext hunt.

## 20. Tests not performed

Physical hardware (everything in §9); real push; notifications under Doze/OEM; actual backup/device-transfer attempts; cross-app attacks and a real tapjacking app; accessibility-service abuse; rooted-device extraction; heap dumps; multi-day fuzzing and sanitizers; load/DoS at scale; HA PostgreSQL; interoperability with other MLS implementations; cross-machine reproducible builds; usability and TalkBack accessibility audits; the GitHub CI pipeline; malformed-media fuzzing against platform codecs.

## 21. Components requiring independent review

OpenMLS 0.9.0 and its RustCrypto provider build; our compositions (vault hierarchy, request signing and binding v2, group metadata/`authorize_commit`, commit sequencer, framing/padding, persistence ordering, rollback counter, KT glue); the Android Keystore wrapper on hardware; `ct-merkle`; the relay under adversarial load; penetration testing of the whole system.

## 22. SECURITY TODOs

Closed in this pass: none (no item met the evidence bar without hardware or independent review). Moved/updated: ST-016 PARTIAL; ST-027 mitigated; ST-030 PARTIAL; new ST-031…ST-034. ST-005 stays OPEN by rule. See `SECURITY_TODO.md`.

## 24. Plaintext hunt and end-to-end evidence (phases 22 and 25)

**Setup:** release-built relay binary over TLS 1.3 (throwaway test CA) + PostgreSQL 17; debug APK on the API 34 emulator; peers = headless Rust engines (`cipher-ffi/examples/e2e_peer.rs`, same `CipherEngine` API, `curl` TLS 1.3 transport). Canary plaintexts: `FINAL-CANARY-dm-text-from-bob-5501`, `-dm-reply-from-app-4429`, `-group-text-from-bob-7702`, `-group-text-from-carol-8813`, `-group-reply-from-app-9924`, `LIVE-CANARY-text-from-the-real-app-4412`, `LIVE-CANARY-attachment-bytes-9921` (inside a 3 MiB PDF), image/PDF/voice markers, plus group/contact/file names.

**Exercised end to end:** UI onboarding (PIN-only) → DM both ways → group of three (the app joined by Welcome) → image, PDF, voice note received and opened in the viewers (no crash, `cache/viewer` empty) → a 3 MiB PDF **sent by the real app stack** (Keystore wrapper, native core, OkHttp, new authenticate-first upload: relay `POST /v1/blobs` → 201) and **decrypted byte-exact** by the peer (3,145,777 bytes, marker present) → process kill → relaunch → locked → PIN unlock → conversations intact → on-device **rollback attack** (vault copy restored after further unlock cycles) → refused, specific message, nothing decrypted → release build refused the software Keystore and was non-debuggable (`run-as` denied).

**Searches and results**

| Location | Searched? | Hits |
| --- | --- | --- |
| App private data (`vault.db`, config, files; raw bytes + `strings`) | yes, `run-as tar` of the whole data dir (the vault is a rollback-journal SQLite file; no `-wal`/`-shm` existed) | **0** |
| `/sdcard`, `/storage/emulated`, `/data/local/tmp` | yes | 1 — `/sdcard/ui.xml`, **written by my own UI-automation dump** (a test-tooling artifact; it contains whatever the screen showed); deleted. No app-written file |
| logcat | yes | **0** |
| Relay log (333+ lines: method, route template, status) | yes | **0** |
| Full `pg_dump` (6.5 MB) | yes (raw + `strings`) | **0** |
| Release APK contents (dex, native libs, resources) | yes | **0** |
| Peers' data directories | not searched (they are test tools) | — |
| App heap / process memory while unlocked | **impossible** without root/debugger | — |
| System keystore DB, kernel page cache/swap, notification history, IME dictionary, other apps | **impossible** without root | — |
| Positive control | the UI dump contained the canaries (so the patterns match what the app shows) | 1 |

A zero-hit result is evidence for this run and these locations only.

## 25. Exact final results (clean tree, one consistent run)

`scripts` sequence executed after `cargo clean` and `gradlew clean`: **20/20 steps exit 0** —
`cargo fmt --check` · `cargo clippy --workspace --all-targets --all-features --locked -D warnings` · `cargo build --workspace --release --locked` · `cargo test --workspace --all-features --locked` (**281 passed, 0 failed, 1 ignored** (a measurement), 24 test binaries; includes the 13 experimental-KT attack tests and the 20 Android static guards) · invariant registry (**38 invariants → 193 mapped tests, all exist**) and generated doc fresh · relay dependency graph · secret scan (196 files, none) · `cargo deny check` (advisories, bans, licences, sources ok) · `cargo audit --deny warnings` (clean; the single reviewed exception retained) · shipped graph free of `ct-merkle`/test-support · `ktlintCheck` · Android lint · **6 JVM unit tests** · `assembleDebug`, `assembleRelease`, `assembleDebugAndroidTest` · merged-manifest gate · release APK analysis · artifact hashes.
Instrumented (emulator, API 34 x86_64, software Keystore): **39 tests, 0 failures, 1 skipped** (the live-relay upload test needs relay arguments; it passed when run manually against the real relay) — including the 7 network-attack tests against adversarial TLS servers.
End-to-end and plaintext hunt: §24. Fuzzing: §18.

## 26. Final artifacts

| Artifact | Path | SHA-256 |
| --- | --- | --- |
| **Release APK (unsigned, verification artifact — not distributable)** | `android/app/build/outputs/apk/release/app-release-unsigned.apk` | `71e659abb502f5bcc6351be3f72c17bc37b029ee0b8c466c49eea702479bbb22` |
| Debug APK | `android/app/build/outputs/apk/debug/app-debug.apk` | `7b236ce60e7e5d7c1f1b7cc449ec37df549259abb2615ce378b9a943cf023268` |
| `libcipher_ffi.so` arm64-v8a / x86_64 | `android/app/build/rustJniLibs/…` | listed in `release-hashes.sh` output (`/tmp/final-artifacts/SHA256SUMS` at the time of the run) |
| `Cargo.lock` | repo root | `6471446e5942568dd0f6198f14b0c46014772c66ca5fd191b4fe8190b007c4d2` |

Reproducibility of the final source: the release APK above was produced **twice** (an incremental build and the fully clean verification run) with the **same SHA-256**. Earlier, two consecutive clean builds of the previous source were identical to each other as well (`271edc7a…`). Same machine, same checkout path, same toolchain every time: cross-machine reproducibility is **not demonstrated**. The tree is **uncommitted**, so the hash file records "git commit: none".

## 27. Readiness

| Stage | Verdict | Why |
| --- | --- | --- |
| Development | **YES** | Works end to end; strong automated coverage; findings found and fixed this pass; reproducible build. |
| Private beta | **CONDITIONAL** | Acceptable only for a small, invited group of technically informed testers **after** (1) the physical-device matrix (ST-028/ST-001) has run and its findings are fixed, (2) the relay is deployed behind real TLS on PostgreSQL with the documented operating limits, (3) testers are told in writing about: no account recovery or device revocation, metadata exposure, no independent review, undetectable message dropping, inbox flooding, and (4) an independent review has at least been commissioned. Without (1) the hardware claims are unverified. |
| Public beta | **NO** | Unreviewed cryptographic compositions, no hardware validation, no recovery/revocation, abuse resistance incomplete (ST-031), no push, no signed/provenanced release pipeline exercised. |
| Production | **NO** | All of the above plus no external review (ST-005), no pen-test, no operational runbook, no long fuzz campaign, CI never run. |

Passing tests does not prove Cipher secure.

---

# Addendum — history-revocation pass (2026-10-04)

Everything from the previous pass was preserved (no security fix undone; `FR-01..FR-13` remain fixed). Nothing is committed (no VCS).

## New / changed
* **Group history revocation** (`HISTORY_REVOCATION.md`, ADR-037): per-epoch exporter-derived history keys, per-message HKDF keys, sealed bodies, tombstone, atomic revocation. 14 engine-level tests against the real relay + PostgreSQL (`engine_revocation.rs`) + 2 unit tests + 1 fuzz target (`history_unseal`). Invariants **REV-001..REV-010** (`SECURITY_INVARIANTS.md`; REV-008/009 partial: no multi-device exists).
* **Found and fixed (new vulnerabilities this pass):**
  1. *Removed offline member could keep sending into a retained past epoch* (MLS `max_past_epochs`) → sender-membership check on past-epoch application messages; a message whose sender leaf no longer exists is `Unauthorized("sender is no longer a member")` (event `RemovedMemberMessageRejected`).
  2. *Committer divergence*: if the relay accepted a commit but the response was lost (or the process died), the committer cleared its MLS pending commit and stayed in the old epoch while the group moved on → persisted pending-commit record + idempotent relay retry (`groups.last_mid/last_from`, migration 0004); `a_lost_response_after_the_relay_accepted_the_removal_does_not_diverge_the_committer` (with and without restart).
  3. *Single sender could fill any recipient's queue* → per-sender share (ST-031, partial).
* **Behaviour change:** a removed member's compliant client no longer keeps old history (previous tests asserted the opposite and were rewritten). Voluntary leave keeps history (documented).
* **Documents:** `HISTORY_REVOCATION.md`, `EXTERNAL_REVIEW_SCOPE.md`, `RECOVERY_AND_DEVICES.md` (**No cryptographic recovery available.**), `DELIVERY_SEMANTICS.md`, `DEVICE_TEST_CHECKLIST.md`, ST-item classification in `SECURITY_TODO.md` (new ST-035..037), ADR-037..041.

## Verification (this run)
| Check | Result |
| --- | --- |
| `cargo fmt`, `clippy --all-targets --all-features -D warnings` | clean |
| Rust tests (`--all-features --locked`) | **300 passed, 0 failed, 1 ignored** |
| Invariant registry / doc freshness | 48 invariants, 221 mapped tests all exist; doc fresh |
| `cargo deny`, `cargo audit --deny warnings`, relay-deps, secret scan | pass (207 files scanned) |
| Android JVM unit, ktlint, lint, debug + release assemble | pass |
| Instrumented tests on the API 34 **emulator** (via `am instrument`) | **39 / 39 passed** |
| Release APK | manifest gate ok; analysis "no hard failures"; sha256 `4cf540f42088305143ea29f4e7b09de861b03fc30f4a155164a24c8d80195241` (single build this pass; reproducibility not re-checked) |
| Fuzz (90 s each) `history_unseal`, `mls_snapshot_restore`, `vault_file`, `app_parsers` | no crashes (≈0.2M / 6.9M / 4.3M / 13.8M executions); short smoke runs, not a campaign |
| Real `cipher-relay` release binary (TLS 1.3) + PostgreSQL + 4 headless peers through the FFI surface | group of 4, removal: removed peer sees 2 history items "unavailable", none readable, `send` refused; remaining peers read all three messages |
| Plaintext hunt for 5 unique canaries (plain, base64, hex) in relay log, `pg_dump`, all four peer data dirs, peer stderr, release APK | 0 hits each (evidence for this run, not proof) |

## Not done / not verified
* No physical device (`adb devices` empty); everything hardware-related stays open (`DEVICE_TEST_CHECKLIST.md`).
* The new UI strings ("Message unavailable — group access revoked", revoked banner, three event texts) compile and pass lint/ktlint but were **not exercised on screen** (no UI-automation run of a removed Android member this pass).
* ST-005 independent review: **open**. ST-032 (drop detection), device revocation and recovery: not built (design decisions documented).
* Relay purge of removed members' queued commit rows: not implemented (ADR-038 explains why app messages cannot be purged).

## Readiness (updated)
Development **YES** · Private beta **CONDITIONAL** (unchanged conditions; the removal story is now stronger but still emulator-tested only) · Public beta **NO** · Production **NO**.
Passing tests does not prove Cipher secure.


---

# Addendum 2 — network-privacy pass (2026-10-04)

Everything from the earlier passes (including history revocation) was preserved; no security fix was undone. Nothing is committed. Details: `PRIVACY_TRANSPORT_REVIEW.md`.

**Built:** SOCKS5 privacy route with fail-closed behaviour and a status that reflects real state (debug-only direct route, absent from release); anonymous, rotating delivery capabilities (`/v1/deliver`, `/v1/caps*`) with queue lanes; frame minimum 1 KiB; STANDARD/ENHANCED profiles with bounded cover; minute-rounded, default-quiet relay logs; PRIV-001..017.
**Found and fixed:** no route abstraction (client IP visible), activity-grade relay logs, stranger flooding through the commit lane, cover with a distinguishable shape, a one-attempt delay when a capability dies. **Unresolved:** ST-038..043 (Tor untested, relay still sees recipients/time, cover distinguishable by the relay and no correlation resistance, onion-service TLS decision, no background delivery, Tor use visible), plus ST-005/001/028/017.

## Readiness (updated)
| Stage | Verdict |
| --- | --- |
| Development | **YES** |
| Private beta | **CONDITIONAL** — as before, plus: the privacy route validated against real Tor/Orbot on a physical device, and testers told in writing what is and is not hidden |
| Public beta | **NO** |
| Production | **NO** |

| Dimension | Rating | Evidence |
| --- | --- | --- |
| Content confidentiality | **STRONG** against relay, DB, network and privacy infrastructure *as tested*; compositions unreviewed (ST-005) | E2EE suites, canary hunts (0 hits), transport sees only ciphertext |
| Server blindness | **PARTIAL** | content-blind; sees recipients (capability→device), timing, size classes, committers, polling |
| Source-IP privacy | **PARTIAL** — plumbing verified, **real Tor NOT TESTED** | relay saw the proxy's address; no local DNS; fail-closed (emulator, test double) |
| Social-graph resistance | **PARTIAL** | no sender in DB/requests for capability deliveries; first contact, commits, polling identified; recipient+time visible |
| Traffic-analysis resistance | **PARTIAL** (link-only observer, ENHANCED) / **WEAK** (observer of both ends) | detector 0.981 → 0.596; candidate set 1.2 → 2.1 |
| ISP observability | **PARTIAL** | no direct connection to Cipher endpoints, no relay DNS/SNI; privacy-network use and cadence visible; no pcap |
| Global-observer resistance | **NOT PROVIDED** | by design; not defended |

Passing tests does not prove Cipher secure.
