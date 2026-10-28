# Release readiness

**Classification (2026-10-10, branch `feat/self-hosted-multi-relay`):**

| Level | Verdict | Why |
| --- | --- | --- |
| Development-ready | **YES** | Automated suites, fault matrix, two-relay tests, Docker acceptance and upgrade scripts pass on one machine. |
| Self-hosted experimental-ready | **YES, for technical operators who accept the limits below** | Relay can be installed, restarted, backed up, restored and upgraded (tested). Onion relay reachable over live Tor (tested with curl). Operators must understand: unaudited code, cross-relay groups are experimental, the Android card/pin UI exists but has not been exercised end-to-end (see below). |
| Private beta-ready | **NO** | The card/relay/pin UI is built and unit-tested. The two-relay emulator E2E passed 5/5 repetitions on the direct route and, over real Tor to pinned onion relays, 14 of 17 repetitions (3 failures, all Tor circuit timeouts; last commit 3/3), with resilience phases (app and relay restarts, outages, offline burst, attachment exactly-once) green on the final commit (`MASTER_IMPLEMENTATION_STATUS.md`, Session 3). Cross-relay GROUPS passed in the same emulator E2E (27/27 in run 38126726477: the real app and two headless peers on three relays over real TLS between processes) but have not been run over Tor, on a device or at scale. All of it is emulator-only with a software Keystore: nothing has run on a physical device (ST-028), Orbot is untested, there is no independent review (ST-005), and cross-relay groups do not exist. |
| Public beta-ready | **NO** | Plus: no independent cryptographic review (ST-005), no signed/reproducible release, no push notifications, no background delivery, no key-update commits in 1:1 conversations across relays, and the cross-relay group protocol is experimental and self-reviewed only (any member can freeze membership changes; no home-relay migration). |
| Production-ready | **NO** | Everything above, plus long-run soak, load, HA, and incident process evidence. |

**Hardening pass (2026-10-11, Session 5 in `MASTER_IMPLEMENTATION_STATUS.md`):** fixed a lock-out of whole onion relays by invalid requests (ST-056), upload-slot exhaustion (ST-057), non-retried transient failures in file transfer (ST-055), silent purge of live groups' home logs (ST-058), and made a lost home relay visible with a successor-group path (ST-052). **The release gates are unchanged and not met:** the physical-device matrix (ST-001/028), independent review (ST-005), push (ST-017), signed reproducible release (ST-014), chunked uploads (ST-046), group UI (ST-048) and a clean, repeated Tor CI record are all still open, so Cipher is **not** private-beta-ready. Tor CI after the pass: 11 of 12 repetitions green, one phase-timeout hang (Session 5); in Session 6 a further 12 of 15 (80 %), the three failures being Tor-side (corrupt directory data at bootstrap, a hidden-service descriptor fetch that never completed) and one test poll — a clean, repeated Tor record does **not** exist yet (ST-055/ST-060).

## Classification as of 2026-10-28 (Session 8; supersedes the table above where they differ)

| Level | Verdict | Gate evidence / what blocks it |
| --- | --- | --- |
| Development | **YES** | `ci` 7/7 green on 40698655145 (Rust + PostgreSQL, audit, secrets, invariants, Android unit/ktlint/lint/release+AAB, 62 instrumented tests, two-relay emulator E2E). |
| Experimental self-hosting | **YES** for technical operators | Docker Compose relay, backup/restore, upgrade/rollback tested in CI (`self-hosting acceptance`); onion relay tested over live Tor. Operators must read `KNOWN_LIMITATIONS.md`. |
| Internal testing (the team, on devices it controls) | **YES, with an unsigned developer build** | CI uploads an unsigned APK/AAB with hashes; sideload only. Testers must be told it is experimental. |
| Private beta (invited outsiders) | **NO** | Open: physical-device matrix (ST-028), no push/background delivery (ST-017/042), no signed release or key plan, no licence, informed-tester process, independent review for any claim beyond "experimental". |
| Public beta | **NO** | Plus: independent audit (ST-005), signed reproducible release, store/legal review (privacy policy and terms are drafts), group-recovery and notification gaps. |
| Production | **NO** | Plus soak/load/incident evidence, audited protocols. |

Gates that remain **external** and cannot be closed from this repository: physical Android devices (StrongBox/TEE/OEM/Doze), an independent security review, a signing key and its custody plan, a licence decision, a push distributor, legal review of the privacy policy/terms, store accounts.
Tor evidence: 20 of 20 consecutive indexed `android-tor` samples green on one commit (38208859706), emulator + host Tor; this is not a failure-rate guarantee.

Passing tests are evidence about the behaviours they test. They are not proof of security or anonymity.

## v0.1.0-alpha candidate (2026-10-28)

**Label: Experimental Alpha — Not Independently Audited. No official signed release exists yet** (the permanent key has not been created). Release notes: `RELEASE_NOTES_v0.1.0-alpha.md`; signing: `RELEASE_SIGNING.md`.

| Item | Status | Evidence |
| --- | --- | --- |
| Signing pipeline (`generate-release-key.sh`, `build-signed-release.sh`) | **Verified with a throwaway key only** | Local run: APK v3-signed, one signer, AAB signed by the same certificate, manifest gate passed, `sha256sum -c` OK, a wrong `CIPHER_RELEASE_PINNED_SHA256` is refused, a missing key prints the commands and builds nothing (exit 2). CI job `release pipeline (throwaway test key)` green in `ci` 40718141378. |
| Signature by the permanent key | **NOT DONE** | The key does not exist; the owner must run `scripts/generate-release-key.sh` and `scripts/build-signed-release.sh`. |
| APK contents (test-signed build) | Checked | `app.cipher.messenger`, versionName 0.1.0-alpha, versionCode 100, `arm64-v8a` + `x86_64`, `libcipher_ffi.so` in both, not debuggable, manifest gate: only the launcher activity exported, no test CA, no debug-route strings. |
| CI on `c226aaf` | **8/8 green** | `ci` 40718141378: audit, secret scan, Rust+PostgreSQL, release pipeline, invariants, Android unit/ktlint/lint/build, instrumented tests (emulator), two-relay E2E. Per-job test counts were not re-extracted for this run. |
| Tor | Unchanged | `android-tor` did not run on `c226aaf` (workflow path filter); last green run 40711101969 on `fdf3e63`. Emulator + host Tor only; no real phone, no Orbot. Stall mitigations (bounded deadlines/time budget) were already in place and were not changed. |
| Push / background notifications | **NOT IMPLEMENTED** | Needs RFC 8291 Web Push encryption through a reviewed library, an SSRF-safe relay notifier, an endpoint-possession challenge, a UnifiedPush distributor and a physical device to test (ST-017/042). Not faked. |
| Installation of the signed APK | **NOT TESTED** | Release builds refuse a software keystore, so an emulator cannot run them; no physical device. |
| Update compatibility, data migration | NOT TESTED | No signed predecessor exists; versionCode drops from 300 (internal unsigned 0.3.0) to 100 by design. |
| Physical devices, independent review | **OPEN** | ST-028, ST-005. |

Next owner actions: create the key (`bash scripts/generate-release-key.sh`), back it up, run `bash scripts/build-signed-release.sh`, fill the fingerprint/checksums into the release notes, then approve creating the GitHub pre-release. Nothing has been merged to `main` or published.

## 1. Build instructions (Rust, relay)
`rustup` honours `rust-toolchain.toml` (1.99.0). `cargo build --locked --release -p cipher-relay`. Container: `docker build -f deploy/Dockerfile.relay -t cipher-relay:local .` (base images are tags, **not** digests — pin digests before publishing an image).
Reproducibility of the relay/container was **not measured**. The Android APK was reproducible once on one host (see `FINAL_SECURITY_REVIEW.md`); not re-checked for this branch; no APK was built in this pass.

## 2. Android
`ANDROID_SECURITY.md`, `DEVICE_TEST_CHECKLIST.md`. Release builds are unsigned unless `CIPHER_RELEASE_KEY*` are set in the environment of the signing host (`RELEASE_SIGNING.md`, `scripts/sign-release.sh`). **Do not publish an APK as suitable for sensitive use** before ST-001/005/028 are closed. The Kotlin side (`PinnedTls.kt`, `RelayAddress.kt`, UI) builds and its JVM/ktlint/lint tests pass in GitHub CI; the 46-test instrumented suite (0 failed, 2 skipped) and the two-relay E2E (14/14) pass on a GitHub emulator (run 38077466094).

## 3. SBOM and dependency audit
`python3 scripts/gen_sbom.py -o sbom.cdx.json` (CycloneDX 1.5; 397 Rust + 575 Android components; hashes from `Cargo.lock` and Gradle verification metadata; reproducible). Licence checks cover Rust only (`cargo deny`). `cargo audit` passes with exceptions listed and justified in `.cargo/audit.toml` (RUSTSEC-2026-0173, -0330, -0331 — ST-045).

## 4. CI gates
`ci.yml`: fmt, clippy `-D warnings`, full tests with PostgreSQL, invariants registry, relay dependency guard, `cargo deny`, `cargo audit`, SBOM determinism, secret scan, Android build/lint. `fuzz.yml`: 14 targets (`home_log` added; no campaign run). `deploy-test.yml` (weekly/manual): Docker acceptance + upgrade — **ran green on GitHub for `84448b1`.** On `84448b1` rust, audit, secrets, invariants, android unit/lint/build and `deploy-test` passed on GitHub; the emulator jobs initially failed (corrupt system image, missing Gradle checksum, build-script bug), were fixed, and all jobs are green on runs 38077466094 and (with resilience phases and Tor) 38090565452 / 38090565453.

## 5. Server compatibility and version policy
* Wire protocol: JSON, additive fields only (`#[serde(default)]`), unknown fields rejected on requests. Cards carry `v`; unknown `v` is refused.
* Relay migrations are forward-only and checksummed; a relay refuses a database newer than itself. **Rollback = restore the pre-upgrade backup** (`SELF_HOSTING.md`).
* Tested pairs: previous `main` client ↔ this relay (`test-upgrade.py`). Newer client ↔ older relay: **not supported** (new endpoints `/v1/intro/*`, `/v1/blobs/by-cap` would be absent; cross-relay features fail closed with an error).
* Client and relay that predate multi-relay interpret `DeliveryCap` without `relay` as "your relay"; new clients always send `relay` when they know it.

## 6. Upgrade and migration
`SELF_HOSTING.md` (upgrade, rollback). Migrations 0007 (`intro` flag) and 0008 (`blobs.cap_hash`) are additive columns with defaults; no data rewrite.

## 7. Security disclosure
`SECURITY.md` (private vulnerability reporting enabled on the repository).

## 8. Remaining blockers before a public beta (ordered)
1. Independent cryptographic and protocol review (ST-005), including the card, capability and outbox-ordering designs.
2. Android UI + onboarding for relay choice, onion pin, cards (ST-048); run the Kotlin tests; physical-device matrix incl. StrongBox/TEE and Orbot (ST-001/028/038/049).
3. Background delivery/push design (ST-017/042) and its metadata disclosure.
4. Cross-relay groups are implemented but experimental (Session 4 in `MASTER_IMPLEMENTATION_STATUS.md`): independent review of the group design and code (ST-005), the member-can-freeze-membership limit (ST-051), home-relay migration (ST-052), tests over real Tor / physical devices / large groups (ST-053); 1:1 key-update commits across relays (ST-044); relay migration (ST-047).
5. Resumable/chunked uploads (ST-046); large-file soak.
6. Signed, reproducible release pipeline with digest-pinned images (ST-014).
7. CI actually green on GitHub for this branch (including `deploy-test.yml`).
