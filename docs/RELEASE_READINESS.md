# Release readiness

**Classification (2026-10-10, branch `feat/self-hosted-multi-relay`):**

| Level | Verdict | Why |
| --- | --- | --- |
| Development-ready | **YES** | Automated suites, fault matrix, two-relay tests, Docker acceptance and upgrade scripts pass on one machine. |
| Self-hosted experimental-ready | **YES, for technical operators who accept the limits below** | Relay can be installed, restarted, backed up, restored and upgraded (tested). Onion relay reachable over live Tor (tested with curl). Operators must understand: unaudited code, no groups across relays, the Android card/pin UI exists but has not been exercised end-to-end (see below). |
| Private beta-ready | **NO** | Card/relay/pin UI is built and unit-tested, and the emulator two-relay E2E passes 14/14 on a GitHub runner (one run, software Keystore, no Tor); pinned TLS is JVM-tested only, never against an onion relay from the app; nothing has run on a physical device (ST-028); Orbot untested. |
| Public beta-ready | **NO** | Plus: no independent cryptographic review (ST-005), no signed/reproducible release, no push notifications, no background delivery, no key-update commits or groups across relays. |
| Production-ready | **NO** | Everything above, plus long-run soak, load, HA, and incident process evidence. |

Passing tests are evidence about the behaviours they test. They are not proof of security or anonymity.

## 1. Build instructions (Rust, relay)
`rustup` honours `rust-toolchain.toml` (1.99.0). `cargo build --locked --release -p cipher-relay`. Container: `docker build -f deploy/Dockerfile.relay -t cipher-relay:local .` (base images are tags, **not** digests — pin digests before publishing an image).
Reproducibility of the relay/container was **not measured**. The Android APK was reproducible once on one host (see `FINAL_SECURITY_REVIEW.md`); not re-checked for this branch; no APK was built in this pass.

## 2. Android
`ANDROID_SECURITY.md`, `DEVICE_TEST_CHECKLIST.md`. Release builds are unsigned unless `CIPHER_RELEASE_KEY*` are set in the environment of the signing host (`RELEASE_SIGNING.md`, `scripts/sign-release.sh`). **Do not publish an APK as suitable for sensitive use** before ST-001/005/028 are closed. The Kotlin side (`PinnedTls.kt`, `RelayAddress.kt`, UI) builds and its JVM/ktlint/lint tests pass in GitHub CI; the 46-test instrumented suite (0 failed, 2 skipped) and the two-relay E2E (14/14) pass on a GitHub emulator (run 38077466094).

## 3. SBOM and dependency audit
`python3 scripts/gen_sbom.py -o sbom.cdx.json` (CycloneDX 1.5; 397 Rust + 575 Android components; hashes from `Cargo.lock` and Gradle verification metadata; reproducible). Licence checks cover Rust only (`cargo deny`). `cargo audit` passes with exceptions listed and justified in `.cargo/audit.toml` (RUSTSEC-2026-0173, -0330, -0331 — ST-045).

## 4. CI gates
`ci.yml`: fmt, clippy `-D warnings`, full tests with PostgreSQL, invariants registry, relay dependency guard, `cargo deny`, `cargo audit`, SBOM determinism, secret scan, Android build/lint. `fuzz.yml`: 13 targets. `deploy-test.yml` (weekly/manual): Docker acceptance + upgrade — **ran green on GitHub for `84448b1`.** On `84448b1` rust, audit, secrets, invariants, android unit/lint/build and `deploy-test` passed on GitHub; the emulator jobs initially failed (corrupt system image, missing Gradle checksum, build-script bug), were fixed, and **all jobs are green on run 38077466094**.

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
4. Cross-relay commit ordering (ST-044) → key updates and groups; relay migration (ST-047).
5. Resumable/chunked uploads (ST-046); large-file soak.
6. Signed, reproducible release pipeline with digest-pinned images (ST-014).
7. CI actually green on GitHub for this branch (including `deploy-test.yml`).
