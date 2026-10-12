# External handoff and execution status

Cipher is **not private-beta-ready** until these are done. They need hardware, keys, infrastructure, an independent mind, or a product decision. Source of truth for each item: `SECURITY_TODO.md`.

**2026-10-12 execution:** the owner selected UnifiedPush and user-held account-control recovery with signed device addition/revocation. The concrete designs, upload protocol proposal, pin rotation ceremony and release/campaign procedures are in [EXTERNAL_IMPLEMENTATION_PLAN.md](EXTERNAL_IMPLEMENTATION_PLAN.md). Android unit tests, ktlint, lint and compilation of the four new group-replacement Compose tests pass locally. Two campaign-summary regression tests pass. Physical devices, distributor access, operator pins, owner signing material and an independent reviewer are unavailable. No item is closed on the strength of a design, compiled UI test or queued campaign. Campaign IDs and completed build evidence are recorded below as they become available.

| # | Item | Why the coding agent cannot do it | What "done" looks like |
|---|---|---|---|
| 1 | **Physical-device matrix (ST-001, ST-028)** | No physical device; everything ran on emulators with a software Keystore | Pixel + one other OEM, hardware-backed Keystore/StrongBox, biometric prompt, lock/background behaviour, FLAG_SECURE, backup/device-transfer attempts, airplane-mode and handover, results recorded per device and Android version |
| 2 | **Orbot / Tor on a device (part of ST-028)** | Only a host `tor` process in CI | Messages and attachments over Orbot and an embedded Tor on a device, over mobile data and Wi-Fi, long idle, battery optimisation on |
| 3 | **Independent cryptographic and protocol review (ST-005)** | The agent wrote the code; it is not an independent reviewer | A written review of the MLS compositions, the cross-relay group design (`CROSS_RELAY_GROUPS.md`), the contact-card/capability protocol, and the signed-request scheme; findings fixed and re-tested |
| 4 | **Fuzz campaign with triage (ST-005)** | Long runs can now execute in GitHub CI; logs, corpus and crashes are retained on every outcome; completion and triage still require evidence | Several hours per target with sanitizers, a persisted corpus, every crash triaged |
| 5 | **Signed, reproducible release (ST-014)** | Needs the signing key and release process | Release keystore held by the owner, reproducible build, SBOM, signed APK/AAB, checksum published, verification instructions |
| 6 | **Push notifications (ST-017)** | UnifiedPush selected; encrypted constant-wake design prepared; no distributor infrastructure or integration exists | UnifiedPush with a constant decrypted message-wake payload, registration review, threat model updated before implementation |
| 7 | **Account authentication, recovery, device revocation (ST-010)** | Owner selected user-held recovery; versioned design prepared; protocol review, implementation and migration remain | A written design, then implementation and tests |
| 8 | **Metadata reduction step (ST-009)** | First versioned capability-envelope proposal prepared; wire implementation and review remain | Sender-free capability delivery with reduced application framing; threat model updated |
| 9 | **Pinning strategy with the relay operator (ST-002)** | Needs the operator's pin and a backup pin | Documented pin set and rotation procedure |
| 10 | **Chunked / resumable upload (rest of ST-046)** | Offset/quota/replay/crash-accounting proposal prepared; independent review and implementation remain | Staged upload endpoints with offsets, quotas and replay protection, resume after a cut, tests |
| 11 | **Tor failure rate, measured after ST-060** | Workflow now schedules 20 indexed samples on one commit; completion and failure-cause triage remain | At least 20 consecutive `android-tor` repetitions with recorded failures and causes |
| 12 | **UI tests and a real-device pass for the new group-replacement screen (ST-048)** | Four Compose tests written and compiled; duplicate in-flight creation guarded; execution/manual device pass remain | A passing Compose suite and a manual pass |

Notes for the reviewer: the diagnostics line format is in `OkHttpCallbacks.kt` (`NetDiag`) and `SafeLog.net`; the relay's idempotent-upload invariant is `MR-016`; the open Tor causes are in `MASTER_IMPLEMENTATION_STATUS.md` Session 6.
