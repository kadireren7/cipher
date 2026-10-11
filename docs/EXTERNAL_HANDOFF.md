# Work that cannot be completed by the coding agent (hand-off for an independent party)

Cipher is **not private-beta-ready** until these are done. They need hardware, keys, infrastructure, an independent mind, or a product decision. Source of truth for each item: `SECURITY_TODO.md`.

| # | Item | Why the coding agent cannot do it | What "done" looks like |
|---|---|---|---|
| 1 | **Physical-device matrix (ST-001, ST-028)** | No physical device; everything ran on emulators with a software Keystore | Pixel + one other OEM, hardware-backed Keystore/StrongBox, biometric prompt, lock/background behaviour, FLAG_SECURE, backup/device-transfer attempts, airplane-mode and handover, results recorded per device and Android version |
| 2 | **Orbot / Tor on a device (part of ST-028)** | Only a host `tor` process in CI | Messages and attachments over Orbot and an embedded Tor on a device, over mobile data and Wi-Fi, long idle, battery optimisation on |
| 3 | **Independent cryptographic and protocol review (ST-005)** | The agent wrote the code; it is not an independent reviewer | A written review of the MLS compositions, the cross-relay group design (`CROSS_RELAY_GROUPS.md`), the contact-card/capability protocol, and the signed-request scheme; findings fixed and re-tested |
| 4 | **Fuzz campaign with triage (ST-005)** | A campaign needs hours and a person to triage; `fuzz.yml` now accepts `seconds` and keeps crash inputs, but no long run has been analysed | Several hours per target with sanitizers, a persisted corpus, every crash triaged |
| 5 | **Signed, reproducible release (ST-014)** | Needs the signing key and release process | Release keystore held by the owner, reproducible build, SBOM, signed APK/AAB, checksum published, verification instructions |
| 6 | **Push notifications (ST-017)** | Needs a push provider account and server infrastructure, and a privacy decision first | FCM or UnifiedPush with a constant payload, threat model updated before implementation |
| 7 | **Account authentication, recovery, device revocation (ST-010)** | Product decision (users will lose phones) | A written design, then implementation and tests |
| 8 | **Metadata reduction step (ST-009)** | Depends on 6 and a protocol decision | Sealed-sender-style delivery tokens, threat model updated |
| 9 | **Pinning strategy with the relay operator (ST-002)** | Needs the operator's pin and a backup pin | Documented pin set and rotation procedure |
| 10 | **Chunked / resumable upload (rest of ST-046)** | Protocol design with security review; see below | Staged upload endpoints with offsets, quotas and replay protection, resume after a cut, tests |
| 11 | **Tor failure rate, measured after ST-060** | Needs many CI repetitions over time | At least 20 consecutive `android-tor` repetitions with recorded failures and causes |
| 12 | **UI tests and a real-device pass for the new group-replacement screen (ST-048)** | No device; no Compose UI test written | A Compose test and a manual pass |

Notes for the reviewer: the diagnostics line format is in `OkHttpCallbacks.kt` (`NetDiag`) and `SafeLog.net`; the relay's idempotent-upload invariant is `MR-016`; the open Tor causes are in `MASTER_IMPLEMENTATION_STATUS.md` Session 6.
