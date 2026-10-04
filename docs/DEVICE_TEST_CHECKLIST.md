# Physical-device test checklist (ST-001, ST-028) — NOT YET PERFORMED

Status of this checklist: **no physical Android device was available** (`adb devices` empty on the build host; only an API 34 x86_64 emulator with a *software* Keystore has ever been used). Every box is open. Do not report Keystore/biometric behaviour as verified until each is ticked with a device model, Android version and date.

For each device record: model, OS/security patch level, StrongBox yes/no, biometric hardware, OEM skin.

## A. Keystore protection level (release APK)
- [ ] First run reports `STRONGBOX` (Pixel 3+/recent Samsung) or `TEE`; **release build refuses** a `SOFTWARE_OR_UNKNOWN` device (use a device without TEE, if any, or verify the refusal text).
- [ ] `KeyInfo.isInsideSecureHardware` and attestation chain read back via the debug diagnostics match the displayed level.
- [ ] StrongBox unavailable → falls back to TEE with an honest label (never silently to software).

## B. Authentication
- [ ] Biometric class-3 prompt per unlock; wrong finger ×N → rate limiting event; cancel → vault stays locked.
- [ ] PIN-only device (no biometrics): onboarding and unlock work; Argon2id 64 MiB timing and peak RSS recorded (ST-003) on a low-end (≤3 GB) device.
- [ ] Enrol a new fingerprint → key invalidated → app says so, **does not wipe**, requires explicit reset; old vault unreadable.
- [ ] Remove the lock screen → key invalidated (setUnlockedDeviceRequired / auth-bound) → same behaviour.
- [ ] Change the lock-screen PIN → record behaviour.

## C. Lifecycle and screen protection
- [ ] Background → locks within the configured timeout; app switcher shows nothing; `FLAG_SECURE` blocks screenshots and screen recording (incl. dialogs, keyboard overlay, notifications shade content).
- [ ] Device reboot → app locked; first-unlock state (before first unlock after boot) cannot decrypt anything.
- [ ] Screen off during an upload/download → lock request cancels the transfer.
- [ ] Process kill during commit/removal; relaunch → state consistent (history-revocation process-death cases on hardware).

## D. Storage and extraction
- [ ] `adb backup` / device-to-device transfer / Auto Backup do not include the vault (manifest + attempt).
- [ ] Rooted/dev device: copy `files/` and `databases/`, confirm no plaintext (canary search) and that the copy fails to open elsewhere.
- [ ] Restore an old vault copy on the same device → rollback refused (StorageRolledBack) with the hardware-backed counter.
- [ ] Flash/forensic image of a locked device after first unlock: canary search (limit of the claim: NAND remanence).

## E. Platform/OEM matrix
- [ ] Android 11, 12, 13, 14, 15, 16 at least one each; Pixel, Samsung, Xiaomi/OPPO (aggressive battery managers), a Go-edition device.
- [ ] Background sync/notifications under Doze and OEM task killers (push is not implemented — ST-017 — so record foreground polling behaviour only).
- [ ] TalkBack pass of onboarding, lock, chat list, conversation, verification.

## F. Network
- [ ] Real cellular + Wi-Fi switch during send/receive; captive portal; TLS 1.3 only against a public CA relay; pinning decision (ST-002).

## G. End-to-end on hardware
- [ ] Two physical phones + the real relay: DM, group of three, add/remove member, removal revocation shows "Message unavailable — group access revoked", attachment >3 MiB, voice note, PDF.
- [ ] Canary plaintext hunt on both phones (app data, /sdcard, logcat, bugreport) and on the relay (logs, `pg_dump`).

## H. Privacy route (network-metadata pass) — NOT YET PERFORMED
- [ ] Install Orbot (or an embedded tor); set Cipher's route to its SOCKS endpoint (default `127.0.0.1:9050`); confirm the status shows *Connecting privately* then *Protected* only after a real request completed.
- [ ] Stop Orbot mid-session: status → *Privacy route unavailable*; send messages; confirm they stay queued (`Pending`) and **nothing** reaches the relay (relay-side connection log / counters); restart Orbot: they send once.
- [ ] Capture on the phone's Wi-Fi AP (or a USB-tethered host with `tcpdump`): no DNS query for the relay hostname, no connection to the relay IP; only the first-hop address. Repeat on mobile data with a hotspot capture.
- [ ] Wi-Fi → mobile → Wi-Fi, airplane mode on/off, captive portal: no direct fallback at any moment; queued messages sent after recovery.
- [ ] Measure STANDARD vs ENHANCED on the device: bytes/hour idle (VPN-less capture), battery drain over 1 h foreground, send-time detector (`scripts/analyze-link-trace.py` on a real capture), message latency over real Tor.
- [ ] Record the relay's view through a real exit: source address is the exit's; rate limits behave behind shared exits.
- [ ] Release build only: confirm Settings offers no direct route, and `adb shell run-as` cannot enable one (marker file ignored).

## I. Doze / background
- [ ] With the app backgrounded for 30 min: no network activity from Cipher (it locks and cancels); on resume, queued messages arrive within one tick.
