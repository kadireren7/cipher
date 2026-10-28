# Cipher v0.1.0-alpha — EXPERIMENTAL ALPHA, NOT INDEPENDENTLY AUDITED

**Do not use Cipher for sensitive or high-risk communication.** Its cryptography and protocols have not been independently audited (ST-005), and it has never run on a physical phone (ST-028): every test so far ran on emulators and in CI. Cipher protects message *content* with end-to-end encryption. It does **not** make you anonymous, and it is not safe against a well-resourced adversary. Read [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) before installing.

> **Release status of this document: DRAFT for a release that has not been published.** The signed APK/AAB below exist only after the owner creates the signing key and runs `scripts/build-signed-release.sh` ([RELEASE_SIGNING.md](RELEASE_SIGNING.md)). Fill in the fingerprint and checksums from `release-artifacts/` at that point; do not publish this file with the placeholders.

## What it is

An Android messenger with user-selected, self-hosted relays.

* End-to-end encrypted 1:1 chats and groups (MLS via OpenMLS, X25519/Ed25519 suite), including groups whose members use different relays (experimental).
* Text, images, video, PDF, audio, voice notes and arbitrary files, encrypted before upload; delivery states (sending, sent, delivered, failed), retry and cancel of uploads.
* Contact invitations by QR code or shareable card; contact identity verification with a changed-identity warning.
* Offline sending (queued, encrypted) and exactly-once delivery across restarts and relay outages (tested in the two-relay emulator end-to-end).
* Tor/onion relay routes with strict TLS pinning and fail-closed behaviour: if the privacy route is unavailable, messages stay queued and are never sent another way.
* Local encrypted storage with an Android Keystore-protected vault; no cloud backup.
* In-conversation search (in memory only), light/dark themes, large-font support.

## Requirements

| | |
| --- | --- |
| Android | 11 (API 30) or newer |
| CPU | `arm64-v8a` (virtually all current phones) or `x86_64` (emulators/Chromebooks). **No 32-bit ARM build.** |
| Keystore | Release builds refuse a software-only keystore, so they will not run on emulators. A device with a hardware-backed Keystore is required. |
| Relay | You need a Cipher relay you or someone you trust runs ([SELF_HOSTING.md](SELF_HOSTING.md)). There is no default server. |
| Installing | Sideloading ("install unknown apps"). Not on Google Play. |

## Files

| File | Purpose |
| --- | --- |
| `cipher-0.1.0-alpha-release.apk` | Install this. Signed with APK Signature Scheme v3. |
| `cipher-0.1.0-alpha-release.aab` | Android App Bundle for a future Play submission; not for sideloading. |
| `SHA256SUMS` | `sha256sum -c SHA256SUMS` |
| `SIGNING-CERT.txt` | The public signing-certificate SHA-256: **`<fill in from SIGNING-CERT.txt>`** |

Verify before installing:

```bash
sha256sum -c SHA256SUMS
apksigner verify --print-certs cipher-0.1.0-alpha-release.apk   # the signer SHA-256 must equal the fingerprint above
```

A checksum downloaded from the same place as the APK only detects corruption. The fingerprint is only meaningful if you obtained it from a second, independent channel.

## Install

1. Verify the files (above), copy the APK to the phone, open it, allow installing from that source when Android asks.
2. Open Cipher, read the experimental notice, create the vault (a lock screen and biometrics or a device credential are required).
3. Add your relay (https URL, or an onion address with its pin) and register with the relay's invite token.
4. Add a contact: show your QR code or card, scan theirs, then compare the safety number (or scan their code) in person or on a channel you trust and mark the contact verified.

## Run your own relay

[SELF_HOSTING.md](SELF_HOSTING.md) covers Docker Compose with PostgreSQL, TLS, onion service, backup/restore and upgrade/rollback. These were exercised in CI (`self-hosting acceptance`) and over live Tor; they have not been load-, soak- or HA-tested.

## Privacy and security limitations (summary; the full list is in KNOWN_LIMITATIONS.md)

* Not independently audited; no physical-device validation; sensitive or high-risk use is not recommended.
* Relays see who a message is addressed to, when, and its padded size. Network observers see that you use Cipher (and that you use Tor, if you do). Tor hides addresses, not timing correlation.
* No account recovery, no multi-device, no key backup: losing the phone or uninstalling the app loses the identity and all messages.
* Cross-relay groups are experimental: a member can freeze membership changes; if the creator's relay is lost the group must be recreated.
* No background notifications (see below).

## Known issues

* **No notifications while the app is closed or locked.** No push provider (UnifiedPush/FCM) is integrated or tested ([NOTIFICATIONS.md](NOTIFICATIONS.md), [PUSH_DESIGN.md](PUSH_DESIGN.md)). Messages wait on the relay until you open the app. The app polls only while it is visible.
* Tor: stalled circuits show as "offline" and are retried within bounded time budgets. A 20/20 CI campaign on one commit and 11/12, 12/15 earlier runs show it works most of the time in an emulator with a host Tor client; that is not a failure-rate guarantee, and real phones, Orbot and mobile networks are untested.
* No resumable uploads: a failed large upload restarts; an abandoned one leaves an expiring ciphertext blob on the relay.
* Only in-conversation search; no cross-conversation search.
* The PDF attachment preview shows a generic icon, not a rendered page.
* Pre-release builds can change or break between versions; data migration is not guaranteed.

## Updating

Install a newer APK over the old one. This works only if it is signed with the **same key** and has the same application ID (`app.cipher.messenger`) and a higher `versionCode`. Never uninstall to update: that deletes the vault and every message, with no recovery. Developer/internal builds of `0.3.0-experimental.1` (unsigned, versionCode 300) cannot be updated by this release; uninstall them first. Debug builds use a different application ID and coexist with a release install.

## Device testing and what is still open

The physical-device matrix is in [DEVICE_TEST_CHECKLIST.md](DEVICE_TEST_CHECKLIST.md) and has **not** been run. Readiness and the open items (ST-001, ST-005, ST-017/042, ST-028, ST-038) are in [RELEASE_READINESS.md](RELEASE_READINESS.md).

Report security issues privately: [SECURITY.md](../SECURITY.md).
