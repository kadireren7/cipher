# Cipher v0.2.0-alpha — EXPERIMENTAL ALPHA, NOT INDEPENDENTLY AUDITED

**Do not use Cipher for sensitive or high-risk communication.** Its cryptography and protocols have not been independently audited (ST-005), and it has **never run on a physical phone** (ST-028): every test so far ran on emulators and in CI. Cipher protects message *content* with end-to-end encryption. It does **not** make you anonymous, and it is not safe against a well-resourced adversary. Read [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) before installing.

**This replaces `v0.1.0-alpha`, which closes right after onboarding** (missing `ACCESS_NETWORK_STATE`; fixed here, with a regression guard in CI). It is signed with the same key, so it installs over `v0.1.0-alpha` without uninstalling.

## What is new

* **Built-in Tor.** The app starts its own Tor (tor-android 0.4.9.14 from Maven Central, signature-verified, in a separate process) and reaches relays only through it. **Orbot is no longer needed.** If Tor is not ready, messages stay queued; there is no direct route and no silent fallback. Details: [EMBEDDED_TOR.md](EMBEDDED_TOR.md).
* **Private invitations.** Expiring, revocable, unguessable invitation links and QR codes for groups; a join request is sealed and signed, and by default an admin must approve it. Approved people join through the normal MLS Add and cannot read earlier messages. Create, revoke, approve and reject screens, and joining with a link. Details and limits: [INVITATIONS.md](INVITATIONS.md).
* **New look.** A near-black design with one steel-blue accent, a new logo and launcher icon, dark and light themes, large-font support. Simpler first launch.
* **Relay administration** (for people who run a relay; off by default): a loopback-only listener with its own secret, coarse identifier-free statistics, a registration switch and a tamper-evident audit log. [RELAY_ADMIN.md](RELAY_ADMIN.md). Operator privacy: [OPERATOR_PRIVACY.md](OPERATOR_PRIVACY.md).
* Onboarding resumes correctly if the app is closed right after your identity is created.

## What has NOT been done

* **No physical-device testing.** A release build refuses a software-only Keystore, so it will not run on an emulator; it needs a phone with a hardware-backed Keystore. The first physical-device run is planned right after this release and its results will be published as they come.
* **No independent security audit.**
* **No push notifications / no background delivery.** Messages wait on the relay until you open the app.
* **No default relay.** You need a relay you or someone you trust runs ([SELF_HOSTING.md](SELF_HOSTING.md)); relay addresses are onion services or https with a pinned certificate.
* Community rooms are design only ([COMMUNITY_ROOMS.md](COMMUNITY_ROOMS.md)); nothing of them is in the app.
* The signing key has **no backup**: the owner explicitly waived it. If the key or its password is lost, no later release can be installed over this one.

## Known issues

* Tor reliability in CI over a host Tor client: 27 of 30 repetitions passed on one commit (90%); failures were an infrastructure Tor bootstrap and the relay-outage attachment scenario. The built-in Tor was verified on an emulator against a real onion relay, not on a phone.
* If a relay silently drops the message that admits a person to a group, that person stays outside and the admin is not told (INV-014).
* The Tor SOCKS port is loopback-only but reachable by other apps on the same phone, which can borrow the circuit (they cannot read your traffic) (ST-064).
* No resumable uploads; only in-conversation search; PDF previews are a generic icon.
* Pre-release builds can change or break between versions; data migration is not guaranteed.

## Files, verification and install

The assets are the APK, `SHA256SUMS` and `SIGNING-CERT.txt`. The signing certificate SHA-256 is unchanged from `v0.1.0-alpha`: **`3e9685ecd673eee2b86fdab25b842d8fb4d2706074f5135c3556bb639b4726fc`**.

```bash
sha256sum -c --ignore-missing SHA256SUMS
apksigner verify --print-certs cipher-0.2.0-alpha-release.apk   # the signer SHA-256 must equal the fingerprint above
```

A checksum downloaded from the same place as the APK only detects corruption; the fingerprint is only meaningful if you got it from a second channel. Requirements: Android 11 (API 30) or newer, `arm64-v8a` or `x86_64`, a lock screen and a hardware-backed Keystore. Sideload only; not on Google Play.

Report security issues privately: [SECURITY.md](../SECURITY.md).
