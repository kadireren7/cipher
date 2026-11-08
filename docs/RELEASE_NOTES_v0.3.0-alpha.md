# Cipher v0.3.0-alpha — EXPERIMENTAL ALPHA, NOT INDEPENDENTLY AUDITED

**Do not use Cipher for sensitive or high-risk communication.** Its cryptography and protocols have not been independently audited (ST-005). Cipher protects message *content* with end-to-end encryption. It does **not** make you anonymous, and it is not safe against a well-resourced adversary. Read [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) before installing.

**This replaces `v0.2.0-alpha`, whose built-in Tor could not connect on the first phone it was tried on** (stuck at "Connecting to Tor… 0%"). The likely cause is ISP filtering of plain Tor connections; this version can connect through bridges that hide Tor. It is signed with the same key, so it installs over `v0.2.0-alpha` without uninstalling.

## What is new

* **Works on networks that block Tor.** Built-in obfs4, snowflake and webtunnel support (IPtProxy, the transport helpers Orbot uses; they run only inside Cipher's separate Tor process). Tor Browser's public default bridges are built in; your own bridge lines from bridges.torproject.org (with or without the leading `Bridge `) are accepted too.
* **Automatic connection (default).** Cipher tries a direct Tor connection first; if it makes no real progress within 40 s, it switches to the built-in bridges by itself and remembers that for the next start.
* **Easier first launch.** If Tor cannot connect during setup, the screen now offers the connection choice (Automatic / Direct / Built-in bridges / My own bridges) next to "Try again"; before, bridges could only be set after setup. Setup waits up to 5 minutes.
* **Honest progress.** "Starting Tor…" and "(through a bridge)" instead of a 0% that looked stuck.

## What has NOT been done

* **This version has not yet run on a physical phone.** The fix was verified on an emulator over the real Tor network, including a simulated block (only the snowflake CDN reachable): Automatic switched to the bridges at 45 s and connected. Results of the next phone run will be published.
* **No independent security audit.**
* **No push notifications / no background delivery.** Messages wait on the relay until you open the app.
* **No default relay.** You need a relay you or someone you trust runs ([SELF_HOSTING.md](SELF_HOSTING.md)), plus an invitation from it.
* The signing key has **no backup**: the owner explicitly waived it.

## Known issues

* The APK is larger (about 88 MB): the transport helpers add about 25 MB of native code per ABI.
* A snowflake connection can take a few minutes on a bad network; obfs4 bridges may be blocked on some networks.
* Bridges hide that the traffic is Tor, not that the phone talks to a bridge or a CDN (ST-043).
* The Tor SOCKS port is loopback-only but reachable by other apps on the same phone (ST-064).
* The issues listed for `v0.2.0-alpha` that are not mentioned here still apply.

## Licences

**Cipher is now licensed under GPL-3.0-only** ([LICENSE](../LICENSE)); earlier versions had no licence. The source of this release is the tagged commit in this repository. The APK contains lyrebird (GPL-3.0) inside IPtProxy (MIT), snowflake (BSD-3-Clause) and tor-android (BSD-3-Clause). See [LICENSE_DECISION.md](LICENSE_DECISION.md).

## Files, verification and install

The assets are the APK, `SHA256SUMS` and `SIGNING-CERT.txt`. The signing certificate SHA-256 is unchanged: **`3e9685ecd673eee2b86fdab25b842d8fb4d2706074f5135c3556bb639b4726fc`**.

```bash
sha256sum -c --ignore-missing SHA256SUMS
apksigner verify --print-certs cipher-0.3.0-alpha-release.apk   # the signer SHA-256 must equal the fingerprint above
```

A checksum downloaded from the same place as the APK only detects corruption; the fingerprint is only meaningful if you got it from a second channel. Requirements: Android 11 (API 30) or newer, `arm64-v8a` or `x86_64`, a lock screen and a hardware-backed Keystore. Sideload only; not on Google Play.

**If it does not connect:** Settings → Network (or the setup screen) → *Built-in bridges*. If those are blocked too, get bridges from bridges.torproject.org and choose *My own bridges*.

Report security issues privately: [SECURITY.md](../SECURITY.md).
