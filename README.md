<div align="center">

<img src="assets/cipher-banner.svg" alt="Cipher: private by protocol, hostile by assumption" width="100%">

# Cipher

**A private Android messenger built around end-to-end encryption, local encrypted history, revocable group access, and metadata-resistant transport.**

![Rust](https://img.shields.io/badge/core-Rust-b7410e?style=flat-square)
![Android](https://img.shields.io/badge/client-Android%20(Kotlin%2FCompose)-3ddc84?style=flat-square)
![OpenMLS](https://img.shields.io/badge/E2EE-OpenMLS%20(RFC%209420)-5b7bd5?style=flat-square)
![License](https://img.shields.io/badge/license-not%20yet%20selected-lightgrey?style=flat-square)
[![CI](https://github.com/kadireren7/cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/kadireren7/cipher/actions/workflows/ci.yml)
![Status](https://img.shields.io/badge/status-experimental%20%C2%B7%20unaudited-d29922?style=flat-square)

</div>

> **Status: experimental. Not independently audited. Not production-ready.**
> Cipher has run on an Android **emulator** against a real relay and PostgreSQL. It has **never** been run on a physical device, and its Tor/Orbot
> integration has **never** been validated against the live Tor network. Read [What Cipher does not claim](#what-cipher-does-not-claim) before relying on anything here.

## Why Cipher

Cipher assumes the network and the server are hostile.

- Messages are encrypted on the sender's device and decrypted only on authorized recipient devices.
- The relay stores opaque ciphertext and holds no message-decryption keys.
- Network privacy is a **separate layer** from message encryption: if the privacy transport (or every node behind it) is malicious, message plaintext is still protected by the E2EE layer.
- Every security claim is tied to a named adversary in the [threat model](docs/THREAT_MODEL.md) and, where possible, to an automated test (see [security invariants](docs/SECURITY_INVARIANTS.md)).

## Architecture

```mermaid
flowchart TD
    A["Android app (Kotlin / Compose)"] --> B["cipher-ffi (narrow UniFFI bridge)"]
    B --> C["cipher-core: OpenMLS E2EE, vault, history keys"]
    C --> D["Privacy transport: SOCKS5 route, fail closed"]
    D --> E["Tor via local SOCKS5 (intended; NOT yet validated live)"]
    E --> F["cipher-relay (untrusted, ciphertext only)"]
    F --> G[("PostgreSQL")]
    F -. "queued ciphertext" .-> H["Recipient device(s)"]
```

| Component | Role |
| --- | --- |
| [`crates/cipher-core`](crates/cipher-core) | Security core: OpenMLS adapter, group policy, encrypted vault, per-epoch history keys, attachments, delivery capabilities, network profiles. |
| [`crates/cipher-wire`](crates/cipher-wire) | Shared wire types, size limits, request-signing canonicalisation. |
| [`crates/cipher-relay`](crates/cipher-relay) | The **untrusted** delivery relay (axum + PostgreSQL): signed requests, bounded queues, group commit sequencer, anonymous capability delivery. |
| [`crates/cipher-ffi`](crates/cipher-ffi) | Narrow UniFFI boundary: no key or MLS state crosses it; every input validated; panics contained. |
| [`android/`](android) | Kotlin/Compose app, Android Keystore wrapper, OkHttp-based SOCKS route, UI. |
| PostgreSQL | Relay persistence: public keys, queued ciphertext, counters. No plaintext column exists. |
| Privacy transport | A fail-closed SOCKS5 route from the app to the relay. Cipher implements **no** anonymity protocol of its own ([ADR](docs/ADR-PRIVACY-TRANSPORT.md)). |

More: [ARCHITECTURE](docs/ARCHITECTURE.md) · [SECURITY_ARCHITECTURE](docs/SECURITY_ARCHITECTURE.md) · [CRYPTOGRAPHIC_DESIGN](docs/CRYPTOGRAPHIC_DESIGN.md).

## What is implemented

### End-to-end encryption
- OpenMLS (RFC 9420) for 1:1 and group conversations; roles (owner / admin / member) enforced by every **receiver**, not by the relay.
- Authenticated, padded message frames; chunked, encrypted attachments (images, files, PDFs, voice notes).
- Contacts by random Cipher ID or QR code (no phone number, no address-book upload); a changed identity key is never accepted silently.

### Revocable group history
When a compliant Cipher client observes that it has been removed from a group, it deletes that group's locally held history-key material. Retained ciphertext then becomes unavailable to that client, while remaining members keep their authorized history. Removal also rotates the group's secrets and routing capability. Design and tests: [HISTORY_REVOCATION](docs/HISTORY_REVOCATION.md).

**Limitation, stated plainly:** Cipher cannot erase plaintext, screenshots, exports, or key material that was deliberately copied outside Cipher while the member was authorized, and it cannot retroactively revoke anything from a malicious, modified client that preserved keys. Revocation takes effect on a removed member's device only once that device observes the removal.

### Local protection
- Encrypted local history (record-level AEAD under a vault key wrapped by the Android Keystore); StrongBox/TEE preferred, software keystores refused in release builds.
- App lock, rollback detection of the local database, `FLAG_SECURE` screenshot / recording protection where Android permits.
- **Hardware validation on physical devices is not done** ([checklist](docs/DEVICE_TEST_CHECKLIST.md)).

### Metadata resistance
- A privacy-transport seam: every relay request can go through a local **SOCKS5** endpoint (intended: Tor via Orbot). The relay hostname is resolved by the proxy, not by the device.
- **Fail closed, no silent direct fallback:** if the route is down, messages stay queued (encrypted) and nothing is sent another way; a direct route exists only in debug builds.
- **Delivery capabilities:** contacts deliver with random, rotating, revocable capabilities instead of authenticated, device-addressed sends, so the relay sees no sender for those deliveries ([DELIVERY_CAPABILITIES](docs/DELIVERY_CAPABILITIES.md)).
- Padding (1 KiB minimum frame class, Padmé for attachments), optional bounded cover traffic, and `STANDARD` / `ENHANCED` network profiles.
- **Tor/Orbot has not been validated against the live Tor network.** What was measured, and what was not: [PRIVACY_TRANSPORT_REVIEW](docs/PRIVACY_TRANSPORT_REVIEW.md).

## What Cipher does not claim

Cipher does **not** currently claim:

- perfect anonymity, or anonymity of accounts (account and device IDs are stable pseudonyms to the relay);
- resistance to a global passive adversary or to end-to-end timing correlation;
- that an ISP cannot detect use of a privacy network;
- production readiness;
- an independent security audit (none has been done; [ST-005](docs/SECURITY_TODO.md) stays open);
- protection from a compromised, unlocked endpoint (malware, rooted OS, hooking, a camera pointed at the screen);
- deletion of plaintext copied outside Cipher;
- complete traffic-analysis resistance.

## Threat model summary

Full model: [THREAT_MODEL](docs/THREAT_MODEL.md) · network metadata: [NETWORK_PRIVACY_THREAT_MODEL](docs/NETWORK_PRIVACY_THREAT_MODEL.md).

| Adversary | What Cipher aims to provide | Main residual |
| --- | --- | --- |
| Compromised relay | No plaintext or keys; cannot forge receipts or restore removed members | Sees recipients (via capabilities), timing, size classes, group-commit authors |
| Database dump | Ciphertext only; no senders for capability deliveries; no raw IPs | Account-to-device directory, unexpired ciphertext by recipient |
| Object-storage compromise | Attachments are client-side encrypted, padded blobs | Blob size class and timing (blobs currently live in PostgreSQL) |
| Malicious network / MITM | TLS 1.3 only, system trust anchors, no downgrade (tested) | No certificate pinning shipped (operator decision) |
| ISP / mobile operator | With the privacy route: no direct connection to Cipher endpoints, no relay DNS/SNI | Privacy-network use and traffic cadence stay visible; live Tor untested |
| Stolen locked phone | Vault key wrapped by the Keystore; no plaintext API while locked | Emulator-only validation; no StrongBox/TEE device tests |
| Removed group member | No new content; Cipher-held history keys deleted on observing removal | What they already copied; a relay that withholds the removal delays it |
| Replay | Signed, nonce-bound requests; MLS replay protection; tombstones for old Welcomes | |
| Malicious privacy relay | Sees only TLS ciphertext; cannot decrypt Cipher messages | Colluding entry+relay can correlate by timing |

**Endpoint compromise is out of scope for cryptographic protection.** If the unlocked device runs hostile code, the attacker can read what the user can read. Cipher reduces the surface (no keys in the UI layer, hardened windows) but does not claim otherwise.

## Security status

| Area | Status |
| --- | --- |
| Content confidentiality | Strong as tested; **unaudited** |
| Server blindness | Partial (content-blind; sees recipients, timing, sizes, committers) |
| Source-IP privacy | Partial; plumbing verified against a test double, **live Tor not tested** |
| Social-graph resistance | Partial |
| Traffic-analysis resistance | Partial (link-only observer); weak against an observer of both ends |
| Global-observer resistance | Not provided |
| Independent review | Not completed |
| Production readiness | **No** (development: yes; private beta: conditional; public beta / production: no) |

Details and evidence: [FINAL_SECURITY_REVIEW](docs/FINAL_SECURITY_REVIEW.md). Open items: [SECURITY_TODO](docs/SECURITY_TODO.md). What an external reviewer should examine: [EXTERNAL_REVIEW_SCOPE](docs/EXTERNAL_REVIEW_SCOPE.md).

### Verified project numbers

Counted from the repository at the time of the public release (see [PUBLIC_RELEASE_AUDIT](docs/PUBLIC_RELEASE_AUDIT.md)):

| | |
| --- | --- |
| Rust tests | 325 (324 run, 1 ignored measurement), including relay-against-PostgreSQL and FFI boundary tests |
| Android tests | 13 JVM unit tests, 45 instrumented tests (run on an API 34 emulator; two need live-relay arguments) |
| Security / privacy invariants | 65 (38 `SEC`, 10 `REV`, 17 `PRIV`) mapped to 263 tests; **18 fully automated, 46 partial, 1 manual**: the gaps are listed per invariant |
| Fuzz targets | 12 libFuzzer targets; the runs so far were short smoke campaigns (about 5 minutes per target), **not** exhaustive fuzzing |

Passing tests does not prove Cipher secure.

## Build and run (development)

Prerequisites: Rust (pinned by `rust-toolchain.toml`) with the Android targets and `cargo-ndk`, JDK 17, Android SDK (API 36) and NDK 27.2, Docker (PostgreSQL for the relay tests), Python 3, OpenSSL, and `cargo-deny` + `cargo-audit` for the supply-chain gates. `. scripts/android-env.sh` sets the Android environment (override the paths by exporting them first).

**Rust: format, lint, test**

```bash
docker run -d --name cipher-pg -e POSTGRES_PASSWORD=devonly-not-a-secret -p 55432:5432 postgres:17-alpine   # public, throwaway test credential
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked        # relay tests use CIPHER_TEST_DATABASE_URL (defaults to the container above)
```

**Security gates**

```bash
python3 scripts/check_invariants.py && python3 scripts/gen_invariants_doc.py --check
bash scripts/check-relay-deps.sh
python3 scripts/secret_scan.py && python3 scripts/public_release_scan.py
cargo deny check && cargo audit
```

**Relay (development)** with a throwaway test CA. `CIPHER_RELAY_AUDIENCE` is the relay's `host[:port]` as clients dial it (`10.0.2.2` is how the emulator reaches the host). All settings: [`.env.example`](.env.example).

```bash
bash scripts/make-test-ca.sh                     # throwaway CA + relay certificate under android/build/test-ca/ (git-ignored)
CIPHER_RELAY_AUDIENCE=10.0.2.2:8443 \
CIPHER_RELAY_REGISTRATION_TOKEN="$(openssl rand -base64 36)" \
CIPHER_RELAY_DATABASE_URL=postgres://postgres:devonly-not-a-secret@127.0.0.1:55432/postgres \
CIPHER_RELAY_PEPPER="$(openssl rand -base64 36)" \
CIPHER_RELAY_LISTEN=0.0.0.0:8443 CIPHER_RELAY_TLS_CERT=android/build/test-ca/relay-chain.pem \
CIPHER_RELAY_TLS_KEY=android/build/test-ca/relay.key cargo run --release -p cipher-relay
```

**Android: build and test** (the Gradle build cross-compiles the Rust core with `cargo-ndk`)

```bash
cd android
./gradlew :app:testDebugUnitTest :app:ktlintCheck :app:lintDebug :app:assembleDebug
./gradlew :app:assembleRelease                   # minified; refuses software Keystore; no relay baked in
./gradlew :app:connectedDebugAndroidTest         # needs an emulator or device; see scripts/ci-emulator-tests.sh
cd .. && bash scripts/check-release-apk.sh && bash scripts/analyze-release-apk.sh
```

The debug app trusts only the throwaway test CA; release builds trust system roots only. To exercise the privacy route without Tor use the development SOCKS5 **test double** [`scripts/dev-socks-proxy.py`](scripts/dev-socks-proxy.py) (it is not an anonymity system).

## Documentation

Start at the [documentation index](docs/README.md). Most useful first reads:

| | |
| --- | --- |
| [FINAL_SECURITY_REVIEW](docs/FINAL_SECURITY_REVIEW.md) | Findings, fixes, open risks, readiness verdicts |
| [NETWORK_PRIVACY_THREAT_MODEL](docs/NETWORK_PRIVACY_THREAT_MODEL.md) · [PRIVACY_TRANSPORT_REVIEW](docs/PRIVACY_TRANSPORT_REVIEW.md) | Network-metadata adversaries, measurements, collusion analysis |
| [HISTORY_REVOCATION](docs/HISTORY_REVOCATION.md) | How removed members lose Cipher-controlled access to history |
| [METADATA_MODEL](docs/METADATA_MODEL.md) | Exactly what each party can observe |
| [EXTERNAL_REVIEW_SCOPE](docs/EXTERNAL_REVIEW_SCOPE.md) · [SECURITY_TODO](docs/SECURITY_TODO.md) | What still needs independent review; every open item |

## Reporting a vulnerability

Please **do not** open a public issue for an exploitable vulnerability. Use GitHub's private vulnerability reporting for this repository. See [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Security-relevant changes must update the threat model and invariants; **no custom cryptography**.

## License

**No license has been selected yet.** Until the maintainer chooses one, all rights are reserved by default: the source is publicly visible for review, but no permission to use, copy, modify or distribute it is granted. This is tracked as a release blocker for any reuse.
