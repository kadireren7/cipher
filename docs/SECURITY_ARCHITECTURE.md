# Security architecture

## 1. Trust zones

```
 ┌──────────────────────────── authorised device (trusted, unlocked only) ────────────────────────────┐
 │  Kotlin/Compose UI ──► cipher-ffi (UniFFI, validates every input) ──► cipher-core (Rust)           │
 │                     ├─ protocol adapter (MLS)      identity · sessions · groups                    │
 │                     ├─ vault + lock state machine  LOCKED/UNLOCKING/UNLOCKED/BACKGROUND/INVALIDATED│
 │                     ├─ encrypted store (AEAD records)                                              │
 │                     ├─ attachments · verification (pins, safety numbers)                           │
 │                     └─ relay client (signed requests, https-only)                                  │
 │  Android Keystore (StrongBox / TEE / software, reported honestly) — wrapping oracle, non-exportable │
 └──────────────────────────────────────────────┬───────────────────────────────────────────────────┘
                              TLS 1.3 (transport only — NOT the E2EE boundary)
 ┌──────────────────────────── UNTRUSTED ──────────▼───────────────────────────────────────────────┐
 │  cipher-relay + PostgreSQL: public keys · commit sequencer · opaque ciphertext queue · opaque blobs │
 │  push provider (content-free wake) · object storage (ciphertext only) · network · database           │
 └───────────────────────────────────────────────────────────────────────────────────────────────────┘
```

The security boundary is the **device**. Everything to the right of the TLS line is assumed hostile (A1–A5).

## 2. Component responsibilities

### Android client (Kotlin UI + `cipher-ffi` + `cipher-core`)

| Responsibility | Where | Notes |
| --- | --- | --- |
| Device identity | `mls.rs` (`MlsClient::generate`, `device_record`, `endorse_device`) | Identity key ≠ transport-auth key |
| Account identity | `cipher-wire::Id16` account id + registration token (relay) | Separate from crypto identity (SEC-018) |
| Cryptographic session state | `mls.rs` snapshot → vault record | MLS state; replay cache |
| Local encrypted persistence | `storage.rs`, `vault.rs` | Record-level AEAD |
| Application lock | `vault.rs` (state machine, PIN, limiter, inactivity) | Single implementation in Rust |
| Secure key storage abstraction | `keystore.rs` + `android/.../security/AndroidKeystoreCallbacks.kt` | Reports actual protection level |
| FFI gate | `cipher-ffi` | Validates every Kotlin input, contains panics, maps errors to a closed set, no keys in any return type |
| Notification text | `app/notify.rs` | Built from privacy mode **and** vault state; locked ⇒ generic |
| Group authorisation | `app/groupmeta.rs` `authorize_commit` | Every receiver, before merging a commit |
| Networking | `relay_client.rs` | https-only; `RelayTransport` seam |
| Message processing | `protocol.rs` `process()` | Replay cache; commit validator hook |
| Group state | `GroupProtocol` (create/add/remove/self-update, epoch, members) | Authenticated by MLS |
| Attachment encryption | `attachment.rs` | Fresh key per file |
| Security event handling | `events.rs` `SecurityEvent` + `SecurityEventSink` | Non-secret payloads only |

### Server (`cipher-relay`)

| Responsibility | Where |
| --- | --- |
| Account/device registry (public keys, endorsements) | `store.rs`, `api.rs` (register/add device/directory) |
| Group commit sequencer (CAS per routing tag, atomic fan-out, tag rotation) | `store.rs`, `api.rs` (`/v1/groups/…`) — ordering only, not authorisation |
| Persistence, migrations | PostgreSQL via `db.rs`, forward-only checksummed `migrations/` under an advisory lock |
| Public cryptographic material (KeyPackages) | `store.rs` |
| Message relay + offline ciphertext delivery | `api.rs` send/fetch/ack, `store.rs` queue |
| Expiry, bounded queues, size limits, strict validation | `store.rs`, `cipher-wire::limits`, `cipher-wire::messages` |
| Authentication (per-request signatures, nonces) | `auth.rs` |
| Rate limiting, replay protection | `ratelimit.rs` + `take_tokens` (PostgreSQL, shared across instances; keys are peppered hashes), `request_nonces` table |
| Overload | `conn_limit.rs`, in-flight cap with 503 shedding, request deadline |
| Transport boundary | `tls.rs` (TLS 1.3 only), `config.rs` (refuses to start without TLS except loopback dev) |
| Group routing metadata | random routing tag + commit sequence per group (no membership table); recipient device ids per delivery |
| Push | `push.rs` (constant payload) |

## 3. Fail-closed policy (Phase 16)

| Failure | Behaviour |
| --- | --- |
| AEAD/authentication failure (message, record, attachment, keystore blob) | Error; no partial plaintext; state unchanged |
| Keystore cannot meet minimum protection | `ProtectionBelowMinimum`; provisioning aborted, key deleted. Software keystore only with explicit opt-in **and** an event |
| Keystore key missing/invalidated | `INVALIDATED` state; no silent re-provisioning over existing data |
| Stored KDF parameters below floor | `KdfParamsBelowFloor`; unlock refused |
| Non-https relay URL | `Transport("https required")` |
| Relay starts without TLS | Refuses to start (except explicit loopback dev flag) |
| Bad signature / skew / replay / wrong audience | `401`, indistinguishable from unknown device |
| Unknown identity key / unendorsed device | Excluded from trusted set + `SecurityEvent`; user acknowledgement required |
| Commit adds device not approved by `CommitValidator` | Commit dropped; epoch unchanged |
| Group commit violating the role policy (any sender, relay-forwarded or not) | Dropped before merge, group state unchanged, `UnauthorizedGroupChange` event |
| Hostile or malformed input at the FFI (ids, lengths, paths, enums, PINs) | `InvalidInput` before any state change; panics are caught, the vault is locked, `Internal` is returned |
| Release build + software-only Keystore | Refused (`ALLOW_SOFTWARE_KEYSTORE=false`); debug builds accept it with an event |
| Lost/invalidated Keystore key | `INVALIDATED`; the vault file is **kept** (no wipe); user-initiated reset only |
| Relay queue/body/connection limits exceeded | `413`/`429`/`503` with bounded memory; never an unbounded queue |
| Corrupt local state | `StorageCorrupt`/`CryptoAuthFailed` + event; never returns garbage |

**Never downgraded silently:** cryptographic verification, identity verification, TLS requirements, secure key storage,
authenticated encryption. There is no "insecure" runtime switch; test-only fakes are behind the
`insecure-test-support` Cargo feature, and CI asserts it never appears in the production dependency graph.

## 4. Lock lifecycle

```
            provision                   unlock_with_device_auth / unlock_with_pin
  (none) ───────────────► UNLOCKED ◄───────────────────────── UNLOCKING ◄──── LOCKED ◄─────────┐
                           │  │  │                                │  failure     ▲  ▲           │
        lock / inactivity  │  │  └ on_background ► BACKGROUND ────┘  (counted)   │  │ on_foreground
                           │  └──────────────────────────────────────────────────┘  │           │
                           ▼ key invalidated / passcode removed / biometrics changed ─┘           │
                       INVALIDATED  (terminal; recovery flow required, never wipes by itself) ────┘
```
* Keys exist in memory **only in UNLOCKED**. LOCKED/BACKGROUND/INVALIDATED drop the store and DEK (`Zeroizing`).
* BACKGROUND → foreground always lands in LOCKED (fresh unlock). Screen-off also locks. While not UNLOCKED, **every plaintext API returns `Locked`** (tested through the FFI on an emulator).
* Inactivity timeout uses a monotonic clock (default 60 s); every data access counts as activity.
* PIN attempts are counted **before** verification (killing the process mid-guess gives no free attempt), persisted,
  with exponential backoff after 5 free failures (30 s doubling to 1 h). This limiter is defence in depth: its file can be reset by
  someone with filesystem write access, so the real offline bound is that PIN derivation also needs the hardware-bound
  secret `S`.
* **No destructive wipe exists by default.** Any future wipe-after-N-attempts feature must be designed separately because
  accidental or malicious triggering destroys user data.

## 5. Transport

TLS 1.3 only on the relay, ring provider, ALPN `http/1.1`. Older Android versions without TLS 1.3 need an updated TLS
provider (decision recorded in `DECISIONS.md`). **TLS is not the E2EE boundary:** all message/attachment content is
protocol ciphertext before it reaches TLS, and the tests capture bytes at the transport seam *below* TLS to prove it.
Every request is signed by the device transport-auth key (audience + method + path + timestamp + nonce + body hash).
Limits: 256 KiB ciphertext/message, 1000 envelopes and 16 MiB queued per device, 100/fetch, TTL 60 s – 30 d, 100 MiB blobs,
512 KiB JSON bodies, 10 devices/account, 100 KeyPackages/device.

## 6. Notification privacy

* Push providers (when one is configured — none is today, ST-017) get only the constant payload `{"v":1}` plus a token. No sender, conversation, text, count or ciphertext. The wake parser accepts only that exact string.
* On wake, the app fetches ciphertext over its authenticated channel and decrypts locally. **A locked vault cannot authenticate to the relay** (the transport key is in the vault), so a wake while locked can only show "New message".
* Visible text is built in Rust (`notify::build`) from the **privacy mode and the vault state**: `NO_CONTENT` (default) always yields the generic text; `SENDER_ONLY` shows the local contact name and `CONTENT_WHEN_UNLOCKED` the message text,
  both **only while unlocked**; every notification is secret on the lock screen. Request-state conversations (not yet accepted) never contribute content.
* **Platform limits:** the OS and push provider learn *that* and *when* a wake happened; Android may retain notification history; background delivery can be delayed by Doze.

## 7. Logging, analytics, crash reports (SEC-010)

No analytics or crash-reporting SDKs. Relay logs: `method route status` only. Android: `SafeLog` accepts a closed set of event
codes plus an int (free text cannot be passed), and R8 strips every `android.util.Log` call in release. `Debug` for key-bearing types prints `<redacted>`. Static
guards forbid `println!`/`dbg!`, ad-hoc RNGs, cleartext `http://`, TLS-verification overrides, and (Kotlin) WebView, SharedPreferences/DataStore, external storage, free-form logging and un-secured dialogs (`android_guards.rs`).

## 7a. Secure coding baseline

`unsafe` forbidden in our crates (workspace lint) — **except** that `cipher-ffi` must allow it for UniFFI's generated scaffolding, so `boundary_guards.rs` asserts its hand-written source contains none; clippy denies `unwrap`/`expect`(warn)/`panic`/`todo`/`dbg`/indexing in
production code; `overflow-checks` on in release; `panic = abort` for the relay and core builds, but the **`android-release` profile uses `panic = unwind`** so the FFI can `catch_unwind` — a panic must never cross into Kotlin; strict `deny_unknown_fields` on every wire type; exact version
pins for security-critical crates; lockfiles committed; `--locked` in CI; fuzz targets for every parser (`fuzz/`).
Memory-safe implementation languages (Rust, Kotlin). Memory *locking* (mlock) and
guard pages would require `unsafe`/platform code and are deferred to the FFI/native layer (SECURITY TODO ST-015).
