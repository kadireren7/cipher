# Architecture

Cipher is an **Android-only** end-to-end encrypted messenger. The Kotlin/Compose UI is a thin, untrusted-for-secrets shell; every
security decision lives in the Rust core behind a narrow UniFFI bridge; the relay and its PostgreSQL database are untrusted.
(React Native, the TypeScript layer and all iOS code were removed; their security logic was ported before deletion — see `DECISIONS.md` ADR-019.)

## 1. Repository structure

```
Cargo.toml / Cargo.lock           Rust workspace (resolver 2, strict clippy lints; android-release profile keeps panic=unwind for the FFI guard)
crates/
  cipher-wire/    shared wire types, limits, request canonicalisation  (no key handling, no heavy deps)
  cipher-core/    CLIENT security core: MLS adapter, group policy, vault + lock, encrypted store, attachments,
                  verification, relay client, keystore abstraction, app engine (conversations, contacts, messages)
  cipher-ffi/     UniFFI bridge: input validation, panic containment, error mapping, Keystore/HTTP/progress callbacks
  cipher-relay/   UNTRUSTED relay: registry, KeyPackages, per-group sequencer, bounded ciphertext queue, blobs, auth,
                  distributed rate limiting, PostgreSQL migrations, TLS 1.3
android/          Gradle project: Kotlin + Compose app, tests; builds the Rust library for arm64-v8a/x86_64 and generates bindings
fuzz/             cargo-fuzz targets (nightly, detached from the workspace)
security/         invariants.json — machine-readable invariant → test registry
scripts/          android-env.sh, make-test-ca.sh, CI guards (invariants, relay deps, secret scan, doc generation)
docs/             this documentation set
.github/workflows CI (ci.yml) and scheduled fuzzing (fuzz.yml)
```

## 2. Layers and what each may know

| Layer | Language | Knows | Must never know |
| --- | --- | --- | --- |
| UI (`android/app/src/main/.../ui`) | Kotlin / Compose | Decrypted text it is asked to display, contact names, public identifiers | Any key, MLS state, vault key, attachment key |
| App shell (`data/`, `security/`, `net/`) | Kotlin | Wrapped (opaque) Keystore blobs; the 32-byte vault key *only* during `unwrap` (see ANDROID_SECURITY §4); TLS bytes of already-signed requests | Identity/auth private keys, plaintext of requests |
| FFI (`cipher-ffi`) | Rust | Everything the core returns, after validation | — (it is the gate: every Kotlin input is hostile) |
| Core (`cipher-core`) | Rust | All secrets while the vault is unlocked | The Keystore key bytes (non-exportable; used as a wrapping oracle) |
| Relay (`cipher-relay`) | Rust | Public keys, KeyPackages, ciphertext, recipient device ids, sizes, timing | Plaintext, private keys, attachment keys/names/types, group membership |
| PostgreSQL | — | Whatever the relay writes: ciphertext + the metadata in `METADATA_MODEL.md` | Same as the relay |

## 3. Component and data flows

**Onboarding.** Relay URL + invite code → vault provisioned (Keystore key created, or PIN-only envelope) → `create_identity`: random
`account_id`/`device_id` (not derived from any key), identity + transport-auth keys, binding signature → `POST /v1/accounts`
(registration token + public record), then 20 KeyPackages uploaded under a signed request.

**First message (1:1).** Directory lookup → `IdentityPins` (TOFU + endorsements; changed key ⇒ `IDENTITY_CHANGED`, never silent) → single-use
KeyPackage validated against the pinned identity → Welcome sent as opaque ciphertext → recipient sees a **message request** (nothing shown until accepted).
Messages: padded frame (512 B … 64 KiB buckets) → MLS encrypt → `POST /v1/messages/batch` (idempotent by `message_id`) → recipient `sync` →
replay cache + MLS decrypt → local encrypted store → ack. Offline send queues in the local outbox and retries.

**Groups.** Metadata (name, kind, roles, routing tag) lives in a GroupContext extension (`0xF1A0`), so MLS itself authenticates it. Every commit goes to
`POST /v1/groups/{tag}/commit` with an expected sequence; the relay serialises with compare-and-swap and stamps `group_seq`, but **receivers**
re-run `authorize_commit` before merging (the relay is not trusted for authorisation). Removal rotates the routing tag. See `GROUP_SECURITY.md`.

**Attachment.** File descriptor from the system picker → `/proc/self/fd/N` (no plaintext copy) → chunked ChaCha20-Poly1305 (STREAM) with a per-file random key and Padmé padding →
ciphertext-only temp file → `POST /v1/blobs` → descriptor (key, hash, MIME, name) inside the E2EE message → recipient downloads, verifies, decrypts **in memory**. Voice notes are
recorded to memory and never touch the disk in plaintext; PDFs are rendered from an unlinked anonymous temp file.

**Local state.** `Vault` (lock state machine) → `EncryptedStore` records in `vault.db` (SQLite, record-level AEAD, location-bound AAD).

## 4. Lock model

`LOCKED → UNLOCKING → UNLOCKED → BACKGROUND → INVALIDATED`. Leaving the foreground, screen-off, or inactivity (default 60 s, configurable 15 s – 1 h) drops the keys; foregrounding alone never unlocks.
While not `UNLOCKED`, **every plaintext API returns `Locked`**, notifications are generic, and nothing is previewed. Details in `SECURITY_ARCHITECTURE.md` §4 and `ANDROID_SECURITY.md`.

## 5. Trust boundaries

The device is the boundary; the relay, push provider, object storage, network and database are untrusted. See `SECURITY_ARCHITECTURE.md` §1.

## 6. What exists vs. what does not

| Exists and is tested | Exists, limited / experimental | Not built |
| --- | --- | --- |
| MLS 1:1 and groups, roles, receiver-side policy, deterministic commit ordering, PCS scheduler | Key transparency verifier (feature-gated, **NOT PRODUCTION READY**, no log server) | Account recovery (by design), multi-device sync |
| Vault, lock states, PIN-only mode, PIN rate limiting, encrypted records, paging | Push: opaque wake interface only, no FCM project (ST-017) | Sealed sender / hidden group ids (ST-009) |
| Attachments (image/video/audio/PDF/file), voice notes, tamper-fails-closed | Android Keystore wrapper: tested on an **emulator only** (software-backed) | Certificate pinning (supported, none shipped; ST-002) |
| Relay on PostgreSQL: migrations, bounded queues, TTL, ack cleanup, idempotency, distributed rate limits, redacted logs | Instrumented UI automation is partial (see `SECURITY_TESTING.md`) | SBOM / reproducible builds / signed releases (ST-014) |
| UniFFI bridge: hostile-input validation, panic containment, lifecycle tests | | Physical-device test matrix (ST-001) |

## 6a. Recommended scope of the next phase

See `SECURITY_TODO.md` §"Next phase".
