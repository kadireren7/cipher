# Attack-surface inventory (final review, phase 1)

Every entry point an adversary can touch, the adversary from `THREAT_MODEL.md` it maps to, the main controls, the evidence, and what was found. "FR-nn" refers to findings in `FINAL_SECURITY_REVIEW.md`.
Legend for evidence: **T** tested automatically, **E** exercised on the emulator, **R** reviewed only, **N** not tested.

| # | Surface | Adversary | Main controls | Evidence | Findings |
| --- | --- | --- | --- | --- | --- |
| 1 | Android UI / Compose input (text fields, PIN pad, QR scan, pickers) | A13, A14 | `PrivateTextField` (no autocorrect, incognito IME hint), autofill off, custom PIN pad (no IME), `FLAG_SECURE`, touch filtering under overlays, overlays hidden (API 31+), non-tool accessibility denied (API 34+) | T guards, T/E instrumented flag checks | FR-02, FR-04 |
| 2 | Compose / Activity saved state, back stack | A14, A7 | No secrets in `rememberSaveable`; guard on variable names | T guard | FR-03 (info) |
| 3 | Android lifecycle (background, screen-off, process death, task switching) | A6, A13 | Keys dropped on background/screen-off/inactivity; `request_lock` + network cancellation before the ordered lock; MLS state flushed before locking | T FFI, E | FR-11, FR-12 |
| 4 | UniFFI bridge (every exported function) | A15 | Validated inputs, bounded sizes, canonical ids, `catch_unwind`, closed error set, no key in any return type, abort flag | T (`boundary_*`, instrumented, fuzz `ffi_validate`) | none new; ST-027 mitigated |
| 5 | Rust FFI callbacks (Keystore, HTTP, progress, SecretSink) | A15, A5 | Faulting/panicking/silent callbacks are contained; a keystore that delivers no secret cannot unlock; sink keeps the secret in Rust memory | T | ST-027 |
| 6 | `cipher-core` protocol engine (sync, welcome, commits, frames) | A2, A9, A10 | Receiver-side group policy; replay cache; held-message bounds; strict frame codec | T (engine/group tests, relay-compromise suite, fuzz) | FR-01 (info), FR-07, FR-12 |
| 7 | OpenMLS integration (ciphersuite, extensions, KeyPackages, Welcome) | A2, A9, A10 | Required-capabilities, GroupContext metadata extension, identity checks against pins, `max_past_epochs=2` | T + R | FR-01 (hypothesis refuted) |
| 8 | Local encrypted database (`vault.db`) | A6, A7, A16 | Record AEAD with location AAD, wrong-key/corruption fail closed, generation counter vs rollback | T, E (plaintext hunt) | FR-05 |
| 9 | Android Keystore (+ StrongBox/TEE abstraction) | A6, A7 | Non-exportable AES-GCM wrapping keys, honest protection level, release refuses software keystores | T/E on emulator only | ST-001, ST-028 open |
| 10 | PIN / biometric path | A6, A7 | Argon2id + hardware-bound secret, rate limiting persisted, PIN-only mode | T | none new |
| 11 | Attachments (encrypt, upload, download, viewers) | A4, A10, A15 | STREAM AEAD, Padmé, size/MIME/filename limits, ciphertext-only temp files, bounded decoding, guarded players | T, E | FR-06 |
| 12 | Temporary files, voice notes, thumbnails | A6, A14 | fd-based source (no copy), unlinked anonymous temp file, in-memory voice recording, thumbnails inside the vault | T/E (cache empty) | none new |
| 13 | Notifications | A6, A14 | Text built in Rust from privacy mode and vault state; constant wake payload; secret on lock screen | T | none new |
| 14 | Group state and authorization | A9, A10 | `authorize_commit` on every receiver, deterministic CAS ordering, tag rotation | T | FR-07 |
| 15 | Relay HTTP API | A2, A12 | Signed requests (audience, nonce, ts, body hash), shared rate limits, strict parsers, bounded bodies, **authenticate-before-read for uploads** | T | FR-08, FR-09, FR-10 |
| 16 | PostgreSQL (relay storage) | A3 | Ciphertext only, peppered rate keys, coarse expiry, forward-only checksummed migrations | T + dump search | none new |
| 17 | TLS (relay and app) | A1, A5 | TLS 1.3 only, system roots only, no pinning (see review), no redirects, no cleartext | T relay, E app (adversarial servers) | none new |
| 18 | Account/device authentication | A8 | Transport key ≠ identity key; endorsement for new devices; account-bound binding signature | T | FR-09 |
| 19 | Rate limiting / abuse | A2, A10 | Per-device, per-IP, per-target KeyPackage limits | T | FR-08; queue flooding unresolved |
| 20 | Key verification (pins, safety numbers, QR) | A2 | TOFU + endorsements, canonical Cipher ID, constant-time compares | T, fuzz | FR-09; Cipher ID alias bug (earlier phase) |
| 21 | Experimental key transparency | A2 | Feature-gated, no trust effect | T (13 attacks) | none new; still NOT PRODUCTION READY |
| 22 | Build pipeline | A11 | Locked Cargo + Gradle verification metadata, pinned CI actions, secret scan, deny/audit | R/T | none unresolved |
| 23 | Dependencies | A11 | Minimal set; no analytics/WebView/Firebase (guard); `ct-merkle` feature-gated and out of the shipped graph | T | see supply-chain section |
| 24 | APK / release configuration | A14, A16 | Merged-manifest gate: only the launcher exported, not debuggable, no backup, no cleartext, no test CA | T, E | library-exported receiver (earlier phase) |

Not covered by any surface above because it does not exist yet: push provider, multi-device sync, account recovery, deep links, content providers.
