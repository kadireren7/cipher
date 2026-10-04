# Local storage security

## 1. Design

`vault.db` is a SQLite file with two tables:

* `vault_meta(k, v)` — **not secret, integrity protected by the AEAD inside each value**: device envelope (keystore-wrapped DEK),
  optional PIN envelope (KDF params, salt, wrapped `S`, AEAD nonce/ciphertext), PIN attempt counter.
* `records(ns, id, ct)` — every record is `nonce(24) ‖ XChaCha20-Poly1305(record_key, plaintext, AAD = 0x01 ‖ len(ns) ‖ ns ‖ id)`.
  The location is bound as AAD, so a file-write attacker cannot swap rows. A `__vault__/check` record detects a wrong key or corruption at unlock.

Namespaces: `mls/state` (snapshot incl. identity + transport-auth private keys), `identity_pins/<account>`, conversations, messages (with delivery state, reply links, local attachment descriptors **including the per-file attachment key**,
thumbnails), contacts and trust states, the outbox, held out-of-order group messages (≤ 64/conversation), replay markers, settings and the security-event log. SQLite runs with `secure_delete=ON` (rollback journal; no `-wal`/`-shm`
files were observed on the device). Multi-record changes use `atomic` transactions (identity creation, MLS snapshot + conversation state on commit).
**Paging:** history is read newest-first in pages (`list_ids_page`, ≤ 40 items per call from the UI) with an opaque cursor, so the UI never loads a whole conversation. Local deletion removes the records (`secure_delete` overwrites freed pages; flash wear-levelling may still retain old blocks — NOT TESTED).

This is *application-layer* authenticated encryption with an established AEAD (RustCrypto). **SQLCipher is a possible additional layer** (and Android file-based encryption already protects the file at rest on supported devices), but it is not used:
the core must build and be tested on a plain toolchain, and adding it is a connection-layer change (SECURITY TODO ST-004, open).
Visible to a file reader today: table names, namespaces, record ids, record count and approximate sizes. The vault lives in `noBackupFilesDir`, so it is excluded from backups and device transfer.

## 2. Unlock paths

| Path | How |
| --- | --- |
| Biometric / device credential | The Android Keystore unwraps the DEK after a per-use `BiometricPrompt` (the OS performs the prompt; the core never sees biometrics). The DEK transits JVM memory during the unwrap (ST-027). |
| PIN | `Argon2id(PIN, salt, params)` and hardware-bound secret `S` → HKDF → KEK → decrypt DEK. No raw PIN is stored. Policy: ≥ 6 chars, not all identical (a numeric PIN has little entropy; the hardware-bound `S` is the real offline barrier). |
| PIN-only vault | Chosen at onboarding: **no biometric path exists**; the PIN envelope is the only way in (used on devices without a secure lock screen, or by choice). On an emulator `S` is only software-protected, so the offline barrier is weaker there (reported honestly as `SOFTWARE_OR_UNKNOWN`). |

## 3. KDF parameters (Argon2id, RFC 9106)

Default `MOBILE_DEFAULT`: **m = 64 MiB, t = 3, p = 1**, 16-byte random salt, 32-byte output. Floor enforced on every load: **m ≥ 19 MiB, t ≥ 2** (OWASP minimum);
ceiling m ≤ 1 GiB, t ≤ 16 (prevents a tampered envelope from forcing a huge allocation). Stored parameters below the floor ⇒ `KdfParamsBelowFloor` (a downgrade
attack by editing the file fails closed — test `kdf_parameter_downgrade_in_storage_fails_closed`).

Benchmark (`cargo run --release -p cipher-core --example kdf_bench`, **dev host: x86-64 Linux, release build**, 5 runs):

| Profile | m (KiB) | t | p | median | min | max |
| --- | --- | --- | --- | --- | --- | --- |
| floor | 19456 | 2 | 1 | 20 ms | 17 ms | 27 ms |
| **MOBILE_DEFAULT** | 65536 | 3 | 1 | **138 ms** | 137 ms | 144 ms |
| high | 131072 | 3 | 1 | 285 ms | 284 ms | 291 ms |

These are **host numbers, not mobile numbers**. Typical mid-range phones are several times slower, so `MOBILE_DEFAULT` is expected to land in the few-hundred-ms range; the target
is ~250–500 ms on the slowest supported device. SECURITY TODO ST-003 (open): re-run on real low-end Android hardware and tune; also validate peak memory (64 MiB) on 2–3 GB devices. (The emulator onboarding completed with this setting on a memory-starved 2.4 GB guest; that is not a benchmark.)

## 4. Attempt limiting

5 free failures, then 30 s doubling to a 1 h cap. The attempt is counted *before* verification and persisted (survives restarts). A success resets it. Caveats: the counter
lives in the same file, so someone with write access can reset it; and a wall-clock rollback shortens a lockout (`unix_secs` is user-adjustable). The limiter is therefore
defence in depth; the offline bound comes from Argon2id **plus** the hardware-bound secret `S`, and from OS/hardware throttling of the biometric/passcode path.

## 5. Lifecycle and memory

States: `LOCKED`, `UNLOCKING`, `UNLOCKED`, `BACKGROUND`, `INVALIDATED` (`SECURITY_ARCHITECTURE.md` §4). The DEK and record key live in `Zeroizing<[u8; 32]>` and exist only while `UNLOCKED`; locking,
backgrounding, device screen-lock, inactivity timeout and invalidation drop the store (key zeroized on drop). `with_store` is the only access path and fails closed with `Locked`/`Invalidated`.
`Debug` impls print `<redacted>`.

**Limits, stated plainly:** Rust cannot guarantee that every copy of a secret is erased (reallocations, stack copies, CPU registers); OpenMLS' in-memory storage is not zeroized on drop;
`mlock`/guard pages need `unsafe` or platform code, which this workspace forbids and defers (ST-015); JVM `String`/`ByteArray` copies of decrypted text and of the transient vault key cannot be reliably wiped (the viewer zero-fills attachment byte arrays on dispose, best effort); swap/crash dumps are the OS's domain.
On a compromised endpoint while unlocked, memory protections do not help (A13).

## 6. Known weaknesses

* **Rollback / deletion:** a file-write attacker can restore an older valid record or delete rows. **Since the final review a whole-vault rollback is detected** (§8); per-record rollback inside a current vault and row deletion are not (ST-016 stays open).
* **Metadata at rest:** namespaces, ids, counts and sizes are visible without the key.
* **Whole-snapshot persistence of MLS state:** coarse; an incremental encrypted `StorageProvider` is future work. Crash between `put`s is not transactional across records yet.
* **Backups:** the vault is excluded from cloud backup and device transfer (`allowBackup=false`, `dataExtractionRules`, `noBackupFilesDir` — TESTED as configuration, NOT TESTED by an actual backup/transfer attempt).
* **Key invalidation** destroys access by design (see `KEY_MANAGEMENT.md` §6).
* **Corruption** is detected (AEAD / check record / SQLite errors → `StorageCorrupt`/`CryptoAuthFailed` + `StorageCorruptionDetected` event) but not repaired.

## 7. Android plaintext-leak audit (summary)

The full table is in `ANDROID_SECURITY.md` §5. Method used on the emulator after a real session (DM both ways, group, image, PDF, voice note): pull the entire app data directory and search every file
(raw bytes and `strings`) for all plaintext fixtures, filenames and contact names; search `/sdcard` and `/data/local/tmp`; search `logcat`; search the relay's log and a full `pg_dump`.
Result: **0 hits** everywhere except the UI itself. This shows the absence of those specific fixtures in those places on that run; it does not prove nothing else leaks (for example, heap contents while unlocked).

## 8. Rollback detection (FR-05)

**Threat.** An attacker (a restored backup, a malicious app with storage access on a rooted device, a forensic tool, `adb` on a debuggable build) replaces the app's files with an OLDER copy. Besides resurrecting deleted messages this is dangerous cryptographically: the restored **MLS state** would make the device encrypt NEW messages with ratchet keys/nonces it had already used — key/nonce reuse across different plaintexts.

**Design.** The vault holds an encrypted `generation` record (under the DEK, so it cannot be forged); the platform keystore holds a **monotonic counter outside the data directory** (`counter_read` / `counter_advance`; on Android the number is the name of a tiny `cipher.gen.<n>` Keystore key). Every unlock and every lock/background sets `generation = max(vault, keystore) + 1`, vault first, keystore second (a crash can leave the vault *ahead*, never behind). On unlock, **vault generation < keystore counter ⇒ `StorageRolledBack`**: the vault is put into `INVALIDATED` (explicit reset required), nothing is decrypted, and a `VaultInvalidated(StorageRolledBack)` event is emitted. Provisioning overtakes a stale counter (after a user-initiated reset).

| Attack | Result |
| --- | --- |
| Restore an older vault.db (device-key or PIN-only vault) after later unlock/lock cycles | **Detected**, refused (T core + E real Keystore) |
| Edit the file to claim a higher generation | **Impossible** without the DEK (any edit is corruption) (T) |
| Restore a snapshot taken during the SAME unlocked session, no lock in between | **Not detected** (same generation) |
| Restore the old files AND delete the `cipher.gen.*` Keystore entries | **Not detected** — needs code execution as the app or root |
| Root attacker who edits the system keystore database | **Not detected** (the counter is not hardware-protected) |
| Roll back a single record inside a current vault | **Not detected** |
| Uninstall/reinstall | Files and counter are both removed; consistent |

**Not claimed:** Android offers no hardware monotonic counter to third-party apps (RPMB is not exposed). StrongBox/TEE keys do not carry counters we can read. Anything stronger would need a server-side or attestation-based design.
