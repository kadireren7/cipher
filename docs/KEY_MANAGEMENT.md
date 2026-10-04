# Key management

## 1. Key inventory

| Key / secret | Algorithm | Generated | Stored | Protection | Lifetime / rotation | Leaves device? |
| --- | --- | --- | --- | --- | --- | --- |
| Device **identity key** (MLS signature key) | Ed25519 | On device at install (`SignatureKeyPair::new`, OS CSPRNG) | Inside vault-encrypted MLS snapshot | Vault AEAD under DEK; DEK wrapped by hardware keystore | Long-term; changing it is an identity change (peers warned) | **Public half only** |
| Device **transport-auth key** | Ed25519 | On device (`rng::secret32`) | Vault snapshot | As above | Long-term; separable from identity | Public half only |
| MLS epoch/ratchet/HPKE keys | per RFC 9420 | By OpenMLS | Vault snapshot; memory while unlocked | Vault; MLS FS deletes consumed keys | Per message / per epoch | Never |
| **DEK** (vault data-encryption key) | random 256-bit | On device at provisioning | **Never stored plaintext.** Wrapped by (a) hardware keystore key (device envelope), (b) PIN envelope | Hardware keystore (+ PIN-derived KEK) | Per installation | Never |
| Record key | HKDF-SHA256(DEK, `cipher/storage/record-key/v1`) | Derived on unlock | Memory only (zeroized on lock) | n/a | Per unlock | Never |
| Keystore wrapping key `cipher.vault.device.v1` | AES-256-GCM (Android Keystore) | Inside the Keystore | Non-exportable | Hardware; user-auth gated; device-bound | Per installation; OS may invalidate | Never (non-exportable) |
| Keystore wrapping key `cipher.vault.pin.v1` | same | same | same | Hardware-bound, **not** auth-gated | Per installation | Never |
| PIN secret `S` | random 256-bit | When a PIN is enabled | Wrapped by `cipher.vault.pin.v1` | Hardware-bound | Rotated when PIN changes | Never |
| PIN | user secret | User | **Never stored** | Argon2id(salt, params) mixed into KEK | n/a | Never |
| Attachment key | random 256-bit | Per attachment | Only inside the E2EE descriptor | MLS | Per file | Only inside E2EE message |
| Registration token | random ≥32 chars | Operator | Relay config (only SHA-256 compared); client holds it transiently | Operator-managed | Rotate per policy | To relay (account credential, never grants content access) |
| Relay TLS key | per deployment | Operator | Operator secret store (file path via env) | Operator | Per cert policy | n/a |

Hard rules (checked by tests/static guards where possible): no hard-coded keys; no keys in source control; no keys sent to the
backend (`sec_001_005_010_*` scans the wire, relay DB and logs for the actual private bytes); no keys in logs; no keys in
`SharedPreferences`/DataStore/files (Android static guards ban those APIs); no debugging endpoints that expose keys. Kotlin never receives identity/auth keys, MLS state or attachment keys
(`boundary_guards.rs`); the one residual is the 32-byte vault key transiting JVM memory during Keystore wrap/unwrap (`ANDROID_SECURITY.md` §4, ST-027).

## 2. Hierarchy

```
 hardware keystore key (non-exportable, auth-gated) ──wraps──► DEK ──HKDF──► record key ──AEAD──► vault records
                                                                │                                  (MLS snapshot incl. identity key,
 hardware-bound key ──wraps──► S ─┐                              └─ also wrapped by PIN envelope     messages, pins, metadata)
 PIN ──Argon2id──► pin_key ───────┴─HKDF(S ‖ pin_key)──► KEK ──AEAD──► DEK   (optional second unlock path)
```

## 3. Protection levels (SEC-009, SEC-016)

`SecureKeyStore` reports the level a key *actually* achieved; the vault refuses to proceed below `VaultConfig.min_protection`
(default `HardwareBacked`).

| Level (`ProtectionLevel` → Kotlin `KeyLevel` → UI) | Meaning | Android source |
| --- | --- | --- |
| `SecureElement` → `STRONGBOX` → "Strongbox" | Dedicated secure element | `KeyInfo.securityLevel == STRONGBOX` (API 31+) |
| `HardwareBacked` → `TEE` → "Tee" | Hardware-isolated | `TRUSTED_ENVIRONMENT` (API < 31: `isInsideSecureHardware`, which cannot tell TEE from StrongBox, so it is reported as TEE — never higher) |
| `OsSoftware` → `SOFTWARE_OR_UNKNOWN` | OS software keystore (e.g. the emulator) | key reported software-only |
| `Insecure` | Test double | Never produced by the Android module |

A software keystore is accepted only with `allow_software_keystore = true` (`BuildConfig.ALLOW_SOFTWARE_KEYSTORE`: **true in debug, false in release**), which emits
`ProtectionDowngradeAccepted` so it is never silent. `Insecure` is never accepted.

## 4. Android implementation (`android/.../security/AndroidKeystoreCallbacks.kt`)

* AES-256-GCM key in `AndroidKeyStore`; `setRandomizedEncryptionRequired(true)`; non-exportable.
* **StrongBox first** (`setIsStrongBoxBacked(true)`), catching `StrongBoxUnavailableException` and falling back to the TEE-backed key; the
  resulting level is *read back* from `KeyInfo`, never assumed.
* Auth-gated key (biometric/credential mode): `setUnlockedDeviceRequired(true)`, `setUserAuthenticationRequired(true)`, per-use authentication
  (`timeout 0`, `AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL`), `setInvalidatedByBiometricEnrollment(…)`; the cipher is authenticated through a `BiometricPrompt`
  `CryptoObject` on the **engine thread** (never the UI thread).
* `wrap`/`unwrap`: `iv(12) ‖ ciphertext‖tag`, caller AAD bound. Errors map to the closed set `Missing | Invalidated | AuthRequired | AuthCancelled |
  Corrupt | Unavailable` and drop platform messages. Creating a key whose alias already exists fails — an existing key is never silently replaced.
* **PIN-only mode** (chosen at onboarding, e.g. for devices without a secure lock screen): no biometric path exists for the vault; the PIN envelope (Argon2id + hardware-bound secret `S`) is the only unlock.
* **Generation counter** (`cipher.gen.<n>`): tiny non-auth Keystore keys whose *name* carries a monotonic number (only the highest is kept). It is not a secret and not hardware-protected; it exists so that restoring old app files cannot lower it (`LOCAL_STORAGE_SECURITY.md` §8). Removed with the other `cipher.*` aliases on a user-initiated reset.
* **Vault key handling across the FFI (ST-027):** `wrap` zeroes its plaintext argument; `unwrap` hands the key to a Rust `SecretSink` and zeroes the Kotlin copy (`ANDROID_SECURITY.md` §4).
* Device-credential fallback caveat: with `AUTH_DEVICE_CREDENTIAL` allowed, biometric-enrolment invalidation does not apply to that path.

> **Status (ST-001, not closed):** the module is compiled and its wrapper behaviour is tested on an **Android emulator (software Keystore)** — see `ANDROID_SECURITY.md` §3 for the exact TESTED / NOT TESTED table.
> StrongBox/TEE hardware, per-use biometric prompts, `setUnlockedDeviceRequired`, enrolment-change invalidation and lock-screen removal have **not** been tested on a physical device, and no independent review has happened.

## 6. Invalidation and recovery

* OS invalidation (biometric change, passcode removal, lost keystore key, restore onto another device) ⇒ `INVALIDATED`. Unlock attempts
  return `Invalidated`; a new `Vault` object over the same file also fails, and `provision` refuses to run over existing data.
* **Recovery is not designed yet.** Data protected only by an invalidated key is unrecoverable by design. Options for a later phase
  (user-held recovery secret, encrypted backup to the user's own key, re-linking as a new device with new identity) each have trade-offs
  and each produces an *identity change* that peers must be warned about. There is deliberately **no automatic wipe**.

## 7. Device linking, rotation, KeyPackages

* New device = new identity key + new auth key, **endorsed by an existing device** (signature over the new keys). Peers show a
  `DeviceListChanged` event. Compromised device removal: remove it from MLS groups (commit) and (SECURITY TODO ST-010) revoke it in the directory.
* KeyPackages are single-use: 20 at onboarding, +10 every 24 h (relay cap 100/device); no last-resort KeyPackage yet (ST-008).
* MLS leaf keys are refreshed by `SelfUpdate` commits (PCS) on a schedule — see `GROUP_SECURITY.md` §6.
* Registration-token rotation is an operator action (config); per-user account credentials are a TODO.
