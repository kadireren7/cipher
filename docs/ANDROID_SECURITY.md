# Android security

Everything specific to the Kotlin app and its OS surface. Evidence labels used throughout: **TESTED** (an automated test or a recorded
emulator run exercised it), **EXPECTED** (follows from the architecture or Android's documented behaviour, not exercised here),
**NOT TESTED**, **EXTERNAL REVIEW** (needs someone other than the author). Nothing here was run on a physical device.

## 1. Attack surface (hardening review)

| Surface | Decision | Evidence |
| --- | --- | --- |
| Exported components | Exactly one: `MainActivity` (MAIN/LAUNCHER). We declare no services, receivers or providers; the screen-off receiver is registered dynamically with `RECEIVER_NOT_EXPORTED`. **Library-contributed components are checked too**: androidx.profileinstaller adds an exported (DUMP-protected) receiver, which is removed with `tools:node="remove"`; debug builds additionally carry Compose tooling activities that do not exist in release | TESTED: `android_guards.rs::manifest_is_locked_down`; instrumented `onlyTheLauncherActivityIsExportedAndNothingElseIs` (installed debug package, every component); `scripts/check-release-apk.sh` on the **merged release manifest** (found the profileinstaller receiver the source-level guard could not see) |
| Deep links / intent filters | None. No `VIEW`/`SEND` filters, no `<data>`; the app never fires `startActivity` with external intents | TESTED (static guard + manifest guard) |
| WebView | Not used; banned by a guard (also `addJavascriptInterface`, `setJavaScriptEnabled`) | TESTED (guard with negative control + mutation run) |
| Backup | `allowBackup=false`, `fullBackupContent=false`, `dataExtractionRules` exclude every domain for cloud backup **and** device transfer; vault lives in `noBackupFilesDir` | TESTED: guard + instrumented `backupAndCleartextAreOff`. NOT TESTED: an actual `adb backup` / device-transfer attempt |
| Cleartext / certificates | `usesCleartextTraffic=false`, NSC `cleartextTrafficPermitted=false`, system trust anchors only (no user CAs). The only extra anchor is the throwaway test CA under `<debug-overrides>`, which exists solely in `src/debug` and applies only to debuggable builds. OkHttp: TLS 1.3 only, HTTP/1.1, no redirects, **no** custom `TrustManager`/`HostnameVerifier`, `https://` enforced per request. There is no option to disable certificate checking or encryption | TESTED: guards, instrumented `NetworkSecurityPolicy` check, and a real handshake against the relay binary in the E2E run. NOT TESTED: a hostile CA / MITM against the app |
| Certificate pinning | Supported by the transport (`pins`), none shipped (operator-owned decision, needs backup pin + rotation) — ST-002 | OPEN |
| Debug flags | `debuggable` only from the build type; release: minified, shrunk, `ALLOW_SOFTWARE_KEYSTORE=false`, no relay or invite baked in | TESTED: guard + instrumented `debugFlagsMatchTheBuildType` (debug variant). The release APK's manifest was inspected with `aapt` (see SECURITY_TESTING §7) |
| Debug-only auth bypass | The marker file `no_backup/config/debug_no_user_auth` (emulators have no secure lock screen) is read in exactly one place, behind `BuildConfig.DEBUG &&`, which R8 folds away in release | TESTED: guard enforces exactly one use and the `BuildConfig.DEBUG` gate |
| Logging | The only logger is `SafeLog` (closed set of event codes + an int; no strings/objects). R8 strips all `android.util.Log` calls in release. Native code logs nothing sensitive (relay logs method/route/status only) | TESTED: guards; logcat of the E2E session contained none of the plaintext fixtures |
| Clipboard | Only `SensitiveClipboard` touches it: marks the clip `EXTRA_IS_SENSITIVE` (API 33+, hides it from previews) and clears it after 60 s if still ours | TESTED: guard (single allowed file). EXPECTED: sensitive flag behaviour |
| File sharing | No `FileProvider`, no external storage APIs, no storage/contacts/location/phone permissions. Attachments come from the system picker; decrypted attachments are never exported | TESTED: manifest + permission guards, instrumented permission check |
| Permissions | `INTERNET`, `USE_BIOMETRIC`, `POST_NOTIFICATIONS`, `CAMERA` (QR scan, optional), `RECORD_AUDIO` (voice notes, optional) | TESTED |
| Notification channels | One channel, lock-screen visibility secret, no sound/vibration content; text built in Rust from the privacy mode **and** vault state | TESTED (Rust notify tests, FFI `SyncReport.notification`) |
| App switcher / screenshots | `FLAG_SECURE` set in `SecureActivity.onCreate` *before* content; every activity must extend it; every dialog goes through `SecureDialog` (`SecureFlagPolicy.SecureOn`) because a new window does not inherit the flag; `setRecentsScreenshotEnabled(false)` on API 33+ | TESTED: guards; instrumented `flagSecureIsSetOnTheMainWindow`; **observed on the running emulator**: `dumpsys window` shows `SECURE` in the window flags, and `screencap` of the foreground app returns 0 bytes while the launcher returns 1.37 MB |

**FLAG_SECURE limits (state this to users):** it blocks screenshots, screen recording, Recents thumbnails and most casting. It does **not**
stop another camera photographing the screen, a compromised OS, a rooted device, or an accessibility service the user has enabled.

## 2. Lock states on Android

| State | Meaning | Trigger |
| --- | --- | --- |
| `LOCKED` | No keys in memory. Every plaintext API returns `Locked`; UI shows only the lock screen; notifications are generic | cold start, lock timeout, screen-off, explicit lock |
| `UNLOCKING` | Keystore or PIN unwrap in progress | user action |
| `UNLOCKED` | Keys live in Rust memory (zeroized on drop) | successful unlock |
| `BACKGROUND` | App left the foreground: keys are dropped immediately | `ProcessLifecycleOwner.onStop` |
| `INVALIDATED` | The Keystore key is gone or invalidated (screen-lock removed, biometric enrolment changed with invalidation on, reinstall). Data is **kept**, nothing is wiped; the user must explicitly reset | Keystore fault |

TESTED (instrumented, real native library + real Keystore wrapper): provision → lock → `Locked` on `listConversations`/`getSettings`; wrong PIN →
`BadCredential` and still locked; restart (new engine over the same directory) comes up `LOCKED`; background → `Locked`, foreground alone does not unlock; brute force is throttled
(`RateLimited`, right PIN refused while throttled); lost key fails closed and does **not** delete the vault; the vault file never contains the PIN.
TESTED on the emulator through the UI: unlock screen after the inactivity timeout, PIN unlock.
NOT TESTED: biometric prompt, `setUnlockedDeviceRequired` behaviour, invalidation on enrolment change, StrongBox.

## 3. Keystore (ST-001 — partly addressed, **not closed**)

`AndroidKeystoreCallbacks` implements the Rust `SecureKeyStore` contract with AES-256-GCM keys generated **inside** the Keystore (non-exportable).
StrongBox is requested first; if absent, the TEE key is used; the level actually achieved is **read back from `KeyInfo`** and reported. A software-backed
key is reported as `SOFTWARE_OR_UNKNOWN` — never as hardware — and a release build (`ALLOW_SOFTWARE_KEYSTORE=false`) refuses it.

| Property | Emulator result | Real device |
| --- | --- | --- |
| Key creation, honest level read-back (`SOFTWARE_OR_UNKNOWN` on the emulator; never StrongBox without the feature) | TESTED (instrumented) | NOT TESTED |
| Non-exportable (`SecretKey.encoded == null`) | TESTED | NOT TESTED |
| Wrap/unwrap round trip; AAD binding; randomised IV; tamper/truncation fail closed (every 5th byte flipped) | TESTED | NOT TESTED |
| Duplicate alias refused (no silent replacement); missing key → `Missing`; keys do not cross aliases | TESTED | NOT TESTED |
| Survives restart; deletion is final | TESTED (new instance / reopened Keystore) | NOT TESTED |
| Per-use biometric/credential prompt (`setUserAuthenticationParameters(0, STRONG|CREDENTIAL)`) | NOT TESTED (emulator has no secure lock screen; the debug marker bypasses auth) | NOT TESTED |
| `setUnlockedDeviceRequired(true)` | NOT TESTED | NOT TESTED |
| Invalidation on biometric enrolment change; timeout; reinstall | Reinstall/key loss path TESTED at engine level (alias deleted ⇒ fails closed, data kept). Enrolment change NOT TESTED | NOT TESTED |
| StrongBox | NOT TESTED | NOT TESTED |

A physical-device test matrix (StrongBox device, TEE-only device, device without biometrics, enrolment change, lock-screen removal) is required before
this item can be closed. We will not claim it until it has happened.

## 4. FFI boundary: what Kotlin can and cannot see

The bridge exposes high-level operations only. Verified by `boundary_guards.rs` (no exported function returns key material or raw MLS state, no hand-written `unsafe`)
and `boundary_behaviour.rs` (hostile inputs, panics, lifecycle misuse, failing callbacks).

* **Never crosses to Kotlin:** identity/transport-auth private keys, MLS state, the Argon2id-derived KEK, the DEK/record key (in Rust), attachment master keys (the file key is generated and used in Rust; the descriptor is stored in the encrypted store).
* **Crosses on purpose:** public identifiers and QR payloads; decrypted message text and attachment bytes the user asked to view; PINs typed by the user (bounded, passed once, not retained by Kotlin).
* **ST-027 (OPEN, mitigated — final review):** the 32-byte vault key still transits JVM memory, but for as short a time as the platform allows. Where it exists:
  1. *Rust → Kotlin at `wrap`*: the key arrives as a `ByteArray` argument; `AndroidKeystoreCallbacks.wrap` **zeroes it in a `finally`** right after the Keystore used it (only at provisioning/PIN enablement — rare).
  2. *Inside the Keystore operation*: `Cipher.doFinal` produces the plaintext in a JVM `ByteArray`. JCA/Keystore-internal temporary buffers are outside our control and may linger until GC.
  3. *Kotlin → Rust at `unwrap`*: the callback no longer **returns** the key (a return value would stay reachable through the generated glue). `unwrapInto(…, sink)` hands it to a Rust-implemented `SecretSink` (kept in `Zeroizing` Rust memory) and Kotlin **zeroes its copy immediately** after `sink.put` returns.
  The lowering into the UniFFI buffer (native memory) is not zeroed on free. The PIN a user types is a Kotlin `String` (cannot be wiped). Attacker capability needed to exploit what remains: read this process's memory *during an unlock* (debugger on a debuggable build, root/Frida, or a heap dump taken in that window) — the same capability that can already call the engine, so the *marginal* exposure is persistence of the key in the heap after lock, which the zeroing removes in the common path. Guards: `keystore_wrapper_never_returns_the_vault_key_and_zeroes_its_copies`, instrumented `theJvmCopyOfTheKeyIsZeroedAfterUnwrapAndWrap`, Rust `a_keystore_that_never_delivers_the_secret_cannot_unlock_the_vault`. A design where the key never enters the JVM needs a Keystore operation whose *output stays in the secure world* (e.g. Keystore-side MAC/derivation used as the KEK input would still return bytes); no such API exists for this pattern.
* **Every input is hostile:** ids are strict 32-hex, text/filename/MIME/thumbnail bounded, paths must be `/proc/self/fd/N`, PINs bounded, enums closed. Rust panics are caught (`catch_unwind`, `android-release` profile uses `panic=unwind`) and turn into `Internal` after the vault is locked; a poisoned lock also locks. Callbacks that panic or fault are contained.

## 5. Local storage audit (plaintext leakage)

| Location | Content | Result |
| --- | --- | --- |
| `no_backup/cipher/vault.db` | Everything sensitive (SQLite, record-level AEAD). `secure_delete=ON`, rollback journal (no `-wal`/`-shm` files were observed) | TESTED: searched the pulled app data directory for every plaintext fixture and for file/contact names: **0 hits** |
| `no_backup/config/*` | `relay.url`, `unlock_mode`, `lock_timeout_secs`, `onboarding_done` — non-secret by design | reviewed |
| Room / shared preferences / DataStore | Not used (banned by guard) | TESTED (guard) |
| `cache/` | JNA stub, `viewer/` (temp dir that must stay empty: PDFs are written to an unlinked file) | TESTED: empty after viewing a PDF, image and voice note |
| `files/` | `profileInstalled` only (androidx profile) | reviewed |
| External storage / `/sdcard` | Never written | TESTED: searched `/sdcard` and `/data/local/tmp` for fixtures: 0 hits |
| Logcat | `SafeLog` event codes only | TESTED: 0 fixture hits |
| Clipboard | Only explicit user copy actions, flagged sensitive, cleared after 60 s | EXPECTED |
| Crash reports / analytics | None shipped; no crash SDK | TESTED (dependency guard) |
| Thumbnails | Generated client-side, stored **inside** the encrypted store (never as a file) | EXPECTED (code review). The E2E run received attachments from a peer without thumbnails and found no image/PDF/voice bytes outside `vault.db`; app-side thumbnail generation was **not** exercised end to end |
| Notifications | Text from Rust by privacy mode and vault state; `NO_CONTENT` is the default | TESTED (Rust), EXPECTED (Android notification history retention) |

NOT TESTED: a rooted/forensic extraction of a **running, unlocked** process; heap dumps; swap.

## 5a. Final-review additions

* **Overlay / tapjacking:** `Window.setHideOverlayWindows(true)` (API 31+, normal permission `HIDE_OVERLAY_WINDOWS`), `filterTouchesWhenObscured` on the decor, content and Compose root views (instrumented-tested), so a malicious overlay can neither cover nor tap through sensitive controls while Cipher is visible.
* **Accessibility (API 34+):** the window is `ACCESSIBILITY_DATA_SENSITIVE_YES`, hiding its content from services that are not genuine accessibility tools. Older Android versions cannot make that distinction.
* **Keyboard and autofill:** all text input goes through `PrivateTextField` (autocorrect off, `privateImeOptions="nm"` = incognito for Gboard and compatible IMEs — **best effort**: a third-party keyboard may ignore it); `importantForAutofill = NO_EXCLUDE_DESCENDANTS` on the window. The PIN pad is a custom Compose keypad, so the system keyboard never sees the PIN.
* **Saved state:** nothing secret goes into `rememberSaveable`/`SavedStateHandle` (guard on variable names). Navigation arguments (random conversation ids) are saved by the system; they are identifiers, not secrets.
* **Untrusted media:** all image decoding of contact-supplied bytes uses `SafeDecode` (header check, ≤100 MP source, sub-sampling, `Throwable`-safe); players and PdfRenderer setup are guarded; PDFs are capped at 300 pages and page height 6000 px. Before this fix a 128 KB thumbnail declaring a huge image crashed the app every time the conversation was opened (FR-06).
* **Prompt lock:** background/screen-off/manual lock first call `requestLock()` and `OkHttp.cancelAll()` on the calling thread, then queue the ordered lock, so a running transfer cannot keep the vault unlocked behind it (FR-11).
* **Rollback detection:** `cipher.gen.<n>` Keystore entries hold a monotonic generation outside the data directory (FR-05); see `LOCAL_STORAGE_SECURITY.md` §8.

## 6. Notifications and background limits (ST-017)

Modes: `NO_CONTENT` (default), `SENDER_ONLY`, `CONTENT_WHEN_UNLOCKED`. Only the third ever puts text in a notification, and never while the vault is locked. No push provider is
configured (no FCM project): the interface accepts only the exact constant wake payload `{"v":1}`. Because the transport signing key lives in the vault, **a locked app cannot even
authenticate to the relay**, so a wake while locked can only show "New message". Delivery while the app is closed depends on a push integration that does not exist yet.

## 7. Release build

`assembleRelease`: minified + resource-shrunk, `isDebuggable=false`, no test CA, no cleartext, no software Keystore, no default relay. Signing needs `CIPHER_RELEASE_KEYSTORE*` environment variables; without them the build is **unsigned**
(and cannot be installed) — it is a verification artifact, not a distributable. Reproducible builds, SBOM and signed provenance are open (ST-014).
