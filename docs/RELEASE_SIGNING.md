# Release signing and artifact provenance

**No signing material is, or may ever be, committed.** This document describes the architecture; nothing here has been exercised with a real release key.

## Roles

| Step | Where | Who | Secrets |
| --- | --- | --- | --- |
| Build the unsigned release APK (`./gradlew :app:assembleRelease`) | Any trusted machine / CI | Anyone | none |
| Manifest gate (`scripts/check-release-apk.sh`) | same | automatic | none |
| Sign (`scripts/sign-release.sh`) | **Offline or hardware-token host** | Release owner | keystore + passwords **only in that process's environment** |
| Hashes (`scripts/release-hashes.sh`) | same | automatic | none |
| Publish APK + `SHA256SUMS` (+ detached signature of the sums) | release host | Release owner | signing key for the sums (separate from the APK key is better) |

CI **never** receives the release key: pull-request builds get no secrets (no `pull_request_target`; `permissions: contents: read`). A protected, manually approved workflow could sign with a key held in a hardware-backed signer, but none is configured.

## Properties and limits

* APK Signature Scheme v2/v3 (`apksigner`); the key alias/password come from `CIPHER_RELEASE_KEY*` environment variables; Gradle's `signingConfigs.release` only activates when they are set, so a plain build is **unsigned** and cannot be installed by accident.
* Key rotation uses APK Signature Scheme v3 lineage; **no rotation plan or key backup exists yet** — losing the key means users must reinstall under a new key and lose their data (there is no recovery by design).
* `release-hashes.sh` records SHA-256 of the APKs, the generated JNI libraries, `Cargo.lock`, the Gradle catalogue and verification metadata, the Rust toolchain file and the git commit (or states that the tree is uncommitted).

## Reproducibility

See `FINAL_SECURITY_REVIEW.md` §Supply chain for the measured result of building twice. Bit-for-bit reproducibility is **not claimed** unless that section says it was achieved.
