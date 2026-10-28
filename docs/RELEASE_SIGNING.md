# Release signing and artifact provenance

**No signing material is, or may ever be, committed, uploaded to GitHub Actions, printed in a log, or put in an artifact.** The permanent release identity is created and held by the owner on their own machine.

**Status (2026-10-28): the pipeline is implemented and was exercised end to end with a throwaway test key (see "What was verified"). No permanent release key exists yet, so no official signed APK/AAB exists yet.** An APK that is unsigned, or signed with the Android debug key or a test key, is never the official release.

## One-time: create the permanent key (you, locally)

```bash
bash scripts/generate-release-key.sh
```

* Interactive: `keytool` asks for the passwords and your identity details itself, so nothing secret reaches a command line, shell history or file.
* Writes `~/.cipher-signing/cipher-release.p12` (PKCS12, RSA 4096, ~27 years). The script refuses to put it inside the repository and refuses to overwrite an existing keystore.
* It prints the public certificate fingerprint. **Record that SHA-256 fingerprint** (it is public): it is the identity every future update must keep.

## Every release: build, sign, verify

```bash
export CIPHER_RELEASE_KEYSTORE="$HOME/.cipher-signing/cipher-release.p12"
export CIPHER_RELEASE_KEY_ALIAS=cipher-release
read -rs CIPHER_RELEASE_KEYSTORE_PASSWORD && export CIPHER_RELEASE_KEYSTORE_PASSWORD   # typed, never written to disk
export CIPHER_RELEASE_PINNED_SHA256=<fingerprint recorded above>                       # from the second release on, mandatory in practice
bash scripts/build-signed-release.sh
```

`build-signed-release.sh` fails closed. It refuses when:
the key variables are missing (it prints the exact commands instead and builds nothing); the keystore is inside the repository; the working tree is dirty; Gradle left the APK unsigned; the release manifest/secret gate (`scripts/check-release-apk.sh`) fails; `apksigner verify` does not report APK Signature Scheme v3 with exactly one signer (the separate v2 block is omitted by design because minSdk is 30; v1 is off); the signer is the Android debug certificate; the certificate differs from `CIPHER_RELEASE_PINNED_SHA256`; the AAB is not signed by the same certificate as the APK.

**Distribution policy:** the signed AAB is built on every release for a possible future Google Play submission, but it is **not** attached to GitHub Releases and nothing uploads it automatically (no workflow or script publishes releases; publishing is a deliberate manual step). GitHub Releases carry the APK, `SHA256SUMS` and `SIGNING-CERT.txt` only; `SHA256SUMS` still lists the AAB, so verify with `sha256sum -c --ignore-missing SHA256SUMS`.

Output in `release-artifacts/` (git-ignored): `cipher-<version>-release.apk`, `cipher-<version>-release.aab`, `SHA256SUMS` (check with `sha256sum -c SHA256SUMS`), `SIGNING-CERT.txt` (public fingerprint), `BUILD-INPUTS.sha256` and `PROVENANCE.txt` (commit, clean/dirty tree, hashes of `Cargo.lock`, the Gradle catalogue and verification metadata, the toolchain file and the native libraries).

Independent re-check by anyone: `apksigner verify --print-certs cipher-<version>-release.apk` and compare the SHA-256 digest with the fingerprint you published.

## Identity and update compatibility

* Application ID is `app.cipher.messenger`; the signing certificate plus the application ID is what Android uses to accept an update. Changing either breaks upgrades: users would have to uninstall, which **deletes their vault** (there is no recovery by design).
* `versionCode = MAJOR*10000 + MINOR*100 + PATCH` from `/VERSION` and must grow with every release handed to anyone. The first signed alpha is `0.1.0-alpha` (code 100); no earlier build was ever distributed signed, so there is no installed base with a higher code. Internal unsigned developer builds of `0.3.0-experimental.1` (code 300) cannot be updated in place by it; uninstall them first.
* Debug builds use the application ID `app.cipher.messenger.debug`, so they never replace or conflict with a release install.

## Backup and recovery of the signing key

Loss of the keystore or its password = no more updates under this identity; there is no recovery by Cipher, Google or GitHub.

1. Immediately after creation, make **two** encrypted copies of the `.p12` on different media (for example an encrypted USB drive kept away from the computer, and an encrypted offline archive). Test that each opens with `keytool -list -keystore <copy>`.
2. Keep the password in a password manager and a sealed offline note, **separately** from the keystore copies.
3. Write down the SHA-256 fingerprint in a place that is not the keystore.
4. Never put the keystore or password in the repository, a GitHub secret, a chat, an email or a cloud-synced folder that is not end-to-end encrypted.
5. If the key may have leaked: stop distributing, publish a notice, and ship a new identity as a new app listing (Android cannot revoke a v2 key). With APK Signature Scheme v3 key rotation (proof-of-rotation lineage) an update signed by a new key can be accepted by devices that trust the old one; this has **not** been set up or tested here, so treat it as an option to design before it is needed.
6. If you later enrol in Google Play App Signing, the key you upload becomes the upload key and Google holds the app-signing key: record that change here.

## CI

CI never receives the release key. Pull-request builds get no secrets (no `pull_request_target`, `permissions: contents: read`). CI builds an **unsigned** release APK/AAB and the `release pipeline (test key)` job proves the signing script on an ephemeral key generated inside the job and discarded with it; its outputs are named `TEST-SIGNED-NOT-OFFICIAL`. A protected, manually approved signing workflow would need a hardware-backed signer; none is configured and none is recommended before a key custody plan exists.

## What was verified

See `RELEASE_READINESS.md` (§ v0.1.0-alpha) for the runs and results: the pipeline against a throwaway key (APK v3, AAB, identical certificate, pin check and refusal cases) and the CI job. **Not verified: a signature by the permanent key, because it does not exist yet; installation of the signed APK on a physical device.**

## Reproducibility

`bash scripts/reproduce-release.sh` builds APK and AAB from two clean committed checkouts at different paths with signing variables removed and Gradle's build cache disabled; results stay under `release-artifacts/repro-*`. Bit-for-bit reproducibility is **not claimed** unless `FINAL_SECURITY_REVIEW.md` §Supply chain says it was measured for the commit in question. An SBOM (`scripts/gen_sbom.py`) and a signature do not prove a build is reproducible or the source is safe.
