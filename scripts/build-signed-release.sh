#!/usr/bin/env bash
# Builds, signs and verifies the official Cipher release artifacts (APK + AAB) in one run, on the machine that holds the key.
# Never generates a signing identity (that is scripts/generate-release-key.sh, run by the owner) and never prints a secret.
#
# Inputs (environment only; nothing signing-related is read from or written to the repository):
#   CIPHER_RELEASE_KEYSTORE            path to the keystore, outside the checkout
#   CIPHER_RELEASE_KEYSTORE_PASSWORD   keystore password
#   CIPHER_RELEASE_KEY_ALIAS           key alias
#   CIPHER_RELEASE_KEY_PASSWORD        optional; defaults to the keystore password (always the case for PKCS12)
#   CIPHER_RELEASE_PINNED_SHA256       optional; the signing certificate SHA-256 you expect. Set it for every release after the
#                                      first one: the build fails if the identity differs, so an update can never be signed by accident
#                                      with the wrong key.
#   CIPHER_ALLOW_TEST_KEY=1            ONLY for pipeline tests with a throwaway key: marks the output "TEST-SIGNED" and non-installable as
#                                      an official release. Never use it for a release.
#
# Output (release-artifacts/): cipher-<version>-release.apk, cipher-<version>-release.aab, SHA256SUMS, PROVENANCE.txt, SIGNING-CERT.txt
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$(pwd -P)"

need_key() {
  cat >&2 <<EOF
No release signing key is configured, so nothing was built or signed (an unsigned or debug-signed APK is never presented as the release).

Create the permanent key once, on your own machine (interactive; the password never touches a file):
    bash scripts/generate-release-key.sh
then sign the release:
    export CIPHER_RELEASE_KEYSTORE="\$HOME/.cipher-signing/cipher-release.p12"
    export CIPHER_RELEASE_KEY_ALIAS=cipher-release
    read -rs CIPHER_RELEASE_KEYSTORE_PASSWORD && export CIPHER_RELEASE_KEYSTORE_PASSWORD
    bash scripts/build-signed-release.sh
EOF
  exit 2
}
[ -n "${CIPHER_RELEASE_KEYSTORE:-}" ] && [ -n "${CIPHER_RELEASE_KEYSTORE_PASSWORD:-}" ] && [ -n "${CIPHER_RELEASE_KEY_ALIAS:-}" ] || need_key
[ -f "$CIPHER_RELEASE_KEYSTORE" ] || { echo "keystore not found: $CIPHER_RELEASE_KEYSTORE" >&2; need_key; }
KS="$(cd "$(dirname "$CIPHER_RELEASE_KEYSTORE")" && pwd -P)/$(basename "$CIPHER_RELEASE_KEYSTORE")"
case "$KS" in "$REPO"/*) echo "refusing: the keystore is inside the repository ($KS). Move it out and rotate if it was ever committed." >&2; exit 2;; esac
export CIPHER_RELEASE_KEYSTORE="$KS"
export CIPHER_RELEASE_KEY_PASSWORD="${CIPHER_RELEASE_KEY_PASSWORD:-$CIPHER_RELEASE_KEYSTORE_PASSWORD}"

if [ -z "${ANDROID_HOME:-}" ]; then
  for d in "$HOME/Android/Sdk" "$HOME/android-sdk"; do [ -d "$d" ] && export ANDROID_HOME="$d" && break; done
fi
: "${ANDROID_HOME:?ANDROID_HOME is not set and no SDK was found}"
BT="$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)"
VERSION="$(tr -d '[:space:]' < VERSION)"
OUT="$REPO/release-artifacts"

# The tree that is signed must be the tree that is recorded: a dirty tree is refused for an official release.
if [ -n "$(git status --porcelain --untracked-files=no)" ] && [ "${CIPHER_ALLOW_TEST_KEY:-}" != "1" ]; then
  echo "refusing: the working tree has uncommitted changes, so the signed artifacts would not match any commit." >&2; exit 2
fi

echo "== build (Rust core for arm64-v8a + x86_64, then APK and AAB), version $VERSION =="
( cd android && ./gradlew --no-daemon --console=plain :app:assembleRelease :app:bundleRelease )
APK_SRC=android/app/build/outputs/apk/release/app-release.apk
AAB_SRC=android/app/build/outputs/bundle/release/app-release.aab
[ -f "$APK_SRC" ] || { echo "no signed APK produced (Gradle left it unsigned: is the signing config active?)" >&2; exit 1; }
[ -f "$AAB_SRC" ] || { echo "no AAB produced" >&2; exit 1; }

echo "== manifest and secret gate on the real release APK =="
bash scripts/check-release-apk.sh

echo "== verify signature =="
CERTS="$("$BT/apksigner" verify --verbose --print-certs "$APK_SRC")"
echo "$CERTS" | grep -E "^Verifies|Verified using|Number of signers|certificate (DN|SHA-256)"
echo "$CERTS" | grep -q "^Verifies" || { echo "apksigner did not verify the APK" >&2; exit 1; }
# minSdk is 30 (>= 28), so apksigner/AGP omit the separate v2 block: v3 alone is verified by every supported Android version.
echo "$CERTS" | grep -q "Verified using v3 scheme (APK Signature Scheme v3): true" || { echo "APK is not v3-signed" >&2; exit 1; }
[ "$(echo "$CERTS" | sed -n 's/^Number of signers: //p')" = "1" ] || { echo "expected exactly one signer" >&2; exit 1; }
if echo "$CERTS" | grep -qi "Android Debug"; then echo "refusing: the APK is signed with the Android DEBUG key, not a release identity" >&2; exit 1; fi
CERT_SHA="$(echo "$CERTS" | sed -n 's/.*[Ss]igner.*certificate SHA-256 digest: //p' | sort -u)"
[ "$(echo "$CERT_SHA" | wc -l)" = "1" ] || { echo "the v2 and v3 signatures carry different certificates: $CERT_SHA" >&2; exit 1; }
[ -n "$CERT_SHA" ] || { echo "could not read the signer certificate digest" >&2; exit 1; }
if [ -n "${CIPHER_RELEASE_PINNED_SHA256:-}" ]; then
  want="$(echo "$CIPHER_RELEASE_PINNED_SHA256" | tr -d ': ' | tr 'A-F' 'a-f')"
  [ "$want" = "$CERT_SHA" ] || { echo "signing identity mismatch: expected $want, got $CERT_SHA. Refusing: updates must keep the same identity." >&2; exit 1; }
  echo "signing identity matches the pinned fingerprint"
fi

echo "== verify AAB signature =="
# jarsigner prints the signer certificate; the AAB must carry the SAME certificate as the APK.
AAB_CERT_SHA="$(keytool -printcert -jarfile "$AAB_SRC" | sed -n 's/^[[:space:]]*SHA256: //p' | head -1 | tr -d ':' | tr 'A-F' 'a-f')"
jarsigner -verify "$AAB_SRC" | grep -q "jar verified" || { echo "AAB signature did not verify" >&2; exit 1; }
[ "$AAB_CERT_SHA" = "$CERT_SHA" ] || { echo "AAB and APK are signed by different certificates ($AAB_CERT_SHA vs $CERT_SHA)" >&2; exit 1; }
echo "AAB verified, same certificate as the APK"

mkdir -p "$OUT"
TAG=""; [ "${CIPHER_ALLOW_TEST_KEY:-}" = "1" ] && TAG="-TEST-SIGNED-NOT-OFFICIAL"
APK="$OUT/cipher-$VERSION-release$TAG.apk"; AAB="$OUT/cipher-$VERSION-release$TAG.aab"
cp "$APK_SRC" "$APK"; cp "$AAB_SRC" "$AAB"
printf 'signer certificate SHA-256 (public): %s\nversion: %s\n' "$CERT_SHA" "$VERSION" > "$OUT/SIGNING-CERT.txt"
bash scripts/release-hashes.sh "$OUT" >/dev/null           # build inputs + provenance, kept apart from the artifact checksums
mv "$OUT/SHA256SUMS" "$OUT/BUILD-INPUTS.sha256"
( cd "$OUT" && sha256sum "$(basename "$APK")" "$(basename "$AAB")" > SHA256SUMS )

echo
echo "SIGNED APK : $APK"
echo "SIGNED AAB : $AAB"
echo "SHA-256    : $OUT/SHA256SUMS   (verify with: cd release-artifacts && sha256sum -c SHA256SUMS)"
echo "SIGNING ID : $CERT_SHA"
[ -z "$TAG" ] || echo "NOTE: built with CIPHER_ALLOW_TEST_KEY=1 — a pipeline test, NOT an official release."
