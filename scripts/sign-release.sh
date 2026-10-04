#!/usr/bin/env bash
# Signs the release APK. NEVER stores or prints key material: everything comes from the environment of the machine that holds the key.
#   CIPHER_RELEASE_KEYSTORE            path to the release keystore (PKCS12/JKS) — kept OFFLINE or on a hardware token/HSM-backed host
#   CIPHER_RELEASE_KEYSTORE_PASSWORD   keystore password           CIPHER_RELEASE_KEY_ALIAS / CIPHER_RELEASE_KEY_PASSWORD
# CI must NOT have these for pull-request builds (the workflow does not pass secrets to PRs). Release signing is a manual,
# protected step on a trusted machine; see docs/RELEASE_SIGNING.md.
set -euo pipefail
: "${CIPHER_RELEASE_KEYSTORE:?set CIPHER_RELEASE_KEYSTORE}" "${CIPHER_RELEASE_KEYSTORE_PASSWORD:?}" "${CIPHER_RELEASE_KEY_ALIAS:?}"
cd "$(dirname "$0")/.."
SDK="${ANDROID_HOME:?ANDROID_HOME not set}"
BT=$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)
IN=android/app/build/outputs/apk/release/app-release-unsigned.apk
OUT_DIR=release-artifacts; mkdir -p "$OUT_DIR"
"$BT/zipalign" -p -f 4 "$IN" "$OUT_DIR/cipher-aligned.apk"
"$BT/apksigner" sign --ks "$CIPHER_RELEASE_KEYSTORE" --ks-key-alias "$CIPHER_RELEASE_KEY_ALIAS" \
  --ks-pass env:CIPHER_RELEASE_KEYSTORE_PASSWORD ${CIPHER_RELEASE_KEY_PASSWORD:+--key-pass env:CIPHER_RELEASE_KEY_PASSWORD} \
  --v2-signing-enabled true --v3-signing-enabled true --out "$OUT_DIR/cipher-release.apk" "$OUT_DIR/cipher-aligned.apk"
rm -f "$OUT_DIR/cipher-aligned.apk" "$OUT_DIR"/*.idsig
"$BT/apksigner" verify --verbose --print-certs "$OUT_DIR/cipher-release.apk" | grep -E "Verifies|Number of signers|SHA-256 digest" 
bash scripts/release-hashes.sh "$OUT_DIR"
