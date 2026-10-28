#!/usr/bin/env bash
# Creates the PERMANENT Cipher release signing key. Run this yourself, on a machine you trust. Interactive on purpose:
# keytool asks for the passwords and your name/organisation itself, so no secret ever appears in a command line, a shell
# history, a script or a log. This script never reads, stores or prints a password.
#
#   bash scripts/generate-release-key.sh                      # keystore goes to ~/.cipher-signing/cipher-release.p12
#   CIPHER_RELEASE_KEYSTORE=/path/key.p12 bash scripts/generate-release-key.sh
#
# The keystore must live OUTSIDE the git checkout. Losing it, or its password, means future updates cannot be signed with the
# same identity: Android will refuse to install them over the old app. Back it up before you ship anything (docs/RELEASE_SIGNING.md).
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$(pwd -P)"
KS="${CIPHER_RELEASE_KEYSTORE:-$HOME/.cipher-signing/cipher-release.p12}"
ALIAS="${CIPHER_RELEASE_KEY_ALIAS:-cipher-release}"

mkdir -p "$(dirname "$KS")"
KS="$(cd "$(dirname "$KS")" && pwd -P)/$(basename "$KS")"
case "$KS" in "$REPO"/*) echo "refusing: the keystore must be outside the repository ($REPO)" >&2; exit 2;; esac
if [ -e "$KS" ]; then
  echo "refusing to overwrite the existing keystore $KS (that would destroy the signing identity)." >&2
  echo "Delete it yourself only if you are certain no release was ever signed with it." >&2
  exit 2
fi
command -v keytool >/dev/null || { echo "keytool not found: install a JDK (17+)." >&2; exit 2; }

echo "Creating $KS (alias '$ALIAS'). keytool will now ask for a keystore password and your identity details."
echo "Choose a long random password and store it in a password manager. For PKCS12 the key password equals the keystore password."
umask 077
# 4096-bit RSA, ~27 years: covers the Google Play requirement that a key stays valid well past the app's life.
keytool -genkeypair -v -storetype PKCS12 -keystore "$KS" -alias "$ALIAS" -keyalg RSA -keysize 4096 -validity 10000
chmod 600 "$KS"

echo
echo "Public certificate fingerprint (safe to publish; this is the identity users and updates are checked against):"
echo "Enter the keystore password again to display it."
keytool -list -v -keystore "$KS" -alias "$ALIAS" | grep -E "Owner|SHA256|Valid"
cat <<EOF

NEXT (all on your machine; nothing here goes into git or GitHub):
  1. BACK UP $KS now: at least two encrypted copies on different media, and the password somewhere separate.
  2. Build and sign the release (the password is read from your terminal, never written to disk):
       export CIPHER_RELEASE_KEYSTORE="$KS"
       export CIPHER_RELEASE_KEY_ALIAS="$ALIAS"
       read -rs CIPHER_RELEASE_KEYSTORE_PASSWORD && export CIPHER_RELEASE_KEYSTORE_PASSWORD
       export CIPHER_RELEASE_KEY_PASSWORD="\$CIPHER_RELEASE_KEYSTORE_PASSWORD"
       bash scripts/build-signed-release.sh
EOF
