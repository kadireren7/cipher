#!/usr/bin/env bash
# One-command signing ceremony for the owner: creates the permanent key (if none exists), makes a VERIFIED backup of it, then builds
# and verifies the signed APK/AAB. The only secret, the key password, is typed at a hidden prompt, lives in this process's environment
# and is never written to a file, a log or a command line.
#
#   bash scripts/release-ceremony.sh
#
# Writes (outside the repo) ~/.cipher-signing/BACKUP-CONFIRMED: where the verified backup is and the keystore SHA-256. No secrets.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$(pwd -P)"
DIR="${CIPHER_SIGNING_DIR:-$HOME/.cipher-signing}"
KS="$DIR/cipher-release.p12"
ALIAS="cipher-release"
MARK="$DIR/BACKUP-CONFIRMED"
command -v keytool >/dev/null || { echo "keytool (JDK 17+) not found" >&2; exit 2; }
case "$DIR" in "$REPO"/*) echo "the signing directory must be outside the repository" >&2; exit 2;; esac
[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo "refusing: uncommitted changes" >&2; exit 2; }
git fetch -q origin
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/feat/self-hosted-multi-relay)" ] || { echo "refusing: HEAD is not the pushed tip of feat/self-hosted-multi-relay" >&2; exit 2; }
mkdir -p "$DIR"; chmod 700 "$DIR"

prompt_password() {
  local a b
  while :; do
    read -rsp "Choose the key password (>= 14 characters; store it in a password manager): " a; echo
    [ "${#a}" -ge 14 ] || { echo "too short"; continue; }
    read -rsp "Repeat it: " b; echo
    [ "$a" = "$b" ] && break || echo "they differ"
  done
  CIPHER_RELEASE_KEYSTORE_PASSWORD="$a"
}

if [ ! -f "$KS" ]; then
  echo "== 1/4 create the permanent signing key =="
  read -rp "Your name or organisation (shown in the certificate): " CN
  [ -n "$CN" ] || { echo "a name is required" >&2; exit 2; }
  prompt_password
  export CIPHER_RELEASE_KEYSTORE_PASSWORD
  umask 077
  keytool -genkeypair -storetype PKCS12 -keystore "$KS" -alias "$ALIAS" -keyalg RSA -keysize 4096 -validity 10000 \
    -dname "CN=$CN, O=Cipher release" -storepass:env CIPHER_RELEASE_KEYSTORE_PASSWORD -keypass:env CIPHER_RELEASE_KEYSTORE_PASSWORD
  chmod 600 "$KS"
else
  echo "== 1/4 using the existing key $KS =="
  read -rsp "Key password: " CIPHER_RELEASE_KEYSTORE_PASSWORD; echo
  export CIPHER_RELEASE_KEYSTORE_PASSWORD
  keytool -list -keystore "$KS" -alias "$ALIAS" -storepass:env CIPHER_RELEASE_KEYSTORE_PASSWORD >/dev/null || { echo "wrong password" >&2; exit 2; }
fi
SUM="$(sha256sum "$KS" | cut -d' ' -f1)"

echo "== 2/4 mandatory backup =="
echo "Losing this key means no future update can ever be signed with the same identity. A backup on ANOTHER device is required."
backup_one() {
  local d="$1" what="$2"
  [ -n "$d" ] && [ -d "$d" ] && [ -w "$d" ] || { echo "not a writable directory: $d" >&2; return 1; }
  d="$(cd "$d" && pwd -P)"
  case "$d" in "$REPO"/*) echo "backup must be outside the repository" >&2; return 1;; esac
  if [ "$(stat -c %d "$d")" = "$(stat -c %d "$DIR")" ]; then echo "$d is on the same filesystem as the key: that is not a backup" >&2; return 1; fi
  cp "$KS" "$d/cipher-release.p12" && chmod 600 "$d/cipher-release.p12"
  cmp -s "$KS" "$d/cipher-release.p12" || { echo "copy differs" >&2; return 1; }
  keytool -list -keystore "$d/cipher-release.p12" -alias "$ALIAS" -storepass:env CIPHER_RELEASE_KEYSTORE_PASSWORD >/dev/null || { echo "backup does not open" >&2; return 1; }
  echo "verified $what: $d/cipher-release.p12"
  BACKUPS+=("$d/cipher-release.p12")
}
BACKUPS=()
if [ "${CIPHER_WAIVE_BACKUP:-}" = "I-ACCEPT-THAT-LOSING-THE-KEY-ENDS-UPDATES" ]; then
  echo "BACKUP WAIVED by the owner: if the keystore or its password is lost, no update can ever be signed with this identity (users must uninstall and lose their data)."
  { echo "keystore sha256: $SUM"; echo "verified at: $(date -u +%FT%TZ)"; echo "backup: WAIVED by owner (CIPHER_WAIVE_BACKUP)"; } > "$MARK"
else
until [ "${#BACKUPS[@]}" -ge 1 ]; do
  read -rp "Backup directory on a DIFFERENT device (e.g. a mounted encrypted USB drive): " D1
  backup_one "$D1" "backup 1" || true
done
read -rp "Optional second backup directory (Enter to skip, strongly recommended): " D2
[ -z "$D2" ] || backup_one "$D2" "backup 2" || true
{ echo "keystore sha256: $SUM"; echo "verified at: $(date -u +%FT%TZ)"; printf 'backup: %s\n' "${BACKUPS[@]}"; } > "$MARK"
fi
echo "Also store the password in a password manager NOW; it is not recorded anywhere."

echo "== 3/4 build, sign and verify =="
export CIPHER_RELEASE_KEYSTORE="$KS" CIPHER_RELEASE_KEY_ALIAS="$ALIAS"
unset CIPHER_ALLOW_TEST_KEY
bash scripts/build-signed-release.sh

echo "== 4/4 done =="
echo "Tell Claude: the ceremony finished. Nothing secret was written to disk."
