#!/usr/bin/env bash
# Static analysis of the RELEASE APK (final review, phase 14). Unpacks it and searches dex, native libraries and resources for things that
# must not ship: secrets, private keys, test fixtures, dev flags/bypasses, debug endpoints, unexpected URLs, developer machine paths.
# Exit code != 0 if any hard failure is found. Usage: analyze-release-apk.sh [apk]
set -uo pipefail
cd "$(dirname "$0")/.."
APK="${1:-android/app/build/outputs/apk/release/app-release-unsigned.apk}"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
unzip -q -o "$APK" -d "$W"
SDK="${ANDROID_HOME:-$HOME/android-sdk}"; BT=$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)
fail=0
note() { printf '%s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*"; fail=1; }
all_strings() { { for f in "$W"/classes*.dex "$W"/lib/*/*.so; do strings -a -n 6 "$f"; done; find "$W/res" "$W/assets" -type f 2>/dev/null -exec strings -a -n 6 {} \; ; strings -a -n 6 "$W/resources.arsc"; } 2>/dev/null; }
all_strings | sort -u > "$W/.all"
note "files: $(find "$W" -type f | wc -l)  unique strings: $(wc -l < "$W/.all")"

note "== must-not-appear (hard failures)"
for pat in 'BEGIN [A-Z ]*PRIVATE KEY' 'PLAINTEXT-FIXTURE' '-MARKER-' 'debug_no_user_auth' 'insecure-test-support' 'INSECURE_DEV_HTTP' 'CIPHER_RELAY_' 'test_ca' 'devonly-not-a-secret' 'registration_token_hash' 'AKIA[0-9A-Z]{16}' 'ghp_[A-Za-z0-9]{20}' '10\.0\.2\.2' 'localhost:|127\.0\.0\.1'; do
  hits=$(grep -aE -e "$pat" "$W/.all" | head -3)
  if [ -n "$hits" ]; then bad "pattern /$pat/ found:"; printf '   %s\n' "$hits"; fi
done
note "== developer machine paths embedded in native code (privacy / reproducibility)"
if grep -aE '/home/[a-z0-9_-]+/' "$W/.all" | head -3 | grep -q .; then
  note "WARN: build-machine paths present:"; grep -aE '/home/[a-z0-9_-]+/' "$W/.all" | sed 's/^/   /' | head -5
else note "none"; fi
note "== URLs in the APK (everything that is not a well-known schema/namespace is listed)"
grep -aoE 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+' "$W/.all" | sort -u | grep -vE 'schemas\.android\.com|www\.w3\.org|apache\.org/licenses|xmlpull\.org|ns\.adobe\.com|purl\.org|github\.com/(square|java-native-access|JetBrains|google|androidx)|developer\.android\.com|kotlinlang\.org|jetbrains\.com|google\.com/|issuetracker|www\.google|reactivex|slf4j\.org' > "$W/.urls"
if grep -q 'http://' "$W/.urls"; then note "cleartext http:// URLs (library docs/constants?):"; grep 'http://' "$W/.urls" | sed 's/^/   /' | head -10; else note "no http:// URLs"; fi
note "https:// URLs: $(grep -c 'https://' "$W/.urls")"; grep 'https://' "$W/.urls" | sed 's/^/   /' | head -12
note "== manifest"
bash scripts/check-release-apk.sh >/dev/null 2>&1 && note "merged-manifest gate: ok" || bad "merged-manifest gate failed (run scripts/check-release-apk.sh)"
note "== native libraries"
for so in "$W"/lib/*/libcipher_ffi.so; do note "$so: $(stat -c %s "$so") bytes; symbols: $(nm -D --defined-only "$so" 2>/dev/null | wc -l) dynamic exports; panic strings: $(strings -a "$so" | grep -c 'panicked at')"; done
note "== dex"
for d in "$W"/classes*.dex; do note "$(basename "$d"): $("$BT/dexdump" -f "$d" 2>/dev/null | grep -c 'Class descriptor')" classes; done
note "BuildConfig flags: $(grep -a 'ALLOW_SOFTWARE' "$W/.all" | head -2 | tr '\n' ' ')"
[ "$fail" = 0 ] && note "RESULT: no hard failures" || note "RESULT: FAILURES (see above)"
exit $fail
