#!/usr/bin/env bash
# Two clean checkouts at DIFFERENT paths, no release keys, no Gradle build cache.
# Usage: source scripts/android-env.sh; bash scripts/reproduce-release.sh
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  echo 'Commit the reviewed source before measuring reproducibility.' >&2
  exit 1
fi
unset CIPHER_RELEASE_KEYSTORE CIPHER_RELEASE_KEYSTORE_PASSWORD CIPHER_RELEASE_KEY_ALIAS CIPHER_RELEASE_KEY_PASSWORD CARGO_TARGET_DIR
commit=$(git rev-parse HEAD)
mkdir -p release-artifacts
work=$(mktemp -d "$PWD/release-artifacts/repro-XXXXXXXX")
printf '%s\n' "$commit" > "$work/commit.txt"
rustc -Vv > "$work/rust-toolchain.txt"
java -version 2> "$work/java.txt"
for name in first second-longer-path; do
  mkdir -p "$work/$name"
  git archive "$commit" | tar -x -C "$work/$name"
  (
    cd "$work/$name/android"
    ./gradlew --no-daemon --no-build-cache :app:assembleRelease :app:bundleRelease
  ) > "$work/$name-build.txt" 2>&1
  cp "$work/$name/android/app/build/outputs/apk/release/app-release-unsigned.apk" "$work/$name.apk"
  cp "$work/$name/android/app/build/outputs/bundle/release/app-release.aab" "$work/$name.aab"
done
cmp "$work/first.apk" "$work/second-longer-path.apk"
cmp "$work/first.aab" "$work/second-longer-path.aab"
python3 scripts/gen_sbom.py -o "$work/sbom.cdx.json"
(
  cd "$work"
  sha256sum first.apk second-longer-path.apk first.aab second-longer-path.aab sbom.cdx.json > SHA256SUMS
)
printf 'PASS: unsigned APK and AAB match byte-for-byte at commit %s\nEvidence: %s\n' "$commit" "$work"
