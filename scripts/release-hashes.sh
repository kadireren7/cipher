#!/usr/bin/env bash
# Writes SHA256SUMS for the final artifacts and the build inputs that matter for provenance. Usage: release-hashes.sh [dir]
set -euo pipefail
cd "$(dirname "$0")/.."
DIR="${1:-release-artifacts}"; mkdir -p "$DIR"
{
  for f in android/app/build/outputs/apk/release/app-release-unsigned.apk android/app/build/outputs/apk/debug/app-debug.apk "$DIR"/*.apk; do
    [ -f "$f" ] && sha256sum "$f"
  done
  sha256sum Cargo.lock android/gradle/libs.versions.toml android/gradle/verification-metadata.xml rust-toolchain.toml
  [ ! -f "$DIR/sbom.cdx.json" ] || sha256sum "$DIR/sbom.cdx.json"
  for f in android/app/build/rustJniLibs/*/libcipher_ffi.so; do [ -f "$f" ] && sha256sum "$f"; done
} > "$DIR/SHA256SUMS"
{
  echo "git commit: $(git rev-parse HEAD 2>/dev/null || echo 'none')"
  if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    echo 'working tree: DIRTY (artifact provenance is not a clean commit)'
  else
    echo 'working tree: clean'
  fi
} > "$DIR/PROVENANCE.txt"
cat "$DIR/SHA256SUMS"
