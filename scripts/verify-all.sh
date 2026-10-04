#!/usr/bin/env bash
# Phase-19 verification: clean build, all tests, all security tooling. Exits non-zero on the first failure.
# Usage: scripts/verify-all.sh [--no-clean]
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }

if [ "${1:-}" != "--no-clean" ]; then
  step "clean state"
  cargo clean
fi

step "rust: format"            ; cargo fmt --all -- --check
step "rust: clippy -D warnings"; cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
step "rust: release build"     ; cargo build --workspace --release --locked
step "rust: all tests"         ; cargo test --workspace --all-features --locked
step "invariant registry"      ; python3 scripts/check_invariants.py
step "invariant doc is fresh"  ; python3 scripts/gen_invariants_doc.py --check
step "relay dependency graph"  ; bash scripts/check-relay-deps.sh
step "secret scan"             ; python3 scripts/secret_scan.py
step "cargo deny"              ; cargo deny check
step "cargo audit"             ; cargo audit --deny warnings
step "ffi: kotlin bindings generate" ; cargo build -p cipher-ffi --features cli --locked && cargo run -q -p cipher-ffi --features cli --locked --bin uniffi-bindgen -- generate --library target/debug/libcipher_ffi.so --language kotlin --out-dir "$(mktemp -d)" --no-format
step "shipped graph has no experimental crates" ; ! cargo tree -p cipher-ffi -e normal --locked | grep -E "ct-merkle|insecure"
if [ -n "${ANDROID_HOME:-}" ]; then
  step "android: unit tests + ktlint + lint + debug/release build"
  (cd android && ./gradlew :app:testDebugUnitTest :app:ktlintCheck :app:lintDebug :app:assembleDebug :app:assembleRelease) && bash scripts/check-release-apk.sh
else
  echo "SKIPPED android steps (ANDROID_HOME not set)"
fi
printf '\nALL VERIFICATION STEPS PASSED (instrumented tests are separate: scripts/ci-emulator-tests.sh or ./gradlew connectedDebugAndroidTest)\n'
