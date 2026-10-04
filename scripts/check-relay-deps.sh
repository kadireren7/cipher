#!/usr/bin/env bash
# SEC-002: the relay must not (transitively) depend on message-crypto / client crates, and
# test-only insecure features must not exist in the production dependency graph.
set -euo pipefail
cd "$(dirname "$0")/.."

FORBIDDEN='^(openmls[a-z_-]*|cipher-core|chacha20poly1305|aes-gcm|argon2|hkdf|hpke-rs[a-z-]*|x25519-dalek|x-wing|ml-kem|ml-dsa|libcrux[a-z-]*)$'
deps=$(cargo tree -p cipher-relay -e normal,build --prefix none 2>/dev/null | awk '{print $1}' | sort -u)
bad=$(echo "$deps" | grep -E "$FORBIDDEN" || true)
if [ -n "$bad" ]; then
  echo "FAIL: relay depends on forbidden crates:"; echo "$bad"; exit 1
fi

# insecure-test-support must never be enabled in the normal/build dependency graph of any member.
if cargo tree --workspace -e normal,build -f '{p} [{f}]' 2>/dev/null | grep -q 'insecure-test-support'; then
  echo "FAIL: insecure-test-support is enabled in a production dependency graph"; exit 1
fi
echo "ok: relay dependency graph has no message-crypto crates; no insecure test features in production graph"
