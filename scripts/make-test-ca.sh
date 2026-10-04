#!/usr/bin/env bash
# Creates a THROWAWAY test CA and a relay certificate for local/emulator testing.
#  * The CA *certificate* is copied into the DEBUG build's res/raw (src/debug, gitignored) so the debug app trusts it through
#    network-security-config <debug-overrides> — release builds never include it.
#  * The CA private key and the relay key stay under android/build/test-ca/ (build output, gitignored). Nothing secret is committed.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=android/build/test-ca
RAW=android/app/src/debug/res/raw
mkdir -p "$OUT" "$RAW"
if [ ! -f "$OUT/ca.pem" ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/ca.key"
  openssl req -x509 -new -key "$OUT/ca.key" -sha256 -days 30 -subj "/CN=Cipher Test CA (throwaway)" -out "$OUT/ca.pem"
  openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/relay.key"
  openssl req -new -key "$OUT/relay.key" -subj "/CN=cipher-test-relay" -out "$OUT/relay.csr"
  printf 'subjectAltName=DNS:localhost,DNS:relay.cipher.test,IP:127.0.0.1,IP:10.0.2.2\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > "$OUT/ext.cnf"
  openssl x509 -req -in "$OUT/relay.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" -CAcreateserial -days 30 -sha256 -extfile "$OUT/ext.cnf" -out "$OUT/relay.pem"
  cat "$OUT/relay.pem" "$OUT/ca.pem" > "$OUT/relay-chain.pem"
fi
cp "$OUT/ca.pem" "$RAW/test_ca.pem"
echo "test CA ready: $OUT (cert installed for debug builds at $RAW/test_ca.pem)"
