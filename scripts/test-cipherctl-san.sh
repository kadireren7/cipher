#!/usr/bin/env bash
# Regression test: a self-signed relay certificate made by `cipherctl.sh init --tls-self-signed` must carry an iPAddress SAN for an IP literal
# (a DNS SAN never matches an IP, so Android refused every LAN-IP relay) and a DNS SAN for a host name. Runs in a temp copy; touches nothing else.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
check() {
  local audience="$1" want="$2" d="$tmp/$3"
  mkdir -p "$d"; cp "$here/deploy/cipherctl.sh" "$d/"
  (cd "$d" && ./cipherctl.sh init --audience "$audience" --tls-self-signed >/dev/null)
  local san; san="$(openssl x509 -in "$d/data/secrets/tls-cert.pem" -noout -ext subjectAltName | tail -n +2 | tr -d ' ')"
  [ "$san" = "$want" ] || { echo "FAIL $audience: SAN is '$san', expected '$want'" >&2; exit 1; }
  echo "PASS $audience -> $san"
}
check 192.168.1.156:8443 "IPAddress:192.168.1.156" ip
check relay.example.org:8443 "DNS:relay.example.org" dns
