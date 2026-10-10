#!/usr/bin/env bash
# cipherctl — local operator helper for a self-hosted Cipher relay. Generates secrets LOCALLY (nothing leaves this machine),
# never overwrites existing ones, and keeps everything under deploy/data/ (git-ignored, mode 700).
#
#   cipherctl.sh init   --audience HOST[:PORT] [--tls-self-signed]     create secrets (Profile B: you then supply tls-cert.pem/tls-key.pem)
#   cipherctl.sh onion-cert                                             Profile A: after tor created its key, issue the relay's pinned cert
#   cipherctl.sh up [onion]   |  down  |  status  |  token             run / stop / health / print the registration token
#   cipherctl.sh backup FILE  |  restore FILE                          PostgreSQL logical backup (ciphertext + public keys only)
set -euo pipefail
cd "$(dirname "$0")"
DATA=data; SEC=$DATA/secrets
need() { command -v "$1" >/dev/null || { echo "missing dependency: $1" >&2; exit 1; }; }
rand() { head -c 48 /dev/urandom | base64 | tr -d '/+=\n' | head -c "$1"; }
compose() { if [ "${PROFILE:-}" = onion ] || [ -f $DATA/profile-onion ]; then docker compose -f compose.yaml -f compose.onion.yaml "$@"; else docker compose -f compose.yaml "$@"; fi; }

cmd_init() {
  need openssl
  local audience="" selfsigned=0
  while [ $# -gt 0 ]; do case $1 in --audience) audience=$2; shift 2;; --tls-self-signed) selfsigned=1; shift;; *) echo "unknown option $1" >&2; exit 2;; esac; done
  [ -n "$audience" ] || { echo "--audience HOST[:PORT] is required (the host form clients use: relay.example.org or relay.example.org:8443)" >&2; exit 2; }
  case $audience in *://*|*/*) echo "--audience is a host, not a URL" >&2; exit 2;; esac
  umask 077; mkdir -p $SEC; chmod 700 $DATA $SEC
  put() { [ -e "$SEC/$1" ] && { echo "keep   $1 (exists)"; return; }; printf '%s' "$2" > "$SEC/$1"; echo "create $1"; }
  put registration_token "$(rand 48)"
  put pepper "$(rand 48)"
  put db_password "$(rand 40)"
  put database_url "postgres://cipher:$(cat $SEC/db_password)@db:5432/cipher?sslmode=require"
  if [ ! -e $SEC/db-ca.pem ]; then
    # Private CA that exists only to authenticate the PostgreSQL server to the relay (hostname `db`, TLS 1.3).
    openssl ecparam -name prime256v1 -genkey -noout -out $SEC/db-ca.key 2>/dev/null
    openssl req -x509 -new -key $SEC/db-ca.key -sha256 -days 3650 -subj "/CN=cipher-db-ca" -out $SEC/db-ca.pem 2>/dev/null
    openssl ecparam -name prime256v1 -genkey -noout -out $SEC/db-server.key 2>/dev/null
    openssl req -new -key $SEC/db-server.key -subj "/CN=db" -out $SEC/db-server.csr 2>/dev/null
    printf 'subjectAltName=DNS:db\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > $SEC/db-ext.cnf
    openssl x509 -req -in $SEC/db-server.csr -CA $SEC/db-ca.pem -CAkey $SEC/db-ca.key -CAcreateserial -days 825 -sha256 -extfile $SEC/db-ext.cnf -out $SEC/db-server.pem 2>/dev/null
    rm -f $SEC/db-server.csr $SEC/db-ext.cnf $SEC/db-ca.srl; echo "create db-ca.pem / db-server.{key,pem}"
  fi
  if [ $selfsigned -eq 1 ] && [ ! -e $SEC/tls-cert.pem ]; then
    local host=${audience%%:*}
    openssl ecparam -name prime256v1 -genkey -noout -out $SEC/tls-key.pem 2>/dev/null
    openssl req -x509 -new -key $SEC/tls-key.pem -sha256 -days 825 -subj "/CN=$host" -addext "subjectAltName=DNS:$host" -out $SEC/tls-cert.pem 2>/dev/null
    echo "create tls-cert.pem / tls-key.pem (SELF-SIGNED: clients must pin it; see docs/SELF_HOSTING.md)"
  fi
  [ -e $SEC/tls-cert.pem ] || : > $SEC/tls-cert.pem; [ -e $SEC/tls-key.pem ] || : > $SEC/tls-key.pem
  chmod 600 $SEC/*
  # Bind-mounted secrets keep their host owner and mode 0600, so the (unprivileged) relay must run as the uid that owns them.
  # An operator running this as root gets a dedicated unprivileged uid instead; the relay never runs as root.
  local uid; uid=$(id -u); local gid; gid=$(id -g)
  if [ "$uid" -eq 0 ]; then uid=10001; gid=10001; chown -R $uid:$gid $SEC; fi
  printf 'CIPHER_RELAY_AUDIENCE=%s\nCIPHER_UID=%s\nCIPHER_GID=%s\n' "$audience" "$uid" "$gid" > .env; chmod 600 .env
  echo; echo "Done. Profile B: place your certificate chain at deploy/$SEC/tls-cert.pem and key at tls-key.pem (non-empty), then: ./cipherctl.sh up"
}

cmd_onion_cert() {
  need openssl
  local host; host=$(docker compose -f compose.yaml -f compose.onion.yaml exec -T tor cat /var/lib/tor/cipher-relay/hostname | tr -d '\r\n')
  [[ $host =~ ^[a-z2-7]{56}\.onion$ ]] || { echo "tor has not published a valid v3 hostname yet (start the stack with: up onion)" >&2; exit 1; }
  umask 077
  openssl ecparam -name prime256v1 -genkey -noout -out $SEC/tls-key.pem 2>/dev/null
  openssl req -x509 -new -key $SEC/tls-key.pem -sha256 -days 825 -subj "/CN=$host" -addext "subjectAltName=DNS:$host" -out $SEC/tls-cert.pem 2>/dev/null
  sed -i "s|^CIPHER_RELAY_AUDIENCE=.*|CIPHER_RELAY_AUDIENCE=$host|" .env
  [ "$(id -u)" -eq 0 ] && chown 10001:10001 $SEC/tls-key.pem $SEC/tls-cert.pem
  local pin; pin=$(openssl x509 -in $SEC/tls-cert.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)
  touch $DATA/profile-onion
  echo "Onion address : https://$host"
  echo "SPKI pin      : sha256/$pin"
  echo "Give BOTH to users out of band (invite). Restart the relay to load the certificate: ./cipherctl.sh up onion"
}

case "${1:-}" in
  init) shift; cmd_init "$@";;
  onion-cert) cmd_onion_cert;;
  up) if [ "${2:-}" = onion ]; then touch $DATA/profile-onion; fi
      [ -s $SEC/tls-cert.pem ] || [ -f $DATA/profile-onion ] || { echo "tls-cert.pem is empty: supply your certificate first" >&2; exit 1; }
      compose up -d --build;;
  down) compose down;;
  status) compose ps; docker inspect --format '{{.Name}} {{.State.Health.Status}}' $(compose ps -q) 2>/dev/null || true;;
  token) cat $SEC/registration_token; echo;;
  backup) [ -n "${2:-}" ] || { echo "usage: backup FILE" >&2; exit 2; }
          umask 077; compose exec -T db pg_dump -U cipher -d cipher --format=custom > "$2"; echo "wrote $2 ($(wc -c < "$2") bytes). Contains ciphertext and public keys; protect it like the database."
          ;;
  restore) [ -n "${2:-}" ] && [ -f "$2" ] || { echo "usage: restore FILE" >&2; exit 2; }
           compose stop relay; compose exec -T db pg_restore -U cipher -d cipher --clean --if-exists --no-owner < "$2"; compose start relay;;
  *) sed -n 2,9p "$0"; exit 2;;
esac
