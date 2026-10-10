# Self-hosting a Cipher relay

> **Status: experimental.** The relay is *untrusted by design* (it stores ciphertext and public keys only), but the code is unaudited (ST-005) and
> the deployment below has been exercised only on one Linux host with Docker Compose (see "What was tested"). Do not run it for users whose
> safety depends on it.

A relay operator can see: connection times, IP addresses (unless you use the onion profile), ciphertext sizes, recipient mailboxes, and the
metadata in [METADATA_MODEL.md](METADATA_MODEL.md). A relay operator cannot read messages or files.

## Requirements
Linux, Docker Engine with the Compose plugin, `openssl`, ~1 GB RAM free, a few GB disk. Nothing from the Cipher developer's infrastructure is needed.

## Files
`deploy/compose.yaml` (relay + PostgreSQL), `deploy/compose.onion.yaml` (adds Tor), `deploy/Dockerfile.relay`, `deploy/Dockerfile.tor`,
`deploy/torrc`, `deploy/cipherctl.sh` (secret generation, backup/restore). Everything generated lands in `deploy/data/` (mode 700, git-ignored).

## What the stack does for you
* **Secrets are generated locally** by `cipherctl.sh init` (registration token, rate-limit pepper, PostgreSQL password, a private CA and server
  certificate for the database link). They reach containers as mounted files (`*_FILE`), never as image layers, build args or environment variables.
* **PostgreSQL is never published.** It lives on an `internal: true` network; the relay talks to it over TLS 1.3 with a verified hostname.
  The relay itself refuses a non-loopback database link without TLS.
* **Migrations** run on relay start under a PostgreSQL advisory lock, are checksummed, and the relay refuses to start if the database is *newer*
  than the binary (no silent downgrade) or an applied migration was altered.
* **Health checks**: `/healthz` and `/readyz` are served on a separate loopback-only listener inside the container (not on the public port);
  the image `HEALTHCHECK` runs `cipher-relay healthcheck`. `docker compose ps` shows `healthy`.
* **Hardening**: non-root user, read-only root filesystem, all capabilities dropped, `no-new-privileges`, memory/CPU/PID limits.
* **Quotas and abuse limits** are in the relay: bounded queues per recipient/capability, per-source token buckets, a global in-flight cap
  (503 when overloaded), a total attachment-storage cap (`CIPHER_RELAY_MAX_BLOB_BYTES`, default 2 GiB in the compose file), message/attachment TTL purge.

## Profile B — public TLS relay
1. `cd deploy && ./cipherctl.sh init --audience relay.example.org` (audience = the host, optionally `:port`, exactly as clients will type it).
2. Obtain a certificate for that name (for example with `certbot certonly --standalone`) and copy the **full chain** to `deploy/data/secrets/tls-cert.pem`
   and the key to `deploy/data/secrets/tls-key.pem` (mode 600). Renew by overwriting both files and `docker compose restart relay`.
   Android validates the certificate with the system trust store and checks the host name; nothing here relaxes that.
3. `./cipherctl.sh up` → relay on `0.0.0.0:8443` (set `CIPHER_PUBLISH=0.0.0.0:443` to change). Put a firewall in front; only that port is needed.
4. Give users the URL `https://relay.example.org:8443` and the registration token (`./cipherctl.sh token`). The token is a shared invite secret: it lets
   a person *create an account*; it does not reveal any message. Rotate it by editing the file and restarting the relay.

Tor-routed clients can use this relay as an ordinary clearnet hidden-from-nobody service through a Tor exit; the exit sees only TLS to your host.

## Profile A — private onion relay
The Tor onion service is the only entry point. The relay publishes **no** host port; it and PostgreSQL sit on internal-only networks.
1. `./cipherctl.sh init --audience placeholder.invalid` (secrets only), then `./cipherctl.sh up onion` — Tor creates the onion key in the `tor-data` volume.
2. `./cipherctl.sh onion-cert` — reads the generated `.onion` name, issues a **self-signed** P-256 certificate whose SAN is that name, rewrites the
   audience, and prints the **SPKI pin** (`sha256/…`). Run `./cipherctl.sh up onion` again to load the certificate.
3. Give users **both** the `https://<name>.onion` URL **and the pin**, over a channel you trust (QR/in person is best).

**Trust model for onion relays (resolves ST-041).** Clients never use cleartext and never disable certificate or host-name validation. A self-signed
certificate cannot chain to a public CA, so for `.onion` the client accepts **only** a certificate whose public key hash equals the pin from the invite
(trust-on-invite, the same trust a QR code gives a contact). Without the pin the connection is refused. The onion address itself is also a public-key hash,
so Tor already authenticates the service; the TLS pin is defence in depth and keeps the app's "https only, no silent downgrade" invariant intact.
*The Android client-side pin enforcement for onion relays is tracked in `MASTER_IMPLEMENTATION_STATUS.md`; until it is verified on a device, do not rely on it.*

The onion service **private key** is in the `tor-data` volume. Back it up offline if you want to keep the address; anyone holding it can impersonate your relay
(the TLS pin still protects users who pinned your certificate). Never publish it or put it in an image.

## Operations
| Task | Command |
| --- | --- |
| Start / stop | `./cipherctl.sh up [onion]` / `./cipherctl.sh down` |
| Status | `./cipherctl.sh status` (health: `healthy`) |
| Logs | `docker compose -f compose.yaml logs relay` (request logs are deliberately quiet: no IPs, rounded times) |
| Backup | `./cipherctl.sh backup relay.dump` — a PostgreSQL custom-format dump (ciphertext, public keys, counters). Encrypt it before it leaves the host. |
| Restore | `./cipherctl.sh restore relay.dump` into a stack created with the **same** `deploy/data/secrets` (the pepper must match or rate-limit state resets, which is harmless) |
| Retention | Message TTL, capability TTL and attachment TTL are compiled into the relay (`cipher-wire` limits); the purge runs every minute. `CIPHER_RELAY_MAX_BLOB_BYTES` caps attachment storage. |

## Upgrade and rollback
1. `git pull` (or fetch the new release), read the release notes and `docs/RELEASE_READINESS.md` for the **version/compatibility policy**.
2. **Back up first** (`./cipherctl.sh backup before-upgrade.dump`).
3. `./cipherctl.sh up` rebuilds the image and restarts the relay; migrations apply automatically and are forward-only.
4. **Rollback:** the relay will refuse to start on a database that is ahead of it. To roll back, `down`, restore the pre-upgrade dump into a fresh volume
   (`docker volume rm cipher_pgdata`, `up`, `restore`), then check out the older version. There is no in-place downgrade.

## What was tested (and what was not)
See the "Self-hosting" section of [MASTER_IMPLEMENTATION_STATUS.md](MASTER_IMPLEMENTATION_STATUS.md) for dated results. Not tested: multi-host deployments,
HA, real Let's Encrypt issuance, real Tor reachability from the internet, load, disk-full behaviour of PostgreSQL itself, Docker rootless mode.
