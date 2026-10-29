# Relay administration

**Status: implemented and tested (relay integration tests on PostgreSQL, invariants ADM-001..ADM-006 below). Not independently reviewed (ST-005).**

An operator needs to know whether the relay is healthy, how full it is, and be able to close registration. They do not need to know anything about people, and this
interface is built so that it cannot tell them.

## What it is

A **separate HTTP listener**, bound to a loopback address (`CIPHER_RELAY_ADMIN_LISTEN`, default none), authenticated by its **own secret**
(`CIPHER_RELAY_ADMIN_TOKEN` or `_FILE`, at least 32 characters). It is not part of the public API: the public router has no `/admin` routes (tested: 404).

| Property | How |
| --- | --- |
| Off by default | Both variables must be set; setting only one refuses to start. |
| Not reachable from the network | The listen address must be loopback. In the container it is not published on any host port; the operator uses `./cipherctl.sh admin ...` (docker compose exec), an SSH tunnel to the host, or nothing. |
| Not tied to any account | The secret is provisioned out of band (`./cipherctl.sh admin-init` writes `data/secrets/admin_token`, mode 600). Registering the first client account, or any account, grants nothing (tested). |
| Distinct secret | The relay refuses to start if the administrator secret equals the registration token. |
| Constant-time check | SHA-256 of the presented secret compared with `subtle`; every failure is the same `401`, delayed 250 ms. Failures are **counted**, never itemised (no IPs, no attempted values). |
| Never cached, never logged | `Cache-Control: no-store`; the secret and the `Authorization` header do not appear in the relay's logs (tested). |

## What it can show (`GET /admin/v1/stats`)

Software version, uptime, schema version, database reachability, whether registration is open, the number of failed administrator logins since start, the age of the
last backup (if `CIPHER_RELAY_BACKUP_MARKER` names a file the backup job touches), and:

* **Coarse counts**: accounts, devices, groups, live invitations, pending join requests, queued messages, blobs. Reported as `0`, `<10`, or rounded **down to tens**
  (`~120`). Enough to see growth and load, not enough to count people.
* **Pressure, exact**: queued bytes and blob bytes. They describe storage, not users.

The answer has a fixed set of fields (tested). No identifier of any kind appears in it: no account, device, group or invitation id, no key, no address.

## What it can never show

Message plaintext or ciphertext, keys, **contact graphs**, **private group membership**, per-user or per-device activity, individual connection times or addresses, the
content of any invitation or join request. There is no endpoint for any of these, and there is no per-user route to find (tested: `404`). The administration code cannot
read these tables except through the fixed aggregate queries in `store.rs`.

## What it can change

Exactly one thing today: `POST /admin/v1/registration {"open": true|false}` opens or closes **new account** registration. Existing accounts are untouched; a closed relay
answers a correct registration token with the same refusal as a wrong one. Unknown fields are refused.

## Audit

Every administrative **change** appends one entry to `admin_audit`: time, action and a short detail. Entries form a **hash chain**
(`hash = SHA-256(prev_hash, time, action, detail)`), and a database trigger refuses `UPDATE` and `DELETE` (tested). `GET /admin/v1/audit?after=N` returns the entries and
`chain_ok`, recomputed over the whole log; a forged or removed entry makes it `false` (tested). Reads are not logged.

Limits, stated plainly: a database superuser can drop the trigger or truncate the table, and an attacker who can rewrite the whole table can recompute a chain. The chain
makes **partial** tampering visible; keep a copy of the latest hash elsewhere if you need more. The audit log records changes made through this interface only.

## Operating it

```
./cipherctl.sh admin-init          # once: create the secret, turn the layer on
./cipherctl.sh up                  # restart the relay to load it
./cipherctl.sh admin stats
./cipherctl.sh admin registration closed
./cipherctl.sh admin audit
```

`docs/SELF_HOSTING.md` has the rest of the operator procedure.

## Invariants

| ID | Statement |
| --- | --- |
| ADM-001 | Only the administrator secret opens any administration route; every other credential (none, a wrong secret, the registration token, a device-signed request) gets the identical refusal. |
| ADM-002 | Registering an account, including the first, grants no administrative power, and the public listener has no administration routes. |
| ADM-003 | The statistics have a fixed field set, are coarse for user-related counts, and contain no identifier. |
| ADM-004 | Closing registration stops new accounts only, is reversible, and is recorded. |
| ADM-005 | The audit log is append-only and hash-chained; a forged entry is detected. |
| ADM-006 | The administrator secret is strict (length, distinct from the registration token, loopback-only listener) and never appears in logs or `Debug` output. |

Tests: `crates/cipher-relay/tests/admin.rs` and the unit tests in `crates/cipher-relay/src/admin.rs`.
