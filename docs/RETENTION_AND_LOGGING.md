# Retention and logging policy (network-privacy pass)

Principle: keep as little network metadata as practical, prefer ephemeral state, and **do not claim operators cannot log** — a relay operator, a TLS terminator, a Tor exit or a hosting provider *can* log whatever they choose. These rules describe what **this repository's** software retains and what the operator is asked to do.

## Relay software (what the code keeps)
| State | Retained | Lifetime | Notes |
| --- | --- | --- | --- |
| Queued ciphertext (`queue`) | recipient, message id, ciphertext, lane, capability **hash** (cap lane), pair hash (open/commit lanes only), expiry rounded up to 10 min | until ack or TTL (default 7 d, max 30 d) | no sender; no enqueue time |
| `seen` tombstones | recipient, message id, expiry | until expiry | idempotency |
| Delivery capabilities | SHA-256(cap), owner device, expiry | ≤ 30 d, rotated every 7 d, deleted on revoke/purge | the capability itself is never stored |
| `request_nonces` | device, nonce | ~2 min | replay protection |
| `rate_buckets` | 16-byte peppered hash of IP / device / capability / pair, token count | purged after 24 h | the pepper is a relay secret; without it a dump cannot be reversed |
| Group rows | tag, epoch, retired flag, day of last activity, last commit id | 180 idle days | |
| Blobs | padded ciphertext, id, expiry | 14 d | uploader/downloader not stored |
| Logs | **default: startup/migration/error lines only**; per-request lines are DEBUG (off). Timestamps are rounded **down to the minute**. Never: bodies, ciphertext, device/account ids, capabilities, tokens, IPs | operator's log rotation | enabling DEBUG records route+status per request with minute-granularity time — an operator decision |

## Client
No analytics, no crash reporter, `SafeLog` accepts only a closed set of event codes (R8 strips `android.util.Log` in release). The privacy route's configuration (the local SOCKS IP:port) is a non-secret file in the no-backup directory. Capabilities and the pending-commit record live inside the encrypted vault and are deleted with the conversation or on group revocation.

## Operator assumptions (to be stated to users)
1. A reverse proxy/CDN in front of the relay will see client (or Tor exit) addresses and timing; do not log them, or log with the same minute rounding and short retention.
2. Tor exit operators and any intermediate infrastructure are third parties outside Cipher's control.
3. The database and its backups hold the account↔device directory, public keys and unexpired ciphertext; encryption-at-rest and backup retention are operator-owned (ST-012 residual).
4. Rate-limit state keyed by source address is less useful behind Tor (shared exits); capability-based limits are the intended mechanism.

## Verified
`security_invariants.rs` (full-trace log capture has no ids/ciphertext), `logging::tests` (minute rounding), `delivery_caps.rs` / `engine_caps.rs` (no sender or capability in the DB), `inbox_flooding.rs`. **Not verified:** a real deployment's reverse-proxy and Tor-node logs.
