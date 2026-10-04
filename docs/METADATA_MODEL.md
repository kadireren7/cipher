# Metadata model and audit

Metadata is treated as sensitive. This document states **exactly what each party can learn**, what the relay persists, and — field by field — whether we **eliminated**, made **ephemeral**,
**coarsened** or **justified** it. It does **not** promise metadata anonymity: a relay operator (or anyone who compromises it) learns a substantial amount about who talks to whom and when, and a network
observer sees the relay IP and traffic shape. **We make no claim of ISP invisibility, anonymity or traffic-analysis resistance.**

Audit method: schema read from the live PostgreSQL used in the E2E run (`\d` of every table), the relay source (`store.rs`, `api.rs`, `logging.rs`), and the relay log + `pg_dump` of a real session
(DMs both ways, a 3-member group, image/PDF/voice note). Labels: TESTED / EXPECTED / NOT TESTED as in `SECURITY_TESTING.md`.

## 1. What each party can see

| Party | Sees | Does not see |
| --- | --- | --- |
| ISP / network observer | Relay IP, SNI (no ECH, ST-019), timing, volume, packet sizes, the fact that the phone uses Cipher | Anything inside TLS |
| TLS terminator / load balancer (if separate) | Client IPs, request line, headers, bodies (ciphertext) | Plaintext |
| **Relay process** | §2 — notably recipient device ids, the sending device at request time, group routing tags and commit sequence, which requests are commits, sizes, timing | Plaintext, private keys, attachment keys/names/types, group membership lists, contact names |
| Relay database (at rest) | §3 | Sender of a message, enqueue time (only a 10-minute-rounded expiry), IPs |
| Push provider | *None configured today.* When one is, a device token, wake time, and the constant payload `{"v":1}` | Sender, conversation, count, content |
| Object storage (when separate) | Not built; today blobs are in the relay's PostgreSQL | — |
| Anyone who can parse MLS framing (a malicious relay) | `group_id`, `epoch` and `content_type` (commit vs application message) are in the clear in `PrivateMessage` | Content |

## 2. Per-endpoint view and persistence (the relay in this repo)

| Endpoint | Relay needs / sees | Persisted | Why |
| --- | --- | --- | --- |
| `POST /v1/accounts` | account id, device id, identity + auth **public** keys, binding signature, registration token (compared by hash), source IP (transient, rate-limit key) | account row, device row | Registry of public material so peers can find keys |
| `POST /v1/devices` | as above + endorsement | device row incl. endorsement signature and endorser id | Peers verify device lists; **reveals the device graph of an account** |
| `GET /v1/accounts/{id}/devices` | requester device (authenticated), target account id | nothing | Directory lookup; *reveals that the requester is interested in that account* |
| `PUT /v1/key-packages` | device id, public KeyPackages | KeyPackages (≤ 100/device) | Asynchronous session setup |
| `POST /v1/devices/{id}/key-package` | requester, target device | nothing (KeyPackage deleted on hand-out) | *Reveals intent to start a conversation* |
| `POST /v1/messages`, `/v1/messages/batch` | sender device (transient, to verify the signature), **recipient device(s)**, message id, ciphertext, size, time | recipient, message id, ciphertext, **expiry rounded up to 10 min**, dedup tombstone `(recipient, message id, expiry)` | Store-and-forward; idempotent retries. **A batch reveals the recipient set of one send** (e.g. group size) |
| `POST /v1/groups/{tag}/commit` | sender device, routing tag, expected sequence, per-recipient deliveries (a commit fans out to every member device; Welcomes to new ones), optional new tag | `groups(tag, epoch, retired, touched_day)`; the deliveries as queue rows with `group_seq` | Commit ordering. **Reveals that this request is a membership/epoch change and how many devices are in the group** |
| `GET /v1/messages`, `POST /v1/messages/ack` | requesting device | deletes acknowledged rows | Delivery acknowledgement |
| `PUT /v1/push-token` | device, opaque token | token on device row | *Links a device to a push-provider identity* (unused until push exists) |
| `POST/GET /v1/blobs` | device, blob bytes, random id | ciphertext, id, expiry (14 d, rounded). **Uploader/downloader are not stored** | Opaque attachment storage |

## 3. Field-by-field audit (live schema)

| Table.column | What it reveals | Decision | Notes / evidence |
| --- | --- | --- | --- |
| `accounts.account_id` | A random 128-bit id (not derived from a key, phone or email) | **Justify** | Needed to address contacts. Linked to devices in `devices` |
| `devices.device_id/account_id/ord` | Account↔device graph, device order | **Justify** | Peers must enumerate devices to encrypt to all of them |
| `devices.identity_key/auth_key/binding_sig/endorser/endorsement_sig` | Public keys and signatures | **Justify** | Public by design; enables detecting key substitution |
| `devices.push_token` | Provider identity of the device | **Coarsen → none today** | Column exists; no provider configured, so it is empty (E2E: not populated) |
| `devices.queued_count/queued_bytes` | How much is waiting for a device right now | **Ephemeral** | Counters are exact and go to 0 on ack/expiry (`queue_counters_stay_exact_*`); needed for bounded queues |
| `key_packages.kp` | Public KeyPackages (≤ 20 + refills) | **Justify** | Single-use; deleted on hand-out |
| `queue.recipient` | **Who a message is for** | **Justify (cannot be eliminated)** | The relay must know where to deliver. Biggest metadata item; sealed sender is ST-009 |
| `queue.message_id` | Random id | **Justify** | Idempotency; random, carries no content |
| `queue.ct` | Ciphertext; length is a **bucket** (512 B … 64 KiB frame buckets + MLS 128 B padding) | **Coarsen** | `codec.rs` buckets; attachments use Padmé. Sizes still leak a size class |
| `queue.expires_at` | Enqueue time ± 10 min (expiry = now + TTL, rounded up) | **Coarsen** | `EXPIRY_GRANULARITY_SECS = 600`. A relay that logs live traffic still sees exact times |
| `queue.seq` | Arrival order within the table | **Justify** | Needed for FIFO delivery |
| `queue.group_seq` | Position in a group's commit sequence (NULL for non-commit traffic) | **Justify** | Makes commit deliveries distinguishable from other traffic **to the relay** |
| `seen(recipient, message_id, expires_at)` | A tombstone that a message id was delivered | **Ephemeral** | Purged at expiry; needed for idempotency after ack |
| `blobs.blob_id/size_bytes/data/expires_at` | Ciphertext, **padded** size, coarse expiry. No uploader/downloader/name/type | **Coarsen** | `size_bytes` is the padded ciphertext length |
| `groups.tag` | A **random** routing tag (not the MLS group id); rotates on removal | **Coarsen** | Not linkable to members by the relay (the relay stores no membership); linkable across messages of one group by anyone seeing the tag in requests |
| `groups.epoch` | Commit counter of the group (an activity measure) | **Justify** | CAS needs it |
| `groups.touched_day` | Day of last activity | **Coarsen** | Day granularity; rows purged after the retention window |
| `rate_buckets.key` | 16-byte **peppered hash** of an IP or device id | **Eliminate raw identifiers** | TESTED `rate_limit_keys_do_not_expose_ips_or_device_ids`: a DB dump cannot be turned back into IPs/device ids without the pepper; rows purged after 24 h |
| `request_nonces(device_id, nonce, expires_at)` | That a device made a signed request within the last ~2 min | **Ephemeral** | Required for replay protection; purged at `expires_at` |
| Logs | `timestamp, level, message, method, route, status` | **Eliminate bodies/ids/IPs** | TESTED: relay log of the whole E2E session had no ids, tokens or fixtures; `security_invariants.rs` captures full-trace logs |
| Sender of a message | — | **Eliminate (stored)** | Not stored or forwarded; MLS authenticates the sender inside the ciphertext. The relay still sees the sending device **transiently** when verifying the signed request |
| Client IP | — | **Ephemeral** | Used as an in-memory/hashed rate-limit key; never stored raw, never logged |

**A database leak (A3) yields:** the account↔device graph, public keys, unexpired queued ciphertext keyed by recipient device, KeyPackages, tombstones, group tags/epochs, encrypted blobs. It does **not** yield senders,
exact delivery times, plaintext, IPs, or any key able to decrypt (`sec_003_*`, and a `pg_dump` of the E2E database contained none of the fixtures).

## 4. What is **not** hidden (be honest with users)

* The relay sees the **recipient device and send time of every message** and the **sending device at request time**. By logging live traffic it can reconstruct who talks to whom and when — we do not log it; a compromised relay can.
* A group message is delivered **as one request with many recipients**, so the relay learns the group's device count and, by the routing tag in commit requests, which commits belong to the same group.
* The relay **knows which requests are group commits** (it sequences them), and anyone parsing MLS framing sees `group_id`, `epoch` and `content_type`. (An earlier version of these docs wrongly claimed commits are indistinguishable from messages.)
* **Sizes** are bucketed, not hidden. **Timing and message counts** are not padded; there is no cover traffic.
* While the app is in the foreground it **polls `GET /v1/messages` every few seconds** (255 of 329 logged requests in the E2E session), so a relay or network observer can tell when the app is open. There is no push channel to replace this yet (ST-017).
* Directory lookups and KeyPackage fetches reveal who is contacting whom (no private information retrieval).
* IP addresses are visible to the TLS terminator and network observers; SNI is visible (no Encrypted Client Hello).
* Push (when added) links a device to Google/UnifiedPush infrastructure and reveals wake times.
* Rate limiting and abuse controls need *some* per-source state.

## 4a. Measured: what a size-observing adversary sees (final review)

Measured with the real engine against PostgreSQL (`measure_observer_visible_sizes`, run with `--ignored --nocapture`): a text of 1–300 characters produces **one** ciphertext size (702 B); 500–900 chars → 1214 B; 1500 → 2238 B; 3000 → 4286 B; 6000–7900 → 8382 B. So message length is leaked only as a power-of-two size class (6 classes up to 8 KB). Attachments are padded with Padmé: relay-visible blob size = file size + 0.4–5.3 % (1 KB: +5.3 %, 10 KB: +2.7 %, 100 KB: +0.4 %, 1 MB: +1.6 %, 20 MB: +2.3 %, 100 MB: +0.7 %), leaking only a coarse size class. The existing buckets are kept: coarser classes would cost real bandwidth for no meaningful gain, because **timing, burst structure, recipient sets and counts remain visible**. Tag rotation was evaluated and not changed: the relay links a group by its recipient device set regardless of the routing tag, so rotating tags on every commit would add coordination risk (members missing a rotation) for no real unlinkability.

**New relay-side state from the final review:** per-target and per-pair KeyPackage buckets are stored as peppered 16-byte hashes in `rate_buckets` (purged after 24 h): they reveal nothing without the pepper, but an operator with the pepper can test the guess "device X claimed a KeyPackage of device Y within 24 h".

## 4b. Added in the history-revocation / flooding pass

* `queue.sender_h` = SHA-256(pepper ‖ "pair" ‖ sending device ‖ recipient device)[..16], present only while the envelope is queued (ST-031 share accounting). Not reversible without the pepper; **with** the pepper (relay operator) it reveals "this sender device has N queued envelopes for this recipient" — the same information the relay already sees transiently in the signed request.
* `groups.last_mid`/`last_from`: the first random delivery id and the consumed epoch of the latest commit per group (idempotent retry). No identities.
* Decision: group application messages carry **no** routing tag (ADR-038), so the relay cannot tell which messages belong to a group.

## 4c. Network-privacy pass: what the final relay can observe now (measured on the implementation)

Method: engine-level sessions against the real relay + PostgreSQL (`engine_caps.rs`, `privacy_experiments.rs`), the emulator through a SOCKS5 test double, and the DB/log hunts in `PRIVACY_TRANSPORT_REVIEW.md`. Actions: REMOVE / ROTATE / COARSEN / PAD / JUSTIFY.

| Observable | Before | Now | Action |
| --- | --- | --- | --- |
| Client source IP | the client's address (hashed only for rate limits) | the privacy route's egress (Tor exit) when the app uses its route; the debug-only direct route still shows the client | **REMOVE** (by route; relies on the selected network; loopback-level measurement only) |
| Sender (stable id) of a message | sender device id in every signed request | **none** for capability deliveries (`/v1/deliver` is unauthenticated); still present for group commits, first contact, KeyPackage claims, directory lookups | **REMOVE** for message deliveries; **JUSTIFY** the rest |
| Recipient (stable id) | device id in the request | an opaque rotating capability; the relay can resolve it to the device; the polling device authenticates with its device id | **ROTATE** (weekly, on removal); **JUSTIFY** (the relay must route) |
| Conversation / group id | routing tag in commit requests; MLS `group_id`/`epoch`/`content_type` readable in the ciphertext framing (ST-009) | unchanged | **JUSTIFY** (not hidden) |
| Message vs commit | by endpoint | by endpoint: commits only via the sequencer; messages via `/v1/deliver` or `/v1/messages` | **JUSTIFY** |
| Message size | power-of-two buckets from 512 B | power-of-two buckets from **1 KiB**: receipts, capability announcements and short texts are one class | **PAD** (measured: leaked class entropy 0.45 → 0.03 bits on a synthetic chat mix; mean frame 560 → 1033 B) |
| Attachment size | Padmé blob size | unchanged | **PAD** (≤ ~12 % overhead, O(log log n) bits leak) |
| Timing | exact request times | exact request times at the relay; optional ENHANCED cadence flattens *client-link* send times; relay logs are minute-rounded and per-request lines are off by default | **COARSEN** (optional, bounded) |
| Online state | visible via polling | visible (ENHANCED makes the cadence fixed, not hidden) | **JUSTIFY** |
| Group membership / size | no member list; fan-out batch size = device count; removal visible as tag rotation | unchanged; one request carrying N capabilities still reveals "these N devices share a conversation" | **JUSTIFY** (splitting into N requests costs latency/bandwidth; not done) |
| Social graph from a DB dump (no pepper) | recipient only; pair hashes unlinkable | recipient only; capability deliveries store **no** pair hash; no sender id anywhere but the sender's own inbox-capability row | **REMOVE** |
| Social graph from a live compromised relay | trivial (authenticated sender + recipient) | sender hidden for capability deliveries; **recipient and time still visible** | **PARTIAL** — see `PRIVACY_TRANSPORT_REVIEW.md` |

## 5. Minimisation choices already made

Random 128-bit ids generated on the device (no hardware, advertising, phone or email ids); **no contacts upload**; no explicit social graph at the relay (membership lives in MLS state on devices); no timestamps stored beyond a
rounded expiry; no sender stored; peppered rate-limit keys; short-lived nonces; no analytics, crash reporting or attribution SDKs (dependency guard); notification content off by default.

## 6. Recommended next steps (not built)

1. **Sealed-sender-style delivery** with anonymous delivery tokens (hides the sender at request time, ST-009) and an outer routing layer that hides MLS `group_id`/`epoch`/`content_type`.
2. Per-recipient fan-out as separate, unlinkable requests (costly) or a relay-side group queue that does not reveal the device count.
3. Private directory lookup, Encrypted Client Hello, padding of timing (batched/dummy sync), cover traffic — each has real cost and must be evaluated, not assumed.
4. A transport behind an OHTTP/proxy hop so the relay never sees client IPs (the client's only network seam is the `HttpCallbacks` transport and `RelayTransport` trait, so this is a transport swap).
