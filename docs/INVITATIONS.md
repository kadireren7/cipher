# Private invitations — design (ST-065)

**Status: DESIGN ONLY. Nothing in this file is implemented, and no invitation button may ship before the protocol below exists and passes its tests.** Self-reviewed; it needs the independent review (ST-005) like every other composition here.

## 1. What is being built, and what is not

| Goal | How |
| --- | --- |
| Admins create unguessable, expiring, revocable **group invitation links and QR codes** | §3–§5 |
| A recipient can **request** to join; the group decides | §6–§7 (approval by default) |
| **1:1 invitations** by link or QR | reuse the Contact Card + intro capability (`MULTI_RELAY_PROTOCOL.md` §3–§5), plus use limits (§9) |
| Works across relays; relay operators learn no group content | §8 |
| New members do not see history | §7.4, tested |

Not built here: joining without any admin online (MLS needs an existing member to commit the Add, so an offline group cannot admit anyone); a public directory of groups; Android **App Links** (they need a domain we control and a published `assetlinks.json`; there is none, so links are QR/paste only until the owner configures one; a custom-scheme link is *not* a verified App Link and is not described as one).

## 2. Constraints from the existing design

* MLS admits a member only through a **commit by an authorised existing member** (owner/admin, `GROUP_SECURITY.md` §2) that consumes the joiner's **KeyPackage** and produces a **Welcome**. So a link is never a key and never a membership: it is a **bearer permission to ask**. The admin's client performs the normal, receiver-verified Add. A relay can neither admit nor refuse the policy check.
* Relays are untrusted mailboxes. Capabilities are bearer secrets scoped to a relay (`DELIVERY_CAPABILITIES.md`). Identities are pinned by contacts, never by relays.
* Plaintext MLS secrets, private identity keys and epoch keys are **never** placed in a link, a QR code, a log or a relay row.

## 3. The invitation secret and what is derived from it

`s` = 128 random bits (OS CSPRNG), generated on the admin's device. Derived with HKDF-SHA-256 (distinct `info` labels, `"cipher-inv-v1/…"`):

| Derived | Use | Who learns it |
| --- | --- | --- |
| `id` (16 B) | lookup key at the relay; the relay stores only `SHA-256(id)` | relay learns `id` when it is used (not `s`) |
| `k_enc` (AEAD key) | encrypts the **preview** (§4) so the relay cannot read it | link holders only |
| `k_mac` (HMAC key) | binds a join request to possession of the link (§6) | link holders and the issuing admin |

A relay that knows `id` (it sees it on every use) can submit junk but **cannot produce a valid `k_mac` tag**, so the admin's client rejects it. A database leak exposes only `SHA-256(id)`.

## 4. Link / QR format

`cipher-invite:v1:` + base64url( `version(1) | s(16) | relay_descriptor` ), where the relay descriptor is the issuer's relay (`https://…` with optional pin; `.onion` requires a pin, as everywhere). It is shown as a QR code and as copy-able text. No group name, member list or key is in the clear. Maximum link lifetime is 7 days, default 24 hours; an expiry is always set.

The **preview** stored at the issuer's relay is `AEAD(k_enc, plaintext, aad = id || version)` of: group display name, inviter display name, the inviter's account id and root key (so the joiner can pin who invited them and compare safety numbers), the join mode (`approval` | `auto`), expiry. It contains **no MLS group secret, no epoch secret, no private key**.

## 5. Relay side (new, additive; migration + endpoints)

Table `invites(id_hash, preview_ct, expires_at, max_uses, used, revoked, issuer_device)` and `invite_requests(invite, request_ct, state, created_at)`.

| Endpoint | Auth | Rule |
| --- | --- | --- |
| `POST /v1/invites` | signed device | create; `expires_at` ≤ 7 d, `max_uses` ≤ 100, per-device cap on live invites |
| `POST /v1/invites/lookup {id}` | none | returns the preview ciphertext + state; unknown / expired / revoked / used-up all answer the **same** `invalid` |
| `POST /v1/invites/request {id, ct}` | none | atomically takes a use slot (`used < max_uses AND NOT revoked AND now < expires_at`), stores the opaque request; bounded pending per invite |
| `POST /v1/invites/poll` | signed issuer device | returns that device's pending requests |
| `POST /v1/invites/resolve {id, request, approved}` | signed issuer device | closes a request; a **rejected** request returns its slot |
| `POST /v1/invites/revoke {id}` | signed issuer device | revoke now; rows are purged at expiry |

All unauthenticated calls are rate-limited per hashed source **and** per invite, identical in cost for valid and invalid ids (no oracle), and the relay never logs `id`, `s` or request bytes (same quiet-log rule as everywhere).

## 6. Join request (joiner → issuer)

`req = { v, id, joiner_root_key, joiner_account, key_package(s), reply: { relay_descriptor, delivery_cap }, nonce(16), ts }`, then
`tag = HMAC(k_mac, canonical(req))` and `sig = Ed25519(joiner_root_key, "cipher-join-v1\0" || canonical(req) || tag)`; the whole `(req, tag, sig)` is **HPKE-encrypted to the issuing admin device's public key** and posted. The relay sees only an opaque blob and its size class.

## 7. Issuer side: approval, admission, history

1. **Verify** (all must hold, else drop silently and count): the invite is still live in *local* state (not revoked/expired/used up — the local state is authoritative, the relay's counters are an optimisation); `tag` verifies under `k_mac`; `sig` verifies; `(id, nonce)` unseen; the joiner account has no other request on this invite; the KeyPackage is signed by the joiner's identity and matches `joiner_root_key`.
2. **Decide.** `approval` mode (the default): the admin sees who is asking (display name if given, account id, **safety number**) and taps Approve/Reject. `auto` mode is allowed only with `max_uses ≤ 10` and expiry ≤ 24 h, only while the issuing admin's device is online, and still produces the normal MLS Add; every auto-admission is listed in the admin's activity log and the group.
3. **Admit.** The issuing client runs the existing Add flow: `authorize_commit` → MLS Add commit through the group's sequencer/home relay → **Welcome** sent client-mediated to the joiner's `reply` mailbox. Receivers re-verify the commit exactly as for any Add; a relay cannot add anyone, and a non-admin who learned a link cannot add anyone.
4. **History protection.** A Welcome opens the group **from the epoch of the Add**. No earlier application message is re-encrypted, forwarded or re-sent; per-epoch keys (`HISTORY_REVOCATION.md`) mean the new member cannot derive earlier epoch secrets. Tests assert that a message sent before the Add cannot be decrypted by the new member, and that the app never replays history on join.
5. **Resolve** the request at the relay (`approved` consumes the slot for good; `rejected` returns it).

## 8. Cross-relay

The invite lives at the **issuer's** relay; the joiner reaches it through his own privacy transport (Tor), exactly like a contact card's intro capability. The Welcome goes to the joiner's own relay mailbox named in `reply`. The group's home relay is unchanged. No relay contacts another relay, and no relay sees group content.

## 9. 1:1 invitations

A 1:1 invitation **is** the Contact Card (QR or link) that already exists: its intro capability lets the scanner fetch directory/KeyPackages and deliver a Welcome, and the recipient sees an unknown inviter as a **message request** they accept or decline. Additions in this design: an optional `max_uses` on the intro capability (default unlimited, "single-use" selectable), the existing expiry (≤ 30 days; shorter selectable) and revocation (`/v1/caps/revoke`), all shown in one "Invitations" screen.

## 10. Threat model

| Threat | Outcome |
| --- | --- |
| **Guessing / enumeration** | 128-bit `id`; uniform `invalid`; per-source and per-invite rate limits; hashed storage. Cost of a guess is dominated by the rate limit, not the keyspace. |
| **Replay** of a join request | `(id, nonce)` dedupe at the issuer; one request per joiner account per invite; KeyPackages are single-use; the relay slot is taken atomically. |
| **Reuse beyond the limit** | the relay refuses slots past `max_uses`; the issuer re-checks locally before admitting. |
| **Leaked / forwarded link** | Whoever holds it may *ask*. In `approval` mode (default) nobody enters without an admin seeing the requester. In `auto` mode the first holders within the limit enter: this is why `auto` is capped (≤ 10 uses, ≤ 24 h) and logged. **A link is a bearer secret: forwarding it forwards the right to ask.** Residual and documented. |
| **Stolen before the intended joiner uses it** | the attacker may be admitted instead (`auto`) or shown as a different requester (`approval`): the admin compares the safety number with the person out of band. |
| **Hostile relay** | cannot read the preview or requests; cannot forge a valid request (needs `k_mac`); cannot admit; can **drop or delay** requests (liveness) and see that an invite was looked up/used and when, plus source addresses unless Tor is used. |
| **Malicious joiner** | can only ask; cannot read the group before the Welcome; spam is bounded by slots, pending caps and revocation. |
| **Compromised admin device** | can admit anyone it is authorised to admit (same as today); out of scope. |
| **Accidental exposure** | the link is never written to logs (`SafeLog` takes closed codes only; the relay does not log); on Android it is copied with the **sensitive-content clipboard flag**, shown behind the screen's secure flag (no screenshots), and excluded from backup. No analytics SDK exists. |
| **Downgrade** | `https`/pinned `.onion` only; unknown `version` is refused; no cleartext path. |

## 11. Implementation plan and tests (none done)

1. `cipher-wire`: link codec, derived keys, preview/request types, strict parsing. Tests: round trips, tamper, unknown version, oversized fields.
2. Relay: migration, the six endpoints, rate limits. Tests (real PostgreSQL): authorisation of every endpoint (a non-issuer cannot poll/resolve/revoke; an unauthenticated caller can only look up/request), slot atomicity under concurrency, expiry, revocation, uniform `invalid`, no id/secret in logs.
3. `cipher-core`: create / lookup / request / verify / approve, wired to the existing Add flow. Tests: valid join, wrong `k_mac`, forged signature, replayed nonce, second request by the same joiner, revoked-after-request, expired, `auto` limits, **history not decryptable by the new member**, forged Add by a non-admin rejected by receivers.
4. Cross-relay E2E (emulator driver): issuer on relay A, joiner on relay B, join, message both ways, revoked and expired invites.
5. Malicious-client tests: a hostile joiner flooding requests, a hostile relay dropping/reordering, a leaked link used by two parties.
6. Android: Invitations screen (create with mode/expiry/limit, share link/QR, pending requests with safety numbers, revoke), scan/paste to join, message-request handling for 1:1. UI tests for each state, including expired/revoked.

Only after steps 1–5 pass does step 6 expose anything to users.
