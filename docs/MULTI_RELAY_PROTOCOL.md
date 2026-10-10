# Multi-relay protocol (draft v1)

**Status: design + partial implementation on branch `feat/self-hosted-multi-relay`. Not independently reviewed (ST-005). Nothing here is production-ready.**
Implementation status of each section is in the table at the end; `MASTER_IMPLEMENTATION_STATUS.md` has the dated evidence.

## 1. Goal and non-goals
Alice (account on relay **A**) and Bob (account on relay **B**) exchange messages and files, also when one is offline, without Alice ever having an
account on B, without A talking to B, and without any infrastructure operated by the Cipher developer.

Non-goals (stated so nobody infers them): hiding *that* Alice talks to relay B from relay B or from the network; federation between relays; a global
directory; anonymity against a global network observer; cross-relay **groups** (§9, blocked).

## 2. Identities — three things that must not be confused
| Thing | What it is | Authenticated by | Can a relay forge it? |
| --- | --- | --- | --- |
| **User identity** | `account_id` + root Ed25519 identity key; each device has a binding-signed `DeviceRecord` | the root key itself; pinned by the contact (QR/TOFU/safety number) | No. A relay can only *withhold* records or lie before the first pin (existing TOFU limit, `KEY_TRANSPARENCY.md`) |
| **Relay identity** | a **Relay Descriptor** `RD = {v, url, spki_pin?}` | TLS: WebPKI + host name when `spki_pin` is absent; the pinned SPKI hash (and no CA) when present | n/a — it *is* the thing being named |
| **Mailbox** | `(RD, capability)`: where to drop ciphertext for one recipient device | the capability is a bearer secret chosen by the recipient | A relay can read/drop what is sent to its own mailboxes; it cannot decrypt |

User identity keys never derive from, and are never replaced by, a relay. A relay that changes a contact's keys in a directory response triggers the
existing `IDENTITY_CHANGED` flow; a relay that substitutes *itself* in a mailbox descriptor is caught by the card signature (§3) or by the MLS-authenticated
`MailboxUpdate` (§7).

## 3. Contact Card (invitation / QR) — versioned and authenticated
Binary, base64url, magic `CCD1`:
```
CCD1 | payload_len(u16) | payload | sig(64)
payload (JSON, UTF-8, exact bytes signed):
  { "v":1, "account":"<32 hex>", "root_key":"<b64 32B>", "relay":{"url":"https://…","pin":"<b64 32B>|null"},
    "intro":"<b64 16B capability>", "issued":<ms>, "expires":<ms> }
sig = Ed25519(root_key, "cipher-card-v1\0" || payload)
```
* Parsing is strict: exact magic, length, `v==1`, `https` only, `.onion` URLs **require** `pin`, expiry ≤ 30 days after issue, unknown fields rejected.
* The card is ~250 bytes (fits a QR). Key packages and device records are *not* in it; they are fetched through the intro capability (§4) and are
  self-authenticating against `root_key`.
* **What the signature buys:** a party that edits `relay`, `intro` or `expires` of someone's card without holding the root key invalidates it. **What it does not buy:**
  if an attacker replaces the whole card with their own, the user pins a different identity — only a safety-number/QR comparison over a trusted channel detects that.
  Scanning in person is the strong path; a card sent over an untrusted channel is TOFU.
* Revocation: the issuer revokes the intro capability at their relay (`/v1/caps/revoke`); an expired or revoked card yields `invalid`.

## 4. Intro capability (first contact without an account on B)
A capability of kind `intro` (relay migration 0007). It authorises exactly three unauthenticated calls **at the issuer's relay**, all rate-limited per capability and per
hashed source, never per identity:
1. `POST /v1/intro/directory {cap}` → the issuer's device records (self-authenticating).
2. `POST /v1/intro/key-package {cap, device}` → consume one KeyPackage of one of the issuer's devices.
3. `POST /v1/deliver` with the same `cap` → queue the Welcome (and later messages) for the issuer's device.
Unknown/expired/revoked/wrong-kind capabilities all answer the single result `invalid` (no oracle). KeyPackage claims are capped (12/h per capability) so a leaked card
cannot drain the pool faster than the owner's hourly refill (ST-022/ST-030 stay open: last-resort KeyPackage is still missing).

## 5. Message flow (client-mediated, one hop to the recipient's relay)
```
Bob  ── shows card(RD_B, intro_B) ──────────────────────────────►  Alice            (QR / link)
Alice ─ verify card sig, pin root_key ─ intro/directory, intro/key-package ──► relay B   (via her privacy transport)
Alice ─ creates the 1:1 MLS group locally; Welcome ──► /v1/deliver(intro_B) ──► relay B   (no sender field exists)
Alice ─ DeliveryCap{ cap_A, RD_A } as first app message ──► /v1/deliver(intro_B)
Bob   ─ polls relay B with his normal signed requests, joins, sees a MESSAGE REQUEST (unknown inviter), accepts
Bob   ─ DeliveryCap{ cap_B, RD_B } ──► /v1/deliver(cap_A) ──► relay A       (Bob needs no account on A)
steady state: every message goes to the peer's current (RD, cap) as an unauthenticated /v1/deliver; each side only ever reads its OWN relay.
```
* Relay A never contacts relay B and vice versa. A learns that *Alice's address* sent something to B only if A is also her network path (she may use Tor, which hides it from A).
* The peer's `(RD, cap)` is stored per conversation device and updated **only** by a `DeliveryCap` frame that arrived inside the MLS conversation (authenticated by the sender's leaf).
  A relay cannot inject or alter it.
* **Acknowledgements.** Relay `queued`/`duplicate` ≠ delivered. Delivery state is unchanged: `Delivered` only on an end-to-end receipt frame (`DELIVERY_SEMANTICS.md`).
  Receipts travel the same way (to the sender's `(RD, cap)`).
* **Idempotency.** `message_id` is the dedupe key at the relay (`duplicate`) and at the recipient (replay cache); retries are safe.
* **Offline queues.** Bob's relay holds ciphertext up to its TTL and per-capability quota; Alice's outbox (encrypted, survives process death) retries with backoff while the
  peer relay is unreachable. A destination that stays `invalid`/unreachable leaves the message `Pending` then `Failed` — never silently `Sent`.
* **No authenticated fallback for remote peers.** For a peer on another relay there is no registered-device path; `invalid` means "wait for a fresh capability", not "try another way".

## 6. Capability distribution, rotation, revocation
Same as `DELIVERY_CAPABILITIES.md` with one addition: the `DeliveryCap` frame carries the owner's `RD`, so the sender knows *which relay* the capability is valid at. Rotation every
7 days with a 1 h grace; revoked immediately on suspected leak. A sender whose capability turns `invalid` waits for the next `DeliveryCap` (the owner re-sends on rotation).

## 7. Relay migration and unavailable destinations
* **Planned move** (Bob moves from B to B′): Bob sends `MailboxUpdate{ RD_B′, cap′ }` (same frame type as `DeliveryCap`, new RD) to the old `(RD_B, cap)` *and* keeps polling B until
  every contact has acknowledged. Because the update is an MLS application message, relay B cannot forge or redirect it (a malicious B can *withhold* it — detectable as "no receipt").
* **Unplanned loss** of B: contacts' outboxes fail after retries; the conversation shows `Failed`; recovery requires a new card (no recovery by design, `RECOVERY_AND_DEVICES.md`).
* **Expired card / capability**: `invalid`, shown as "invitation expired".

## 8. Why client-mediated, and what that costs
Server-to-server federation would make relays learn each other's users and require relay authentication and trust between operators. Client-mediated delivery keeps the relay purely a
mailbox. Cost: the sender (via her privacy transport) connects to every recipient's relay, so **relay B sees a connection from Alice's network address** (hidden if she uses Tor).

## 9. Groups and commit ordering — BLOCKED, with reasons
MLS commits (membership changes, key updates) must be applied in one agreed order. Today the relay holding the group's tag is the sequencer (`/v1/groups/{tag}/commit`), and every member is
authenticated *there*. With members on different relays there is no authenticated path for a visitor and no single sequencer. Options (none implemented, none safe to improvise):
1. **Home-relay groups**: every member registers at the group's home relay. Works today; not cross-relay.
2. **Capability-gated sequencer on the home relay** with commit capabilities handed out inside the group. Needs a security design for who can mint/revoke commit capabilities and for fan-out.
3. **Deterministic tie-break without a sequencer** (2-member only): not suitable for groups.
Until option 2 is designed and reviewed, **cross-relay groups are not supported**, and **cross-relay 1:1 conversations do not perform MLS key-update commits** (so no automatic post-compromise
security refresh; ST-044). Welcome-only creation needs no sequencer.

## 10. Attachments across relays
Files are uploaded to the **recipient's** relay with a *blob capability* (Phase 4), so the recipient downloads from the relay he already authenticates to. See `MULTI_RELAY_ATTACHMENTS` section in
`MASTER_IMPLEMENTATION_STATUS.md` once implemented.

## 11. Attack analysis (hostile relay B)
| Attack | Outcome |
| --- | --- |
| B substitutes Bob's device records / keys | Card pinned `root_key`; mismatching records fail the binding check or raise `IDENTITY_CHANGED`. |
| B swaps the intro capability or relay in a card in transit | Card signature fails. |
| B hands Alice KeyPackages that are not Bob's | A KeyPackage must be signed by a key whose identity matches the pinned device record (`ExpectedPeer` check, already enforced). |
| B drops / delays / reorders messages | Possible; detectable only as missing receipts (ST-032). Later messages still decrypt. |
| B replays Alice's ciphertext | Replay cache + MLS generation checks at Bob; `message_id` dedupe. |
| B learns the social graph | B sees, per capability, that *something* arrived and when; not the sender identity. B can group deliveries by source address unless Tor is used. |
| Leaked intro/delivery capability | Bounded junk (quota) until rotation/revocation; junk fails MLS authentication. |
| Downgrade to cleartext / another relay | No: `https` only, `.onion` requires a pin, RD changes only via an MLS-authenticated frame. |

## 12. Implementation status
| § | Item | Status |
| --- | --- | --- |
| 3 | Contact Card codec + signature | see status doc |
| 4 | Intro capability + relay endpoints | see status doc |
| 5 | Cross-relay DM engine path | see status doc |
| 6 | Relay descriptor in `DeliveryCap` | see status doc |
| 7 | `MailboxUpdate` migration | designed, not built |
| 9 | Cross-relay groups | **blocked** (design decision) |
| 10 | Cross-relay attachments | see status doc |
