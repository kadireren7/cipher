# Delivery capabilities (anonymous, recipient-issued, rotating)

Implemented in this pass (relay migration 0006, `engine_msg.rs` capability section). **Not independently reviewed (ST-005).** Does not change any E2EE property: a capability only lets its holder *queue ciphertext* for one device; it cannot decrypt anything, read the queue, or authenticate as anybody.

## Problem
Every send used the recipient's **stable device id** and an **authenticated** request: the relay learns sender device, recipient device and time for each message, and any account can fill any victim's queue (ST-031).

## Design
```
recipient B ──authenticated──► POST /v1/caps {caps:[c]}       (c = fresh random 128 bit, chosen by B; relay stores SHA-256(c) only)
B ──inside the MLS conversation──► DeliveryCap{c}  (control frame: never shown, never in history)
sender A ──UNAUTHENTICATED──► POST /v1/deliver {deliveries:[{cap:c, message_id, ciphertext}]}
relay: looks up hash(c) → B's device queue; per-capability quota; no sender identity exists in the request or the database
```
* **Per (own device, conversation)**: one capability, shared with that conversation's members through E2EE (so the relay cannot see who holds it, and a capability reveals no conversation id).
* **Rotation:** every 7 days (grace 1 h so in-flight sends survive) and **immediately on group removal** (old capability revoked with *no* grace; the new one is announced in the new epoch, which the removed member cannot read).
* **Revocation / expiry:** `POST /v1/caps/revoke` (owner only); relay caps live 30 days; unknown, revoked, expired and guessed capabilities all answer the single result `invalid`. A sender that gets `invalid` forgets the capability and **in the same attempt** falls back to the authenticated path (open lane) — no message is lost; the fallback is visible in `delivery_path_counts` and is not silent: it is the pre-existing behaviour.
* **Queue lanes (ST-031):** `OPEN` (authenticated, no capability: first contact, legacy) ≤ 100 envelopes / 2 MiB per recipient in total, however many accounts send; `CAPABILITY` ≤ 250 envelopes / 4 MiB **per capability**; `COMMIT` (group sequencer) shares the remainder with a per-sender share. Strangers cannot starve contacts.
* **Abuse controls without identity:** per-capability token bucket and a generous per-(hashed)-source bucket (sources are Tor exits); ≤ 256 live capabilities per device; mint rate-limited; guesses cost 2^-128 each.
* **Not a decryption right:** capability + ciphertext without MLS keys is noise (PRIV-010).

## What the relay sees now
| | before | after (capability delivery) |
| --- | --- | --- |
| Sender device at request time | yes (signed request) | **no** (unauthenticated) |
| Recipient | stable device id in the request | opaque capability; maps to a device **in the relay DB** (the relay can still resolve it) |
| Sender stored | no (pair hash for share accounting) | no, **and no pair hash** |
| Message vs commit | by endpoint | commits still go through the authenticated sequencer (`/v1/groups/{tag}/commit`) — the relay sees the committer and the group tag |

## Residual (honest)
* The relay **can** map capability → recipient device, so a *compromised relay still learns the recipient side of every delivery and the time*; what it no longer learns from the request is the **sender**. Recipient-side metadata needs sealed-sender/mailbox designs the relay cannot resolve — **not built**.
* Fan-out of a group message is one request carrying N capabilities, so the relay learns "these N devices are in one conversation" for that request (splitting into N requests costs latency/bandwidth; not done).
* Group commits/Welcomes are authenticated (sequencer needs it); first contact and the `DeliveryCap` control frame itself travel the authenticated open lane.
* A capability leaked to an attacker allows ≤ 250 junk envelopes per capability until rotation; the junk fails MLS authentication at the recipient and is dropped.
* The relay still holds the account↔device directory (ST-010) and rate-limit/pair state described in `METADATA_MODEL.md`.
