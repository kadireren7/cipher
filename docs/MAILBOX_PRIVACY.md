# Mailbox privacy: what changed, what was measured, what remains

Scope: the relay-side metadata of Cipher mailboxes after the multi-relay work on branch `feat/self-hosted-multi-relay`.
Every claim below is either backed by a named automated test, or labelled as design/not done. **Nothing here is a claim of anonymity.**

## 1. Terms — five different things people call "privacy"
| Property | Meaning here | Status |
| --- | --- | --- |
| **Sender anonymity (toward the recipient's relay)** | the relay holding the recipient's mailbox cannot tell *who* delivered | **Improved** for capability deliveries and cross-relay first contact (§3). Not toward the sender's own relay, and not toward a network observer. |
| **Recipient privacy (toward their own relay)** | the relay cannot tell who reads which mailbox / who they talk to | **Not provided.** The relay maps a capability to a device and sees every poll and delivery to it. Needs PIR/mixnet: §5. |
| **IP-address privacy** | the relay and peers do not learn the client's network address | **Only via Tor** (outside Cipher's control): `NETWORK_ADVERSARY_MODEL.md`. |
| **Account pseudonymity** | accounts are random ids, no phone number/e-mail | Yes, unchanged. A relay still holds an `account ↔ device` directory (ST-010). |
| **Relationship unlinkability** | the relay cannot tell that A and B talk | **Partly.** Within one relay a recipient's relay no longer sees the sender of capability deliveries; it still sees that *some* holder of a capability wrote to that mailbox, how often, when. Colluding with the sender's network path restores the link. |
| **Traffic-analysis resistance** | timing/size correlation is hard | **Weak.** Padding classes and optional cover (ENHANCED) only; measured gain is small (ST-040). |

## 2. Baseline (before this branch)
`METADATA_MODEL.md` and `DELIVERY_CAPABILITIES.md` describe it: signed requests for first contact (directory lookup + KeyPackage claim + sequenced Welcome); capability deliveries
already anonymous *within one relay*; queue lanes; keyed pair hashes for quota accounting.

## 3. What changed — and the measurement
Change 1 — **cross-relay mailbox delivery** (`MULTI_RELAY_PROTOCOL.md`): a contact on another relay delivers to your mailbox with a capability, from their own device, with *no* account on your relay.
Change 2 — **card-based first contact** with an *intro capability* instead of an authenticated directory lookup + KeyPackage claim.

Measured with `cargo test -p cipher-relay --test metadata_measurement -- --nocapture` (real engines, real relays, real PostgreSQL). Same user goal — *start a conversation with Bob and send one message* —
observed by **the relay that holds Bob's mailbox**:

| metric | before (same relay, directory flow) | after (cross-relay, card flow) |
| --- | ---: | ---: |
| requests signed by Alice (her identity revealed) | 8 | **0** |
| requests naming Bob by a stable id | 6 | 1 (the KeyPackage claim names Bob's device on **his own** relay) |
| requests that link Alice → Bob | 6 | **0** |
| database mentions of Alice's account/device ids | 73 | **0** |
| queue rows carrying a (keyed) sender hash | 3 | **0** |

How to read it: "before" is not a flaw in the old design — Alice and Bob shared one relay, so that relay necessarily knew both. The point is that **choosing a relay for yourself no longer reveals
you to the relays of the people you talk to.** Also measured: neither relay's database holds any record of the other relay's user (`a_peer_on_another_relay_is_never_reached_through_the_authenticated_path`).

## 4. What the mailbox relay STILL sees (remaining correlations)
1. That a capability/card holder connected from some network address at time *t*, with a ciphertext of padded size *s* — and how often. With Tor the address is an exit/onion circuit.
2. The recipient's device id, polling times and online pattern (authenticated `fetch`). Every poll is signed by a stable device key.
3. For group commits (same-relay groups only): the committer and the group routing tag.
4. Which capability a delivery used. Capabilities rotate every 7 days (1 h grace) and immediately on group removal, so linking deliveries across rotations needs another signal.
5. A leaked card/intro capability lets its holder claim KeyPackages (bounded: 4/h per capability, 12/h per target) and fill the capability's quota until it is revoked or expires (≤ 30 days).
6. Relay migration: a contact who learns your new relay learns where you moved; the old relay learns that you stopped polling.

## 5. Considered and deliberately NOT built
| Idea | Why not (yet) |
| --- | --- |
| Opaque rotating mailbox ids replacing the device id as the queue key | Does not stop the relay mapping mailbox → device on every authenticated poll; the poll itself is the leak. Cheap to add, but no measurable benefit without batching/PIR. |
| Sealed sender (hide the sender from the *recipient's own* relay for authenticated sends) | Already achieved for capability deliveries; for commits the sequencer needs authentication. A redesign, not a patch (ST-009). |
| Polling many mailboxes / decoy mailboxes (k-anonymity) | Costs bandwidth linearly, protects only against a relay that cannot see the decoys' timing; needs a measured design first. |
| PIR for fetch, or a mixnet | Specialised cryptography (SimplePIR-class schemes, Sphinx-class packet formats). **First requires a focused security and performance design and external review; not deployed experimentally.** Open item ST-039. |
| Server-side group membership records | None exist today: the sequencer stores only a random tag, epoch and a coarse day (`0002_groups.sql`). Nothing to remove. |
| Permanent per-user reputation for abuse control | Rejected: abuse limits are per capability and per hashed source address, never per identity. |

## 6. Abuse resistance without permanent identity tracking
Per-capability token buckets and quotas (messages and bytes), per-source buckets (sources behind Tor are shared, so generous), a cap on live capabilities per device (256) and live cards (8),
KeyPackage claim limits, global in-flight load shedding, and a registration token for account creation (operator-controlled). Limits and tests: `delivery_caps.rs`, `intro.rs`, `inbox_flooding.rs`.
A hostile *sender* who holds a valid capability can cost the recipient storage up to the quota; revocation ends it. A hostile *relay operator* can drop or delay (undetectable apart from missing receipts).

## 7. Retention and deletion
Messages: TTL on the relay (default and max in `cipher-wire` limits), deleted on acknowledgement; purge every minute. Attachments: 14 days. Capabilities: 30 days (expired rows deleted on the next mint).
The Welcome/commit rows are deleted with the queue entry. Backups of the database contain whatever the database contains at that moment (ciphertext, hashes, public keys): protect them like the database.
Not covered: flash-storage remanence on the server, filesystem snapshots.
