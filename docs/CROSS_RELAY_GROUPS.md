# Cross-relay MLS groups and commits — sequencing and consistency design (ST-044)

**Status: v2 of this design (§7, as corrected by §8) is IMPLEMENTED as an experimental feature (2026-10-11) with the limits in §8. Self-reviewed only; it still needs an independent review (ST-005) before it is relied on.** §3–§5a record the earlier proposal and its review.
Cross-relay 1:1 conversations today perform no commits and groups with members on another relay are refused (`MULTI_RELAY_PROTOCOL.md` §9). This document says what a safe lift of that restriction would require.

## 1. What must hold
1. **Total order of commits per group** (MLS requires every member to apply the same commit sequence). Two commits for one epoch must never both be accepted by different members.
2. **Receiver-side authorization stays authoritative.** The ordering service is untrusted for authorization, exactly as the single-relay sequencer is today: every receiver re-runs `authorize_commit`.
3. **No new identity exposure.** An ordering service must not learn account ids or the member list; it may learn timing and volume.
4. **A hostile ordering service may delay, drop or equivocate but must not be able to cause silent acceptance of a forged membership**; equivocation must at worst split the group detectably (ST-029).
5. **Removal must still cut access**: after removal the removed member's capabilities stop working and the new epoch's secrets are unreadable to them (same as `HISTORY_REVOCATION.md`).
6. **No relay-to-relay trust.** Relays still never contact each other.

## 2. Rejected options
| Option | Why rejected |
| --- | --- |
| Members elect/rotate a sequencer ad hoc | Needs a consensus protocol among mutually distrusting clients that are mostly offline. Not a place to improvise. |
| Each member's own relay sequences "its" commits | Two relays can accept different commits for one epoch: a fork by construction. |
| Deterministic tie-break without a sequencer (lowest leaf index wins) | Works for 2 members that see both commits; for N offline members a commit can be invisible to the one who must lose. |
| Relay-to-relay federation | Violates §1.6; makes relays learn each other's users. |

## 3. Proposed design: one HOME relay per group, reached by capabilities
* The group has a **home relay** `H` (a `RelayDescriptor`), chosen by the creator, recorded in the MLS-authenticated group metadata extension (like the roles are). Changing it is a commit that only an owner can make.
* `H` already implements the sequencer (`/v1/groups/{tag}/commit`, compare-and-swap on the sequence, atomic fan-out, idempotency by commit id). New, additive endpoints (not built):
  * `POST /v1/groups/{tag}/commit-by-cap` — body as today, `Authorization: GroupCap <cap>`; the cap is a random 128-bit secret scoped to (tag, "commit"). Unauthenticated otherwise.
  * `GET /v1/groups/{tag}/log?after=N` with `Authorization: GroupCap <read cap>` — returns the retained commit log (ciphertext blobs with sequence numbers), bounded in size and retention.
* **Caps are distributed inside the group** as MLS application frames (`GroupCaps{commit_cap, read_cap, home}`), minted at `H` by a device that is an owner/admin of the group, and are **rotated with the routing tag on every removal** (the removed member cannot read the new epoch's frame). Members who are not admins hold only the read cap; an admin additionally holds the commit cap. (The relay cannot enforce "admin only" — a leaked commit cap lets anyone submit; see §4.)
* **Commit flow:** committer builds the commit locally → `commit-by-cap` with `expected_seq` → on `Accepted(seq)` merges locally (exactly the current flow) → the Welcome for new members goes to their mailbox through the **client-mediated delivery of the 1:1 design** (card/intro capability), because `H` cannot reach their relay.
* **Receiving commits:** every member polls `H`'s log with the read cap in addition to its own mailbox (gap-free sequence numbers; a missing number is detected). Application messages are **not** routed through `H`: they use the per-member mailbox capabilities as in 1:1 (client-mediated fan-out, one request per distinct member relay, never one request naming all members).
* **Epochs and sequence numbers stay decoupled** (as today: `relay_seq` vs MLS epoch). A garbage commit that consumed a slot is skipped by receivers because it fails MLS/policy validation.

## 4. Threats and the design's answers
| Threat | Outcome |
| --- | --- |
| `H` censors/delays commits | Group liveness stops (same as today for a single relay). Detectable by committers (no `Accepted`). Remedy: owner creates a new group (no in-place home change if `H` is dead). |
| `H` equivocates (shows different logs to different members) | Members apply different commits → MLS state diverges → messages become undecryptable (ST-029). Detection only; **not prevented**. Mitigation to evaluate: members include the log head hash in application frames so divergence is noticed early. |
| Leaked commit cap | Attacker can burn log slots with garbage (DoS/spam) until the next rotation; cannot forge membership (receivers validate). Rate limit per cap; rotate on suspicion. |
| Leaked read cap | Attacker reads commit ciphertext; learns timing and size, not content. |
| `H` learns membership | Sees poll timing per read cap and source address: it can estimate group size/activity. Not account ids. Over Tor the address is not available. |
| Removed member keeps polling | Old caps are revoked at rotation; the new epoch is unreadable to them. A relay that withholds the removal commit keeps their old access (ST-035, unchanged). |
| Race: two admins commit at the same time | CAS: exactly one wins; the loser rebases (existing code path). |
| Partial fan-out of a Welcome | The new member is not in the group until the Welcome arrives; committer's outbox retries (existing machinery). |

## 5. Open questions that need review before any implementation
1. Is "owner/admin holds the commit cap" acceptable given the relay cannot verify it? (A malicious *member* who learns the cap can only spam; confirm no way to also cause a state fork.)
2. Log retention vs. offline members: how long may a member be away and still catch up? (Today: queue TTL.) Needs a rule for members that fall behind the retained log (re-add by an admin).
3. Poll cost and metadata for N groups × M members; whether a single batched poll endpoint leaks group co-membership to `H`.
4. Migration of the home relay when the operator is leaving (a two-phase commit that `H` must still serve once).
5. Interaction with PCS: scheduled self-update commits become cap-submitted commits from every member (not only admins) — requires a self-update-only cap class or accepting that members hold commit caps.

## 5a. Self-review of this design (2026-10-10) — conclusion: NOT yet defensible; do not implement
Re-reading §3–§4 as an attacker found these gaps. Each must be closed in the *design* first.
1. **A single shared commit cap gives a liveness attack, not only spam.** Anyone holding it can submit a garbage commit with the *correct* `expected_seq`; CAS accepts it, every honest committer loses the race, rebases, and the attacker repeats. Receivers reject the garbage (no fork), but progress stops until rotation. Fix direction: **per-device commit caps** (minted by `H` per member device, individually revocable and rate-limited), so a leak is attributable to a device and cuttable without re-keying every holder. Cost: `H` can then count distinct member devices (a metadata leak to weigh).
2. **Removal window.** The cap-rotation frame is sent *after* the removal commit is accepted, so the removed member's old commit/read caps work for the slots in between. Receivers still validate, but the removed member can burn the first slot after removal. Needs: rotation published in the same atomic step as the removal commit, or a rule that the slot immediately after a removal is reserved for the remover.
3. **Shared read cap links all pollers.** One read cap for a group lets `H` count distinct source addresses polling it = group size/online pattern. Per-device read caps do not remove this (H still sees which caps belong to one log). Mitigation requires the poll to go through Tor (Profile A) — then it is a **precondition** for any cross-relay group privacy claim, not an option.
4. **Equivocation is detection-only and detection is not specified.** "Include the log head hash in application frames" needs an exact definition (hash chain over commit ciphertext, included in the MLS-authenticated application data, checked by every receiver, UI behaviour on mismatch). Until specified and tested against a malicious `H`, a forking `H` can silently split a group for as long as members exchange no frames across the split.
5. **Welcome ordering.** A new member's Welcome is delivered client-mediated *after* the commit is accepted; a committer that crashes between the two leaves a member in the group who cannot join. Needs a durable "pending welcome" record in the committer's outbox (the 1:1 outbox machinery exists but is not proven for this case) and a re-add path.
6. **Self-update (PCS) commits** from every member imply every member holds a commit cap — this compounds item 1. A separate cap class for self-updates (cannot add/remove) is required, and the *receiver* must enforce "self-update only" for non-admin senders (exists as `authorize_commit`; must be tested with caps in the loop).
7. **Home-relay failure is terminal** (no in-place migration) — acceptable only if stated to users; open question 4 stays open.
8. **Test plan is not strong enough**: the matrix needs a *malicious* `H` (reorder, drop, equivocate, replay stale log) and a *malicious member* (leaked cap, garbage commits at every slot) in the fault schedule, not just outages.

**Decision:** ST-044 stays *unimplemented*. The engine keeps refusing groups with members on another relay. Next step is a revised design addressing 1–6 and an independent review (ST-005), not code.

## 6. What changes in the code (estimate, not done)
Relay: two endpoints + `group_caps` table + log retention + tests (`delivery_caps.rs`-style). Core: group metadata `home`, `GroupCaps` frame, polling of `H`, client-mediated fan-out of application messages for groups, per-relay Welcome delivery, removal rotation. Tests: extend `delivery_matrix.rs` with 3 members on 3 relays, concurrent admins, home-relay outage, removal races, malicious-`H` equivocation (expect detection, not prevention).

**(Superseded: see §8. The engine now creates cross-relay groups through a home relay.)**

## 7. Revised design v2 (2026-10-10) — answers to §5a, still NOT implemented
The §3 proposal used long-lived random "commit"/"read" capabilities handed around in application frames. §5a showed that this makes removal racy and leaks a liveness attack. v2 replaces them with **epoch-derived authentication**, which needs no separate rotation message.

### 7.1 Authentication to the home relay `H` = knowledge of the current epoch
* Both secrets are derived from the MLS epoch with the RFC 9420 exporter: `commit_key = Export("cipher-home-commit-v1", group_id, 32)`, `read_key = Export("cipher-home-read-v1", group_id, 32)`. Only current members can compute them; a removed member cannot compute them for any epoch after its removal.
* `H` stores, per group tag, only `SHA-256("verifier" ‖ key)` for each of the two keys of the **current** log head epoch. A request carries a MAC (or the key itself over the pinned TLS channel; a MAC is preferred) that `H` checks against the verifier.
* **A commit request carries the verifiers for the epoch it creates** (`next_commit_verifier`, `next_read_verifier`). `H` accepts the commit and switches verifiers **in the same database transaction** (the existing compare-and-swap on the sequence). Consequence: there is no window in which a removed member's credentials still work after its removal commit is accepted (closes §5a item 2), and no cap-rotation frame exists to be lost.
* *Feasibility check required before code:* the committer must compute the **next** epoch's exporter before merging. If OpenMLS cannot expose it from a staged commit, compute it on a throw-away clone of the group state (load the group from storage, merge the clone, export, discard). If neither is possible, v2 does not work as written and a two-step "commit, then publish verifiers with a monotonic epoch number" protocol with a visible window must be designed instead.

### 7.2 What a hostile member can and cannot do (closes §5a items 1 and 6)
* Every current member can submit a commit, exactly as MLS allows. The receivers' `authorize_commit` decides whether a commit is acceptable (non-admins: update-only). No separate "self-update" capability is needed — PCS commits are ordinary commits.
* A malicious *member* can therefore burn a log slot with a commit that receivers reject. This is **not preventable** by the home relay (it cannot validate MLS state) and is the same denial-of-service any hostile group member has in MLS. It is **attributable** when the commit is validly signed by a leaf (admins remove that leaf), and **not attributable** when it is unparseable garbage. Mitigation: `H` accepts only bodies that parse as an MLS `PublicMessage`/`PrivateMessage` commit of bounded size and rate-limits per tag; it cannot do more. This limitation must be shown to users (a group's liveness is only as good as its least trusted member).
* A malicious member cannot forge membership: every receiver re-validates.

### 7.3 Fork and rollback detection (closes §5a item 4)
* Log entries are **hash-chained by `H` and re-checked by clients**: `h_i = SHA-256("cipher-home-log-v1" ‖ h_{i-1} ‖ be64(seq_i) ‖ SHA-256(commit_blob_i))`. Every `GET log` response includes `h_i`; a client verifies the chain it receives and refuses any response whose chain does not extend its stored head (rollback or rewrite ⇒ alarm, not silent acceptance). Sequence numbers must be gap-free.
* Every application message carries, **inside its MLS-authenticated data**, `(seq, h_seq)` of the sender's current head. A receiver compares it with its own chain at the same `seq`. Mismatch ⇒ **fork alarm**: the group is frozen for sending until the user decides (the equivocation case of ST-029). A matching head proves the sender and receiver saw the same history up to `seq`.
* *Not detectable:* a **permanent partition** in which `H` shows disjoint logs to two sets of members who never exchange a message across the split. That is inherent to any single-sequencer design. State it.

### 7.4 Welcome delivery (closes §5a item 5)
* **Write-ahead outbox:** before sending the commit, the committer durably records `PendingAdd{commit_id, joiner_card, welcome_blob}`. After `Accepted(seq)` — or after recovering from a crash by looking up `commit_id` in the log (idempotent by commit id) — the Welcome is delivered through the 1:1 client-mediated path (card/intro capability) with the usual retry/ordering machinery. If the commit turned out **not** to be accepted, the record is discarded and the add is rebuilt on the new head.
* The Welcome carries the home relay descriptor (with pin) in the MLS-authenticated group-info extension, so the joiner learns `H` only from authenticated data.
* A joiner whose Welcome is undeliverable (its relay is down) stays a *ghost leaf*: receivers must not treat it as a participant for security statements (UI shows "invitation pending"); an admin removes it after a timeout. Messages encrypted to the new epoch remain unreadable for the ghost until it joins, which is correct.

### 7.5 Capability / metadata (closes §5a item 3, partially)
* All members share the same two keys for an epoch, so `H` can only see *how many distinct sources* poll a tag. Over Tor (Profile A) the source is not visible; on Profile B (public TLS) `H` sees group size/online pattern by source address. **Tor is therefore a precondition for any claim of membership-size privacy for cross-relay groups**, and the UI must say so otherwise.
* A batched poll across groups is **rejected**: it would give `H` the co-membership of groups for one device. One request per group, with randomised polling jitter.
* Application messages never touch `H` (client-mediated fan-out to each member's relay, one request per distinct relay).

### 7.6 Home relay failure and move
* Failure of `H` stops **membership changes** (commits). Application messages continue in the last epoch (they do not use `H`), so a dead home relay degrades but does not kill a group. Recovery = an owner creates a new group and re-invites by card (no in-place recovery; stated, not hidden).
* Planned move: an owner commits `MoveHome(new_descriptor)` through the *old* `H` (the last entry it serves); members then follow the descriptor in the new epoch. The old `H` marks the tag moved. A hostile old `H` that withholds the `MoveHome` commit only delays the move.

### 7.7 Tests required before any code is considered done
Extend `delivery_matrix.rs` (seeded) and `multi_relay.rs` with: 3 members on 3 relays plus `H` on a 4th; concurrent commits (CAS winner exactly one, loser rebases); removal then immediate use of old credentials (must fail at once); malicious `H` modes — drop one entry, reorder, duplicate, serve a stale head, equivocate between two members (**expected: detection via §7.3, never silent**); malicious member garbage at every slot (expected: liveness loss, no state fork, no forged membership); crash between commit and Welcome at every step; `H` outage and recovery with gap-free catch-up; move of home. Plus fuzz targets for the log and request codecs.

### 7.8 What is still open (needs the independent review)
(a) the feasibility check in §7.1; (b) whether hashing the whole commit blob in the chain is sufficient or the epoch authenticator should also be bound; (c) exact UI semantics of a fork alarm; (d) retention: a member offline longer than the log retention must be re-added — the rule and the re-add flow are not specified; (e) interaction with scheduled PCS updates under a hostile member (rate rules). **Conclusion: v2 closes the specific defects found in §5a on paper, but it is untested and unreviewed; ST-044 stays open and the engine keeps refusing cross-relay groups.**

## 8. What was built, what changed from §7 while building it, and what is NOT solved (2026-10-11)
Code: `crates/cipher-wire/src/home.rs` (wire format, hash chain, request signing message), `crates/cipher-relay` (migration 0009, `/v1/home/{tag}/commit|log`), `crates/cipher-core/src/home.rs` (credentials, verifier, ledger), `app/engine_home.rs` (creation, commits, polling, introductions), changes in `engine_msg.rs` (per-device outbox, Welcome gating, frames carrying the log head) and `engine_att.rs` (one ciphertext copy per member relay). Invariants GR-001…GR-008; tests: `cipher-relay/tests/{home_log,cross_relay_groups}.rs`, `cipher-core/tests/{home_keys,home_client}.rs`.

### 8.1 Corrections to §7 found while implementing
1. **Public keys instead of verifiers.** The relay stores, per epoch, two Ed25519 PUBLIC keys; a request is signed with the secret derived from the MLS exporter (label `cipher/home/commit/v1` or `…/read/v1`). A hash "verifier" could not be checked without handing the relay the secret. `seq` equals the MLS epoch the commit creates.
2. **A key reads only up to the next entry.** §7 let any current-epoch key read the whole log, which would lock out a member that was offline for more than one commit. A key of epoch *e* appends only at head *e* and reads entries up to *e+1*; a member catches up one entry at a time (each applied commit yields the next key); a removed member can read its own removal commit and nothing after it.
3. **Garbage commits are worse than §5a/§7.2 said.** A member who submits a commit the relay cannot validate also chooses the *next epoch's public keys*, so the commit channel is captured, not just a slot burned: honest members hold keys for an older epoch and can no longer sign. This cannot be fixed without the relay validating MLS state. The implementation detects it (the commit is rejected by every receiver, the log position is recorded, the group is marked *blocked*), reports `GroupForkDetected`/`UnauthorizedGroupChange`, **blocks membership changes and keeps messaging working**. Recovery = a new group. **Any current member can therefore freeze membership changes of a cross-relay group.** Ordinary single-relay groups do not have this weakness.
4. **Joiner anchor.** A joiner cannot know the chain value before its own add entry. It reads the entry that added it, requires that entry's public keys to equal the ones it derived itself, and takes its chain value on first use. Equivocation about earlier history is outside what it can check; later equivocation is caught by head comparison.
5. **Capability bootstrap** was missing from §7. Members who only meet through the creator cannot learn each other's relay and capability from MLS. Owners/admins broadcast a *directory* (`GroupCaps`: every capability they know, including their own) when they learn a device's capability for the first time and when members are added; every member re-announces its own capability when the group grows; a device's own announcement always overrides hearsay. A malicious member can misdirect other members' messages to a relay it controls (it can already read them); the real recipient then does not receive them.
6. **Capability grace.** In single-relay groups a removal revokes the remaining members' old inbox capabilities at once. In a cross-relay group that deadlocks (each side needs the other's new capability, deliverable only through the revoked one), so cross-relay groups keep the normal grace (1 h). The removed member can deposit undecryptable ciphertext at remaining members' relays until it ends.
7. **Outbox ordering is per recipient device**, not per conversation: an unreachable member relay must not stall everyone else (`single_relay_delivery_matrix` and the two-relay matrix still pass). Devices of a cross-relay group whose location is unknown wait for their capability and consume no retry attempts; a device is never assumed to be on our relay.
8. **Held messages.** A message of epoch *n+1* can reach a member's mailbox before the commit reaches it through the log; it is held and retried when the commit has been applied.
9. **Group files.** One ciphertext copy is stored on every member relay (uploaded with a member's capability there, plus the sender's own relay); the message carries a per-relay table and each member reads the copy on its own relay.

### 8.2 Implemented and tested
Creation with members on other relays; Welcome delivery through cards' intro capabilities (write-ahead, per device, retried); joining and anchoring; text between all members; offline members; one dead member relay; home-relay restart and outage; concurrent commits (CAS, loser rebases); lost responses (idempotent by commit id); adding and removing members including a removed member winning a slot first; hostile home relay (tamper, renumber, roll back, replay, equivocate, withhold); forged and garbage commits; encrypted attachments to every relay; minimal knowledge of the home relay.

### 8.3 NOT built / NOT solved
* **Any member can freeze membership changes** (8.1-3). **A dead home relay blocks membership changes** (messages continue). **No home migration** (the home relay is immutable metadata); no log pruning or retention policy beyond hard bounds (4096 entries, 8 MiB per group, 20 000 groups per relay).
* **The home relay sees** timing, volume and the source address of every member's polls (all members share one credential per epoch); over Tor that address is hidden, on public TLS it is not. Polls are one request per group per sync.
* **Not tested:** real TLS or Tor between processes for groups, an Android emulator or physical device for groups, large groups (>~30 members: many introduction frames), mid-stream upload interruption of group files, multi-device accounts in cross-relay groups, relay databases restored from backup (rollback is detected by members, not repaired).
* **Not reviewed** by anyone other than the author; ST-005 stays open.
