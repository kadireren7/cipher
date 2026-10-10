# Cross-relay MLS groups and commits — sequencing and consistency design (ST-044)

**Status: DESIGN ONLY. Nothing here is implemented. It needs independent review before code (ST-005).**
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

**Until this is reviewed, the engine keeps refusing groups with members on another relay.**
