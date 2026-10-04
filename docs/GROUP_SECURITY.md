# Group security (resolves ST-007; PCS part of ST-008)

Groups are MLS groups (RFC 9420, OpenMLS 0.9.0, ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`). A 1:1 chat is a two-member group with `kind = DM`.
The relay is **cryptographically untrusted and not trusted for authorisation**: it orders and carries ciphertext, nothing more.

## 1. Authenticated group metadata

Name, kind, roles and the routing tag live in a **GroupContext extension (type `0xF1A0`)** (`app/groupmeta.rs`). Because it is part of the MLS GroupContext it is
covered by the confirmation tag and key schedule: every member agrees on it, and the relay cannot alter it. The group also declares `RequiredCapabilities`
so a member that does not understand the extension cannot be added (`InsufficientCapabilities` instead of silently diverging).

## 2. Roles and permissions (pure function, `authorize_commit`)

| Action | Owner | Admin | Member |
| --- | --- | --- | --- |
| Add a new account | yes | yes | no |
| Add another device of an existing member | yes | yes | only their own |
| Remove a member | yes (not themselves — the owner must transfer ownership first) | members only (not admins/owner) | no |
| Unlink own device | yes | yes | yes |
| Leave the group | after transferring ownership | yes | yes. MLS lets a member only *propose* leaving, so the app sends a `LeaveRequest` and the conversation is marked `Left` locally; an owner/admin's client performs the removal commit (`process_pending_actions`) |
| Rename group | yes | yes | no |
| Promote/demote admin, transfer ownership | yes | no | no |
| Change `kind`, schema version | never | never | never |
| Rotate routing tag | only together with a removal, **required** on removal | same | — |

Rules enforced regardless of who sends: exactly one owner; roles only for current members; the owner cannot be removed; removing an account must remove **all** its devices;
a DM never gains a third account; any proposal type outside the supported set is refused.

## 3. Receiver-side enforcement (the relay is not trusted)

Every receiver stages the incoming commit, extracts a `CommitInfo` (sender account, adds, removes, metadata change, unsupported proposals), runs the same deterministic
`authorize_commit` against the epoch state *before* the commit, and **merges only if allowed**. A violation is rejected, reported as the `SecurityEvent::UnauthorizedGroupChange`, and the group state is unchanged
(it does not brick the group). The relay's own checks are only an optimisation. Tests: `crates/cipher-core/tests/group_policy.rs` (7), `groupmeta.rs` unit tests,
`engine_groups.rs::group_messaging_roles_and_enforced_authorization`, `::a_forged_commit_from_a_member_is_rejected_by_everyone_and_does_not_brick_the_group`.

## 4. Commit ordering and concurrent commits

* The relay keeps, per routing tag, a **commit sequence**. `POST /v1/groups/{tag}/commit` carries `expected` (the sender's last seen sequence). In one PostgreSQL transaction the relay compares-and-swaps,
  stamps the next `group_seq` on every delivery (commit to existing devices, Welcomes to new ones) and enqueues them **atomically** — all or nothing. A stale `expected` returns `409 Conflict` with the current value.
* A client whose commit lost the race clears its pending commit, **pulls and applies the winner**, re-evaluates its intent against the new state (it may now be unauthorised or redundant) and retries (≤ 4 attempts).
  Because the sequence is total, every honest member applies the same commits in the same order ⇒ deterministic convergence. Tests: `postgres_relay.rs::concurrent_commits_have_exactly_one_winner_and_no_partial_delivery`,
  `::group_commit_is_compare_and_swap_with_deterministic_ordering`, `engine_groups.rs::concurrent_commits_are_ordered_deterministically_and_the_loser_rebases`.
* **Out-of-order / withheld commits:** application messages for an epoch the member has not reached are *held* (bounded: 64 per conversation) and retried when the commit arrives; they are never dropped and never decrypted with the wrong state.
  `max_past_epochs = 2` lets a member still decrypt a late message from one of the two previous epochs. Test: `::a_commit_withheld_by_the_relay_holds_later_messages_until_it_arrives`.
* **Replay:** a replayed commit/message is rejected by the per-device replay cache and by MLS generation counters; a replayed commit never advances an epoch twice.

**Residual risk (documented, not solved):** a malicious relay can **partition** a group by delivering different commit orders to different members (or withholding a commit from some). MLS makes the resulting states
mutually undecryptable, so it shows up as undecryptable messages — it is detectable, not preventable, and there is no automatic partition healing. The relay can also delay or drop commits (availability).

## 5. Removal and history

* **Removed members cannot read future epochs.** A removal commit rekeys the group; the routing tag **rotates** with it, so a removed member (who knows the old tag) can neither keep submitting commits nor receive new traffic.
  TESTED: Rust invariant tests (even if the relay misroutes ciphertext to the removed member, with a stolen pre-removal state), and **on the real relay binary with the Android app as a member**: after removal the removed peer's history
  contained only pre-removal messages, its sync returned nothing new, and `send` was refused (`conversation is not active`).
* **History revocation (new).** On removal the removed member's compliant client deletes every per-epoch history key of the group; its retained ciphertext can no longer be opened and the UI shows "Message unavailable — group access revoked". Remaining members keep their history. Design, limits and tests: [`HISTORY_REVOCATION.md`](HISTORY_REVOCATION.md). The committer's outcome is made crash/lost-response safe (persisted pending commit + idempotent relay retry).
* **No pre-join history.** A new member joins from a Welcome at the current epoch; earlier epochs' keys do not exist for them and the app never forwards history. Anyone who was a member earlier still has what they saw — removal cannot make them forget.

## 6. Post-compromise security (PCS) scheduler

PCS only helps if members actually update their leaf keys. `maintenance()` (run by `sync`) issues a `SelfUpdate` commit per active conversation when **≥ 24 h** have passed since the last update **and** the member has sent something since,
or after **100 sent messages** — never more often than once per **hour**. It is counter-based, not clock-attack-sensitive. Tests: `mls_protocol.rs` (old state compromised → epoch update → later messages unreadable to the holder of the old state),
`engine_groups.rs::scheduled_key_refresh_advances_the_epoch_and_keeps_the_group_working`. Limits: PCS requires the compromised state to be *only* a snapshot, not an attacker that stays active; a member that never comes online never updates.

## 7. KeyPackages

20 KeyPackages are uploaded at onboarding and 10 more are added every 24 h by `maintenance()` (the relay caps a device at 100 and hands each out once). **No last-resort KeyPackage** exists: if a device's pool is drained
(ST-022, abuse), new contacts cannot start a session until it replenishes — a denial of service, not a confidentiality loss. Open as part of ST-008.
