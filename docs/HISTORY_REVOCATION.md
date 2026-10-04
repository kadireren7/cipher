# Group history revocation

Status: implemented and tested at engine level against the real relay + PostgreSQL (`crates/cipher-relay/tests/engine_revocation.rs`, 13 tests;
`crates/cipher-core/src/history.rs` unit tests). **Not independently reviewed (ST-005).** Never tested on a physical device.

## Guarantee (exact wording)

> Once membership revocation is committed, a removed member loses cryptographic access to future group content and loses
> **Cipher-controlled** cryptographic access to retained group history, while remaining authorised members preserve their permitted history.

"Committed" means: for the removed member, once their **compliant Cipher client has observed the removal commit**. Until then it still holds the
keys it was legitimately given (see *Limitations*). Remaining members never lose anything.

### What is NOT claimed

* Plaintext copied outside Cipher (clipboard, screenshots, photographs, exports/share-outs made before removal) is not erased.
* A modified/malicious client that kept keys or plaintext before it observed the removal keeps them. Cryptography cannot un-tell a secret.
* Flash storage (NAND wear levelling) may retain old ciphertext blocks; the guarantee is *cryptographic unavailability* (the keys are deleted and
  the vault is DEK-encrypted), not physical erasure.
* Anything the relay could not know: the relay stays untrusted and has **no** kill switch, no history key and no ability to read or restore anything.

## Design

No novel primitive. Only: MLS exporter (RFC 9420 §8.5), HKDF-SHA256, XChaCha20-Poly1305 (existing vault AEAD).

```
MLS epoch secret ──exporter("cipher/history/epoch-key/v1", group_id ‖ epoch_be, 32)──► HEK_e   (per-epoch history key)
HEK_e ──HKDF-SHA256(info = "cipher/history/msg-key/v1" ‖ conv ‖ epoch_be ‖ msg_id)──► per-message key K_m
body ──XChaCha20-Poly1305(K_m, random 24-byte nonce, AAD = domain ‖ conv ‖ epoch ‖ msg_id ‖ sender)──► sealed body stored in the vault record
```

* **Why per-epoch exporter keys, not a long-lived "history generation" key.** A member added in epoch *e* must derive `HEK_e` from MLS state it is
  given in the Welcome, without access to earlier epochs; a forward-ratcheted chain would let a removed member compute *later* keys, and a master
  key would be a permanent universal secret. The exporter binds `HEK_e` to the MLS key schedule: anybody who is not in the epoch cannot derive it,
  and removal advances the epoch with a Update path that excludes the removed leaf.
* **Why per-message keys.** Domain-separated, context-bound keys: a sealed body cannot be moved to another conversation, epoch, message id or
  claimed sender (AAD + key derivation). We store ONE 32-byte key per epoch, not one key per message ("avoid thousands of raw keys").
* **Where it lives.** `HEK_e` is stored in the vault namespace `hk` (record-level AEAD under the Keystore-wrapped DEK, location-bound AAD). The
  epoch key for a new epoch is persisted **in the same atomic `commit_state` transaction** as the new MLS snapshot — there is no state in which the
  group advanced but the history key was not stored.
* **Local history encryption.** Every group message body is sealed (as above) before it is written; the vault record then wraps that again with the
  normal vault AEAD. Previews are cleared on revocation. DM history is unchanged (DMs have no membership removal).
* **Relation to MLS epochs.** One `HEK` per epoch the device lived through (`max_past_epochs = 2` only bounds *MLS decryption* of late
  messages; history keys are kept for every epoch the device has been a member of).

## What happens on removal (committer A, removed D)

1. A authorises (owner/admin; receivers re-check — `authorize_commit`) and builds one commit: `Remove(all devices of D's account)` + new metadata
   with a **rotated routing tag** + the role list without D.
2. The relay's CAS sequencer accepts the commit and fans it out; the old tag is retired (REV-007).
3. The commit advances the MLS epoch (fresh secrets D cannot derive) → new `HEK_{e+1}` (REV-006). A persists it atomically with the snapshot.
4. A emits `GroupMemberRemoved` for the remaining members' security log. The UI shows success only after the commit was applied.
5. When **D's** client processes the commit (`apply_processed` / `revoke_group_access`) — in one atomic vault transaction — it:
   deletes **all** `hk` keys of the group, writes the tombstone `revoked/<group>` (the highest epoch seen), drops the MLS group state, deletes the
   outbox and held (out-of-order) messages of the group, clears the conversation preview, marks the conversation `access_revoked`,
   and emits `GroupAccessRevoked`.
   Remaining bodies are sealed ciphertext whose keys no longer exist → "Message unavailable — group access revoked".
6. Failure at any point: the transaction is atomic (nothing half-revoked); a crash before the ack makes the relay redeliver the commit, which is
   idempotent on a revoked conversation (`process_death_around_the_removed_members_revocation_is_safe`).

## Behaviour matrix

| Situation | Result | Test |
| --- | --- | --- |
| A/B/C read M1 before and after removal; D reads M1 only before; M3 (post) unreadable to D | per-epoch keys | `removal_splits_history_access_cryptographically` |
| Admin removes member; owner removes admin | same | `admin_and_owner_removals_revoke_the_removed_member` |
| Plain member / forged removal commit | refused by every receiver; no key changes | `unauthorised_removal_attempts_change_nothing` |
| D offline during removal, reconnects, sends into old epoch, tries a commit | sender-membership check on retained past epochs; commit refused (retired tag); no rollback | `an_offline_removed_member_cannot_send_receive_or_force_a_rollback` |
| Old vault snapshot restored | whole-vault rollback detected at unlock (keystore-held counter) | `an_old_vault_snapshot_cannot_restore_access` |
| Relay replays the old Welcome / legitimate re-add | tombstone rejects Welcome with epoch ≤ tombstone; a newer Welcome gives only the *new* era | `replayed_welcome_and_a_legitimate_readd_restore_only_new_history` |
| Relay withholds the removal from D | D gets nothing new; D keeps old keys until it observes the removal (limitation) | `withheld_removal_blocks_new_content_and_ends_old_access_when_it_arrives` |
| Relay reorders commit after later message | message held, resolved when the commit arrives | `a_reordered_removal_is_resolved_without_losing_history` |
| Send / attachment concurrent with removal | remaining members read it; removed member cannot after revocation | `a_message_sent_during_the_removal_…`, `an_attachment_sent_during_the_removal_…` |
| Several rapid removals | one key per epoch; remaining members keep all history | `rapid_successive_removals_…` |
| Restart / process death after removal | revocation persists; redelivery harmless | `restart_after_removal_…`, `process_death_around_…` |

## Multi-device (A7)

Cipher currently has **one device per account** (no linked-device sync, ST-020). The removal commit removes **every MLS leaf of the removed
account** (`remove_group_member` filters by account, not by device). Therefore, under the documented model "removal is account-level", a forgotten
second device of a removed account would be removed with the first. Today this is a design property, tested at the single-device level only;
when multi-device ships it MUST add an engine-level test with two devices of one account (tracked: ST-020/ST-033). Device-level removal of a
single device without removing the account is **not implemented**.

## Offline removed member and queued messages (A8, A9)

* Offline D never receives post-removal content: it is encrypted to epochs D has no secrets for.
* D cannot send accepted messages: a message from D into a retained past epoch is rejected by every remaining member (`sender is no longer a member`),
  and D's commits are rejected by the relay (retired routing tag) and by receivers.
* D cannot silently rejoin or force rollback: tombstone + Welcome epoch check; MLS epochs only move forward; a commit from a stale epoch is stale.
* **Pending pre-removal messages** queued for D at the relay are *not* purged for application messages: the relay cannot identify group application
  messages (they carry no group tag, deliberately — adding one would leak group membership metadata; see METADATA_MODEL). Security does not rely
  on this: D can decrypt such a message only before observing the removal, and loses it with the rest of the history on revocation.

## Stale-state attacks (A10)

| Attack | Outcome |
| --- | --- |
| Old DB snapshot / vault restored | Detected at unlock (keystore generation counter) → `StorageRolledBack`; nothing readable. |
| Old MLS state alone | MLS state and history keys live in the same vault; there is no separate artefact to restore. |
| Same-session partial rollback of single records | Not detected (ST-016 residual). |
| Relay replays old Welcome / commits | Tombstone + epoch ordering reject; replay cannot re-authorise. |
| Relay replays responses | Signed-request nonces/ audience binding; MLS replay protection. |

Residual: an attacker who restores a snapshot on a device whose keystore counter was also reset (e.g. keystore wiped → vault unusable anyway) cannot
decrypt it; one who has a *copy* of the pre-removal vault **and** the pre-removal Keystore key (a compromised device) has the keys → outside the model.

## Cryptographic erasure (A11)

* `HEK` bytes are `Zeroizing`; they exist in memory only while a body is sealed/opened; the store record is deleted (`secure_delete` + vault AEAD).
* There is no second serialisation of the key (not logged, not in the FFI, no Kotlin copy — `boundary_guards.rs` already forbids key material in FFI types).
* Old ciphertext copies on flash cannot be proven erased; but without the vault DEK + the deleted `HEK` they are not decryptable. The guarantee is
  cryptographic unavailability, not physical erasure.

## Limitations (explicit)

1. Revocation takes effect on D's device only when D's compliant client observes the removal. A relay that withholds the commit from D keeps D's old
   access (but not new content). Tested explicitly.
2. A modified client can ignore the revocation. Out of scope by design.
3. Voluntary *leave* keeps the leaver's history (a deliberate product choice; a compromised leaver is equivalent to a copied export).
4. Per-record rollback and same-session snapshots (ST-016).
5. The removed member keeps what they saw (export/screenshots/copies).
6. No claim of hardware protection: emulator only.
