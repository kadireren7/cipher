# Scope for the independent cryptographic / security review (ST-005 — OPEN)

**ST-005 remains OPEN.** Nothing in this repository counts as an independent review; the author reviewing their own code cannot close it.
This file is the brief to hand to a reviewer. Code references are to the repository at the time of writing; the reviewed commit will be recorded in the first public tag.

## 0. Deliverable requested from the reviewer
Findings by severity, with a statement of what was *not* reviewed, a re-test of fixes, and permission to publish the summary.

## 1. Threat model and invariants
`docs/THREAT_MODEL.md` (A1–A18), `docs/SECURITY_INVARIANTS.md` (SEC-001..038, REV-001..010 → tests), `docs/ATTACK_SURFACE.md`, `docs/FINAL_SECURITY_REVIEW.md`.
Questions: are adversaries missing? Are invariants stated strongly enough to be falsifiable?

## 2. Compositions that are ours (highest value)
`docs/CRYPTOGRAPHIC_DESIGN.md` §6: vault (DEK wrap by Keystore, record AEAD with location AAD, PIN envelope with Argon2id + hardware-bound secret), attachment chunking, frame/Padmé padding, request signing (canonical string, `bh=` body hash, audience binding), device binding signature (v2), safety numbers, key-transparency verifier (experimental), **history keys (new)**.

## 3. OpenMLS integration (OpenMLS 0.9.0, RustCrypto provider)
`crates/cipher-core/src/mls.rs`, `protocol.rs`: ciphersuite choice, credential format (account‖device), KeyPackage validation, Welcome handling, `max_past_epochs = 2`, past-epoch sender-membership check, storage provider snapshotting, exporter use. Provider/OpenMLS audit status and the `proc-macro-error2` exception (ST-018).

## 4. Group authorisation
GroupContext extension `0xF1A0` (roles/tag/name/kind); `authorize_commit` on every receiver; commit sequencer and rebase; owner-only role changes; removal of all devices of an account; forged-commit rejection. `crates/cipher-core/src/app/groupmeta.rs`, `tests/group_policy.rs`, relay `store.rs::group_commit`.

## 5. History revocation (new)
`docs/HISTORY_REVOCATION.md`, `crates/cipher-core/src/history.rs`, `app/engine_msg.rs` (`revoke_group_access`, `finish_commit`, `resolve_pending_commits`, `handle_welcome` tombstone logic). Questions: exporter label/context separation; AEAD AAD completeness; atomicity of key persistence vs. MLS snapshot; tombstone epoch ordering; residual leak paths (logs, previews, FFI, notifications, search); re-add semantics; idempotent commit retry races.

## 6. Device revocation and multi-device
Not implemented (ST-010/ST-020/ST-033). Reviewer is asked to review the *design constraints* in `docs/RECOVERY_AND_DEVICES.md`, not code.

## 7. Persistence and rollback
`crates/cipher-core/src/storage*.rs`, `vault.rs`, `docs/LOCAL_STORAGE_SECURITY.md`: generation counter, same-session snapshots (ST-016), atomic transactions, `secure_delete`, crash consistency.

## 8. Keystore integration
`android/.../keystore/*`, `docs/ANDROID_SECURITY.md`: key attributes, auth-per-use, invalidation on enrolment change, StrongBox fallbacks, the 32-byte key in JVM memory (ST-027). **Requires physical devices (ST-001/ST-028); see `docs/DEVICE_TEST_CHECKLIST.md`.**

## 9. FFI boundary
`crates/cipher-ffi`: no key material in return types, input validation, panic containment, callback re-entrancy, zeroisation.

## 10. Relay
`crates/cipher-relay`: authentication, replay protection, rate limiting, queue bounds and per-sender share (ST-031), blob upload, sequencer CAS and idempotency, migrations, TLS configuration, logging. The relay is **untrusted**; review it as an adversary-in-the-middle's server, plus as an availability target.

## 11. Metadata
`docs/METADATA_MODEL.md`: what the relay/DB/network see, sealed-sender absence (ST-009), per-pair hash (§4b), timing, size buckets.

## 12. Key transparency
`docs/KEY_TRANSPARENCY.md`, `crates/cipher-core/src/transparency` (feature-gated, **not production**): proof verification, signed tree heads, gossip split-view detection; no log operator exists.

## 12b. Network-privacy layer (new; ALSO requires independent review before production)
`docs/NETWORK_PRIVACY_THREAT_MODEL.md`, `docs/ADR-PRIVACY-TRANSPORT.md`, `docs/DELIVERY_CAPABILITIES.md`, `docs/PRIVACY_TRANSPORT_REVIEW.md`, `docs/ISP_OBSERVABILITY_REPORT.md`.
Code: `android/.../net/` (SOCKS route, fail-closed mapping, status tracker), `crates/cipher-relay` (`/v1/deliver`, `/v1/caps*`, lanes, per-capability quotas, minute-rounded logs), `cipher-core` `engine_msg.rs` capability section, `netprofile.rs` (profiles, cover). Questions: capability lifecycle (rotation races, removal), unauthenticated-endpoint abuse surface, cover-traffic shape fidelity, SOCKS5/DNS behaviour on Android (remote resolution, IPv6, Orbot specifics), whether the Tor integration choice and the clearnet-vs-onion relay decision are sound, and the collusion/correlation claims. **The Tor network was not exercised in this repository's tests.**

## 13. Out of scope for this review
UI usability, the OS, hardware Keystore implementations, supply chain of Rust/Gradle dependencies (covered by ST-014 work), legal.
