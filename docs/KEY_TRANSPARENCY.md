# Key transparency — design and status

> **Status: EXPERIMENTAL — NOT PRODUCTION READY.** A client-side verifier exists behind the Cargo feature `transparency-experimental`. There is **no log server**, nothing in the app or relay calls it,
> and it is not part of any shipped build (`cargo tree -p cipher-ffi` contains no `ct-merkle`). Manual QR / safety-number verification is independent of it and remains the only first-contact defence.

## 1. The problem

TOFU pins protect against *later* key substitution, but a relay that lies from the very first lookup — or that shows different keys to different people (a **split view**) — is invisible without out-of-band comparison.
A key-transparency log makes such lies **detectable** by publishing every `(account, identity key)` binding in an append-only, publicly auditable structure.

## 2. Approaches investigated

| Approach | What it is | Verdict for Cipher now |
| --- | --- | --- |
| RFC 6962/9162 Merkle log (Certificate-Transparency style) — crate `ct-merkle` 0.3.0 | Append-only tree; inclusion proofs, consistency proofs, signed tree heads; needs gossip/monitors for split views | **Chosen for the verifier**: small, standard, proofs are checked by library code we do not write. Crate is **unaudited** and needs `digest`/`sha2` 0.11 (kept optional so the shipped tree is unaffected) |
| `akd` 0.13.0 (the Rust AKD behind WhatsApp's design) | Auditable key directory with VRF-hidden labels, epochs, append-only proofs, lookup/history proofs | Better privacy (labels not enumerable) but a large dependency and a *server* design; integrating it without a deployed directory and an operator-run auditor would add attack surface for no protection. Re-evaluate when a log operator exists |
| CONIKS / SEEMless / Parakeet-style VRF directories | Research-grade private directories | Same: needs a server and an auditing ecosystem |
| Blockchain / third-party notaries | — | Not considered: new trust and metadata exposure |

## 3. What the experimental module does (`crates/cipher-core/src/transparency.rs`)

* **Pinned log key** (Ed25519, out of band) signs **tree heads** over `context ‖ size ‖ root ‖ timestamp`.
* `LogVerifier` keeps one accepted head and moves **only forward with a valid consistency proof**: smaller head ⇒ `Rollback`; same size, different root ⇒ `Fork` (carries both validly signed heads as **transferable evidence**);
  larger head without or with an invalid proof ⇒ `NotConsistent`; head dated > 5 min in the future ⇒ rejected; size 0 ⇒ rejected; a persisted head is **re-verified** on load (storage is not trusted).
* **Inclusion**: `check_inclusion(leaf, evidence)` verifies a Merkle audit path of the leaf `cipher-kt-leaf-v1 ‖ account ‖ identity_key ‖ seq` against the verifier's *current* head. A key change is a **new leaf**, never an overwrite.
* **Gossip**: `gossip_compare(a, b, key, proof)` reports a split view only for two **validly signed heads of equal size with different roots** (transferable evidence). Heads of different sizes are `Consistent` with a valid
  consistency proof and otherwise `Inconclusive` — a bad or missing proof alone proves nothing (anyone can send garbage), so it is never used to accuse the log.
* Proof input from the network is length-bounded (≤ 64 hashes) and parsed by library code; nothing panics on malformed input.

**Independence from manual verification (structural):** the only verdicts are `NotAvailable` and `Included` — there is **no `Verified`**. The module cannot read or write a trust state (a test fails if it mentions `TrustState`,
`Contact`, `crate::verification`, …) and no engine code depends on it. A log can *add a warning* later; it can never mark a contact VERIFIED or override a safety-number / QR comparison.

## 4. Attack tests (`crates/cipher-core/tests/transparency_attacks.rs`, 13 tests, run with the feature)

Forged/tampered heads (every field), wrong pinned key, persisted-head tampering, rollback, same-size fork with evidence, history rewrite + extension, extension without proof, key substitution (different key, different seq),
wrong/out-of-range index, **every bit of an inclusion proof flipped**, truncated/oversized/misaligned proofs, future-dated and empty heads, gossip split-view / garbage-proof / argument order, the structural-independence checks,
and two property tests over random trees (every leaf verifies, any other leaf does not; honest growth verifies, any edit of an old leaf is refused).

## 5. Why it is not production ready (all open, ST-006)

1. **No log, no monitor, no gossip transport.** Nothing publishes bindings, and clients have nobody to compare heads with; a verifier alone detects nothing.
2. **Log-head TOFU:** the first head a client sees is accepted. A fake log shown to a victim from day one is only caught by gossip.
3. **No self-monitoring:** a user's own client should watch the log for unexpected bindings for their account; not built.
4. **Key rotation / revocation of the log key**, freshness policy (maximum head age), and consequences of a detected fork (UX, reporting) are undesigned.
5. **Leaf format and privacy:** account ids are visible in a plain Merkle log (enumerable). Hiding them needs VRF-style directories (the `akd` direction). The leaf format is a draft.
6. `ct-merkle` has no independent audit; the glue code is unreviewed (EXTERNAL REVIEW).

## 6. Integration plan (when a log exists)

Relay serves `(leaf, inclusion proof, head)` with directory lookups → client verifies → shows an *additional* indicator (never changes trust state) → stores the latest head in the vault → exchanges heads opportunistically over existing E2EE channels
(`gossip_compare`) → fork evidence becomes a high-severity `SecurityEvent`. Each step needs its own threat-model update and tests before enabling.
