# Cryptographic design

**Rule: no invented cryptography.** Every primitive and protocol below is a published standard implemented by a
maintained third-party library. This repository composes them; where a *composition* is ours, it is listed in §6 so a
cryptographer can review it. Nothing here has been independently audited as a whole.

## 1. Protocol selection

Requirements: asynchronous 1:1 messaging, forward secrecy (FS), post-compromise security (PCS), authenticated device
identity, secure groups with member removal.

| Candidate | FS | PCS | Groups | Library status (as evaluated) | Decision |
| --- | --- | --- | --- | --- | --- |
| **MLS (RFC 9420)** via **OpenMLS** | yes | yes (via update commits) | native, O(log n) | OpenMLS 0.9.0 on crates.io, MIT, active; RustCrypto provider | **Selected for 1:1 and groups** |
| Signal (X3DH/PQXDH + Double Ratchet) via `libsignal` | yes | yes | pairwise fan-out or Sender Keys (weaker removal/PCS) | Maintained by Signal, **AGPL-3.0**, consumed from Signal's repository rather than a crates.io release. The crates.io crate `libsignal-protocol` 0.1.0 is an unrelated third-party crate and was rejected | Not selected: licence and distribution model; groups would need a second protocol |
| Matrix Olm/Megolm via `vodozemac` | yes (Olm) / limited (Megolm) | weak for Megolm | Megolm sessions | Maintained, Apache-2.0 | Not selected: weaker group removal/PCS |
| Noise-based custom framing | depends | depends | none | n/a | Rejected: would be a custom protocol |

**Why one protocol for both 1:1 and groups.** "Do not blindly combine protocols." A 1:1 conversation is an MLS group of
two devices. This gives one state machine, one audit surface, one set of properties, and a clean path from 1:1 to
groups. Cost: MLS requires KeyPackages (provided by the relay directory) and an ordering authority for commits
(solved without trusting the relay for authorisation; see `GROUP_SECURITY.md`).

**Not selected, and why it is fine to revisit:** the adapter boundary (`GroupProtocol` trait in
`crates/cipher-core/src/protocol.rs`) takes and returns opaque bytes plus ids, so the OpenMLS implementation can be
replaced, audited in isolation, or run out-of-process without touching storage, transport, or UI.

## 2. Selected protocol, libraries, versions

| Component | Crate (exact pin in `Cargo.toml`/`Cargo.lock`) | Purpose |
| --- | --- | --- |
| MLS | `openmls =0.9.0` | Group/1:1 protocol (RFC 9420) |
| MLS crypto provider | `openmls_rust_crypto =0.6.0` (pulls RustCrypto `aes-gcm 0.10.3`, `x25519-dalek`, `ed25519-dalek 2.2`, `hpke-rs 0.7.0`, `sha2`, `hkdf`) | Primitives for the MLS ciphersuite |
| MLS credentials | `openmls_basic_credential =0.6.0` | Ed25519 signature key pair |
| Record/KeyStore AEAD | `chacha20poly1305 0.10.1` (XChaCha20-Poly1305) | Local records, test keystore wrap |
| Attachment AEAD | `chacha20poly1305 0.10.1` `aead::stream` (STREAM, ChaCha20-Poly1305) | Chunked attachment encryption |
| Password KDF | `argon2 0.6.0` (Argon2id, RFC 9106) | PIN → key |
| KDF | `hkdf 0.12.4` (HKDF-SHA-256, RFC 5869) | Subkey separation, PIN KEK |
| Hash | `sha2 0.10.9` | Hashes, fingerprints, body digest |
| Signatures | `ed25519-dalek 2.2.0` (RFC 8032) | Transport auth, binding, endorsements, relay verification |
| Constant-time compare | `subtle 2.6.1` | Secret/identity comparisons |
| Zeroization | `zeroize 1.9.0` | Key memory hygiene |
| OS randomness | `getrandom 0.3.4` | Only RNG entry point (`crate::rng`) |
| TLS (relay) | `rustls 0.23.45` + `ring 0.17.14`, TLS 1.3 only | Transport protection |

**MLS ciphersuite:** `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (ciphersuite 1, the RFC 9420
mandatory-to-implement suite). Handshake messages use the *pure ciphertext* wire format (`PrivateMessage`), which encrypts the
commit **body** and sender data — but, per RFC 9420 §6.3, the `PrivateMessage` framing still carries `group_id`, `epoch` **and `content_type`
in the clear**. So anyone who parses the framing can tell an application message from a commit/proposal, and learns the group id and epoch.
(An earlier revision of these documents claimed the relay "cannot distinguish commits from messages". That claim was **wrong** and is withdrawn;
the relay additionally *knows* which requests are commits because it sequences them, see `METADATA_MODEL.md`.)
MLS padding: 128 bytes, on top of our own frame buckets (§5a). `max_past_epochs = 2`: a member can still decrypt a late message from one of the
two previous epochs, at the cost of retaining those epochs' decryption secrets slightly longer (documented trade-off for out-of-order delivery).

**Interoperability boundary.** The relay carries opaque MLS messages and public KeyPackages. Another RFC 9420
implementation with the same ciphersuite could in principle join, but this foundation uses only `BasicCredential`
(identity = account id ‖ device id) with our own directory/endorsement layer on top; there is no interop testing.

## 3. Device identity

Each installation generates, client-side:

* **Identity key:** Ed25519 key pair (the MLS signature key). Long-term; private half only inside the vault.
* **Transport-auth key:** a second, independent Ed25519 key used *only* to sign relay requests, so relay
  authentication never exercises the identity key.
* **Binding signature:** identity key signs `"cipher-device-binding-v1\n" ‖ device_id ‖ auth_public_key`. The relay
  verifies it at registration (proof of possession of the identity key); clients re-verify it for every directory record,
  so a server swapping the auth key (to impersonate a device) is detected.
* **Endorsement (additional devices):** an existing device's identity key signs
  `"cipher-device-endorsement-v1\n" ‖ account_id ‖ new_device_id ‖ new_identity_key ‖ new_auth_key`.
  A server holding the account credential cannot mint one.

`account_id`/`device_id` are 128-bit random values generated on the client.

## 4. Key verification (SEC-011)

* **Pinning (TOFU + endorsements):** first contact pins the account's unique unendorsed (root) device; later devices must be
  endorsed by a pinned device. A different identity key for a known device id → `IdentityChanged`; an unendorsed or
  badly endorsed device → `UnendorsedDevice`; a valid new device → `DeviceListChanged`. Untrusted devices are excluded
  from the trusted set (fail closed) until the user acknowledges after comparing safety numbers.
* **KeyPackage substitution:** `add_member` validates the KeyPackage signature (OpenMLS) and then requires its credential
  identity to equal the expected `(account, device)` and its signature key to equal the pinned identity key
  (constant-time compare).
* **Safety number:** per party `SHA-256` over `"cipher-fingerprint-v1" ‖ account_id ‖ identity_key`, iterated 5200 times,
  first 30 bytes → six 5-digit groups; the two 30-digit halves are sorted and joined → 60 digits. Symmetric.
  This follows the structure of Signal's published numeric-fingerprint scheme (hash iteration, digit groups) but is **our
  encoding**; it is a display format over a hash, not a cryptographic protocol. Each half carries ≈ 100 bits of
  second-preimage resistance (30 digits).
* **QR payload:** `"CQR1" ‖ account_id ‖ identity_key`, base64url; the scanner compares against *its own pin* in constant time.

## 5. Attachments (SEC-004)

Fresh 256-bit key from the OS CSPRNG per attachment (never derived from message keys); chunked STREAM construction
with ChaCha20-Poly1305, 64 KiB chunks, 7-byte random nonce prefix, header bound as AAD, last-chunk flag (truncation and
reordering detected). The key, size, ciphertext SHA-256, MIME type and sanitised filename travel only inside the E2EE
message as `AttachmentDescriptor`. Limits: 100 MiB, MIME allow-list with magic-byte consistency, filename
sanitisation (path separators, control/bidi characters, NFC, ≤128 bytes).

## 5a. Message framing and padding

Before MLS encryption every application message is a strict frame `0x01 ‖ u32_be(len) ‖ JSON ‖ zero padding`, padded to a **bucket**
(512 B, 1 KiB, 2 KiB … 64 KiB, then multiples of 64 KiB); the decoder rejects a wrong version, an inconsistent length, non-zero padding or unknown fields.
Attachments are padded to **Padmé** sizes (≤ ~12 % overhead, leaks O(log log n) bits of length) before STREAM encryption; the relay-visible blob size is therefore a coarse bucket, not the file size.
Padding reduces length leakage; it does not eliminate it (relay-visible size classes, timing and counts remain).

## 6. Compositions that are ours (review these)

These use standard primitives but are *our* constructions or encodings. They are small and explicit, and each is a
candidate for review by a cryptographer (SECURITY TODO ST-005):

1. **Vault key hierarchy** (`vault.rs`): `DEK` (random) wrapped by a hardware keystore key; optional PIN envelope
   `KEK = HKDF-SHA256(salt, S ‖ Argon2id(PIN))`, `S` a random secret wrapped by a hardware-bound key; envelope =
   XChaCha20-Poly1305 with fixed AAD. Record key = `HKDF(DEK, "cipher/storage/record-key/v1")`.
2. **Request signing** (`cipher-wire/signing.rs`): Ed25519 over a domain-separated canonical string of
   audience, method, path+query, timestamp, nonce, SHA-256(body), device id. (Same idea as HTTP Message Signatures,
   not that RFC.)
3. **Device binding and endorsement messages** (§3).
4. **Safety-number encoding** (§4).
5. **Group metadata extension and `authorize_commit`** (`app/groupmeta.rs`): our GroupContext extension `0xF1A0` (roles, name, kind, routing tag) and the pure
   role-policy function every receiver runs before merging a commit (`GROUP_SECURITY.md`). The cryptographic binding is MLS's; the *policy* is ours.
6. **Relay commit sequencer** (`cipher-relay`): per-tag compare-and-swap + atomic fan-out. No cryptography, but it is the ordering authority (untrusted for content and authorisation).
7. **Message frame + padding buckets, attachment Padmé padding, attachment descriptor/STREAM header binding** (§5, §5a).
8. **Cipher ID encoding** (`app/cipher_id.rs`): Crockford base32 + a 10-bit checksum for typo detection. It is **not cryptography**: the id is 128 random bits, not derived from any key, and parsing is canonical (a regression test covers the padding-bit alias bug found by property testing).
9. **Experimental key-transparency glue** (`transparency.rs`, feature-gated, NOT PRODUCTION READY): signed-tree-head format and leaf encoding around `ct-merkle` proofs (`KEY_TRANSPARENCY.md`).

### Composition 6.x — group history keys (new; **review these**, ST-005)

`HEK_e = MLS-Exporter("cipher/history/epoch-key/v1", group_id ‖ epoch_be, 32)`; `K_m = HKDF-SHA256(HEK_e, info = "cipher/history/msg-key/v1" ‖ conv ‖ epoch_be ‖ msg_id)`; bodies sealed with XChaCha20-Poly1305 (random 24-byte nonce, AAD binds conv/epoch/msg id/sender). No new primitive; the composition and its use of the exporter, the atomic persistence with the MLS snapshot, the tombstone logic and the idempotent commit retry are ours. See [`HISTORY_REVOCATION.md`](HISTORY_REVOCATION.md).

## 7. Known limitations and assumptions

* **Not audited.** We have not verified an independent audit of OpenMLS 0.9.0 or of the RustCrypto provider build used
  here. Check upstream audit status before any production use. **Reviewing our own code does not count as the independent review (ST-005).**
* **Group id, epoch and message type are visible to a relay that parses MLS framing** (§2); the relay also sees our routing tag and `group_seq`. Hiding them needs an outer routing / sealed-sender layer (ST-009).
* **Commit ordering is solved against honest-but-untrusted relays, not malicious ones:** the relay serialises commits and members verify authorisation, but a malicious relay can still *partition* a group by showing different orders
  to different members (detected as undecryptable traffic; no automatic healing). See `GROUP_SECURITY.md` §4.
* **PCS requires action** and is scheduled automatically (daily when active, or every 100 messages, ≥ 1 h apart); a member who never comes online never updates.
* **KeyPackages:** single-use; replenished (+10/day) but no *last-resort* KeyPackage; exhaustion blocks new conversations with that device until replenished.
* **State persistence:** the whole MLS state is serialised as one snapshot into the vault, written atomically with the conversation state. OpenMLS' in-memory storage is
  not zeroized on drop. An incremental, vault-backed `StorageProvider` is future work (ST-024).
* **Classical crypto only;** no post-quantum protection.
* **Argon2id parameters** are benchmarked on the dev host only (`LOCAL_STORAGE_SECURITY.md`, ST-003).
* **Clock dependence:** signed requests need a clock within ±60 s of the relay (ST-025).
