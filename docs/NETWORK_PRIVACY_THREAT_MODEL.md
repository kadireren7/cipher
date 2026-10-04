# Network-privacy threat model

Scope: **network metadata** (who connects to Cipher, when, how much, who talks to whom) — not message content, which is E2EE (MLS) independently of everything here (`THREAT_MODEL.md`).
Architecture: `Application → OpenMLS/Cipher E2EE → Privacy Transport (SOCKS5 → Tor) → Cipher relay → PostgreSQL`. The privacy transport is **not** a trust boundary for content: with every privacy node malicious, plaintext stays protected (PRIV-001/010; tests in `engine_*` run through an in-process transport that sees every byte, and nothing it records contains plaintext).

Labels: **PROTECTED** = the adversary cannot learn the item under the stated assumptions *and we tested or can point to the mechanism*; **PARTIAL** = reduced, not eliminated; **NOT PROTECTED**. "Tor" statements rest on Tor's published design — **the Tor network was not exercised here** (`ADR-PRIVACY-TRANSPORT.md`). Nothing here is a claim of anonymity.

Assumed deployment: client uses Tor via a local SOCKS5 endpoint (PRIVACY mode); the relay is a clearnet TLS 1.3 service reached through an exit; capabilities exchanged (`DELIVERY_CAPABILITIES.md`).

| # | Adversary | Learns without the privacy layer | With it (PRIVACY mode) | Rating |
| --- | --- | --- | --- | --- |
| P1 | Local Wi-Fi observer | That the phone talks to the relay's IP/SNI, timing, volume | Sees a connection to the local SOCKS endpoint's upstream (Tor entry/bridge), not the relay; timing/volume of Tor traffic; that the user uses Tor | **PARTIAL** — no longer connects *directly to Cipher-owned endpoints*; "uses Tor" is visible (no bridges built) |
| P2 | ISP / mobile operator | Same as P1 plus long-term records | Same as P1; ENHANCED flattens when-the-user-sends within a session | **PARTIAL** (`ISP_OBSERVABILITY_REPORT.md`) |
| P3 | Cipher "entry" infrastructure | (n/a: no Cipher entry exists) The Tor guard is the entry: sees phone IP, not the relay name | Entry does not see Cipher destination or content | **PARTIAL** (Tor-inherited; untested) |
| P4 | Cipher delivery infrastructure (relay + DB) | Client source IP, sender device, recipient device, sizes, timing, commit vs message | Sees exit IP instead of client IP; **no sender** for capability deliveries; still sees recipient device (via capability), sizes (classes), timing, online state (poll), group commit authors/tags | **PARTIAL** — source IP and (capability) sender hidden; recipient side and timing exposed |
| P5 | Compromised privacy relay (one Tor node) | — | A single node never sees both client IP and destination; any node sees only TLS ciphertext | **PROTECTED for content; PARTIAL for metadata** (needs non-collusion) |
| P6 | Compromised Cipher relay | Everything in P4 | As P4. Cannot read content (E2EE), cannot forge delivery receipts (REV-010), cannot restore removed members (REV-005) | **PARTIAL** |
| P7 | Colluding infrastructure (exit + relay; entry + relay; entry + exit) | Full graph + IP | Entry+exit or entry+relay-with-timing can correlate by timing/volume; exit+relay learns nothing new about the client IP | **NOT PROTECTED** against collusion that sees both ends (§Collusion in `PRIVACY_TRANSPORT_REVIEW.md`) |
| P8 | Passive observer with partial internet view | Endpoints of observed flows | Sees only the segment it taps; correlation needs both ends | **PARTIAL** |
| P9 | Malicious recipient | Sender's account, MLS-authenticated | Unchanged: contacts know who messages them. Capability delivery gives the recipient nothing about the sender's IP (the relay is not told, and a recipient never sees addresses) | **PROTECTED** for IP; **NOT PROTECTED** for identity (by design) |
| P10 | Push provider | Wake-up times, device token | **No real push exists** (ST-017). Designed payload is the constant `{"v":1}`; Google/Apple would still see device token and wake times | **NOT TESTED** |
| P11 | DNS observer | That the phone resolves the relay's name | The relay name is not resolved on the device (hostname goes to the proxy: `PrivacyRouteTest`); the *proxy endpoint itself is an IP literal*. The OS may still resolve names of other apps; Orbot's own resolution is outside Cipher | **PROTECTED in the app (tested against a test double)**; **NOT TESTED** on a device with a real DNS observer |
| P12 | Traffic-analysis attacker | Sizes, timing, bursts | Frame classes (1 KiB minimum), optional ENHANCED cadence + one send-shaped request per tick | **PARTIAL** (measured in `PRIVACY_TRANSPORT_REVIEW.md` §experiments) |
| P13 | Temporary network capture (e.g. a seized pcap) | Relay IP, timing | Tor-entry traffic only; no relay name in DNS/SNI visible on the client link | **PARTIAL** |
| P14 | Global passive observer | Everything above, plus end-to-end correlation | Tor does **not** defend against it; cover traffic here is bounded and does not either | **NOT PROTECTED** |

## Non-goals / explicit non-claims
Anonymity of accounts; hiding Tor use from the ISP; defeating end-to-end timing correlation; protecting a compromised phone; hiding contact relationships from the recipient. "Protected" never means "undetectable".
