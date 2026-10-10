# Network adversary model (multi-relay, Tor)

Who can see what, for each way a Cipher client can reach a relay. Read with [METADATA_MODEL.md](METADATA_MODEL.md) (what the relay stores), [MAILBOX_PRIVACY.md](MAILBOX_PRIVACY.md)
(what changed in this branch and by how much) and [MULTI_RELAY_PROTOCOL.md](MULTI_RELAY_PROTOCOL.md).

**Cipher implements no anonymity protocol of its own.** Network anonymity, to the extent it exists, is Tor's. Nothing here promises protection against a global passive adversary
that can correlate traffic entering and leaving the Tor network, against an adversary who controls both your guard and the relay you talk to, or against a compromised phone.

## 1. Evidence labels
`TESTED-LIVE` = observed on the real Tor network in this branch. `TESTED-LOCAL` = automated test against a local double or in-process transport. `DESIGN` = argued, not measured.
`NOT TESTED` = no evidence. A local SOCKS5 test double is **not** evidence about Tor's anonymity.

## 2. Routes
| Route | Client → … | Used when |
| --- | --- | --- |
| R0 direct (debug builds only) | TLS to the relay | development; the release build has no direct route |
| R1 SOCKS5 → Tor → clearnet relay | Tor circuit, exit node, TLS to relay (CA-validated host name) | Profile B relay |
| R2 SOCKS5 → Tor → onion relay | six-hop rendezvous circuit, TLS to the relay validated by the **pin from the invitation** | Profile A relay |
| R3 cross-relay delivery | the sender's route (R1/R2) to the **recipient's** relay, unauthenticated requests | contact on another relay |

## 3. What each observer learns
| Observer | R1 (Tor → clearnet relay) | R2 (Tor → onion relay) | Notes |
| --- | --- | --- | --- |
| **Your ISP / local network** | that you talk to Tor (guard IP), volume and timing of your Tor traffic. Not the relay, not the content. | same | "Uses Tor" is visible (no bridges/pluggable transports: ST-043). `DESIGN` |
| **Tor guard (entry)** | your IP, that you use Tor, circuit timing | same | cannot see destination or content |
| **Tor exit** | the relay's address and TLS handshake (SNI: the relay host name — ECH unsupported, ST-019); ciphertext sizes and timing of a TLS 1.3 stream | **no exit exists** — the traffic never leaves Tor | The exit cannot read TLS content; it can observe and disrupt. R2 removes this observer entirely. |
| **Relay operator** | for authenticated requests: your pseudonymous device id, request times, padded sizes, queue contents (ciphertext); for capability deliveries: a capability, time, size — **no sender id**. Source address = the exit (R1) or the onion service's Tor-side circuit (R2). | same, never an exit | cannot read messages or files; sees mailbox activity and who polls when |
| **Relay's database administrator** | everything in the relay's database: public keys, queued ciphertext, capability **hashes**, pair hashes keyed with a secret pepper, rate-limit buckets, device directory. A dump of a stolen database does not contain usable capabilities (only hashes). | same | The DBA with access to the running relay also sees what the operator sees. |
| **Two colluding observers** (e.g. exit + relay, or guard + relay) | R1: exit and relay can match **a TLS stream's timing/size** to relay-side requests → they link an exit-side flow to a device id, and the guard-side flow to your IP only if the guard is also theirs. | R2: guard + relay operator can attempt rendezvous-side timing correlation. | This is the classic Tor limit. Cover traffic (ENHANCED profile) reduces **naive** detection only: measured candidate-set effect is small (ST-040). |
| **Global passive adversary** | can correlate entry and exit/onion traffic by volume and timing | same | **Not defended.** |
| **Other relay (cross-relay peer's relay)** | that someone holding a capability delivered ciphertext at a time; never the sender's identity | same | See MAILBOX_PRIVACY.md §3 (measured). |
| **A malicious contact** | everything their own client is told; not your IP (Tor) | same | A contact who learns your relay name learns which relay you use. |

## 4. DNS, IPv4/IPv6
* The app resolves **no** relay host names itself: the SOCKS5 proxy resolves them (`socks5h` behaviour; `dns(NoDns)` in the client). `TESTED-LOCAL` (JVM test against a SOCKS5 test double that asserts the request uses the domain-name address type; a throwing `Dns`; emulator run; **no** packet capture) and
  `TESTED-LIVE` for curl (`--socks5-hostname`) reaching an onion name — which cannot be resolved by anything but Tor.
* The Android client has **no** direct-network fallback in release builds; if the proxy is down or malformed the message stays queued (encrypted). `TESTED-LOCAL`.
* IPv6: not tested separately; the proxy decides the outgoing family. `NOT TESTED`.

## 5. Onion-relay trust model (resolves ST-041)
The relay serves TLS 1.3 with a self-signed certificate. The user's invitation carries the relay's `https://….onion` URL **and the SHA-256 of the certificate's public key**. The Android transport
accepts, for that host only, a certificate that is currently valid, matches the pin, and (via OkHttp's default verifier) names the host. No pin ⇒ no connection. A second, different pin for the
same host is refused. Evidence:
* `TESTED-LIVE` (Tor network, Oct 2026): a Tor client reached the onion relay; the correct pin → HTTP 401 from the relay; a wrong pin → refused; no pin → refused (self-signed).
* `TESTED-LOCAL`: guards forbid any other trust-manager/socket-factory use; descriptor validation refuses an onion URL without a pin.
* `NOT TESTED`: the Android `PinningTrustManager` against a real onion relay or on a physical device; Orbot.
Residual: whoever gave you the invitation chose the pin. A malicious invitation can name a malicious relay (it still cannot read messages).

## 6. Measured Tor behaviour that shaped the design
* A TLS handshake to the onion relay through a fresh circuit took **6–18 s**; the relay's default 10 s handshake deadline made it unreachable. The onion profile now sets 60 s.
  (`TESTED-LIVE`; one request in three failed at the SOCKS stage — circuit churn; clients must retry, and the outbox does.)
* Descriptor publication took several minutes after first start; a fresh onion relay is not reachable immediately. Operators should wait.

## 7. Fail-closed invariants (automated)
No direct route in release; proxy down ⇒ nothing sent; malformed SOCKS reply ⇒ nothing sent; a descriptor can only be `https`; an onion descriptor needs a pin; a pinned host cannot be re-pinned;
a conversation with a peer on another relay never uses the authenticated path (`a_peer_on_another_relay_is_never_reached_through_the_authenticated_path`).

## 8. Not tested (blockers)
Orbot integration on a device; Tor circuit changes during an in-flight attachment; airplane mode and network handover on hardware; process death during upload; IPv6; physical-device TLS stack differences.
These are listed in `DEVICE_TEST_CHECKLIST.md` and `MASTER_IMPLEMENTATION_STATUS.md` and are **not** claimed.
