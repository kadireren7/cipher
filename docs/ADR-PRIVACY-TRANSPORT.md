# ADR — Privacy transport: Tor over a local SOCKS5 endpoint (selected); alternatives evaluated

Status: **accepted for the client plumbing; the Tor network itself was NOT exercised in this environment** (no `tor` binary, no Orbot, no permission to join the live Tor network from the build host; only a local SOCKS5 *test double* was used — see `scripts/dev-socks-proxy.py`). Everything claimed about Tor below comes from Tor's published design, not from our measurements.
Not independently reviewed (ST-005, `EXTERNAL_REVIEW_SCOPE.md`).

## Decision
Cipher's client sends **every** relay request (TLS 1.3 to the relay, unchanged) through a **SOCKS5 proxy on the device's loopback** that is provided by an established privacy network client — Tor (Orbot, or an embedded tor later). The proxy receives the relay's *hostname* and resolves it itself (no local DNS). Cipher contains **no** anonymity protocol, no onion encryption and no proxy code beyond the SOCKS client already in the JVM/OkHttp.

* **Not a trust boundary for content.** Everything that crosses the proxy is E2EE ciphertext inside TLS to the relay; a malicious proxy/Tor node learns what any network observer learns, never plaintext (PRIV-001, PRIV-010).
* **Fail closed.** Proxy unreachable / refusing / malformed ⇒ the request fails (`HttpFault.RouteUnavailable`), the encrypted message stays in the outbox, and *no other route is tried* (PRIV-005/006/015). There is no direct fallback in release builds; a direct route exists only in debug builds behind a marker file (`src/debug` source set).
* **Topology (clearnet relay).** `phone → Tor guard (entry) → middle → exit → relay (TLS 1.3, public CA)`. Entry sees the phone's IP and not the relay; exit sees the relay's name and not the phone's IP; the relay sees the exit's IP. The relay-as-onion-service variant (`.onion`, no exit) would remove the exit but needs either TLS for an onion name (no public CA) or allowing HTTP over Tor's own authenticated transport — **not adopted**: it would relax the "no cleartext, public-CA TLS only" invariant and is a separate design decision.

## Options compared

| Option | Security properties | Android fit | Latency | Battery / data | Operations | Metadata leakage | Maintenance / dependency risk | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Tor via SOCKS5 (Orbot or embedded tor)** | 3-hop onion routing, widely studied and deployed; separates client IP from destination; **no protection against a global passive adversary / end-to-end timing correlation** (Tor's own threat model) | Orbot is an existing app exposing SOCKS5 on 127.0.0.1:9050; embedding `tor` (tor-android) adds ~10 MB native code; Arti (Rust) is maturing | +0.5–3 s per request (circuits), first use slower (bootstrap) | Circuit upkeep and cell overhead (514-byte cells) — moderate; foreground-only use limits it | User needs Orbot (or we embed tor); exit relays are third parties; relay should tolerate shared exit IPs (rate limits per capability, not per IP) | ISP sees "uses Tor" (bridges/obfs4 are an optional mitigation, not built); exit sees destination hostname | Mature, active; native-code dependency if embedded | **Selected** |
| MASQUE / CONNECT-UDP-IP two-hop (RFC 9298/9484), "private relay" style | Two non-colluding operators separate IP from destination; standard QUIC | Android has no first-class two-hop client; Cronet MASQUE is not a drop-in | Low | Low | **Needs two independent operators — we have none; if Cipher runs both hops the separation is void** | Operators see their half | Few mature open implementations | Rejected for now; revisit if two independent operators exist |
| Oblivious HTTP (RFC 9458) via a third-party relay | Per-request HPKE encapsulation; relay sees client IP and ciphertext, gateway sees the request but not the IP | Fits request/response API well; Rust `ohttp` crate exists | Low | Low | Needs an independent OHTTP relay operator and key-config distribution | Relay operator sees client IP/timing; gateway (Cipher) sees requests | Moderate (new crypto composition in our client = more review) | Candidate follow-up; same `HttpCallbacks` seam |
| Own multi-hop relays / own onion routing | — | — | — | — | — | — | **Inventing an anonymity network: out of scope and unwise (no home-grown cryptography)** | Rejected |
| Commercial VPN / WireGuard | Single hop; trust moves to the VPN provider | Android `VpnService` is the OS's job | Low | Low | Not under our control | Provider sees everything Tor's entry+exit would | n/a | Not a Cipher feature (users may run one) |
| Nym mixnet | Mix-net with cover traffic; stronger against some timing attacks | Limited Android tooling | High (seconds) | High (cover traffic) | Token economics, smaller network | Better against global observers in theory | Young; dependency risk | Not selected |
| I2P | Garlic routing, smaller network, Java router | Android I2P app exists | Variable | Moderate | Fewer exits to clearnet | Different trust model | Smaller community | Not selected |

## Consequences
* Properties **achieved by construction in this repository (and tested against a test double):** no local DNS for relay names; no direct fallback; privacy status reflects real route state; the relay API no longer needs the sender's identity for contact deliveries (`DELIVERY_CAPABILITIES.md`).
* Properties **inherited from Tor and NOT verified here:** IP separation across entry/exit, multi-hop non-collusion, circuit isolation. Cipher does not isolate streams per identity (Orbot default). Not tested: Android DNS behaviour for the proxy itself, Doze, real carrier networks, battery.
* **Not provided:** protection from a global passive adversary, end-to-end timing correlation, hiding Tor usage from the ISP, anonymity of the account (account/device ids are stable pseudonyms to the relay).
* **Relay operator note:** behind Tor many users share exit IPs; per-IP limits must be generous (`/v1/deliver` uses a per-capability bucket plus a generous per-source bucket).


## Deadlines on the privacy route (hardening pass, 2026-10-11)
Why not "just raise every timeout": each deadline guards a different failure and a longer one hides the failure it guards. Current layers:

| Layer | Where | Value | What it bounds |
| --- | --- | --- | --- |
| Connection establishment (TCP to the SOCKS proxy + SOCKS CONNECT, i.e. Tor circuit / rendezvous build) | `OkHttpCallbacks.connectTimeout` | 120 s privacy route, 10 s direct dev route | One circuit build. Tor itself abandons a stalled build after ~60 s and retries, so a shorter limit cuts off a retry about to succeed |
| TLS handshake and waiting for response bytes | `readTimeout` (OkHttp has no separate handshake timer) | 60 s | No progress from the relay. Relay side: `CIPHER_RELAY_TLS_HANDSHAKE_SECS` (10 s direct, 60 s onion) |
| Sending the request body | `writeTimeout` | 60 s | A stalled upload on the client side |
| Whole call | `callTimeout` | 5 min | Absolute bound for one attempt |
| Relay: request body progress | `CIPHER_RELAY_BODY_IDLE_SECS` | 20 s, 90 s onion | A peer that stops sending (frees the upload slot) |
| Relay: whole request | `CIPHER_RELAY_REQUEST_TIMEOUT_SECS` | 30 s (x4 for blobs), 120 s onion | Absolute bound per request |
| Core: transfers | `relay_client::TRANSFER_ATTEMPTS` | 4 attempts, 1/2/4 s + ≤ 50 % jitter | Transient failures only (timeout, 408, 502–504, dropped link); each attempt is a freshly signed request; TLS/pin failures are never retried |

Properties that did not change: the proxy is fixed and there is no direct fallback; a pin mismatch is a TLS fault, not retried and not downgraded; OkHttp's own connection-failure retry is left at its default (turning it off broke existing network-attack tests), so a stale pooled connection may still cause the transport to re-send a signed request once; the relay's replay protection rejects the duplicate and the core retry then re-signs. Duplicate submission cannot happen at message level because a message is created only after its blob upload succeeded; a lost response can leave one unreferenced blob until its TTL (ST-046). Whether these values reduce failures over real Tor is measured by repeated runs of the `android-tor` workflow (Session 5, `MASTER_IMPLEMENTATION_STATUS.md`); they were chosen from the observed Tor log behaviour, not tuned against the result.
