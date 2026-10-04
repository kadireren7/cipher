# Privacy transport review (network-metadata pass)

Companion documents: `NETWORK_PRIVACY_THREAT_MODEL.md` (adversaries P1–P14), `ADR-PRIVACY-TRANSPORT.md` (technology choice), `DELIVERY_CAPABILITIES.md`, `ISP_OBSERVABILITY_REPORT.md`, `RETENTION_AND_LOGGING.md`, `METADATA_MODEL.md` §4c.
**Passing tests does not prove Cipher secure. The privacy layer is unreviewed (ST-005) and was never run on a physical device or against the real Tor network.**

## 1–3. Technology, rationale, topology
**Tor, used through a local SOCKS5 endpoint** (Orbot or an embedded tor later). Selected because it is the only mature, widely deployed, openly studied multi-hop network with a standard client interface that works with an unmodified TLS stack; alternatives (MASQUE two-hop, OHTTP, mixnets, I2P, VPN) and the reasons they were not chosen are in the ADR. Cipher implements **no** anonymity protocol.
Topology (clearnet relay): `phone → [local SOCKS5 → Tor guard → middle → exit] → relay (TLS 1.3) → PostgreSQL`. The relay-as-onion-service variant is not adopted (ST-041).
**What was actually exercised:** the app's real OkHttp/Android SOCKS client against a local SOCKS5 *test double* on an emulator. **Tor itself: not tested.**

## 4–9. Who sees what (PRIVACY mode, capability delivery)
| Party | Sees | Does not see |
| --- | --- | --- |
| ISP / local network (4) | a connection to the local privacy network's first hop; timing, volume, cadence; that a privacy network is used | the relay's name or address (no DNS/SNI for it), content, which messages are sent when (ENHANCED) |
| Entry infrastructure (5) | the phone's IP, timing/volume | the relay name (inside the tunnel), content |
| Exit infrastructure (6) | the relay's hostname and TLS to it, timing/volume | the phone's IP, content |
| Cipher relay (7) | the exit's IP (not the client's), for capability deliveries **no sender**, the recipient capability (resolvable to a device), ciphertext size class, time; for polling: the polling device and its cadence; for commits/first contact/KeyPackage claims: the authenticated sender | plaintext, keys, the client IP, which conversation a delivery belongs to (no tag on messages), group membership lists |
| PostgreSQL / a DB dump (8) | account↔device directory, public keys, unexpired ciphertext by recipient device, capability **hashes** with owner device, group tags/epochs | senders of deliveries, pair relationships (cap lane stores none), IPs, exact enqueue times, capabilities in clear |
| Push provider (9) | **none exists**; a future one would see device token + wake times (`PUSH_DESIGN.md`) | content |

## 10. DNS
The relay name is passed to the proxy (SOCKS5 domain type). `Dns` is replaced by a throwing implementation; the proxy is an IP literal. Verified: JVM test with an unresolvable `.invalid` name, emulator success with a name only the proxy can resolve. **Not tested:** packet capture of device DNS, Orbot's own resolver, IPv6-only networks.

## 11–13. Remaining identifiers, social graph, group metadata
* **Stable identifiers remaining:** account id and device ids (directory, commits, first contact, polling authentication), routing tags (rotate on removal), capability→device mapping at the relay.
* **Social graph:** from a DB dump without the pepper, no sender→recipient edge is derivable for capability deliveries (test: `a_database_dump_links_no_sender_to_any_recipient…`; the only mentions of a sender's device are its own inbox-capability row). From a **live** compromised relay, the *recipient* and delivery time of every message are visible and the sender is hidden only for capability deliveries; **first-contact, group commits and polling remain identified**. Timing correlation with an observer of the sender's link re-identifies the sender (§ correlation). Residual correlation attacks are therefore: timing, volume, recipient-side polling, commit authorship.
* **Group metadata:** relay sees a random tag, epoch counter, per-request device count, activity day, and a removal (tag rotation); not membership lists or names. Group application messages carry no tag (ADR-038).

## 14–16. Timing, size, cover traffic
* **Size:** frame minimum raised 512 B → 1 KiB; receipts, capability announcements and short texts now share one class. Synthetic chat mix (200 000 frames: 45 % control, 10 % attachment descriptors, 45 % log-normal text, median 45 chars): class entropy **0.45 → 0.03 bits**; mean frame **560 → 1033 B** (×1.85 on frames; ≈ +0.5 KB per message on the wire). The mix is a **model**, not real traffic. Attachments: Padmé (≤ ~12 % overhead) unchanged.
* **Timing:** profiles `STANDARD` (4 s ±10 %, immediate sends) and `ENHANCED` (≈10 s ±25 %, sends held to the tick, one send-shaped request per tick). Bounded: foreground only, ≤ 1 dummy per tick.
* **Cover traffic:** implemented for ENHANCED only because measurement showed a benefit against a **link-only** observer: send-time detector 0.981 → 0.596 (emulator) / 1.000 → 0.551 (model). Cover is random bytes of the real size class, unauthenticated or an authenticated batch to a nonexistent device (imitating our real shape), answered `invalid`/`not_found`, stores nothing, cannot trigger any action. It does **not** stop correlation (below).

## 17. Bandwidth overhead
Idle foreground, application layer (model): STANDARD **168 KB/h**, ENHANCED **659 KB/h** (≈ 4×). Emulator link-level incl. 10 real sends in 6 minutes and TLS: STANDARD 796 KB/h, ENHANCED 1102 KB/h. Nothing runs in the background. Tor cell/circuit overhead **not measured**.

## 18. Latency overhead
Emulator, SOCKS test double: per-request round trip median **5 ms direct vs 5 ms via the double** (p90 7 ms both); fresh connection (TCP+SOCKS+TLS 1.3) median **519 ms direct vs 567 ms via the double** (+48 ms). **These say nothing about Tor** (real circuits add roughly hundreds of ms to seconds; not measured). ENHANCED adds up to one tick (≤ 12.5 s) before a send leaves.

## 19. Fail-closed tests
`PrivacyRouteTest` (JVM): dead proxy → `RouteUnavailable`, canary destination never contacted; proxy refusal; garbage proxy; hostname handed to proxy; IP-literal proxy; status state machine; source guard (only `net/` touches sockets; direct-route marker only in `src/debug`). Emulator: dead route with the relay reachable directly → request fails, relay log unchanged (8 → 8 lines); the full network-attack suite (TLS 1.2 downgrade, expired, wrong-host, untrusted-CA, redirect, plain HTTP: 7/7) re-run **through** the SOCKS route → all refused. Engine: route down → message stays `Pending` and nothing leaves; delivered after the route returns. Release gate: `scripts/check-release-apk.sh` fails if the debug direct-route marker is in the release dex or native libs.

## 20. Collusion analysis
| Colluding set | Becomes observable |
| --- | --- |
| Entry only | phone IP, online times, volume; not the relay, not content |
| Exit only | that "some user" talks to the relay, volume/timing; not the phone IP, not content |
| Cipher relay only | exit IP, recipient capability/device and time of every delivery, polling devices, committers; not the phone IP, not content |
| Entry + exit | flow-level correlation by timing/volume ⇒ phone IP ↔ relay use; not identity, not content |
| Exit + Cipher relay | nothing about the phone IP beyond what the exit sees; adds nothing against IP privacy |
| **Entry + Cipher relay** | **timing correlation ⇒ phone IP ↔ recipient/sender device** (de-anonymisation); not content |
| All infrastructure | the full who/when/size graph; **no content** (E2EE) |
No protection is claimed against end-to-end correlation or a global passive observer.

## 21. Traffic-correlation experiment (6 senders → 1 receiver, 20 simulated minutes, real engines)
For each real delivery at the relay, how many senders had a send-shaped request on their link in the matching window (Tor-like latency noise 0.2–1.5 s added)?
| Profile | Mean candidate set | Top-1 attacker accuracy |
| --- | --- | --- |
| STANDARD | 1.21 | 0.90 |
| ENHANCED | 2.06 | 0.61 |
Cover **enlarges** the candidate set but an attacker with both views still narrows to ≈ 2 of 6. With thousands of concurrent users the set would be larger, but that was **not** measured. This is not a defence against a global observer.

## 22–24. Findings
**Vulnerabilities / weaknesses found this pass**
1. The client could only connect directly to the relay (no route abstraction): relay and ISP saw the client's address — **fixed** (privacy route; direct route debug-only, absent from release).
2. Relay logged an INFO line per request with a millisecond timestamp (an activity log) — **fixed** (DEBUG, off by default; timestamps rounded to the minute).
3. Every message delivery was authenticated and addressed by the stable recipient device id — **partly fixed** (capability deliveries are unauthenticated); first contact, commits, KeyPackage claims, polling still identified.
4. Strangers could fill the victim's queue through the commit lane by creating fake group tags (found while building the lanes; the open-lane test alone did not show it) — **fixed** (commit lane bounded at 200/8 MiB; test `strangers_flooding_the_commit_lane…`). Strangers can still delay legitimate commits/Welcomes to that recipient for as long as they keep the lane full (not capability deliveries).
5. ENHANCED cover initially had a different request shape from authenticated real sends (a size/path tell) — **fixed** (cover imitates the shape of the last real delivery).
6. A revoked/expired capability delayed delivery by one back-off period — **fixed** (immediate authenticated fallback in the same attempt).
**Unresolved:** ST-038 (Tor/Orbot/device untested), ST-039 (recipient/time visible to the relay), ST-040 (cover distinguishable by the relay; correlation not defeated), ST-041 (onion service TLS decision), ST-042 (no background delivery), ST-043 (Tor use visible), plus ST-005/ST-001/ST-028/ST-017.

## 25. New privacy invariants
PRIV-001 … PRIV-017 (`SECURITY_INVARIANTS.md`; PRIV-003 manual, others partial/automated with explicit gaps).

## 26–27. Test counts and fuzzing
See the final section "Verification" (filled from the clean run). New tests this pass: `delivery_caps.rs` 8, `engine_caps.rs` 5, `engine_privacy.rs` 5, `privacy_experiments.rs` 3, `inbox_flooding.rs` 3 (previous pass), codec 1, `netprofile` 1, `logging` 1; Kotlin JVM `PrivacyRouteTest` 7; instrumented `PrivacyRouteInstrumentedTest` 5 (+ the traffic experiment). New fuzz target `privacy_wire` (+ existing `history_unseal`, `app_parsers`, `wire_json`): 300 s each, **no crashes** (≈ 13.1 M, 34.0 M, 31.6 M and 17.4 M executions respectively). A 5-minute run per target is a smoke campaign, not a long one; no sanitizer variants were run.

## 28–30. Physical device
**No physical device was available (`adb devices` empty).** Everything labelled "emulator" ran on one API 34 x86_64 emulator with a software Keystore. **NOT TESTED:** mobile-network behaviour, Wi-Fi↔mobile handover, airplane mode on hardware, battery, Doze/OEM task killers, real carrier observations, Orbot on a device, real Tor circuits, hardware Keystore. Procedures: `DEVICE_TEST_CHECKLIST.md` §H (privacy route) and §I.
**Components requiring independent review:** `net/` route + tracker, capability lifecycle and the unauthenticated `/v1/deliver`, cover/profile logic, relay lanes and quotas, the Tor-integration decision itself (`EXTERNAL_REVIEW_SCOPE.md` §12b).

## Verification (clean run, this pass)
| Check | Result |
| --- | --- |
| `cargo clean` + fmt + clippy `-D warnings` + release build | clean |
| Rust tests (`--all-features --locked`) | **324 passed, 0 failed, 1 ignored** |
| Invariants | 65 registered (SEC-001..038, REV-001..010, PRIV-001..017), 263 mapped tests all exist, doc fresh |
| `cargo deny`, `cargo audit --deny warnings`, relay-deps graph, secret scan (229 files) | pass |
| Android: clean + JVM unit (13) + ktlint + lint + debug/release/androidTest assemble | pass |
| Instrumented on the emulator (`am instrument`) | **45 run: 43 passed, 2 skipped without arguments** (live-relay and the traffic experiment, both run separately with arguments and passed) |
| Network-attack suite (7 TLS attacks) through the SOCKS route | 7/7 refused/passed |
| Release APK | manifest gate (incl. new dex/native gate) ok; analysis "no hard failures"; sha256 `8773ce7ccb739eec6feb716d98c9474a42695467f7f0664648a4c7801e66db95` (single build; reproducibility not re-checked) |
| Real chain: emulator app → SOCKS test double → release relay (TLS 1.3) → PostgreSQL → headless recipient, unique canaries | text + 3 MiB PDF delivered; **0 hits** for both canaries in relay log, `pg_dump`, proxy log/trace, recipient vault dir, recipient stderr, logcat, app data (`run-as tar`), `/sdcard`, release APK; 1 expected hit in the authorised recipient's decrypted history; relay log: 7 lines, no IP-like string |
| Real-chain anomaly | **One run** in which the app's 3 queued messages (Welcome + 2) were not fetched by the recipient process (6 syncs, 0 messages) was **not explained**; the same scenario succeeded in 3 later runs. Logged as an open observation, not a claim. |
| Flaky test | `boundary_behaviour::rapid_lock_unlock_racing…` failed once under heavy machine load ("race must have been exercised"); 4/4 and 1/1 passes afterwards. A bounded-retry attempt made it take 7 minutes and was reverted. Pre-existing, load-sensitive, unresolved. |
| Not run | physical device; real Tor; packet capture; battery; multi-day fuzzing |
