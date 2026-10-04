# ISP / mobile-operator observability report

**Scope and honesty.** What a link observer (Wi-Fi, ISP, mobile operator) can infer from the client's traffic, compared across **DIRECT TEST MODE** (debug-only direct route), **PRIVACY STANDARD** and **PRIVACY ENHANCED** (`netprofile.rs`).
Measurements come from (a) real engines against the real relay + PostgreSQL with a per-request size/time log (`privacy_experiments.rs`), and (b) the real Android app stack on an **API 34 emulator** talking through a **SOCKS5 test double** (`scripts/dev-socks-proxy.py --trace`) that records what a link observer would see: time, direction and number of encrypted bytes per chunk (`scripts/analyze-link-trace.py`).
**Not measured:** a real packet capture (no `tcpdump` privileges on the host), real Tor (cell quantisation, circuit setup, bridges), a physical device, a carrier network. The emulator's own NAT sits below the observation point. Treat everything here as a model of the observer, not a field result.

## What was concluded (precise statements only)
* With the privacy route in use, **the client no longer connects directly to Cipher-owned delivery endpoints**: the device's only outbound connection is to the local SOCKS endpoint, which in a Tor deployment leads to a Tor entry. This is the exact claim; it is **not** "an ISP cannot know Cipher is used".
* The relay's hostname is **not resolved on the device** in privacy mode (SOCKS5 ATYP=3 was observed at the proxy; a name the emulator cannot resolve works only through the proxy).
* The ISP **can still see**: that the user runs a Tor-like privacy network (no bridges/pluggable transports were built), when the phone is online, volume, and the cadence of requests. A periodic polling cadence (≈4 s ± 10 % STANDARD, ≈10 s ± 25 % ENHANCED) is itself a **fingerprint** of a messenger; we did not test whether a classifier can identify it inside Tor.
* **STANDARD leaks when the user sends**; **ENHANCED removes most of that signal**, at a data cost, and does not hide that the user is online. Neither defeats an observer who watches both ends (§ correlation).

## Observables
| Observable | DIRECT TEST MODE | PRIVACY STANDARD | PRIVACY ENHANCED |
| --- | --- | --- | --- |
| Destination IP | the relay's address | the privacy route's first hop (here: the SOCKS test double) | same |
| DNS | a lookup of the relay name by the device (when a hostname is used) | **none for the relay name**; the proxy endpoint is an IP literal (tested: `PrivacyRouteTest`, instrumented remote-resolution test). Orbot's own bootstrap resolution and the OS's other queries are **not tested** | same |
| SNI | relay name in the TLS ClientHello, visible on the path | the ClientHello travels inside the SOCKS tunnel; the proxy/exit side sees it, the first-hop observer does not see a Cipher name | same |
| Connection pattern | one persistent TLS connection (OkHttp keep-alive) | **1 connection for the whole 6-minute run** (measured at the proxy: `connections: 1`) — no connect/send/disconnect pattern | same (1 connection) |
| Request cadence | 4 s poll ±10 % | same | ~10 s tick ±25 % |
| When the user sends | visible as extra requests/bytes | **visible**: measured detector accuracy 0.981 (emulator trace), 1.000 (in-process model) | **mostly hidden**: 0.596 (emulator trace, 36 windows, 10 positives — low statistical power), 0.551 (in-process model, 180 windows); chance = 0.5 |
| Volume | ≈ 168 KB/h idle (app layer) | measured link-level 796 KB/h including 10 sends in 6 min | measured link-level 1102 KB/h; ≈ 659 KB/h idle at the app layer (model) |
| Packet sizes | frame class ≥ 1 KiB + MLS + TLS; Tor would re-quantise to 514-byte cells (not modelled) | same | cover has the same size class as a real send (test: `cover_requests_store_nothing_and_share_the_real_message_size_class`); imitates authenticated vs anonymous request shape (`cover_imitates_the_shape_…`) |

Detector: per 10-second window, "did the user send in this window?" decided from uplink bytes alone with the **best possible threshold chosen on the same data** (optimistic for the attacker). Balanced accuracy 0.5 = no information.

## Residual leakage (not fixed)
* Online/offline and session boundaries; the polling fingerprint; that Tor is in use; first-contact and commit requests are authenticated and differ in shape from capability deliveries; the relay (not the ISP) can tell cover from real traffic.
* ENHANCED is foreground-only and costs ≈ 4× the idle data of STANDARD in the model (≈ 40 % more on the emulator trace, which includes real traffic).
* No cover traffic exists in STANDARD; none exists in the background (the app does not run in the background).
