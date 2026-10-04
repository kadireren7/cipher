# Push notification design (ST-017 — OPEN)

**No push provider is integrated and no provider credentials exist.** What exists is the production-safe abstraction on both sides, so a provider can be added without touching security-relevant code.
We will not fake an integration: ST-017 stays open until real provider behaviour (token lifecycle, delivery under Doze, throttling, OEM limits) has been tested on devices.

## What is built

* **Relay:** `PushNotifier::wake(token)` (`push.rs`). The ENTIRE payload ever handed to a provider is the constant `{"v":1}` (`WAKE_PAYLOAD`). `NullPush` is the default; `RecordingPush` proves in tests (`push_provider_receives_only_a_constant_content_free_wakeup`) that nothing else is passed. Tokens are stored on the device row, never logged.
* **Client:** `WakeHandler.onWake` accepts only the exact constant payload (`is_valid_wake`, fail closed). Visible text is produced by the Rust core from the privacy mode and the vault state; a wake while the vault is locked can only ever show "New message" (the transport key lives in the vault, so a locked app cannot even authenticate to the relay).
* **Rules a provider integration must keep (and tests to add with it):** payload constant; no group name, sender name, attachment file name, counts or timestamps; no collapse key derived from conversations; no analytics SDK (Firebase analytics, Crashlytics are banned by `android_guards.rs`); token registration only over the authenticated, signed channel; wake → authenticated fetch → local decrypt.

## What a push provider inevitably learns (cannot be designed away)

| Provider | Learns |
| --- | --- |
| FCM (Google) | That this app installation (package, device token, Google account infrastructure) received a high-priority message at time T, from the relay's IP/credentials; delivery failures and token churn. Binds the Cipher device to a Google identity/device. Google can also deny or delay delivery. |
| UnifiedPush (self-hosted or third-party distributor) | The distributor's endpoint URL per device and wake times; trust moves to whoever runs the distributor. Preferable for privacy, worse for reliability on stock Android. |
| The relay | Which device is woken, when (it triggers the wake on enqueue). It already knows recipient devices (see `METADATA_MODEL.md`). |
| A network observer | A TLS connection to the provider at wake time, correlated in time with a connection to the relay: **wake timing correlates sender activity with recipient activity**. |

Mitigations that are possible but not built: batching/delaying wakes, dummy wakes (cost battery and still observable), per-device opt-out of push (fall back to foreground polling).

## Decision

Keep ST-017 open. Before enabling any provider: write the provider threat-model addendum, add `RecordingPush`-style conformance tests for the real notifier, and run the delivery matrix on physical devices.


## Addendum — network-privacy pass
* Status unchanged: **no real provider (FCM/UnifiedPush) was integrated or tested; ST-017 stays open.** No fake provider exists.
* The relay's push seam (`PushNotifier::wake(token)`) still receives an opaque token only; the payload is the constant `{"v":1}` (PRIV-012). Anonymous capability deliveries wake the recipient exactly like authenticated ones, so push timing does not distinguish them.
* What a provider (Google/Apple/UnifiedPush server) would still observe: the device token, every wake time, the app package, and the relay's address. Wake times correlate with message arrival times — a metadata leak that cannot be removed while a push provider is used, and one reason PRIVACY mode works **without push**.
* Without push, delivery in PRIVACY mode relies on foreground polling (`network_tick`, 4 s STANDARD / ~10 s ENHANCED with jitter) and on the user opening the app. The app does not run background polling, hold wake locks, or use foreground services to defeat Doze; messages wait on the relay (≤ TTL) until the app is open. A battery-friendly background strategy (WorkManager, ≥ 15 min periodic) was **not** built: it would add a recognisable periodic connection pattern and needs on-device Doze/OEM testing (NOT TESTED).
