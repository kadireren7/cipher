# Notifications and background delivery — evaluation and decision

**Status: no push provider is integrated, no live delivery has been verified, and background delivery while the app is locked does not exist.** This file records what was evaluated; the protocol work is in `PUSH_DESIGN.md` and `EXTERNAL_IMPLEMENTATION_PLAN.md` (owner decision of 2026-10-12: opt-in UnifiedPush, constant wake payload).

| Option | Works when | Privacy cost | Verdict |
| --- | --- | --- | --- |
| **UnifiedPush** (chosen direction) | A distributor app (ntfy, Conversations-style, self-hosted) is installed and allowed to run | Distributor learns endpoint + wake times; no Google dependency | Implement behind an explicit opt-in. Blocked on: RFC 8291 Web Push encryption through a reviewed library, SSRF-safe relay notifier, endpoint-possession challenge (a reviewed exception to the constant-wake rule), a distributor to test against. |
| **FCM** | Google Play services present | Google sees device token, app package and wake times; ties the install to a Google identity | **Not built, not default.** Would be an optional flavour only; self-hosted deployments must never require it. |
| **Foreground service** | While the user has enabled a persistent notification | None extra, but permanent notification, battery cost, Android 14+ service-type rules | Possible opt-in "keep connected" mode for users without a distributor. Not built. |
| **WorkManager periodic work** | Roughly every 15 min at best, deferred by Doze and standby buckets | None extra | **Cannot provide instant messaging.** Fit only for housekeeping (retry stalled uploads, purge expired caches). Not used for delivery. |
| Foreground polling (today) | App visible | None extra | What exists: 4 s STANDARD / ~10 s ENHANCED with jitter. |

**Why locked wakes show only "New message":** relay requests are signed with a key that lives in the vault. While the vault is locked the app cannot authenticate, so it cannot fetch or decrypt anything. Making this work would mean keeping a transport key outside the vault, which is a security trade-off the owner has not approved.

**Notification content:** VISIBILITY_SECRET on the lock screen with a generic public version in every privacy mode; text produced by the Rust policy (default: "New message" only); no sender, group, file name, count or timestamp in any wake.

**Battery optimisation:** no wake locks, no exemption requests, no attempt to defeat Doze. Users on aggressive OEM skins will not receive background notifications until push exists, and may not even then.

**Remaining actions:** choose a distributor for testing; supply a physical device; complete the reviewed design; then run the delivery matrix (Doze, app standby, force-stop, reboot, OEM kill) and record results in `DEVICE_TEST_CHECKLIST.md`.
