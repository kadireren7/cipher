# Known limitations (read before installing)

* **Not independently audited** (ST-005). All reviews so far are self-reviews and automated tests.
* **Never run on a physical phone** (ST-028). Keystore behaviour on real hardware (StrongBox/TEE, biometric enrolment changes, OEM variants), battery behaviour and Orbot are untested.
* **No background notifications** and no delivery while the app is locked or closed (`NOTIFICATIONS.md`).
* **No account recovery, no multi-device, no key backup.** Lose the phone, lose the identity.
* **Metadata:** relays see who a message is addressed to, when, and padded size. A network observer sees that you use Cipher. Tor hides addresses, not timing correlation. No sealed-sender, PIR or mixnet.
* **Cross-relay groups are experimental:** the creator's relay orders membership changes; if it is lost, membership changes stop (messages continue) and the group must be recreated with every member re-accepting. Any current member can freeze membership changes (ST-051). A hostile home relay is detected, not prevented.
* **Attachments:** single-blob upload up to the relay limit; no resumable/chunked transfer (ST-046); an abandoned upload can leave an orphan ciphertext blob on the relay until it expires.
* **Search:** only in-conversation search exists: in memory over the decrypted history of one open chat (up to 3000 messages), no persistent index, discarded when the screen closes. There is no cross-conversation search.
* **Tor reliability:** circuit stalls surface as "offline" and are retried within bounded budgets. A 20-sample CI campaign passed 20/20 on one commit; that does not establish a failure rate.
* **Releases:** no production signing key, no store listing, no update channel (`UPDATE_STRATEGY.md`). Build outputs from CI are unsigned developer artifacts.
