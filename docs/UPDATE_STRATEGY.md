# Update strategy

Cipher has no auto-update channel of its own and will not add one that bypasses the platform's signature checks. Updates reach users through channels that verify the signing key.

* **Android's package installer** only installs an update signed by the same key as the installed app. The release key therefore is the update trust root. Losing it means users must reinstall and lose their data (no recovery by design); back it up under a documented key-management plan (`RELEASE_SIGNING.md`). **No production key exists yet.**
* **Distribution (pick one explicitly; none is configured):** GitHub release with `SHA256SUMS` and a detached signature, F-Droid (reproducible-build verification is possible: `scripts/reproduce-release.sh`), Obtainium/self-hosted repository, or Play (requires an account and review: not done).
* **No in-app update check** is shipped; a check would reveal the install to a third party. If one is added it must be opt-in, fetch a signed manifest over a pinned channel, and only *notify*.
* **Relay ↔ client compatibility:** see `RELEASE_READINESS.md` §5. A newer client against an older relay is unsupported; upgrade relays first.
* **Rollback:** the app refuses a database written by a newer app version; relays refuse a newer schema. Roll back by restoring backups.
* **Revoking a bad release:** pull the artifact, publish a security advisory on the repository, ship a fixed higher `versionCode`.
