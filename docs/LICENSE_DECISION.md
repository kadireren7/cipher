# Open-source licence decision checklist

**No licence is selected; all rights are reserved until the owner decides** (`README.md`, `PUBLIC_RELEASE_AUDIT.md`). Nothing here selects one.

| Question | Why it matters | Owner answer |
| --- | --- | --- |
| Must forks that run a network service publish their changes? | Relay operators are the main audience. AGPL-3.0 requires it; Apache-2.0/MIT do not. | ☐ |
| Patent grant wanted? | Apache-2.0 and MPL-2.0 include one; MIT does not. | ☐ |
| Same licence for client and relay, or split? | The Android client can be AGPL/GPL (F-Droid friendly) while the relay differs. | ☐ |
| Compatibility with dependencies | `cargo deny` enforces the Rust set (`deny.toml`); the Android set has no automated licence check yet (see SBOM). OpenMLS is MIT; verify every Gradle dependency, including zxing (Apache-2.0), OkHttp (Apache-2.0), CameraX (Apache-2.0). | ☐ |
| Contributor terms | DCO sign-off or CLA, and who may relicense later. | ☐ |
| Trademark and name "Cipher" | Name availability has not been checked. | ☐ |
| Store policy | Google Play and F-Droid have their own rules for encryption declarations and anti-features. | ☐ |
Once chosen: add `LICENSE`, set `license` in `Cargo.toml`, add SPDX headers if wanted, update `README.md`, SBOM metadata and the in-app "About" text.

## Third-party licences that constrain the choice (added 2026-11-08)

The Android APK now bundles IPtProxy (MIT), which contains **lyrebird (GPL-3.0)** and snowflake (BSD-3-Clause), in the same native library. Distributing the APK therefore distributes GPL-3.0 code: the app's licence must be compatible with GPL-3.0 for the combined work (GPL-3.0/AGPL-3.0 are; a proprietary or "all rights reserved" licence is not), and the corresponding source must be offered. tor-android (BSD-3-Clause) does not add such a constraint.
