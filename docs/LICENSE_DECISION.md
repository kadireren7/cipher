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
