# Cipher documentation index

Cipher is **experimental and unaudited**. These documents describe what is built, what was tested, what was *not*, and what is still open. When a document and the code disagree, the code and its tests win; please open an issue.

Start here: [FINAL_SECURITY_REVIEW](FINAL_SECURITY_REVIEW.md) (findings, fixes, readiness) → [THREAT_MODEL](THREAT_MODEL.md) → [SECURITY_TODO](SECURITY_TODO.md).

## Security
| Document | What it covers |
| --- | --- |
| [FINAL_SECURITY_REVIEW](FINAL_SECURITY_REVIEW.md) | Adversarial self-review: findings, fixes, residual risks, readiness verdicts (with addenda for history revocation and network privacy) |
| [THREAT_MODEL](THREAT_MODEL.md) | Adversaries A1–A18, assets, assumptions |
| [SECURITY_ARCHITECTURE](SECURITY_ARCHITECTURE.md) | Trust boundaries and controls |
| [SECURITY_INVARIANTS](SECURITY_INVARIANTS.md) | Generated registry: each invariant mapped to threats and tests, with known gaps |
| [SECURITY_TODO](SECURITY_TODO.md) | Every open security item and its classification |
| [ATTACK_SURFACE](ATTACK_SURFACE.md) | Surface-by-surface attack analysis |
| [EXTERNAL_REVIEW_SCOPE](EXTERNAL_REVIEW_SCOPE.md) | The brief for an independent reviewer (ST-005 remains open) |

## Cryptography
| Document | What it covers |
| --- | --- |
| [CRYPTOGRAPHIC_DESIGN](CRYPTOGRAPHIC_DESIGN.md) | Protocol choice (OpenMLS), our own compositions to be reviewed, limitations |
| [HISTORY_REVOCATION](HISTORY_REVOCATION.md) | Per-epoch history keys and what removal does (and does not) revoke |
| [GROUP_SECURITY](GROUP_SECURITY.md) | Roles, commit authorization, ordering, removal |
| [KEY_MANAGEMENT](KEY_MANAGEMENT.md) | Key lifecycle and storage |
| [KEY_TRANSPARENCY](KEY_TRANSPARENCY.md) | Experimental, feature-gated verifier (not production) |

## Privacy and metadata
| Document | What it covers |
| --- | --- |
| [NETWORK_PRIVACY_THREAT_MODEL](NETWORK_PRIVACY_THREAT_MODEL.md) | Network adversaries P1–P14 with PROTECTED / PARTIAL / NOT PROTECTED ratings |
| [PRIVACY_TRANSPORT_REVIEW](PRIVACY_TRANSPORT_REVIEW.md) | What the privacy layer does, measurements, collusion and correlation analysis, unresolved issues |
| [ADR-PRIVACY-TRANSPORT](ADR-PRIVACY-TRANSPORT.md) | Why Tor over SOCKS5; alternatives compared |
| [DELIVERY_CAPABILITIES](DELIVERY_CAPABILITIES.md) | Anonymous, rotating, revocable delivery capabilities |
| [METADATA_MODEL](METADATA_MODEL.md) | Field-by-field: what each party can observe |
| [ISP_OBSERVABILITY_REPORT](ISP_OBSERVABILITY_REPORT.md) | What a link observer can infer, by profile |
| [RETENTION_AND_LOGGING](RETENTION_AND_LOGGING.md) | What the relay keeps, for how long |
| [PUSH_DESIGN](PUSH_DESIGN.md) | Content-free push design (no provider integrated) |
| [DELIVERY_SEMANTICS](DELIVERY_SEMANTICS.md) | Sent / delivered meanings; what a relay cannot forge |
| [RECOVERY_AND_DEVICES](RECOVERY_AND_DEVICES.md) | No cryptographic recovery; device model |

## Android
| Document | What it covers |
| --- | --- |
| [ANDROID_SECURITY](ANDROID_SECURITY.md) | Keystore, manifest, windows, lifecycle, FFI boundary |
| [LOCAL_STORAGE_SECURITY](LOCAL_STORAGE_SECURITY.md) | Vault, rollback detection, deletion |
| [DEVICE_TEST_CHECKLIST](DEVICE_TEST_CHECKLIST.md) | Physical-device tests that have **not** been performed |
| [RELEASE_SIGNING](RELEASE_SIGNING.md) | Signing architecture (no signing material is committed) |

## Relay
| Document | What it covers |
| --- | --- |
| [ARCHITECTURE](ARCHITECTURE.md) | Components and data flow |
| [METADATA_MODEL](METADATA_MODEL.md) · [RETENTION_AND_LOGGING](RETENTION_AND_LOGGING.md) | What the relay stores and logs |

## Testing
| Document | What it covers |
| --- | --- |
| [SECURITY_TESTING](SECURITY_TESTING.md) | TESTED / ARCHITECTURALLY EXPECTED / NOT TESTED, per area |
| [SECURITY_INVARIANTS](SECURITY_INVARIANTS.md) | Invariant → test mapping |

## Auditing and release
| Document | What it covers |
| --- | --- |
| [PUBLIC_RELEASE_AUDIT](PUBLIC_RELEASE_AUDIT.md) | Secret/personal-data/artifact audit performed before this repository was made public |
| [DECISIONS](DECISIONS.md) | Architecture decision records |
