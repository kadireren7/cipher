# Contributing to Cipher

Thank you for looking. Cipher is a security project: **correctness and honesty about limits matter more than features.** By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not as issues.

## Development setup

Prerequisites and exact commands are in the README's [Build and run](README.md#build-and-run-development) section: Rust (pinned by `rust-toolchain.toml`), JDK 17, Android SDK/NDK, `cargo-ndk`, Docker (PostgreSQL for relay tests), Python 3, `cargo-deny`, `cargo-audit`.

## Before you open a pull request

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
python3 scripts/check_invariants.py && python3 scripts/gen_invariants_doc.py --check
bash scripts/check-relay-deps.sh
python3 scripts/secret_scan.py && python3 scripts/public_release_scan.py
cargo deny check && cargo audit
(cd android && ./gradlew :app:ktlintCheck :app:lintDebug :app:testDebugUnitTest)   # Android changes
```

`scripts/verify-all.sh` runs the Rust gates in one go. Instrumented tests need an emulator or device (`scripts/ci-emulator-tests.sh`).

## Security invariants

Security properties are registered in [`security/invariants.json`](security/invariants.json) with the threats they address, the tests that exercise them and an honest **gap** statement. If you rename or delete a mapped test, `scripts/check_invariants.py` fails. After editing the registry run `python3 scripts/gen_invariants_doc.py` to regenerate [`docs/SECURITY_INVARIANTS.md`](docs/SECURITY_INVARIANTS.md). Never weaken an existing invariant to make a feature easier.

## Fuzzing

Parsers and boundaries have libFuzzer targets in [`fuzz/`](fuzz) (needs nightly + `cargo-fuzz`). A new parser, wire type or decoder needs a target, and any crash gets minimized, fixed and covered by a regression test. Corpora and artifacts are not committed. Short runs are smoke tests, not evidence of exhaustive coverage; say so in your PR.

## Cryptographic and protocol changes

**No custom cryptography.** Use maintained, reviewed libraries and standard constructions. A change to cryptography, key handling, the wire protocol, group policy, history revocation, delivery capabilities or the privacy transport **requires**, in the same pull request:

1. design documentation (what, why, alternatives considered);
2. a threat-model update ([THREAT_MODEL](docs/THREAT_MODEL.md) and/or [NETWORK_PRIVACY_THREAT_MODEL](docs/NETWORK_PRIVACY_THREAT_MODEL.md));
3. new or updated invariants with an honest gap;
4. negative tests (tampering, replay, downgrade, stale state, hostile peer/relay) — not only happy paths;
5. independent review before it is relied upon (see [EXTERNAL_REVIEW_SCOPE](docs/EXTERNAL_REVIEW_SCOPE.md)).

Propose protocol changes by opening an issue (or a draft PR containing only the design document) *before* writing code.

## Style and scope

- Match the surrounding code: Rust formatting by `rustfmt`, Kotlin by `ktlint`; no new dependency without a reason, `cargo deny` clean, and the relay must keep having no message-crypto dependency.
- Never log plaintext, keys, tokens, identifiers or addresses. Never commit secrets, keystores, dumps, traces or captured traffic (`scripts/public_release_scan.py` checks).
- Keep claims honest: don't write "secure", "anonymous" or "audited" in docs unless the evidence is linked.
