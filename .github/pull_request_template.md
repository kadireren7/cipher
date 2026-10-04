## What and why

<!-- Short description. Link the issue/design. -->

## Checklist

- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo test` pass; Android changes: `ktlintCheck`, `lintDebug`, unit tests pass
- [ ] `python3 scripts/check_invariants.py` and `python3 scripts/public_release_scan.py` pass
- [ ] No secrets, keys, tokens, logs, dumps, traces or personal data added
- [ ] No existing security invariant weakened
- [ ] **Crypto / protocol / privacy-transport change?** Design doc, threat-model update, new invariants and negative tests are included; no custom cryptography
- [ ] Docs updated; claims match the evidence (no "secure/anonymous/audited" without a link)
