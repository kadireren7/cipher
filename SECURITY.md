# Security policy

## Status

Cipher is **experimental and has not been independently audited**. It has been run only on an Android emulator, never on a physical device, and its privacy route has not been validated against the live Tor network. Do not rely on it to protect anyone who could be harmed by a failure. See the [security status](README.md#security-status) and [SECURITY_TODO](docs/SECURITY_TODO.md) for known open issues.

## Reporting a vulnerability

**Please do not report exploitable vulnerabilities in public issues, pull requests or discussions.**

Use GitHub's **private vulnerability reporting**: open the repository's **Security** tab and choose **Report a vulnerability**. Include what you found, how to reproduce it, the affected component and version/commit, and what an attacker gains. If you can, include a failing test.

If private reporting is unavailable for any reason, open a public issue that says only that you have a security report and ask for a private channel — **without any technical detail**.

This is a small project. We will try to acknowledge reports and keep you informed, but we do not promise a response time, a fix time or a bounty.

## Scope

In scope:

- the Rust crates (`cipher-core`, `cipher-wire`, `cipher-relay`, `cipher-ffi`) and the Android app in this repository;
- the cryptographic compositions listed in [EXTERNAL_REVIEW_SCOPE](docs/EXTERNAL_REVIEW_SCOPE.md) (history keys, vault, request signing, delivery capabilities);
- failures of a documented security invariant ([SECURITY_INVARIANTS](docs/SECURITY_INVARIANTS.md)) or of a claim in the threat models;
- the privacy transport's fail-closed behaviour (any path that sends data to the relay without the configured route in a release build);
- secrets or personal data accidentally committed to this repository.

Out of scope:

- vulnerabilities in upstream dependencies that are not reachable through Cipher (report those upstream; tell us if Cipher is affected);
- a compromised, unlocked, rooted or malware-infected device, and attacks that require physical coercion;
- anonymity or global-observer / end-to-end timing-correlation attacks (Cipher states it does not defend against them);
- the throwaway test CA, the `devonly-not-a-secret` test database password and the development SOCKS5 test double (public, test-only, documented);
- denial of service by volume against a self-hosted relay without a demonstrated amplification flaw;
- reports without a security impact (missing headers on non-sensitive responses, theoretical issues with no scenario).

## Disclosure

Please give us a reasonable chance to fix a problem before disclosing it. We will credit you in the fix if you wish.
