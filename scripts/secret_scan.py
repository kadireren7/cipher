#!/usr/bin/env python3
"""Dependency-free secret scan (defence in depth next to gitleaks in CI).

Scans every tracked-or-untracked, non-ignored file for private key blocks, cloud credentials,
tokens, and long hex/base64 blobs assigned to secret-looking names. Exit 1 on findings.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PATTERNS = {
    "private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY"),
    "AWS access key id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Stripe live key": re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "secret assignment": re.compile(
        r"(?i)\b(?:secret|passw(?:or)?d|api[_-]?key|private[_-]?key|auth[_-]?token)\b\s*[:=]\s*[\"']?([A-Za-z0-9+/=_-]{24,})[\"']?"
    ),
}
SKIP_SUFFIX = {".lock", ".png", ".jpg", ".ico", ".woff", ".woff2"}
PLACEHOLDER = re.compile(r"(?i)(example|placeholder|changeme|<[^>]+>|xxxx|your[_-])")

files = subprocess.run(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT, capture_output=True, text=True, check=True
).stdout.splitlines()

findings = []
for rel in files:
    p = ROOT / rel
    if p.suffix in SKIP_SUFFIX or rel.endswith("package-lock.json") or not p.is_file():
        continue
    try:
        text = p.read_text(errors="ignore")
    except OSError:
        continue
    for n, line in enumerate(text.splitlines(), 1):
        if "secret-scan:allow" in line:
            continue
        for name, rx in PATTERNS.items():
            m = rx.search(line)
            if m and not PLACEHOLDER.search(line):
                findings.append(f"{rel}:{n}: {name}")

if findings:
    print("POSSIBLE SECRETS:")
    print("\n".join(" - " + f for f in findings))
    sys.exit(1)
print(f"ok: scanned {len(files)} files, no secrets found")
