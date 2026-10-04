#!/usr/bin/env python3
"""Public-release scanner: run BEFORE publishing. Scans every file git would commit (tracked + untracked-not-ignored) and, optionally, git history.

Checks: private-key blocks, well-known token shapes, credential assignments, high-entropy strings, absolute home paths, local usernames,
e-mail addresses, non-private IPv4 addresses, forbidden artifact types (keystores, dumps, pcaps, vaults, logs), oversized files.
Findings print file:line and the KIND only (never the matched value). Exit 1 on any finding.

  scripts/public_release_scan.py [--history] [--allow-file scripts/public_release_allow.txt]
"""
import math, os, re, subprocess, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
os.chdir(ROOT)
def _owner_terms():
    """Personal terms are derived at run time (login name, git identity, GH login, extra CIPHER_SCAN_PERSONAL_TERMS) so this file publishes none."""
    import getpass
    t = {getpass.getuser()}
    for cmd in (["git", "config", "user.name"], ["git", "config", "user.email"], ["gh", "api", "user", "--jq", ".login"]):
        try:
            v = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
        except Exception:
            v = ""
        if v:
            t.add(v.split("@")[0] if "@" in v else v)
    t |= {x for x in os.environ.get("CIPHER_SCAN_PERSONAL_TERMS", "").split(",") if x}
    return sorted(x for x in t if len(x) >= 4)

OWNER_TERMS = _owner_terms()

PATTERNS = {
    "private-key block": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "github token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}"),
    "aws key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "google api key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "credential in url": re.compile(r"[a-z]+://[^/\s:@]+:[^/\s:@]{4,}@[^/\s]+"),
    "credential assignment": re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|auth[_-]?token|bearer)\b\s*[:=]\s*[\"']?[A-Za-z0-9+/_\-]{16,}"),
    "absolute home path": re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+/"),
    "e-mail address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}
FORBIDDEN_SUFFIX = (".jks", ".keystore", ".p12", ".pfx", ".pem", ".key", ".db", ".sqlite", ".sqlite3", ".log", ".pcap", ".pcapng", ".trace", ".apk", ".aab",
                    ".tar", ".tgz", ".zip", ".snapshot", ".hprof", ".der", ".csr", ".srl")
SAFE_IPS = re.compile(r"^(127\.|10\.0\.2\.|0\.0\.0\.0|255\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|1\.2\.3\.4$)")
BIN = re.compile(rb"[\x00]")
MAX_BYTES = 2_000_000

allow = set()
allow_file = None
if "--allow-file" in sys.argv:
    allow_file = sys.argv[sys.argv.index("--allow-file") + 1]
elif (ROOT / "scripts/public_release_allow.txt").exists():
    allow_file = "scripts/public_release_allow.txt"
if allow_file:
    for l in pathlib.Path(allow_file).read_text().splitlines():
        l = l.split("#")[0].strip()
        if l:
            allow.add(l)  # "path|kind" pairs, each with a justification comment in the file

def entropy(s):
    c = {ch: s.count(ch) for ch in set(s)}
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())

def files():
    out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], capture_output=True, text=True, check=True).stdout.split("\n")
    return [f for f in out if f and os.path.isfile(f)]

findings = []
def add(path, line, kind):
    if f"{path}|{kind}" in allow or f"*|{kind}" in allow:
        return
    findings.append((path, line, kind))

def scan_text(path, text):
    for i, line in enumerate(text.split("\n"), 1):
        for kind, rx in PATTERNS.items():
            for m in rx.finditer(line):
                if kind == "e-mail address" and re.search(r"@[A-Za-z0-9.-]*(example|invalid|test|localhost)\b", m.group(0)):
                    continue
                if kind == "e-mail address" and re.search(r"https?://[^\s]*@", line):
                    continue
                if kind == "credential in url" and re.search(r"devonly-not-a-secret|<password>|u:p@|user:pass", m.group(0)):
                    continue  # documented PUBLIC test credential / placeholders
                if kind == "ipv4":
                    ip = m.group(0)
                    if SAFE_IPS.match(ip) or any(int(p) > 255 for p in ip.split(".")) or re.search(r"\d\.\d+\.\d+\.\d+\.\d", line[max(0, m.start() - 1): m.end() + 2]):
                        continue
                    if re.search(r"(?i)version|v?\d+\.\d+\.\d+\.\d+-|checksum", line) or path.endswith(("Cargo.lock", ".xml", "gradle.properties")):
                        continue
                add(path, i, kind)
        for t in OWNER_TERMS:
            if t.lower() in line.lower() and not re.search(r"github\.com/" + re.escape(t) + r"[/\"')\s]", line, re.I):  # the public GitHub login in a repo URL is intended
                add(path, i, "personal term")
        for tok in re.findall(r"(?<![A-Za-z0-9+/=_.-])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=_.-])", line):
            if not re.fullmatch(r"[0-9a-f]+", tok) and entropy(tok) > 4.5 and re.search(r"[a-z]", tok) and re.search(r"[A-Z]", tok) and re.search(r"\d", tok):
                add(path, i, "high-entropy string")

def main():
    for f in files():
        p = pathlib.Path(f)
        if p.suffix.lower() in FORBIDDEN_SUFFIX or p.name in (".env", "local.properties", "google-services.json"):
            add(f, 0, "forbidden artifact type")
            continue
        if p.stat().st_size > MAX_BYTES:
            add(f, 0, "oversized file")
            continue
        data = p.read_bytes()
        if BIN.search(data[:4096]):
            if not f.endswith((".jar", ".png", ".webp")):
                add(f, 0, "unexpected binary file")
            continue
        scan_text(f, data.decode("utf-8", "replace"))
    if "--history" in sys.argv:
        r = subprocess.run(["git", "rev-list", "--all"], capture_output=True, text=True)
        for c in r.stdout.split():
            for f in subprocess.run(["git", "ls-tree", "-r", "--name-only", c], capture_output=True, text=True).stdout.split("\n"):
                if f and pathlib.Path(f).suffix.lower() in FORBIDDEN_SUFFIX:
                    add(f"{c[:8]}:{f}", 0, "forbidden artifact type (history)")
            diff = subprocess.run(["git", "show", "--format=", c], capture_output=True, text=True, errors="replace").stdout
            scan_text(f"history:{c[:8]}", diff)
    seen = set()
    for path, line, kind in findings:
        k = (path, kind)
        if k in seen:
            continue
        seen.add(k)
        n = sum(1 for p, _, kk in findings if (p, kk) == k)
        print(f"FINDING {path}:{line} {kind} (x{n})")
    print(f"scanned {len(files())} files; {len(seen)} distinct findings")
    return 1 if findings else 0

sys.exit(main())
