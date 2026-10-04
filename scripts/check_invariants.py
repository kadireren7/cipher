#!/usr/bin/env python3
"""Verify that every test mapped in security/invariants.json actually exists.

A renamed or deleted invariant test must fail CI loudly instead of silently
dropping coverage. Rust tests are discovered with `cargo test -- --list`; Kotlin tests (JVM unit and
instrumented) by file existence plus a `fun name(` declaration; scripts by file existence.
"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
data = json.loads((ROOT / "security/invariants.json").read_text())

listing = subprocess.run(
    ["cargo", "test", "--workspace", "--all-features", "--locked", "--", "--list"],
    cwd=ROOT, capture_output=True, text=True, check=True,
).stdout
rust_tests = set(re.findall(r"^(?:.*::)?([A-Za-z0-9_]+): test$", listing, re.M))

problems = []
required = {f"SEC-{n:03d}" for n in range(1, 39)}  # SEC-001..SEC-014 from the first task, SEC-015..037 added since
ids = {i["id"] for i in data["invariants"]}
required |= {f"REV-{n:03d}" for n in range(1, 11)}  # history/membership revocation (docs/HISTORY_REVOCATION.md)
required |= {f"PRIV-{n:03d}" for n in range(1, 18)}  # network-privacy layer (docs/NETWORK_PRIVACY_THREAT_MODEL.md)
for missing in sorted(required - ids):
    problems.append(f"{missing}: missing from registry")

for inv in data["invariants"]:
    if inv["status"] not in ("automated", "partial", "manual"):
        problems.append(f"{inv['id']}: bad status")
    if inv["status"] != "manual" and not inv["tests"]:
        problems.append(f"{inv['id']}: no tests mapped")
    if not inv.get("threats"):
        problems.append(f"{inv['id']}: every invariant must map to at least one threat-model adversary")
    if inv["status"] != "automated" and not inv.get("gap"):
        problems.append(f"{inv['id']}: partial/manual requires a documented gap")
    for t in inv["tests"]:
        if t["kind"] == "rust":
            if t["name"] not in rust_tests:
                problems.append(f"{inv['id']}: rust test not found: {t['name']}")
        elif t["kind"] == "kotlin":
            f = ROOT / t["file"]
            if not f.exists() or not re.search(r"fun\s+`?" + re.escape(t["name"]) + r"`?\s*\(", f.read_text()):
                problems.append(f"{inv['id']}: kotlin test not found: {t['file']} :: {t['name']}")
        elif t["kind"] == "script":
            if not (ROOT / t["name"]).exists():
                problems.append(f"{inv['id']}: script not found: {t['name']}")
        else:
            problems.append(f"{inv['id']}: unknown test kind {t['kind']}")

if problems:
    print("INVARIANT COVERAGE PROBLEMS:")
    for p in problems:
        print(" -", p)
    sys.exit(1)
n = sum(len(i["tests"]) for i in data["invariants"])
print(f"ok: {len(data['invariants'])} invariants, {n} mapped tests all exist")
