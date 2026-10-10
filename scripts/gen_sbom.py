#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM for the relay and the Android app from files that are already in the repository.

  * Rust: every package in Cargo.lock (name, version, crates.io checksum = SHA-256 of the .crate file; workspace members have none).
  * Android: every component in android/gradle/verification-metadata.xml (group:name:version, SHA-256 of each artifact as Gradle verified it).

Deterministic (sorted, no timestamps unless --timestamp), offline, no network, no dependency. It is an INVENTORY of what a build resolves, not a vulnerability report
(that is `cargo audit` / `cargo deny`), and not a statement about licences (that is `cargo deny check licenses` for Rust; Android licences are NOT checked here).
Usage: scripts/gen_sbom.py [-o sbom.cdx.json] [--timestamp]
"""
import json, pathlib, re, sys, time, uuid
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent
out = pathlib.Path(sys.argv[sys.argv.index("-o") + 1]) if "-o" in sys.argv else ROOT / "release-artifacts/sbom.cdx.json"

components = []

lock = (ROOT / "Cargo.lock").read_text()
for block in lock.split("[[package]]")[1:]:
    f = dict(re.findall(r'^(name|version|source|checksum) = "([^"]+)"', block, re.M))
    if "name" not in f:
        continue
    c = {"type": "library", "bom-ref": f"cargo:{f['name']}@{f['version']}", "name": f["name"], "version": f["version"],
         "purl": f"pkg:cargo/{f['name']}@{f['version']}", "properties": [{"name": "cipher:ecosystem", "value": "rust"}]}
    if "checksum" in f:
        c["hashes"] = [{"alg": "SHA-256", "content": f["checksum"]}]
    if "source" not in f:
        c["properties"].append({"name": "cipher:origin", "value": "workspace"})
    components.append(c)

ns = {"g": "https://schema.gradle.org/dependency-verification"}
tree = ET.parse(ROOT / "android/gradle/verification-metadata.xml")
for comp in tree.getroot().findall("g:components/g:component", ns):
    g, n, v = comp.get("group"), comp.get("name"), comp.get("version")
    hashes = sorted({a.find("g:sha256", ns).get("value") for a in comp.findall("g:artifact", ns) if a.find("g:sha256", ns) is not None})
    c = {"type": "library", "bom-ref": f"maven:{g}:{n}@{v}", "group": g, "name": n, "version": v, "purl": f"pkg:maven/{g}/{n}@{v}",
         "hashes": [{"alg": "SHA-256", "content": h} for h in hashes], "properties": [{"name": "cipher:ecosystem", "value": "android-gradle"}]}
    components.append(c)

components.sort(key=lambda c: c["bom-ref"])
bom = {
    "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
    "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "cipher-sbom:" + ",".join(c["bom-ref"] for c in components))),
    "metadata": {"component": {"type": "application", "name": "cipher", "bom-ref": "cipher"},
                 "properties": [{"name": "cipher:scope", "value": "Cargo.lock + Gradle verification metadata; build tools and the OS are not listed"}]},
    "components": components,
}
if "--timestamp" in sys.argv:
    bom["metadata"]["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(bom, indent=1, sort_keys=True) + "\n")
rust = sum(1 for c in components if c["bom-ref"].startswith("cargo:"))
print(f"wrote {out}: {len(components)} components ({rust} Rust, {len(components) - rust} Android)")
