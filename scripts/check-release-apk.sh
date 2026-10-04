#!/usr/bin/env bash
# Gate on the REAL release artifact (merged manifest, so library-contributed components are included):
# not debuggable, no backup, no cleartext, no test CA, and the ONLY exported component is the launcher activity.
set -euo pipefail
cd "$(dirname "$0")/../android/app/build/outputs/apk/release"
APK=$(ls *.apk | head -1)
BT=$(ls -d "${ANDROID_HOME:-$HOME/android-sdk}"/build-tools/* | sort -V | tail -1)
"$BT/aapt2" dump xmltree --file AndroidManifest.xml "$APK" > /tmp/cipher-release-manifest.txt
python3 - "$APK" <<'PY'
import re, sys
t = open("/tmp/cipher-release-manifest.txt").read()
fail = []
if "debuggable" in t: fail.append("release APK mentions debuggable")
if not re.search(r"allowBackup\(0x[0-9a-f]+\)=false", t): fail.append("allowBackup is not false")
if not re.search(r"usesCleartextTraffic\(0x[0-9a-f]+\)=false", t): fail.append("cleartext is not forbidden")
# split into component blocks
blocks = re.split(r"\n(?=\s{10}E: (?:activity|service|receiver|provider)(?:-alias)? )", t)
exported = []
for b in blocks[1:]:
    kind = re.match(r"\s*E: (\S+)", b).group(1)
    name = re.search(r':name\(0x[0-9a-f]+\)="([^"]+)"', b).group(1)
    first = b.split("\n          E:")[0]  # attributes of the component element only
    if re.search(r"exported\(0x[0-9a-f]+\)=true", first) or ("intent-filter" in b and "exported(" not in first):
        exported.append(f"{kind}:{name}")
if exported != ["activity:app.cipher.messenger.MainActivity"]:
    fail.append(f"exported components must be exactly the launcher activity, found {exported}")
import zipfile
z = zipfile.ZipFile(sys.argv[1])
if any("res/raw/test_ca" in n for n in z.namelist()): fail.append("throwaway test CA is packaged in release")
# PRIV-005/015/011: the debug-only direct route must not exist in the release dex (its opt-in marker string is the tell), and there is no dev SOCKS proxy.
dex = b"".join(z.read(n) for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n))
for needle in (b"allow_direct_dev", b"dev-socks-proxy", b"insecure-test-support"):
    if needle in dex: fail.append(f"release dex contains {needle.decode()}")
for n in z.namelist():
    if n.startswith("lib/") and n.endswith(".so"):
        so = z.read(n)
        for needle in (b"allow_direct_dev", b"insecure-test-support"):
            if needle in so: fail.append(f"{n} contains {needle.decode()}")
if fail:
    print("FAIL: " + "; ".join(fail)); sys.exit(1)
print("ok: release APK manifest gate passed (only the launcher activity is exported)")
PY
