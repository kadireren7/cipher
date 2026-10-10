#!/usr/bin/env python3
"""Emulator end-to-end test: TWO independently hosted relays (separate processes, separate PostgreSQL databases), the real Android app on relay A and a
headless peer on relay B. Covers: contact card across relays, pinned self-signed relay B (PinnedTls on a real device stack), messages while either side
is offline, encrypted attachments both ways, process restarts between phases, end-to-end delivery receipts.

Honest scope: emulator (software-backed Keystore), debug direct route (no Tor), no physical device. Run by the `android-e2e-multirelay` CI job (scripts/ci-emulator-tests.sh with CIPHER_E2E=multirelay).

Needs: a booted emulator reachable by adb (host = 10.0.2.2 from inside), built APKs (gradlew :app:assembleDebug :app:assembleDebugAndroidTest),
target/release/cipher-relay, target/release/examples/e2e_peer, android/build/test-ca (scripts/make-test-ca.sh), docker container cipher-pg.
Usage: scripts/android-e2e-multirelay.py
"""
import base64, hashlib, os, re, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SDK = os.environ.get("ANDROID_HOME", os.path.expanduser("~/android-sdk"))
ADB = os.path.join(SDK, "platform-tools/adb")
RELAY = os.path.join(ROOT, "target/release/cipher-relay")
PEER = os.path.join(ROOT, "target/release/examples/e2e_peer")
CA = os.path.join(ROOT, "android/build/test-ca")
APK = os.path.join(ROOT, "android/app/build/outputs/apk/debug/app-debug.apk")
TAPK = os.path.join(ROOT, "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk")
HOST = "10.0.2.2"
PA, PB = 8443, 8444
TOKEN = "e2e-multirelay-registration-token-0123456789abcdef"
tmp = tempfile.mkdtemp(prefix="cipher-mr-e2e-")
sfx = str(os.getpid())
results, procs = [], []


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (f"  [{str(detail)[:1800]}]" if detail and not ok else ""), flush=True)


def sh(*a, **kw):
    return subprocess.run(list(a), capture_output=True, text=True, **kw)


def psql(sql, db="postgres"):
    if os.environ.get("CIPHER_E2E_PG_HOST"):  # CI: PostgreSQL service container reached over TCP with the psql client
        return sh("psql", "-h", os.environ["CIPHER_E2E_PG_HOST"], "-p", "55432", "-U", "postgres", "-d", db, "-tAc", sql,
                  env=dict(os.environ, PGPASSWORD="devonly-not-a-secret")).stdout.strip()
    return sh("docker", "exec", "cipher-pg", "psql", "-U", "postgres", "-d", db, "-tAc", sql).stdout.strip()


def start_relay(port, db, cert, key, label):
    env = dict(os.environ, CIPHER_RELAY_AUDIENCE=f"{HOST}:{port}", CIPHER_RELAY_REGISTRATION_TOKEN=TOKEN,
               CIPHER_RELAY_PEPPER=f"pepper-{label}-0123456789abcdef0123456789", CIPHER_RELAY_LISTEN=f"0.0.0.0:{port}",
               CIPHER_RELAY_DATABASE_URL=f"postgres://postgres:devonly-not-a-secret@127.0.0.1:55432/{db}",
               CIPHER_RELAY_TLS_CERT=cert, CIPHER_RELAY_TLS_KEY=key)
    p = subprocess.Popen([RELAY], env=env, stdout=open(f"{tmp}/relay-{label}.log", "w"), stderr=subprocess.STDOUT)
    procs.append(p)
    for _ in range(60):
        time.sleep(0.5)
        if sh("curl", "-sk", "-o", "/dev/null", f"https://127.0.0.1:{port}/").returncode == 0:
            return p
    raise SystemExit(f"relay {label} did not start: " + open(f"{tmp}/relay-{label}.log").read()[-300:])


class Peer:
    def __init__(self, d, host, env):
        self.p = subprocess.Popen([PEER, d, host, f"{CA}/ca.pem", "127.0.0.1"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1, env=dict(os.environ, **env))

    def cmd(self, line):
        self.p.stdin.write(line + "\n"); self.p.stdin.flush()
        return self.p.stdout.readline().strip()


def instrument(phase, **kw):
    a = [ADB, "shell", "am", "instrument", "-w", "-r", "-e", "class", "app.cipher.messenger.MultiRelayE2EInstrumentedTest#phase", "-e", "phase", phase]
    for k, v in kw.items():
        a += ["-e", k, v]
    a.append(RUNNER)
    sh(ADB, "logcat", "-c")
    r = sh(*a, timeout=600)
    out = r.stdout
    ok = "OK (1 test)" in out and "FAILURES" not in out and "INSTRUMENTATION_RESULT: shortMsg" not in out
    vals = dict(re.findall(r"INSTRUMENTATION_STATUS: (\w+)=(\S+)", out))
    if not ok:
        print(f"--- instrumentation phase '{phase}' output (tail) ---\n{out[-2500:]}\n---", flush=True)
        print(sh(ADB, "logcat", "-d", "-t", "400", "AndroidRuntime:E", "TestRunner:E", "DEBUG:*", "libc:F", "*:S").stdout[-3000:], flush=True)
    return ok, vals, out


def sha(b):
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------------------------------------------------------- setup
inst = sh(ADB, "shell", "pm", "list", "instrumentation").stdout
m = re.search(r"instrumentation:(\S+)/androidx\.test\.runner\.AndroidJUnitRunner", inst)
if "device" not in sh(ADB, "devices").stdout.split("List of devices attached")[-1]:
    raise SystemExit("no emulator/device attached")
for f in (RELAY, PEER, APK, TAPK, f"{CA}/ca.pem"):
    if not os.path.exists(f):
        raise SystemExit(f"missing prerequisite: {f}")
print(sh(ADB, "install", "-r", "-t", APK).stdout.strip(), sh(ADB, "install", "-r", "-t", TAPK).stdout.strip())
inst = sh(ADB, "shell", "pm", "list", "instrumentation").stdout
m = re.search(r"instrumentation:(\S+)/androidx\.test\.runner\.AndroidJUnitRunner", inst)
RUNNER = f"{m.group(1)}/androidx.test.runner.AndroidJUnitRunner"

dba, dbb = f"e2e_a_{sfx}", f"e2e_b_{sfx}"
psql(f"CREATE DATABASE {dba}"); psql(f"CREATE DATABASE {dbb}")
# relay B: SELF-SIGNED certificate, authenticated only by its pin (the card carries it)
subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", f"{tmp}/b.key", "-out", f"{tmp}/b.pem", "-days", "3",
                "-subj", "/CN=relay-b", "-addext", f"subjectAltName=IP:{HOST},IP:127.0.0.1,DNS:localhost"], capture_output=True, check=True)
der = sh("openssl", "x509", "-in", f"{tmp}/b.pem", "-pubkey", "-noout").stdout
spki = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=der.encode(), capture_output=True).stdout
PIN_B = base64.urlsafe_b64encode(hashlib.sha256(spki).digest()).decode().rstrip("=")
try:
    start_relay(PA, dba, f"{CA}/relay-chain.pem", f"{CA}/relay.key", "a")
    start_relay(PB, dbb, f"{tmp}/b.pem", f"{tmp}/b.key", "b")
    check("two independent relays are up (separate processes and databases; B is self-signed)", True)

    url_a, url_b = f"https://{HOST}:{PA}", f"https://{HOST}:{PB}"
    bob = Peer(f"{tmp}/bob", f"{HOST}:{PB}", {"CIPHER_PEER_OWN_PIN": PIN_B})
    bob.cmd("provision")
    check("peer registers on relay B", "Ok" in bob.cmd(f"register {TOKEN}"))
    check("peer names its relay (with pin)", "Ok" in bob.cmd(f"ownrelay {url_b} {PIN_B}"))
    bob_card = bob.cmd("card 7").split('"')[1]
    check("peer issues a contact card", bob_card.startswith("Q0NEMQ"), bob_card[:30])

    # ---- phase 1: the app creates its account on relay A and a card
    ok, v, out = instrument("init", relayUrl=url_a, invite=TOKEN)
    check("app: onboarding on relay A + contact card (real Keystore/OkHttp/TLS)", ok and "card" in v, out[-400:])
    app_card = v.get("card", "")

    # ---- phase 2 (new process): the app adds Bob's card (ANOTHER relay, pinned) and writes first
    ok, v, out = instrument("connect", relayUrl=url_a, peerCard=bob_card)
    check("app: adds a card from another relay, starts a conversation, sends (pinned TLS to relay B on-device)", ok and "conv" in v, out[-500:])
    conv_app = v.get("conv", "")

    # ---- peer side: join, read, reply while the APP IS NOT RUNNING (offline), with an attachment
    for _ in range(4):
        bob.cmd("sync")
        c = bob.cmd("convs")
        cid = re.search(r'id: "([0-9a-f]{32})"', c)
        if cid:
            bob.cmd(f"accept {cid.group(1)}")
    conv_bob = cid.group(1) if cid else ""
    for _ in range(3):
        bob.cmd("sync")
    h = bob.cmd(f"history {conv_bob}") if conv_bob else ""
    check("peer on relay B received the app's message from relay A", "app-hello-1" in h, h[:300])
    for i in (1, 2, 3):
        bob.cmd(f"send {conv_bob} off-{i}")
    data = bytes((i * 17 + 3) % 251 for i in range(900_000))
    path = f"{tmp}/from-bob.bin"
    open(path, "wb").write(data)
    r = bob.cmd(f"file {conv_bob} {path} application/octet-stream")
    check("peer sends 3 texts + a 900 KB file while the app is offline", "Ok" in r, r[:200])

    # ---- phase 3 (new process): app comes back and must have everything, in order
    ok, v, out = instrument("read", relayUrl=url_a, conv=conv_app, expectTexts="off-1,off-2,off-3", expectSha=sha(data), expectName="from-bob.bin")
    check("app: offline messages in order + attachment from relay B decrypts intact; app replies + sends an attachment", ok and "sentSha" in v, out[-1500:])

    # ---- peer: receives the app's text + attachment from relay A, and acknowledges
    got = ""
    for _ in range(6):
        bob.cmd("sync")
        got = bob.cmd(f"history {conv_bob}")
        if "app-reply-2" in got and "from-app.bin" in got:
            break
        time.sleep(1)
    check("peer received the app's text and attachment", "app-reply-2" in got and "from-app.bin" in got, got[:300])
    mid = re.search(r'id: "([0-9a-f]{32})"[^}]*?filename: "from-app\.bin"', got)
    if mid:
        out_path = f"{tmp}/bob-got.bin"
        bob.cmd(f"open {conv_bob} {mid.group(1)} {out_path}")
        check("peer decrypts the app's attachment byte-for-byte", os.path.exists(out_path) and sha(open(out_path, "rb").read()) == v.get("sentSha"))
    else:
        check("peer decrypts the app's attachment byte-for-byte", False, got[:400])
    for _ in range(3):
        bob.cmd("sync")

    # ---- phase 4 (new process): end-to-end receipts reached the app through relay A
    ok, v, out = instrument("final", relayUrl=url_a, conv=conv_app)
    check("app: its messages are DELIVERED by end-to-end receipts from the other relay", ok, out[-500:])

    # ---- what each relay knows: only its own user's device, and nothing in either database names the other relay's user
    da, db_ = psql("SELECT count(*) FROM devices", dba), psql("SELECT count(*) FROM devices", dbb)
    check("each relay stores exactly one device (its own user); neither knows the other's", (da, db_) == ("1", "1"), (da, db_))
    app_dev = psql("SELECT encode(device_id,'hex') FROM devices", dba)
    leak = psql(f"SELECT count(*) FROM queue WHERE sender_h IS NOT NULL", dbb)
    check("relay B holds no sender hash for anything the app delivered, and no record of the app's device",
          leak == "0" and psql(f"SELECT count(*) FROM devices WHERE encode(device_id,'hex')='{app_dev}'", dbb) == "0", leak)
finally:
    for p in procs:
        p.terminate()
    time.sleep(1)
    psql(f"DROP DATABASE IF EXISTS {dba} WITH (FORCE)"); psql(f"DROP DATABASE IF EXISTS {dbb} WITH (FORCE)")
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
