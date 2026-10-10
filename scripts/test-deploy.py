#!/usr/bin/env python3
"""Self-hosting acceptance test: fresh install, relay restart, PostgreSQL restart, backup -> wipe -> restore, with real clients.

Drives the real Docker Compose stack in deploy/ (already `init`ed and `up`) with two headless FFI peers (the same CipherEngine surface the app uses).
Evidence of what happens to a message queued while the recipient is offline across each failure. Exit code 0 only if every check passes.
Usage: scripts/test-deploy.py HOST:PORT   (e.g. localhost:18443; CIPHER_PUBLISH must publish that port on 127.0.0.1)
"""
import os, re, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY = os.path.join(ROOT, "deploy")
HOST = sys.argv[1]
CA = os.path.join(DEPLOY, "data/secrets/tls-cert.pem")
TOKEN = open(os.path.join(DEPLOY, "data/secrets/registration_token")).read().strip()
PEER = os.path.join(ROOT, "target/release/examples/e2e_peer")
ENV = dict(os.environ, CIPHER_PUBLISH=os.environ.get("CIPHER_PUBLISH", "127.0.0.1:18443"))
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""), flush=True)


class Peer:
    def __init__(self, d):
        self.p = subprocess.Popen([PEER, d, HOST, CA, "127.0.0.1"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def cmd(self, line):
        self.p.stdin.write(line + "\n"); self.p.stdin.flush()
        return self.p.stdout.readline().strip()

    def close(self):
        try: self.p.stdin.write("quit\n"); self.p.stdin.flush(); self.p.wait(timeout=10)
        except Exception: self.p.kill()


def ctl(*a, **kw):
    return subprocess.run(["./cipherctl.sh", *a], cwd=DEPLOY, env=ENV, capture_output=True, text=True, **kw)


def dc(*a):
    return subprocess.run(["docker", "compose", "-f", "compose.yaml", *a], cwd=DEPLOY, env=ENV, capture_output=True, text=True)


def wait_healthy(timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        r = subprocess.run(["docker", "inspect", "--format", "{{.State.Health.Status}}", "cipher-relay-1"], capture_output=True, text=True)
        if r.stdout.strip() == "healthy":
            return True
        time.sleep(2)
    return False


def hexid(s):
    m = re.search(r"[0-9a-f]{32}", s)
    return m.group(0) if m else None


def cipher_id(s):
    m = re.search(r'cipher_id: "([^"]+)"', s) or re.search(r'"(cipher[^"]+)"', s)
    return m.group(1) if m else None


tmp = tempfile.mkdtemp(prefix="cipher-deploy-test-")
check("stack healthy after fresh install", wait_healthy())
a = Peer(tmp + "/a")
a.cmd("provision")
ra = a.cmd(f"register {TOKEN}")
check("client registers through the container", "Ok" in ra, ra)
acc = None

# The peer's keystore is in-memory per process (dev tool), so Bob stays alive for the whole matrix; "offline" is modelled by not calling sync.
bob = Peer(tmp + "/b")
bob.cmd("provision")
rb = bob.cmd(f"register {TOKEN}")
check("second client registers", "Ok" in rb, rb)
idb2 = cipher_id(bob.cmd("id"))
print("add bob2:", a.cmd(f"add {idb2} bob2")[:60])
contacts = a.cmd("contacts")
accs = re.findall(r"[0-9a-f]{32}", contacts)
acc2 = accs[0]
conv2 = hexid(a.cmd(f"dm {acc2}"))
check("DM with the always-on recipient created", conv2 is not None)

# 1. relay restart while a message is queued
a.cmd(f"send {conv2} m1-before-relay-restart"); a.cmd("flush")
r = dc("restart", "relay"); check("relay restarts", r.returncode == 0 and wait_healthy(), r.stderr)
bob.cmd("sync"); cid = hexid(bob.cmd("convs")); bob.cmd(f"accept {cid}")
h = bob.cmd(f"history {cid}")
check("message queued before relay restart is delivered after it", "m1-before-relay-restart" in h, h[:200])

# 2. PostgreSQL restart
a.cmd(f"send {conv2} m2-before-db-restart"); a.cmd("flush")
r = dc("restart", "db"); time.sleep(3)
check("PostgreSQL restarts and relay recovers", r.returncode == 0 and wait_healthy(180), r.stderr)
bob.cmd("sync"); h = bob.cmd(f"history {cid}")
check("message queued before PostgreSQL restart is delivered after it", "m2-before-db-restart" in h, h[:200])

# 3. backup -> wipe volume -> restore, with an undelivered message in the queue
a.cmd(f"send {conv2} m3-in-backup"); a.cmd("flush")
bk = os.path.join(tmp, "relay.dump")
r = ctl("backup", bk); check("backup written", r.returncode == 0 and os.path.getsize(bk) > 1000, r.stderr)
dc("down"); r = subprocess.run(["docker", "volume", "rm", "cipher_pgdata"], capture_output=True, text=True)
check("database volume destroyed", r.returncode == 0, r.stderr)
r = dc("up", "-d", "db"); time.sleep(8)
dc("up", "-d", "relay"); ok = wait_healthy(180)
check("empty stack comes up (fresh schema)", ok)
r = ctl("restore", bk); check("restore succeeds", r.returncode == 0, r.stderr[-300:])
check("relay healthy after restore", wait_healthy(120))
bob.cmd("sync"); h = bob.cmd(f"history {cid}")
check("message in the backup is delivered after restore", "m3-in-backup" in h, h[:200])
a.cmd(f"send {conv2} m4-after-restore"); a.cmd("flush"); bob.cmd("sync")
h = bob.cmd(f"history {cid}")
check("new messages flow after restore (accounts, keys, sequencer survived)", "m4-after-restore" in h, h[:200])

# 4. upgrade: rebuilding and restarting the same version is a no-op migration; the relay must refuse a database from the future
dc("exec", "-T", "db", "psql", "-U", "cipher", "-d", "cipher", "-c", "INSERT INTO schema_migrations VALUES (999,'future','\\x00')")
dc("restart", "relay"); time.sleep(8)
st = subprocess.run(["docker", "inspect", "--format", "{{.State.Running}} {{.RestartCount}}", "cipher-relay-1"], capture_output=True, text=True).stdout
logs = subprocess.run(["docker", "logs", "--tail", "5", "cipher-relay-1"], capture_output=True, text=True)
check("relay refuses to start on a database newer than itself (no silent downgrade)", "refusing to start" in (logs.stdout + logs.stderr), logs.stdout + logs.stderr)
dc("exec", "-T", "db", "psql", "-U", "cipher", "-d", "cipher", "-c", "DELETE FROM schema_migrations WHERE version=999")
dc("restart", "relay"); check("relay starts again once the database is compatible", wait_healthy(120))

a.close(); bob.close()
bad = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(bad)}/{len(results)} checks passed")
sys.exit(1 if bad else 0)
