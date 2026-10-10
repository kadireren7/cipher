#!/usr/bin/env python3
"""Upgrade/rollback acceptance test with REAL binaries on a REAL PostgreSQL, using an OLD client against a NEW relay.

  1. start the OLD relay (a previous release) on a fresh database, register two clients with the OLD client binary, queue a message for an offline client;
  2. stop it, start the NEW relay on the SAME database (migrations apply), and verify that the queued message is delivered, that new messages flow,
     and that the previously applied migrations kept their checksums;
  3. start the OLD relay again against the upgraded database: it must REFUSE (no in-place downgrade), leaving the data untouched.

Usage: scripts/test-upgrade.py OLD_RELAY NEW_RELAY OLD_CLIENT (peer example binary)    Needs: docker container `cipher-pg` (port 55432), openssl.
"""
import os, re, subprocess, sys, tempfile, time

OLD, NEW, PEER = sys.argv[1:4]
PORT = 19443
HOST = f"localhost:{PORT}"
DB = "upgrade_" + str(os.getpid())
tmp = tempfile.mkdtemp(prefix="cipher-upgrade-")
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""), flush=True)


def psql(sql, db="postgres"):
    return subprocess.run(["docker", "exec", "cipher-pg", "psql", "-U", "postgres", "-d", db, "-tAc", sql], capture_output=True, text=True).stdout.strip()


psql(f"CREATE DATABASE {DB}")
subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", f"{tmp}/k.pem", "-out", f"{tmp}/c.pem",
                "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], capture_output=True, check=True)
TOKEN = "upgrade-test-registration-token-0123456789abcdef"
ENV = dict(os.environ, CIPHER_RELAY_AUDIENCE=HOST, CIPHER_RELAY_REGISTRATION_TOKEN=TOKEN, CIPHER_RELAY_PEPPER="upgrade-test-pepper-0123456789abcdef0123",
           CIPHER_RELAY_DATABASE_URL=f"postgres://postgres:devonly-not-a-secret@127.0.0.1:55432/{DB}", CIPHER_RELAY_LISTEN=f"127.0.0.1:{PORT}",
           CIPHER_RELAY_TLS_CERT=f"{tmp}/c.pem", CIPHER_RELAY_TLS_KEY=f"{tmp}/k.pem")


def start(binary, label):
    log = open(f"{tmp}/{label}.log", "w")
    p = subprocess.Popen([binary], env=ENV, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(60):
        time.sleep(0.5)
        if p.poll() is not None:
            return p, False
        if subprocess.run(["curl", "-sk", "-o", "/dev/null", f"https://127.0.0.1:{PORT}/v1/accounts/00000000000000000000000000000000/devices"], capture_output=True).returncode == 0:
            return p, True
    return p, False


class Peer:
    def __init__(self, d):
        self.p = subprocess.Popen([PEER, d, HOST, f"{tmp}/c.pem", "127.0.0.1"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def cmd(self, line):
        self.p.stdin.write(line + "\n"); self.p.stdin.flush()
        return self.p.stdout.readline().strip()


def hexid(s):
    m = re.search(r"[0-9a-f]{32}", s)
    return m.group(0) if m else None


old, ok = start(OLD, "old")
check("old relay starts on a fresh database", ok, open(f"{tmp}/old.log").read()[-300:])
before_versions = psql("SELECT version||':'||encode(checksum,'hex') FROM schema_migrations ORDER BY version", DB).split("\n")
a, b = Peer(tmp + "/a"), Peer(tmp + "/b")
for p in (a, b):
    p.cmd("provision")
check("two OLD clients register", "Ok" in a.cmd(f"register {TOKEN}") and "Ok" in b.cmd(f"register {TOKEN}"))
bid = re.search(r'cipher_id: "([^"]+)"', b.cmd("id")).group(1)
a.cmd(f"add {bid} bob")
conv = hexid(a.cmd(f"dm {hexid(a.cmd('contacts'))}"))
a.cmd(f"send {conv} sent-under-the-old-relay"); a.cmd("flush")
check("message queued for the offline client under the old relay", psql("SELECT count(*) FROM queue", DB) != "0")
old.terminate(); old.wait(timeout=20)

new, ok = start(NEW, "new")
check("new relay starts on the OLD database and migrates it", ok, open(f"{tmp}/new.log").read()[-300:])
after_versions = psql("SELECT version||':'||encode(checksum,'hex') FROM schema_migrations ORDER BY version", DB).split("\n")
check("previously applied migrations keep their checksums", after_versions[:len(before_versions)] == before_versions, f"{before_versions} vs {after_versions}")
check("new migrations were applied", len(after_versions) > len(before_versions), str(after_versions))
b.cmd("sync"); cid = hexid(b.cmd("convs")); b.cmd(f"accept {cid}")
check("the message queued under the OLD relay is delivered under the NEW one", "sent-under-the-old-relay" in b.cmd(f"history {cid}"))
a.cmd(f"send {conv} sent-under-the-new-relay"); a.cmd("flush"); b.cmd("sync")
check("an OLD client keeps working against the NEW relay", "sent-under-the-new-relay" in b.cmd(f"history {cid}"))
new.terminate(); new.wait(timeout=20)

counts_before = psql("SELECT (SELECT count(*) FROM devices)||','||(SELECT count(*) FROM schema_migrations)", DB)
old2, ok = start(OLD, "old2")
time.sleep(1)
check("the OLD relay refuses to start on the upgraded database (no downgrade)", old2.poll() is not None and not ok, "")
log = open(f"{tmp}/old2.log").read()
check("it says so and does not touch the data", "refusing to start" in log and psql("SELECT (SELECT count(*) FROM devices)||','||(SELECT count(*) FROM schema_migrations)", DB) == counts_before, log[-200:])
psql(f"DROP DATABASE {DB} WITH (FORCE)")
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
