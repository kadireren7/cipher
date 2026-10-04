#!/usr/bin/env python3
"""DEVELOPMENT / TEST TOOL ONLY. A minimal SOCKS5 proxy used as a TEST DOUBLE for the privacy route.

It is NOT an anonymity system, NOT shipped, NOT part of any release artifact and provides no privacy by itself. It exists so the client-side
plumbing (remote name resolution, fail-closed behaviour, what the relay sees as the connection source) can be exercised without a Tor network.
Real deployments use Tor (or another established SOCKS5 privacy network); see docs/ADR-PRIVACY-TRANSPORT.md.

  dev-socks-proxy.py --listen 0.0.0.0:1081 --map relay.cipher.test=127.0.0.1:8443 --map 10.0.2.2=127.0.0.1 --source 127.0.0.2 --log proxy.log --trace trace.log

* names are resolved HERE (only names given with --map are known; everything else is refused), which is what remote DNS means;
* outbound connections are made from --source, so the destination sees an address different from the client's;
* the log records (time, atyp, requested name, port, client address) — what a proxy operator could see — never any payload.
"""
import argparse, socket, struct, sys, threading, time

def recvn(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            raise EOFError
        b += d
    return b

TRACE = None
CONN = [0]

def pipe(a, b, direction="", conn=0):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            if TRACE:  # what a LINK OBSERVER sees: when, which way, how many (encrypted) bytes — never content
                TRACE.write(f"{time.time():.3f} {direction} {len(d)} {conn}\n")
                TRACE.flush()
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

def handle(c, addr, args, names, log):
    try:
        ver, n = recvn(c, 2)
        recvn(c, n)
        c.sendall(b"\x05\x00")
        ver, cmd, _, atyp = recvn(c, 4)
        if atyp == 1:
            host = socket.inet_ntoa(recvn(c, 4))
        elif atyp == 3:
            host = recvn(c, recvn(c, 1)[0]).decode("ascii", "replace")
        else:
            c.sendall(b"\x05\x08\x00\x01" + b"\0" * 6)
            return
        port = struct.unpack(">H", recvn(c, 2))[0]
        log.write(f"{time.time():.3f} atyp={atyp} name={host} port={port} client={addr[0]}\n")
        log.flush()
        target = names.get(host if atyp == 3 else f"{host}")
        if cmd != 1 or target is None:
            c.sendall(b"\x05\x04\x00\x01" + b"\0" * 6)  # host unreachable: unknown names are NOT resolved by any other means
            return
        up = socket.socket()
        up.bind((args.source, 0))
        up.connect((target[0], target[1] or port))
        c.sendall(b"\x05\x00\x00\x01" + b"\0" * 6)
        CONN[0] += 1
        n = CONN[0]
        t = threading.Thread(target=pipe, args=(up, c, "down", n), daemon=True)
        t.start()
        pipe(c, up, "up", n)
    except (EOFError, OSError):
        pass
    finally:
        c.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1:1080")
    ap.add_argument("--map", action="append", default=[], help="name=host:port (repeatable)")
    ap.add_argument("--source", default="127.0.0.2")
    ap.add_argument("--log", default="/dev/stderr")
    ap.add_argument("--trace", default=None, help="per-chunk (time, direction, bytes) trace: the link observer's view")
    args = ap.parse_args()
    names = {}
    for m in args.map:
        k, v = m.split("=")
        if ":" in v:
            h, p = v.rsplit(":", 1)
            names[k] = (h, int(p))
        else:
            names[k] = (v, None)  # keep the port the client asked for
    h, p = args.listen.rsplit(":", 1)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((h, int(p)))
    s.listen(64)
    global TRACE
    TRACE = open(args.trace, "a") if args.trace else None
    log = open(args.log, "a")
    while True:
        c, a = s.accept()
        threading.Thread(target=handle, args=(c, a, args, names, log), daemon=True).start()

if __name__ == "__main__":
    sys.exit(main())
