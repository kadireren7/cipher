#!/usr/bin/env python3
"""Adversarial TLS servers for testing the ANDROID client's transport (final review, phase 9). DEV TOOL ONLY.

Listens on 0.0.0.0 (the emulator reaches the host as 10.0.2.2). Uses the throwaway test CA from scripts/make-test-ca.sh.
  9501 good      valid cert (SAN 10.0.2.2) signed by the trusted test CA, TLS 1.2 AND 1.3 offered; GET /version -> negotiated version,
                 GET /hits?port=N -> how many connections server N received
  9502 tls12     valid cert, TLS 1.2 ONLY            -> client must refuse (downgrade)
  9503 expired   cert whose validity ended in the past -> client must refuse
  9504 wronghost cert for other.example (valid CA)      -> client must refuse (hostname mismatch)
  9505 untrusted valid-looking cert from an UNTRUSTED CA (what a MITM proxy presents) -> client must refuse
  9506 redirect  good TLS, answers 302 Location: http://10.0.2.2:9507/ -> client must NOT follow
  9507 plain     plain HTTP; counts hits                -> client must never connect
"""
import datetime, http.server, json, os, socket, ssl, sys, tempfile, threading
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CA_DIR = os.path.join(ROOT, "android/build/test-ca")
ca_key = serialization.load_pem_private_key(open(f"{CA_DIR}/ca.key", "rb").read(), None)
ca_cert = x509.load_pem_x509_certificate(open(f"{CA_DIR}/ca.pem", "rb").read())
tmp = tempfile.mkdtemp(prefix="adv-tls-")
HITS = {}

def make_cert(name, san_dns=(), san_ip=(), not_before=None, not_after=None, issuer_key=ca_key, issuer_cert=ca_cert):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    sans = [x509.DNSName(d) for d in san_dns] + [x509.IPAddress(__import__("ipaddress").ip_address(i)) for i in san_ip]
    b = (x509.CertificateBuilder().subject_name(subject)
         .issuer_name(issuer_cert.subject if issuer_cert else subject)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(not_before or now - datetime.timedelta(days=1))
         .not_valid_after(not_after or now + datetime.timedelta(days=20))
         .add_extension(x509.SubjectAlternativeName(sans), critical=False)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    cert = b.sign(issuer_key or key, hashes.SHA256())
    cpath, kpath = f"{tmp}/{name}.pem", f"{tmp}/{name}.key"
    open(cpath, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kpath, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cpath, kpath

def make_untrusted_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Evil MITM CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=20))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return key, cert

class H(http.server.BaseHTTPRequestHandler):
    port = 0
    mode = "good"
    def log_message(self, *a): pass
    def do_GET(self):
        HITS[self.port] = HITS.get(self.port, 0) + 1
        if self.mode == "redirect":
            self.send_response(302); self.send_header("Location", "http://10.0.2.2:9507/"); self.send_header("Content-Length", "0"); self.end_headers(); return
        body = b"ok"
        if self.path.startswith("/version"):
            body = self.connection.version().encode()
        elif self.path.startswith("/hits"):
            p = int(self.path.split("port=")[1]); body = str(HITS.get(p, 0)).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    do_POST = do_GET

def serve(port, mode, cert=None, key=None, minv=None, maxv=None):
    handler = type(f"H{port}", (H,), {"port": port, "mode": mode})
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), handler)
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        if minv: ctx.minimum_version = minv
        if maxv: ctx.maximum_version = maxv
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    # failed handshakes must not kill the server
    orig = srv.get_request
    def get_request():
        s, a = orig()
        HITS[port] = HITS.get(port, 0) + 1 if not cert else HITS.get(port, 0)
        return s, a
    srv.get_request = get_request
    threading.Thread(target=srv.serve_forever, daemon=True).start()

now = datetime.datetime.now(datetime.timezone.utc)
good = make_cert("good", san_ip=["10.0.2.2", "127.0.0.1"], san_dns=["localhost"])
serve(9501, "good", *good, minv=ssl.TLSVersion.TLSv1_2, maxv=ssl.TLSVersion.TLSv1_3)
serve(9502, "tls12", *good, minv=ssl.TLSVersion.TLSv1_2, maxv=ssl.TLSVersion.TLSv1_2)
exp = make_cert("expired", san_ip=["10.0.2.2"], not_before=now - datetime.timedelta(days=30), not_after=now - datetime.timedelta(days=1))
serve(9503, "expired", *exp, minv=ssl.TLSVersion.TLSv1_3)
wh = make_cert("wronghost", san_dns=["other.example"])
serve(9504, "wronghost", *wh, minv=ssl.TLSVersion.TLSv1_3)
ukey, ucert = make_untrusted_ca()
un = make_cert("untrusted", san_ip=["10.0.2.2"], issuer_key=ukey, issuer_cert=ucert)
serve(9505, "untrusted", *un, minv=ssl.TLSVersion.TLSv1_3)
serve(9506, "redirect", *good, minv=ssl.TLSVersion.TLSv1_3)
serve(9507, "plain")
print("adversarial TLS servers up on 9501-9507", flush=True)
threading.Event().wait()
