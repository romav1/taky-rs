"""S-403 (T-31 part 1) integration harness: TLS / monitor / mgmt / process, Python taky vs taky-rs.

Every case starts the ORIGINAL Python taky (read-only source tree, `python -B`) and the `taky-rs` binary with
the same generated config + test PKI (Python on 127.0.0.6, Rust on 127.0.0.7), drives both with the same
probes (openssl s_client, python ssl, AF_UNIX mgmt client, signals) and compares the observable outcome.
A case passes when both targets match the expectation; a documented deviation (D-n) is checked explicitly.

Run (opt-in, not part of scripts/check.sh):  tools/integ/integ            (all groups, ~2-3 min)
                                             tools/integ/integ --only tls,mgmt
Env: TAKY_RS_BIN (default target/debug/taky-rs), S403_TMP (default /tmp/s403-integ; keep it short: AF_UNIX
paths must stay < 108 bytes), INTEG_LONG_DIR (parent for the long-socket-path case).
Results: $S403_TMP/results.json; exit 1 on any FAIL. Every started server is stopped (SIGTERM, then SIGKILL).
"""

import argparse
import datetime as dt
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
RS_ROOT = os.path.realpath(os.path.join(HERE, "..", ".."))
TAKY_SRC = os.environ.get("TAKY_SRC", os.path.realpath(os.path.join(RS_ROOT, "..", "taky")))
RS_BIN = os.environ.get("TAKY_RS_BIN", os.path.join(RS_ROOT, "target", "debug", "taky-rs"))
TMP = os.environ.get("S403_TMP", "/tmp/s403-integ")
PY = sys.executable
IP = {"py": "127.0.0.6", "rs": "127.0.0.7"}
TGTS = ("py", "rs")
TLS_PORT, PLAIN_PORT, MON_PORT = 18089, 18087, 18088
KEY_PW = "s403-secret"
PY_LAUNCH = 'import sys; sys.argv[0] = "taky"; from taky.cot.__main__ import main; main()'

RESULTS = []
SERVERS = []


# ----------------------------------------------------------------------------------------------- reporting
def rec(row, cid, desc, py, rs, ok, note="", open_q=None):
    """open_q: a divergence that is reported (D-n question / bug id) and awaits classification -> OPEN, not FAIL."""
    RESULTS.append({"row": row, "case": cid, "desc": desc, "py": py, "rs": rs, "ok": bool(ok) or bool(open_q),
                    "status": "PASS" if ok else ("OPEN" if open_q else "FAIL"), "note": note, "open": open_q})
    tag = "PASS" if ok else ("OPEN" if open_q else "FAIL")
    if open_q and not ok:
        note = f"{note} [open: {open_q}]"
    print(f"{tag:4} [{row}] {cid}: {desc} | py={py!r} rs={rs!r}{(' | ' + note) if note else ''}", flush=True)


def both(row, cid, desc, obs, want, note=""):
    """Both targets must equal `want`."""
    rec(row, cid, desc, obs["py"], obs["rs"], obs["py"] == want and obs["rs"] == want, note)


def same(row, cid, desc, obs, note=""):
    """Both targets must observe the same value."""
    rec(row, cid, desc, obs["py"], obs["rs"], obs["py"] == obs["rs"], note)


def expect(row, cid, desc, obs, py_want, rs_want, note):
    """Documented deviation: each target must show its own expected value."""
    rec(row, cid, desc, obs["py"], obs["rs"], obs["py"] == py_want and obs["rs"] == rs_want, note)


# ----------------------------------------------------------------------------------------------- PKI
def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write_key(path, key):
    with open(path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))


def _write_crt(path, crt):
    with open(path, "wb") as f:
        f.write(crt.public_bytes(serialization.Encoding.PEM))


class Pki:
    def __init__(self, d):
        self.d = d
        os.makedirs(d, exist_ok=True)
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.ca_key, self.ca = self._ca("S403 Test CA", now)
        self.fca_key, self.fca = self._ca("S403 Foreign CA", now)
        _write_crt(self.p("ca.crt"), self.ca)
        _write_crt(self.p("fca.crt"), self.fca)
        # server cert (SAN: both bench IPs)
        sk = _key()
        san = x509.SubjectAlternativeName([x509.DNSName("srv")] + [x509.IPAddress(__import__("ipaddress").ip_address(i))
                                                                  for i in IP.values()] +
                                          [x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))])
        crt = (self._builder("srv", sk, now - dt.timedelta(days=1), now + dt.timedelta(days=30), self.ca)
               .add_extension(san, False)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
               .sign(self.ca_key, hashes.SHA256()))
        _write_key(self.p("server.key"), sk)
        _write_crt(self.p("server.crt"), crt)
        with open(self.p("server-combined.pem"), "wb") as f:
            f.write(open(self.p("server.crt"), "rb").read() + open(self.p("server.key"), "rb").read())
        subprocess.run(["openssl", "pkcs8", "-topk8", "-v2", "aes-256-cbc", "-in", self.p("server.key"),
                        "-out", self.p("server-pkcs8enc.key"), "-passout", f"pass:{KEY_PW}"], check=True)
        subprocess.run(["openssl", "rsa", "-aes256", "-traditional", "-in", self.p("server.key"),
                        "-out", self.p("server-legacyenc.key"), "-passout", f"pass:{KEY_PW}"], check=True,
                       stderr=subprocess.DEVNULL)
        # clients
        self.serial = {}
        db = []
        for cn, nb, na, issuer in [
            ("alice", -1, 30, "ca"), ("bob", -1, 30, "ca"), ("carol", -1, 30, "ca"), ("dave", -1, 30, "ca"),
            ("erin", -1, 30, "ca"), ("expired", -10, -1, "ca"), ("notyet", 2, 30, "ca"), ("foreign", -1, 30, "fca"),
        ]:
            k = _key()
            ca, cak = (self.ca, self.ca_key) if issuer == "ca" else (self.fca, self.fca_key)
            subj = "alice" if cn == "foreign" else cn
            c = (self._builder(subj, k, now + dt.timedelta(days=nb), now + dt.timedelta(days=na), ca)
                 .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
                 .sign(cak, hashes.SHA256()))
            _write_key(self.p(f"{cn}.key"), k)
            _write_crt(self.p(f"{cn}.crt"), c)
            self.serial[cn] = c.serial_number
            if issuer == "ca":
                status = "R" if cn == "carol" else "V"
                nbf = c.not_valid_before_utc.replace(tzinfo=None).isoformat()
                naf = c.not_valid_after_utc.replace(tzinfo=None).isoformat()
                db.append(f"{status}\t{nbf}\t{naf}\t{c.serial_number:040x}\t{subj}\n")
        with open(self.p("cert-db.txt"), "w") as f:
            f.writelines(db)

    def p(self, n):
        return os.path.join(self.d, n)

    def _builder(self, cn, key, nb, na, issuer):
        return (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(issuer.subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(nb).not_valid_after(na)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True))

    def _ca(self, cn, now):
        k = _key()
        c = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(k.public_key())
             .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=2))
             .not_valid_after(now + dt.timedelta(days=60))
             .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
             .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True)
             .sign(k, hashes.SHA256()))
        return k, c


PKI = None


# ----------------------------------------------------------------------------------------------- sites/servers
def site(case, tgt, ssl_on=True, over=None, raw=None):
    """Write <TMP>/<case>/<tgt>/taky.conf. `over` = {section: {key: value|None}} (None = valueless key)."""
    d = os.path.join(TMP, case, tgt)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    shutil.copy(PKI.p("cert-db.txt"), os.path.join(d, "cert-db.txt"))
    conf = {
        "taky": {"hostname": "srv", "node_id": "TAKY", "bind_ip": IP[tgt], "root_dir": "."},
        "cot_server": {"port": str(TLS_PORT if ssl_on else PLAIN_PORT)},
        "ssl": {"enabled": "true" if ssl_on else "false", "client_cert_required": "true", "ca": PKI.p("ca.crt"),
                "cert": PKI.p("server.crt"), "key": PKI.p("server.key"), "cert_db": os.path.join(d, "cert-db.txt")},
    }
    for s, kv in (over or {}).items():
        for k, v in kv.items():
            if v == "<DEL>":
                conf.setdefault(s, {}).pop(k, None)
            else:
                conf.setdefault(s, {})[k] = v
    with open(os.path.join(d, "taky.conf"), "w") as f:
        if raw is not None:
            f.write(raw)
        else:
            for s, kv in conf.items():
                f.write(f"[{s}]\n")
                for k, v in kv.items():
                    f.write(f"{k}\n" if v is None else f"{k} = {v}\n")
                f.write("\n")
    return d


def cmd_for(tgt, args):
    if tgt == "py":
        return [PY, "-B", "-W", "ignore", "-c", PY_LAUNCH] + args
    return [RS_BIN] + args


def env_for(tgt):
    e = dict(os.environ)
    if tgt == "py":
        e["PYTHONPATH"] = TAKY_SRC
        e["PYTHONDONTWRITEBYTECODE"] = "1"
    return e


class Srv:
    def __init__(self, tgt, d, args=None):
        self.tgt, self.d = tgt, d
        self.args = args if args is not None else ["-c", "taky.conf", "-l", "debug"]
        self.out = os.path.join(d, f"{tgt}.stdout")
        self.err = os.path.join(d, f"{tgt}.stderr")
        self.p = None
        self.rc = None

    def start(self):
        self.p = subprocess.Popen(cmd_for(self.tgt, self.args), cwd=self.d, env=env_for(self.tgt),
                                  stdin=subprocess.DEVNULL, stdout=open(self.out, "wb"), stderr=open(self.err, "wb"),
                                  start_new_session=True)
        SERVERS.append(self)
        return self

    def alive(self):
        return self.p is not None and self.p.poll() is None

    def log(self):
        try:
            return open(self.err, encoding="utf8", errors="replace").read()
        except OSError:
            return ""

    def stdout(self):
        try:
            return open(self.out, encoding="utf8", errors="replace").read()
        except OSError:
            return ""

    def wait_exit(self, timeout=15):
        try:
            self.rc = self.p.wait(timeout)
        except subprocess.TimeoutExpired:
            self.rc = None
        return self.rc

    def stop(self, sig=signal.SIGTERM, timeout=12):
        if not self.alive():
            self.rc = self.p.poll() if self.p else None
            return self.rc
        self.p.send_signal(sig)
        rc = self.wait_exit(timeout)
        if rc is None:
            os.killpg(self.p.pid, signal.SIGKILL)
            self.p.wait(5)
            return "killed"
        return rc

    @property
    def sock(self):
        return os.path.join(self.d, "taky-mgmt.sock")


def stop_all():
    for s in SERVERS:
        try:
            if s.alive():
                os.killpg(s.p.pid, signal.SIGTERM)
                try:
                    s.p.wait(10)
                except subprocess.TimeoutExpired:
                    os.killpg(s.p.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def listening(ip, port, timeout=0.3):
    try:
        socket.create_connection((ip, port), timeout).close()
        return True
    except OSError:
        return False


def wait_listen(srvs, port, timeout=20):
    """Wait until every server listens on IP[tgt]:port; returns {tgt: bool}."""
    t0 = time.time()
    res = {s.tgt: False for s in srvs}
    while time.time() - t0 < timeout and not all(res.values()):
        for s in srvs:
            if not res[s.tgt]:
                res[s.tgt] = s.alive() and listening(IP[s.tgt], port)
        time.sleep(0.1)
    return res


def pair(case, port, **kw):
    """Start py+rs on the same config; return {tgt: Srv} (asserts both listen)."""
    srvs = {t: Srv(t, site(case, t, **kw)).start() for t in TGTS}
    ok = wait_listen(srvs.values(), port)
    if not all(ok.values()):
        for s in srvs.values():
            print(f"--- {s.tgt} log ---\n{s.log()[-2000:]}", flush=True)
    return srvs, ok


def stop_pair(row, case, srvs, check_sock=True):
    rcs = {t: s.stop() for t, s in srvs.items()}
    both(row, f"{case}.stop", "SIGTERM -> exit 0", rcs, 0)
    if check_sock:
        both(row, f"{case}.sock", "mgmt socket removed on stop", {t: os.path.exists(s.sock) for t, s in srvs.items()},
             False)


# ----------------------------------------------------------------------------------------------- clients
def now(off=0):
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=off)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def sa(uid, cs):
    return (f'<event version="2.0" uid="{uid}" type="a-f-G-U-C" how="m-g" time="{now()}" start="{now()}" '
            f'stale="{now(300)}"><point lat="1.0" lon="2.0" hae="0" ce="9999999" le="9999999"/>'
            f'<detail><contact callsign="{cs}" endpoint="*:-1:stcp"/><__group name="Cyan" role="Team Member"/>'
            '<takv device="qa" platform="qa" os="linux" version="1"/></detail></event>').encode()


class Peer:
    """A connected CoT client, polled from the calling thread only (an SSL object must not be shared between a
    reader thread and a writer thread: that loses records)."""

    def __init__(self, sock):
        self.s = sock
        self.buf = b""
        self.eof = False
        self.err = None
        self.s.settimeout(0.05)

    def pump(self, dur=0.0):
        t0 = time.time()
        while not self.eof:
            try:
                b = self.s.recv(65536)
                if not b:
                    self.eof = True
                    break
                self.buf += b
                continue
            except (socket.timeout, ssl.SSLWantReadError):
                pass
            except (OSError, ssl.SSLError) as e:
                self.err = str(e)
                self.eof = True
                break
            if time.time() - t0 >= dur:
                break

    def send(self, b):
        try:
            self.s.settimeout(5)
            self.s.sendall(b)
            return True
        except (OSError, ssl.SSLError):
            return False
        finally:
            try:
                self.s.settimeout(0.05)
            except OSError:
                pass

    def count(self, needle):
        self.pump(0.1)
        return self.buf.count(needle)

    def wait_for(self, needle, timeout=2.0, n=1):
        t0 = time.time()
        while time.time() - t0 < timeout and not self.eof:
            self.pump(0.05)
            if self.buf.count(needle) >= n:
                return True
        return self.buf.count(needle) >= n

    def wait_eof(self, timeout=3.0):
        self.pump(timeout)
        return self.eof

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def tls_ctx(cert=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.load_verify_locations(PKI.p("ca.crt"))
    if cert:
        c.load_cert_chain(PKI.p(f"{cert}.crt"), PKI.p(f"{cert}.key"))
    return c


def connect(tgt, port, cert=None, tls=True):
    s = socket.create_connection((IP[tgt], port), 5)
    if tls:
        s = tls_ctx(cert).wrap_socket(s)
    return Peer(s)


def try_connect(tgt, port, cert=None, tls=True):
    try:
        return connect(tgt, port, cert, tls)
    except (OSError, ssl.SSLError):
        return None


def sclient(tgt, port, flags, cert=None, payload=b"", hold=1.5):
    cmd = ["openssl", "s_client", "-connect", f"{IP[tgt]}:{port}", "-CAfile", PKI.p("ca.crt"), "-brief"] + flags
    if cert:
        cmd += ["-cert", PKI.p(f"{cert}.crt"), "-key", PKI.p(f"{cert}.key")]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        p.stdin.write(payload)
        p.stdin.flush()
    except OSError:
        pass
    t0 = time.time()
    while time.time() - t0 < hold and p.poll() is None:
        time.sleep(0.05)
    closed = p.poll() is not None
    if not closed:
        try:
            p.stdin.close()
        except OSError:
            pass
    try:
        out, err = p.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
    err = err.decode(errors="replace")
    m = re.search(r"Protocol version: (\S+)", err)
    c = re.search(r"Ciphersuite: (\S+)", err)
    alerts = sorted(set(re.findall(r"(?:alert|tlsv13 alert) ([a-z ]+?)(?::|\n|$)", err)))
    return {"est": "CONNECTION ESTABLISHED" in err, "closed": closed, "proto": m.group(1) if m else None,
            "cipher": c.group(1) if c else None, "alerts": alerts}


def verdict(r, delivered):
    if not r["est"]:
        return "reject-hs"
    if r["closed"] and not delivered:
        return "reject-after"
    if not r["closed"] and delivered:
        return "accept"
    return f"mixed(closed={r['closed']},delivered={delivered})"


def mgmt(path, chunks, n_replies, timeout=2.0, gap=0.15):
    """Send chunks over the AF_UNIX mgmt socket; return (replies, closed_by_server)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
    except OSError as e:
        return ([f"<connect error: {e.__class__.__name__}>"], True)
    buf, closed = b"", False
    try:
        for ch in chunks:
            s.sendall(ch)
            time.sleep(gap)
        t0 = time.time()
        while buf.count(b"\0") < n_replies and time.time() - t0 < timeout:
            try:
                b = s.recv(65536)
            except socket.timeout:
                break
            if not b:
                closed = True
                break
            buf += b
    except OSError:
        closed = True
    finally:
        s.close()
    parts = buf.split(b"\0")
    return ([p.decode(errors="replace") for p in parts[:-1]], closed)


def norm_status(txt, tgt):
    """Normalize a status reply: floats -> type names, bench IP -> <ip>."""
    try:
        j = json.loads(txt)
    except ValueError:
        return txt
    j["uptime"] = type(j.get("uptime")).__name__
    for c in j.get("clients", []):
        c["connected"] = type(c.get("connected")).__name__
        c["last_rx"] = type(c.get("last_rx")).__name__ if c.get("last_rx") else c.get("last_rx")
        if c.get("ip") == IP[tgt]:
            c["ip"] = "<ip>"
    return json.dumps(j)


def par(fn, *args):
    """Run fn(tgt, *args) for both targets in parallel threads; return {tgt: result}."""
    out = {}

    def run(t):
        out[t] = fn(t, *args)

    ths = [threading.Thread(target=run, args=(t,)) for t in TGTS]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    return out


# ----------------------------------------------------------------------------------------------- TLS
TLS_MATRIX = [
    # (id, s_client flags, cert, expected verdict)
    ("v12-valid", ["-tls1_2"], "bob", "accept"),
    ("v13-valid", ["-tls1_3"], "bob", "accept"),
    ("v12-nocert", ["-tls1_2"], None, "reject-hs"),
    ("v13-nocert", ["-tls1_3"], None, "reject-after"),
    ("v12-foreign", ["-tls1_2"], "foreign", "reject-hs"),
    ("v13-foreign", ["-tls1_3"], "foreign", "reject-after"),
    ("v12-expired", ["-tls1_2"], "expired", "reject-hs"),
    ("v13-expired", ["-tls1_3"], "expired", "reject-after"),
    ("v13-notyet", ["-tls1_3"], "notyet", "reject-after"),
    ("v12-revoked", ["-tls1_2"], "carol", "reject-after"),
    ("v13-revoked", ["-tls1_3"], "carol", "reject-after"),
    ("v12-ecdhe-rsa", ["-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256"], "bob", "accept"),
]
TLS_OPTIONAL = [
    ("opt-v12-nocert", ["-tls1_2"], None, "accept"),
    ("opt-v13-nocert", ["-tls1_3"], None, "accept"),
    ("opt-v13-valid", ["-tls1_3"], "bob", "accept"),
    ("opt-v12-foreign", ["-tls1_2"], "foreign", "reject-hs"),
    ("opt-v13-foreign", ["-tls1_3"], "foreign", "reject-after"),
    ("opt-v12-expired", ["-tls1_2"], "expired", "reject-hs"),
    ("opt-v13-revoked", ["-tls1_3"], "carol", "reject-after"),
]


def run_matrix(row, case, matrix, srvs):
    refs = {t: connect(t, TLS_PORT, "alice") for t in TGTS}
    for t in TGTS:
        refs[t].send(sa(f"REF-{case}", "REFCALL"))
    for cid, flags, cert, want in matrix:
        uid = f"PROBE-{case}-{cid}"

        def probe(t):
            r = sclient(t, TLS_PORT, flags, cert, sa(uid, cid))
            return verdict(r, refs[t].wait_for(uid.encode(), 0.5)), r

        res = par(probe)
        v = {t: res[t][0] for t in TGTS}
        detail = "; ".join(f"{t}:{res[t][1]['proto']}/{res[t][1]['cipher']}/alerts={res[t][1]['alerts']}"
                           for t in TGTS)
        both(row, f"{case}.{cid}", f"s_client {' '.join(flags)} cert={cert}", v, want, detail)
    for r in refs.values():
        r.close()


def g_tls():
    row = "TLS"
    # --- client_cert_required = true, ssl.ca = test CA
    srvs, ok = pair("tls-req", TLS_PORT)
    both(row, "tls-req.start", "server starts (TLS, cert required)", ok, True)
    run_matrix(row, "tls-req", TLS_MATRIX, srvs)

    # version / kex negatives (compat 1.1.16): record and compare
    for cid, flags in [("v11", ["-tls1_1", "-cipher", "DEFAULT@SECLEVEL=0"]),
                       ("v12-rsa-kex", ["-tls1_2", "-cipher", "AES128-GCM-SHA256"]),
                       ("v12-cbc-sha1", ["-tls1_2", "-cipher", "ECDHE-RSA-AES128-SHA"])]:
        res = par(lambda t: sclient(t, TLS_PORT, flags, "bob", b"", 0.8))
        v = {t: res[t]["est"] for t in TGTS}
        if cid == "v12-cbc-sha1":
            same(row, f"tls-req.{cid}", f"s_client {' '.join(flags)} established", v,
                 "compat 1.1.16 S; Python 3.13 default ciphers exclude SHA1 suites")
        else:
            both(row, f"tls-req.{cid}", f"s_client {' '.join(flags)} refused (no handshake)", v, False,
                 "compat 1.1.16: Python 3.13 ssl (min TLS1.2, ECDHE-only default ciphers) = rustls here")

    # python-ssl functional: two TLS clients broadcast + status + kickban + reconnect refused
    def func(t):
        a = connect(t, TLS_PORT, "alice")
        d = connect(t, TLS_PORT, "dave")
        a.send(sa("UID-ALICE", "ALICE"))
        d.send(sa("UID-DAVE", "DAVE"))
        got = a.wait_for(b"UID-DAVE") and d.wait_for(b"UID-ALICE")
        time.sleep(0.3)
        st, _ = mgmt(srvs[t].sock, [b'{"cmd": "status"}\0'], 1)
        kb, _ = mgmt(srvs[t].sock, [b'{"cmd": "kickban", "user": "dave"}\0'], 1)
        kicked = d.wait_eof(3)
        a_alive = not a.wait_eof(0.5)
        re_dave = sclient(t, TLS_PORT, ["-tls1_3"], "dave", sa("UID-DAVE2", "DAVE2"))
        db = open(os.path.join(srvs[t].d, "cert-db.txt")).read()
        a.close()
        return {"bcast": got, "status": norm_status(st[0] if st else "", t), "kickban": kb, "kicked": kicked,
                "alice_alive": a_alive, "reconnect": verdict(re_dave, False),
                "db_R": f"R\t" in db and f"{PKI.serial['dave']:040x}\tdave" in db and
                        any(ln.startswith("R\t") and ln.endswith("\tdave") for ln in db.splitlines())}

    f = par(func)
    both(row, "tls-req.bcast", "two TLS clients (python ssl) broadcast", {t: f[t]["bcast"] for t in TGTS}, True)
    same(row, "tls-req.status", "mgmt status with 2 identified TLS clients (normalized)",
         {t: f[t]["status"] for t in TGTS})
    both(row, "tls-req.kickban", "kickban dave -> revoked_sns = [serial]", {t: f[t]["kickban"] for t in TGTS},
         [json.dumps({"revoked_sns": [PKI.serial["dave"]]})])
    both(row, "tls-req.kicked", "kicked peer gets EOF, other peer stays",
         {t: (f[t]["kicked"], f[t]["alice_alive"]) for t in TGTS}, (True, True))
    both(row, "tls-req.reban", "revoked dave reconnect -> closed after handshake", {t: f[t]["reconnect"] for t in TGTS},
         "reject-after")
    both(row, "tls-req.certdb", "cert-db line for dave rewritten with R", {t: f[t]["db_R"] for t in TGTS}, True)

    # kickban request without "user" must not disable the cert-db (ban-on-connect / later kickban)
    def nouser(t):
        r0 = mgmt(srvs[t].sock, [b'{"cmd": "kickban"}\0'], 1)[0]
        r1 = mgmt(srvs[t].sock, [b'{"cmd": "kickban", "user": null}\0'], 1)[0]
        carol = verdict(sclient(t, TLS_PORT, ["-tls1_3"], "carol", sa("UID-CAROL", "CAROL")), False)
        erin = mgmt(srvs[t].sock, [b'{"cmd": "kickban", "user": "erin"}\0'], 1)[0]
        return (r0, r1, carol, erin)

    both(row, "tls-req.kickban-nouser", "kickban w/o user, user=null -> []; then revoked carol still refused and "
         "kickban erin still revokes", par(nouser),
         (['{"revoked_sns": []}'], ['{"revoked_sns": []}'], "reject-after",
          [json.dumps({"revoked_sns": [PKI.serial["erin"]]})]),
         "bug: hub.rs kickban() takes cert_db before the user check (MSG-20261026-qa01-05 to dev01)")

    # handshake timeout: silent TCP client on the TLS port
    def silent(t):
        s = socket.create_connection((IP[t], TLS_PORT), 5)
        s.settimeout(20)
        t0 = time.time()
        try:
            s.recv(1)
        except OSError:
            pass
        el = time.time() - t0
        s.close()
        return el

    el = par(silent)
    rec(row, "tls-req.hs-timeout", "silent client closed by server after 10..12.5 s", round(el["py"], 1),
        round(el["rs"], 1), all(10.0 <= el[t] <= 12.5 for t in TGTS))
    logs = {t: "SSL Handshake timeout" in srvs[t].log() for t in TGTS}
    both(row, "tls-req.hs-timeout-log", "log 'SSL Handshake timeout'", logs, True)
    stop_pair(row, "tls-req", srvs)

    # --- client_cert_required = false
    srvs, ok = pair("tls-opt", TLS_PORT, over={"ssl": {"client_cert_required": "false"}})
    both(row, "tls-opt.start", "server starts (cert optional)", ok, True)
    run_matrix(row, "tls-opt", TLS_OPTIONAL, srvs)
    stop_pair(row, "tls-opt", srvs)

    # --- ssl.ca empty => system CAs (our CA untrusted)
    for case, req, matrix in [
        ("tls-noca-req", "true", [("valid", ["-tls1_3"], "bob", "reject-after"),
                                  ("v12-valid", ["-tls1_2"], "bob", "reject-hs")]),
        ("tls-noca-opt", "false", [("nocert", ["-tls1_3"], None, "accept"),
                                   ("v12-valid", ["-tls1_2"], "bob", "reject-hs")]),
    ]:
        srvs, ok = pair(case, TLS_PORT, over={"ssl": {"ca": "", "client_cert_required": req}})
        both(row, f"{case}.start", f"ssl.ca empty, client_cert_required={req}: starts (system CAs)", ok, True)
        if all(ok.values()):
            # the ref client of run_matrix needs a trusted cert: use per-probe delivery to a cert-less ref
            for cid, flags, cert, want in matrix:
                def probe(t):
                    ref = try_connect(t, TLS_PORT, None) if req == "false" else None
                    uid = f"PROBE-{case}-{cid}"
                    r = sclient(t, TLS_PORT, flags, cert, sa(uid, cid))
                    dl = ref.wait_for(uid.encode(), 0.5) if ref else (not r["closed"] and r["est"])
                    if ref:
                        ref.close()
                    return verdict(r, dl)
                both(row, f"{case}.{cid}", f"s_client {' '.join(flags)} cert={cert}", par(probe), want)
        stop_pair(row, case, srvs)

    # --- key variants
    for case, over, want_up in [
        ("tls-pkcs8enc", {"ssl": {"key": PKI.p("server-pkcs8enc.key"), "key_pw": KEY_PW}}, True),
        ("tls-legacyenc", {"ssl": {"key": PKI.p("server-legacyenc.key"), "key_pw": KEY_PW}}, True),
        ("tls-keyincrt", {"ssl": {"cert": PKI.p("server-combined.pem"), "key": None}}, True),
        ("tls-badpw", {"ssl": {"key": PKI.p("server-pkcs8enc.key"), "key_pw": "wrong"}}, False),
        ("tls-nopw", {"ssl": {"key": PKI.p("server-legacyenc.key")}}, False),
        ("tls-nocrt", {"ssl": {"cert": PKI.p("missing.crt")}}, False),
    ]:
        srvs = {t: Srv(t, site(case, t, over=over)).start() for t in TGTS}
        if want_up:
            ok = wait_listen(srvs.values(), TLS_PORT)
            both(row, f"{case}.start", "server starts", ok, True)
            v = par(lambda t: verdict(sclient(t, TLS_PORT, ["-tls1_3"], "bob"), True))
            both(row, f"{case}.hs", "valid client handshake (TLS1.3) accepted", v, "accept")
            stop_pair(row, case, srvs)
        else:
            rcs = {t: srvs[t].wait_exit(15) for t in TGTS}
            both(row, f"{case}.exit", "startup fails with exit 1", rcs, 1)
            msg = {t: "Unable to start COTServer" in srvs[t].log() for t in TGTS}
            both(row, f"{case}.msg", "ERROR 'Unable to start COTServer'", msg, True)
            both(row, f"{case}.sock", "no mgmt socket left", {t: os.path.exists(srvs[t].sock) for t in TGTS}, False)
            for t in TGTS:
                srvs[t].stop()

    # `key =` (empty string) instead of valueless `key`: Python passes keyfile="" to load_cert_chain
    case = "tls-keyempty"
    srvs = {t: Srv(t, site(case, t, over={"ssl": {"cert": PKI.p("server-combined.pem"), "key": ""}})).start()
            for t in TGTS}
    ok = wait_listen(srvs.values(), TLS_PORT, 8)
    rcs = {t: (srvs[t].p.poll() if not ok[t] else "up") for t in TGTS}
    rec(row, f"{case}.start", "`key =` (empty) with key inside cert file", rcs["py"], rcs["rs"], rcs["py"] == rcs["rs"],
        "Python: keyfile='' -> load_cert_chain error, exit 1; Rust treats empty as unset and starts",
        open_q="MSG-20261026-qa01-06 (an01 D-n question)")
    for t in TGTS:
        srvs[t].stop()


# ----------------------------------------------------------------------------------------------- monitor
def g_monitor():
    row = "Monitor"
    srvs = {}
    for t in TGTS:
        srvs[t] = Srv(t, site("mon", t, over={"cot_server": {"mon_ip": IP[t], "mon_port": str(MON_PORT)}})).start()
    ok = wait_listen(srvs.values(), TLS_PORT)
    okm = wait_listen(srvs.values(), MON_PORT)
    both(row, "mon.listen", "SSL + mon_ip: monitor port listens", okm, True)

    def scen(t):
        a = connect(t, TLS_PORT, "alice")
        a.send(sa("UID-A", "ACALL"))
        time.sleep(0.3)
        m = connect(t, MON_PORT, tls=False)         # monitor: plain TCP, gets the replay
        replay = m.wait_for(b"UID-A", 1.5)
        b = connect(t, TLS_PORT, "bob")
        b.send(sa("UID-B", "BCALL"))
        time.sleep(1.0)
        twice = m.count(b'uid="UID-B"')
        b_once = a.count(b'uid="UID-B"')
        m.send(sa("UID-MON", "MONCALL"))            # monitor event: routed as anonymous to the TLS clients
        routed = a.wait_for(b"UID-MON", 1.5) and b.wait_for(b"UID-MON", 1.5)
        time.sleep(0.3)
        st, _ = mgmt(srvs[t].sock, [b'{"cmd": "status"}\0'], 1)
        js = json.loads(st[0]) if st else {}
        anon = [c for c in js.get("clients", []) if c.get("anonymous")]
        tls_on_mon = sclient(t, MON_PORT, ["-tls1_3"], "bob", b"", 0.8)["est"]
        for p in (a, b, m):
            p.close()
        return {"replay": replay, "twice": twice, "once": b_once, "routed": routed,
                "num_clients": js.get("num_clients"), "anon": len(anon), "tls_on_mon": tls_on_mon}

    r = par(scen)
    both(row, "mon.replay", "monitor gets the persisted replay on connect", {t: r[t]["replay"] for t in TGTS}, True)
    both(row, "mon.double", "monitor receives a TLS client's broadcast twice (Q6)", {t: r[t]["twice"] for t in TGTS}, 2)
    both(row, "mon.once", "TLS peer receives it once", {t: r[t]["once"] for t in TGTS}, 1)
    both(row, "mon.routed", "monitor's own event is routed to TLS clients", {t: r[t]["routed"] for t in TGTS}, True)
    same(row, "mon.status", "status: num_clients / anonymous count with a monitor client",
         {t: (r[t]["num_clients"], r[t]["anon"]) for t in TGTS})
    both(row, "mon.plain", "monitor port is plain TCP (TLS handshake fails)", {t: r[t]["tls_on_mon"] for t in TGTS},
         False)
    stop_pair(row, "mon", srvs)

    # SSL without mon_ip -> no monitor; plain mode with mon_ip -> no monitor
    for case, ssl_on, over, port in [
        ("mon-noip", True, {"cot_server": {"mon_port": str(MON_PORT)}}, TLS_PORT),
        ("mon-plain", False, {"cot_server": {"mon_ip": "<IP>", "mon_port": str(MON_PORT)}}, PLAIN_PORT),
    ]:
        srvs = {}
        for t in TGTS:
            o = json.loads(json.dumps(over).replace("<IP>", IP[t]))
            srvs[t] = Srv(t, site(case, t, ssl_on=ssl_on, over=o)).start()
        wait_listen(srvs.values(), port)
        time.sleep(0.3)
        both(row, f"{case}.nolisten", "monitor port NOT listening", {t: listening(IP[t], MON_PORT) for t in TGTS},
             False)
        stop_pair(row, case, srvs)


# ----------------------------------------------------------------------------------------------- mgmt
def g_mgmt():
    row = "Mgmt"
    srvs, ok = pair("mgmt", PLAIN_PORT, ssl_on=False)
    both(row, "mgmt.start", "plain server starts", ok, True)
    cases = [
        ("multi", [b'{"cmd": "ping"}\0{"cmd": "status"}\0{"cmd": "ping"}\0'], 3),
        ("split", [b'{"cmd": "pi', b'ng"}', b'\0'], 1),
        ("unterminated", [b'{"cmd": "ping"}'], 1),
        ("unknown", [b'{"cmd": "nope"}\0'], 1),
        ("nocmd", [b'{}\0'], 1),
        ("cmd-list", [b'{"cmd": [1, "a"]}\0'], 1),
        ("unicode", [b'{"cmd": "\\u00e9t\xc3\xa9"}\0'], 1),
        ("kickban-nouser", [b'{"cmd": "kickban"}\0'], 1),
        ("kickban-unknown", [b'{"cmd": "kickban", "user": "nobody"}\0'], 1),
    ]
    for cid, chunks, n in cases:
        r = par(lambda t: mgmt(srvs[t].sock, chunks, n, timeout=1.0))
        v = {t: ([norm_status(x, t) if x.startswith('{"uptime"') else x for x in r[t][0]], r[t][1]) for t in TGTS}
        same(row, f"mgmt.{cid}", f"request {chunks!r}", v)
    # D-24: invalid JSON / UTF-8 -> {"error": <text>} (text may differ), connection stays usable
    for cid, chunk in [("badjson", b'{not json\0'), ("badutf8", b'\xff\xfe\0'), ("empty", b'\0')]:
        r = par(lambda t: mgmt(srvs[t].sock, [chunk, b'{"cmd": "ping"}\0'], 2, timeout=1.0))
        shape = {t: (len(r[t][0]) == 2 and r[t][0][0].startswith('{"error": "') and r[t][0][1] == '{"pong": "taky"}')
                 for t in TGTS}
        both(row, f"mgmt.{cid}", f"{chunk!r} -> error reply, then ping works", shape, True,
             "texts: " + " || ".join(f"{t}={r[t][0][:1]}" for t in TGTS) + " (D-24: text may differ)")
    # plain-mode kickban revokes in cert-db (N-1 / compat 1.1.17)
    r = par(lambda t: mgmt(srvs[t].sock, [b'{"cmd": "kickban", "user": "bob"}\0'], 1)[0])
    both(row, "mgmt.plain-kickban", "plain mode (after a user-less kickban): kickban bob -> serial returned", r,
         [json.dumps({"revoked_sns": [PKI.serial["bob"]]})])
    # takyctl status of both versions against both servers
    ctl_rs = os.path.join(os.path.dirname(RS_BIN), "takyctl-rs")
    for who, cmd in [("py-takyctl", [PY, "-B", "-W", "ignore", "-c",
                                     'import sys; sys.argv[0]="takyctl"; from taky.cli.__main__ import main; '
                                     'sys.exit(main())']),
                     ("takyctl-rs", [ctl_rs])]:
        def st(t):
            p = subprocess.run(cmd + ["status", "-j", "-U", srvs[t].sock], capture_output=True, env=env_for("py"),
                               cwd=srvs[t].d, timeout=10)
            try:
                j = json.loads(p.stdout)
                return (p.returncode, sorted(j.keys()), j.get("num_clients"))
            except ValueError:
                return (p.returncode, p.stdout[:80], p.stderr[-200:])
        both(row, f"mgmt.{who}-status", f"{who} status -j", par(st), (0, ["clients", "num_clients", "uptime"], 0))

    # D-9: an open (idle) mgmt connection does not block CoT traffic in Rust; Python blackholes
    def d9(t):
        a = connect(t, PLAIN_PORT, tls=False)
        b = connect(t, PLAIN_PORT, tls=False)
        m = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        m.connect(srvs[t].sock)
        time.sleep(0.3)
        a.send(sa("UID-D9", "D9CALL"))
        got = b.wait_for(b"UID-D9", 2.0)
        m.close()
        late = b.wait_for(b"UID-D9", 2.0)
        a.close()
        b.close()
        return (got, late)

    expect(row, "mgmt.D-9", "CoT delivery while a mgmt connection is open (delivered, delivered after close)",
           par(d9), (False, False), (True, True),
           "D-9 (compat 1.1.14): Python blackholes CoT while a mgmt client is connected")
    # D-10 last (it crashes Python): non-object JSON
    r = par(lambda t: mgmt(srvs[t].sock, [b'[1, 2]\0'], 1, timeout=1.5))
    time.sleep(1.0)
    alive = {t: srvs[t].alive() for t in TGTS}
    expect(row, "mgmt.D-10", "non-object JSON: (reply, server alive)", {t: (r[t][0], alive[t]) for t in TGTS},
           ([], False), (['{"error": "Invalid cmd: None"}'], True),
           "D-10 (compat 1.4.13): Python AttributeError -> server exits")
    pyrc = srvs["py"].wait_exit(5)
    rec(row, "mgmt.D-10-rc", "Python exit code after the crash (informative)", pyrc, None, pyrc == 1)
    rcs = {t: srvs[t].stop() for t in TGTS}
    rec(row, "mgmt.stop", "Rust SIGTERM -> exit 0", rcs["py"], rcs["rs"], rcs["rs"] == 0)

    # already running + socket kept for the first instance
    srvs, ok = pair("mgmt-run", PLAIN_PORT, ssl_on=False)
    second = {t: Srv(t, srvs[t].d, ["-c", "taky.conf", "-l", "info"]) for t in TGTS}
    for t in TGTS:
        second[t].err = os.path.join(srvs[t].d, f"{t}.second.stderr")
        second[t].out = os.path.join(srvs[t].d, f"{t}.second.stdout")
        second[t].start()
    rcs = {t: second[t].wait_exit(15) for t in TGTS}
    both(row, "mgmt.already-running", "second instance exits 1", rcs, 1)
    both(row, "mgmt.already-running-msg", "'Taky already appears to be running via <sock>'",
         {t: "Taky already appears to be running via" in second[t].log() for t in TGTS}, True)
    both(row, "mgmt.first-survives", "first instance still answers ping",
         {t: mgmt(srvs[t].sock, [b'{"cmd": "ping"}\0'], 1)[0] for t in TGTS}, ['{"pong": "taky"}'])
    stop_pair(row, "mgmt-run", srvs)

    # stale socket path: regular file, dangling symlink
    for case, mk in [("mgmt-stalefile", lambda p: open(p, "w").close()),
                     ("mgmt-dangling", lambda p: os.symlink("/nonexistent-s403-target", p))]:
        ds = {t: site(case, t, ssl_on=False) for t in TGTS}
        for t in TGTS:
            mk(os.path.join(ds[t], "taky-mgmt.sock"))
        srvs = {t: Srv(t, ds[t]).start() for t in TGTS}
        ok = wait_listen(srvs.values(), PLAIN_PORT)
        time.sleep(0.3)
        pong = {t: mgmt(srvs[t].sock, [b'{"cmd": "ping"}\0'], 1)[0] for t in TGTS}
        if case == "mgmt-stalefile":
            both(row, f"{case}", "stale regular file at socket path: taken over, ping works",
                 {t: (ok[t], pong[t]) for t in TGTS}, (True, ['{"pong": "taky"}']))
        else:
            v = {t: (ok[t], pong[t][:1]) for t in TGTS}
            rec(row, f"{case}", "dangling symlink at socket path: (CoT up, mgmt ping)", v["py"], v["rs"],
                v["py"] == v["rs"],
                "Python os.path.exists() follows the link (False) -> bind EADDRINUSE -> runs without mgmt; "
                "Rust symlink_metadata -> removes the link and binds", open_q="MSG-20261026-qa01-06 (an01 D-n question)")
        for t in TGTS:
            srvs[t].stop()

    # long socket path (> 107 bytes): server lives without mgmt
    long_parent = os.environ.get("INTEG_LONG_DIR", os.path.join(TMP, "L" * 60))
    long_root = {t: os.path.join(long_parent, ("r" * 50) + t) for t in TGTS}
    ds = {}
    for t in TGTS:
        os.makedirs(long_root[t], exist_ok=True)
        ds[t] = site("mgmt-long", t, ssl_on=False, over={"taky": {"root_dir": long_root[t]}})
    lens = {t: len(os.path.join(long_root[t], "taky-mgmt.sock")) for t in TGTS}
    srvs = {t: Srv(t, ds[t]).start() for t in TGTS}
    ok = wait_listen(srvs.values(), PLAIN_PORT)

    def cot(t):
        a = connect(t, PLAIN_PORT, tls=False)
        b = connect(t, PLAIN_PORT, tls=False)
        a.send(sa("UID-LONG", "LONG"))
        r = b.wait_for(b"UID-LONG", 2)
        a.close()
        b.close()
        return r

    both(row, "mgmt-long.cot", f"socket path {lens['py']} bytes: server runs, CoT works",
         {t: ok[t] and cot(t) for t in TGTS}, True)
    both(row, "mgmt-long.nosock", "no socket file created",
         {t: os.path.exists(os.path.join(long_root[t], "taky-mgmt.sock")) for t in TGTS}, False)
    rec(row, "mgmt-long.log", "ERROR logged about the management socket",
        "Unable to open management socket" in srvs["py"].log(), "management socket" in srvs["rs"].log().lower()
        or "mgmt" in srvs["rs"].log().lower(),
        "Unable to open management socket" in srvs["py"].log() and bool(
            re.search(r"ERROR:[^\n]*(mgmt|management)", srvs["rs"].log(), re.I)))
    rcs = {t: srvs[t].stop() for t in TGTS}
    both(row, "mgmt-long.stop", "SIGTERM -> exit 0", rcs, 0)
    shutil.rmtree(long_parent, ignore_errors=True)


# ----------------------------------------------------------------------------------------------- process
def run_once(t, d, args, timeout=15):
    try:
        p = subprocess.run(cmd_for(t, args), cwd=d, env=env_for(t), capture_output=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return None, "", "<timeout: still running>"
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


def g_process():
    row = "Process"
    d = {t: site("proc", t, ssl_on=False) for t in TGTS}
    r = {t: run_once(t, d[t], ["--version"]) for t in TGTS}
    rec(row, "proc.version", "--version: exit 0, '<prog> version <v>' on stdout", r["py"], r["rs"],
        all(r[t][0] == 0 and re.fullmatch(r"\S+ version \S+\n", r[t][1]) and r[t][2] == "" for t in TGTS),
        "value differs by design (G-3/R3)")
    for cid, args in [("bad-level", ["-l", "bogus"]), ("unknown-flag", ["--bogus"]), ("c-noarg", ["-c"]),
                      ("positional", ["extra"])]:
        r = {t: run_once(t, d[t], args) for t in TGTS}
        v = {t: (r[t][0], r[t][1] == "", "error:" in r[t][2]) for t in TGTS}
        both(row, f"proc.{cid}", f"{args}: (exit 2, empty stdout, 'error:' on stderr)", v,
             (2, True, True), "compat 1.4.7: clap texts differ; only code + stream compared || " +
             " || ".join(f"{t}: {[x for x in r[t][2].splitlines() if 'error' in x][:1]}" for t in TGTS))
    r = {t: run_once(t, d[t], ["-c", d[t]]) for t in TGTS}
    v = {t: (r[t][0], f"Unable to load config file: '{d[t]}'" in r[t][2]) for t in TGTS}
    both(row, "proc.c-dir", "-c <directory>: exit 2 'Unable to load config file'", v, (2, True))

    # ParsingError (incl. MissingSectionHeaderError): identical text
    for cid, text in [("no-section", "garbage\n[taky]\n"), ("parse-error", "[taky]\nbind_ip = x\n= value\n  \n")]:
        for t in TGTS:
            open(os.path.join(d[t], "bad.conf"), "w").write(text)
        r = {t: run_once(t, d[t], ["-c", "bad.conf"]) for t in TGTS}
        lines = {t: [ln for ln in r[t][2].splitlines() if not ln.startswith("INFO:")] for t in TGTS}
        rec(row, f"proc.{cid}", f"{text!r}: exit 1, same 'Configuration file error' text",
            (r["py"][0], lines["py"]), (r["rs"][0], lines["rs"]),
            r["py"][0] == r["rs"][0] == 1 and lines["py"] == lines["rs"] and
            any("Configuration file error" in x for x in lines["rs"]))
    # ValueError / Duplicate*: D-13 (traceback vs message), exit 1 both
    for cid, text, needle in [
        ("bad-port", "[cot_server]\nport = abc\n", "Invalid port: abc"),
        ("port-65535", "[cot_server]\nport = 65535\n", "Invalid port: 65535"),
        ("bad-ttl", "[cot_server]\nmax_persist_ttl = x\n", "Invalid max_persist_ttl: x"),
        ("dup-option", "[cot_server]\nport = 1\nport = 2\n", "already exists"),
        ("dup-section", "[taky]\n[taky]\n", "already exists"),
        ("dup-empty-key", "[taky]\n: x\n=y\n", "option '' in section 'taky' already exists"),
        ("bad-bool", "[ssl]\nenabled = maybe\n", "Not a boolean: maybe"),
    ]:
        for t in TGTS:
            open(os.path.join(d[t], f"{cid}.conf"), "w").write(text)
        r = {t: run_once(t, d[t], ["-c", f"{cid}.conf"]) for t in TGTS}
        v = {t: (r[t][0], needle in r[t][2]) for t in TGTS}
        tb = {t: "Traceback" in r[t][2] for t in TGTS}
        both(row, f"proc.{cid}", f"{text.strip()!r}: (exit 1, message contains {needle!r})", v, (1, True),
             f"traceback py={tb['py']} rs={tb['rs']} (D-13: Rust prints a message, no traceback)")
        if tb["rs"]:
            rec(row, f"proc.{cid}-notb", "Rust: no traceback", None, True, False)

    # -c /nonexistent (QUIRK: defaults) and no -c with ./taky.conf present; sequential (defaults bind 0.0.0.0:8087)
    for t in TGTS:
        dd = os.path.join(TMP, "proc-nonex", t)
        shutil.rmtree(dd, ignore_errors=True)
        os.makedirs(dd)
        for cid, args in [("c-nonexistent", ["-c", "/nonexistent/taky.conf", "-l", "debug"]),
                          ("no-c-no-conf", ["-l", "debug"])]:
            if listening("127.0.0.1", 8087):
                rec(row, f"proc.{cid}", "port 8087 busy before the test", t, None, False)
                continue
            s = Srv(t, dd, args)
            s.err = os.path.join(dd, f"{cid}.stderr")
            s.out = os.path.join(dd, f"{cid}.stdout")
            s.start()
            t0 = time.time()
            while time.time() - t0 < 15 and not listening("127.0.0.1", 8087):
                time.sleep(0.1)
            up = listening("127.0.0.1", 8087)
            sockp = os.path.exists(os.path.join(dd, "taky-mgmt.sock"))
            rc = s.stop()
            log = s.log()
            okk = up and sockp and rc == 0 and (t == "py" or cid != "c-nonexistent" or "WARNING" in log)
            RESULTS.append({"row": row, "case": f"proc.{cid}", "tgt": t, "obs": (up, sockp, rc),
                            "warn": "WARNING" in log, "ok": okk,
                            "desc": f"{args}: defaults (plain 0.0.0.0:8087, mgmt in cwd), SIGTERM rc 0"})
            print(f"{'PASS' if okk else 'FAIL'} [{row}] proc.{cid} {t}: up={up} sock={sockp} "
                  f"rc={rc} warning_logged={'WARNING' in log}", flush=True)
    # ./taky.conf lookup
    srvs = {}
    for t in TGTS:
        srvs[t] = Srv(t, d[t], ["-l", "info"]).start()
    ok = wait_listen(srvs.values(), PLAIN_PORT)
    both(row, "proc.cwd-conf", "no -c, ./taky.conf present -> used ('Assuming')", {t: ok[t] and "Assuming" in
                                                                                   srvs[t].log() for t in TGTS}, True)
    stop_pair(row, "proc.cwd-conf", srvs)

    # signals
    def sig_case(t, sigs, debug):
        dd = site(f"proc-sig{'d' if debug else ''}{sigs[0].name[-4:].lower()}", t, ssl_on=False)
        s = Srv(t, dd, ["-c", "taky.conf", "-l", "debug"] + (["-d"] if debug else [])).start()
        up = wait_listen([s], PLAIN_PORT)[t]
        a = connect(t, PLAIN_PORT, tls=False)
        out = []
        for sg in sigs[:-1]:
            s.p.send_signal(sg)
            time.sleep(1.0)
            out.append(s.alive())
        b = connect(t, PLAIN_PORT, tls=False)
        a.send(sa("UID-SIG", "SIG"))
        works = b.wait_for(b"UID-SIG", 2)
        rc = s.stop(sigs[-1])
        eof = a.wait_eof(2)
        return {"up": up, "alive_after": out, "works": works, "rc": rc, "eof": eof,
                "sock": os.path.exists(s.sock), "log": s.log()[-3000:], "stdout": s.stdout()[-300:]}

    for cid, sigs, debug in [("sigterm", [signal.SIGTERM], False), ("sigint", [signal.SIGINT], False),
                             ("sigusr1", [signal.SIGUSR1, signal.SIGTERM], False),
                             ("d-sigusr1", [signal.SIGUSR1, signal.SIGTERM], True)]:
        r = par(sig_case, sigs, debug)
        v = {t: (r[t]["up"], r[t]["alive_after"], r[t]["works"], r[t]["rc"], r[t]["eof"], r[t]["sock"])
             for t in TGTS}
        note = ""
        if debug:
            note = (f"D-7: py log has 'PDB'={'PDB' in r['py']['log']}, stdout={r['py']['stdout']!r}; "
                    f"rs ignores")
        want = (True, [True] * (len(sigs) - 1), True, 0, True, False)
        desc = (f"{[s.name for s in sigs]}{' -d' if debug else ''}: "
                "(up, alive after non-final signals, CoT works, rc, clients EOF, socket left)")
        if debug:  # D-7: Python enters PDB (stdin /dev/null: the loop stays stopped in pdb); Rust ignores
            pyw = (True, [True], False, 0, True, False)
            rec(row, f"proc.{cid}", desc, v["py"], v["rs"], v["rs"] == want and v["py"] in (want, pyw), note)
        else:
            both(row, f"proc.{cid}", desc, v, want, note)
        if cid == "sigterm":
            both(row, "proc.sigterm-log", "'Got SIGTERM' + 'Stopped' logged",
                 {t: "Got SIGTERM" in r[t]["log"] and "Stopped" in r[t]["log"] for t in TGTS}, True)

    # startup errors: port busy, unresolvable bind_ip
    blockers = []
    for t in TGTS:
        b = socket.socket()
        b.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        b.bind((IP[t], PLAIN_PORT))
        b.listen()
        blockers.append(b)
    srvs = {t: Srv(t, site("proc-busy", t, ssl_on=False)).start() for t in TGTS}
    v = {t: srvs[t].wait_exit(15) for t in TGTS}
    both(row, "proc.port-busy", "CoT port busy: exit 1", v, 1)
    both(row, "proc.port-busy-msg", "ERROR 'Unable to start COTServer' + no socket left",
         {t: ("Unable to start COTServer" in srvs[t].log(), os.path.exists(srvs[t].sock)) for t in TGTS}, (True, False))
    for b in blockers:
        b.close()
    srvs = {t: Srv(t, site("proc-badip", t, ssl_on=False, over={"taky": {"bind_ip": "no-such-host.invalid"}})).start()
            for t in TGTS}
    v = {t: (srvs[t].wait_exit(20), "Unable to determine address info for bind_ip: no-such-host.invalid"
             in srvs[t].log()) for t in TGTS}
    both(row, "proc.bad-bind-ip", "unresolvable bind_ip: exit 1 + message", v, (1, True))
    # max_persist_ttl / mon_port normalisation errors only with SSL: mon_port invalid
    srvs = {t: Srv(t, site("proc-badmon", t, over={"cot_server": {"mon_port": "0"}})).start() for t in TGTS}
    v = {t: (srvs[t].wait_exit(15), "Invalid port: 0" in srvs[t].log()) for t in TGTS}
    both(row, "proc.bad-mon-port", "ssl on, mon_port = 0: exit 1, 'Invalid port: 0'", v, (1, True), "D-13 text")


GROUPS = {"tls": g_tls, "monitor": g_monitor, "mgmt": g_mgmt, "process": g_process}


def main():
    global PKI
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--only", default=",".join(GROUPS), help="comma list of groups: " + ",".join(GROUPS))
    a = ap.parse_args()
    if not os.access(RS_BIN, os.X_OK):
        sys.exit(f"taky-rs binary not found: {RS_BIN} (cargo build -p taky-server --bin taky-rs)")
    for ip in IP.values():
        for port in (TLS_PORT, PLAIN_PORT, MON_PORT):
            if listening(ip, port):
                sys.exit(f"{ip}:{port} is busy; stop the server using it first")
    shutil.rmtree(TMP, ignore_errors=True)
    os.makedirs(TMP)
    PKI = Pki(os.path.join(TMP, "pki"))
    t0 = time.time()
    try:
        for g in a.only.split(","):
            print(f"== {g}", flush=True)
            try:
                GROUPS[g]()
            except Exception as e:  # a crashed group is a FAIL, the others still run
                import traceback
                traceback.print_exc()
                rec(g, f"{g}.harness", "group raised", repr(e), None, False)
            finally:
                stop_all()
    finally:
        stop_all()
    fails = [r for r in RESULTS if not r["ok"]]
    with open(os.path.join(TMP, "results.json"), "w") as f:
        json.dump(RESULTS, f, indent=1, default=str)
    rows = {}
    for r in RESULTS:
        st = r.get("status") or ("PASS" if r["ok"] else "FAIL")
        rows.setdefault(r["row"], {"PASS": 0, "FAIL": 0, "OPEN": 0})[st] += 1
    print(f"\nSUMMARY ({time.time() - t0:.0f} s): " + ", ".join(
        f"{k}: {v['PASS']} pass / {v['FAIL']} fail / {v['OPEN']} open" for k, v in rows.items()))
    print(f"results: {os.path.join(TMP, 'results.json')}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
