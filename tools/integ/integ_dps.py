"""S-404 (T-31 part 2) DPS integration group for tools/integ: Python taky_dps (gunicorn path) vs taky_dps-rs.

Both servers get the same taky.conf shape, test PKI (integ.Pki) and planted upload_path; Python binds 127.0.0.6,
Rust 127.0.0.7 (ports are fixed by the product: 8443 TLS / 8080 plain). The original is started exactly as
`python -m taky.dps` does it (taky.dps.__main__.main -> gunicorn StandaloneApplication, ClientCertificateWorker).
Groups: dps-start, dps-auth (endpoints x identity), dps-spoof, dps-http (HEAD/OPTIONS/Range/404/405),
dps-names (non-ASCII), dps-revoke (D-11), dps-large (opt-in size: INTEG_LARGE_MB, default 500; 0 = skip).
Called from integ.py (GROUPS "dps"): g_dps(h) where h is the running integ module (rec/both/expect, PKI, IP ...).
"""

import hashlib
import http.client
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import time
import traceback
import urllib.parse

DPS_TLS, DPS_PLAIN = 8443, 8080
HOST = "taky.example:8443"
PY_DPS = 'import sys; sys.argv[0] = "taky_dps"; from taky.dps.__main__ import main; main()'
H = None  # the integ module


def rs_dps_bin():
    return os.environ.get("TAKY_DPS_RS_BIN", os.path.join(H.RS_ROOT, "target", "debug", "taky_dps-rs"))


def non_loopback_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        ip = s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
    return None if ip.startswith("127.") else ip


# ----------------------------------------------------------------------------------------------- sites/servers
PLANT_DATA = bytes(range(256)) * 40  # 10240 bytes


def dps_site(case, tgt, ssl_on=True, over=None, plant=True):
    over = dict(over or {})
    base = {"dp_server": {"upload_path": "./dp-user"}}
    for s, kv in base.items():
        over.setdefault(s, {})
        for k, v in kv.items():
            over[s].setdefault(k, v)
    d = H.site(case, tgt, ssl_on=ssl_on, over=over)
    up = os.path.join(d, "dp-user")
    if plant and over["dp_server"]["upload_path"] == "./dp-user":
        os.makedirs(os.path.join(up, "meta"))
        with open(os.path.join(up, "C_pkg.zip"), "wb") as f:
            f.write(PLANT_DATA)
        meta = {"UID": "C_pkg.zip", "Name": "pkg.zip", "Hash": "h1", "PrimaryKey": 1,
                "SubmissionDateTime": "2030-01-01T00:00:00.000000Z", "SubmissionUser": "alice", "CreatorUid": "C",
                "Keywords": "kw", "MIMEType": "application/zip", "Size": len(PLANT_DATA), "Visibility": "public"}
        with open(os.path.join(up, "meta", "C_pkg.zip.json"), "w") as f:
            json.dump(meta, f)
        os.symlink("C_pkg.zip.json", os.path.join(up, "meta", "h1.json"))
    return d


def make_dsrv_class():
    class _DSrv(H.Srv):
        def start(self):
            if self.tgt == "py":
                cmd = [H.PY, "-B", "-W", "ignore", "-c", PY_DPS] + self.args
            else:
                cmd = [rs_dps_bin()] + self.args
            env = H.env_for(self.tgt)
            env.pop("TAKY_CONFIG", None)
            self.p = subprocess.Popen(cmd, cwd=self.d, env=env, stdin=subprocess.DEVNULL,
                                      stdout=open(self.out, "wb"), stderr=open(self.err, "wb"),
                                      start_new_session=True)
            H.SERVERS.append(self)
            return self

        def stop(self, sig=signal.SIGTERM, timeout=12):
            # gunicorn master + workers: stop the whole process group
            if not self.alive():
                self.rc = self.p.poll() if self.p else None
                return self.rc
            os.killpg(self.p.pid, sig)
            rc = self.wait_exit(timeout)
            if rc is None:
                os.killpg(self.p.pid, signal.SIGKILL)
                self.p.wait(5)
                return "killed"
            return rc
    return _DSrv


def start_pair(case, ssl_on=True, over=None, plant=True, wait=True):
    srvs = {t: DSRV(t, dps_site(case, t, ssl_on, over, plant), ["-c", "taky.conf", "-l", "info"]).start()
            for t in H.TGTS}
    ok = H.wait_listen(srvs.values(), DPS_TLS if ssl_on else DPS_PLAIN, 30) if wait else None
    return srvs, ok


def stop_pair(srvs):
    for s in srvs.values():
        s.stop()


DSRV = None


# ----------------------------------------------------------------------------------------------- client
def ctx_for(ident, tls_ver=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    if tls_ver:
        c.minimum_version = c.maximum_version = tls_ver
    if ident:
        c.load_cert_chain(H.PKI.p(f"{ident}.crt"), H.PKI.p(f"{ident}.key"))
    return c


def req(t, method, path, headers=(), body=None, ident=None, ssl_on=True, src=None, tls_ver=None, timeout=20,
        host=HOST):
    """One request on a fresh connection. Returns (status, {lower header: value}, body) or (tag, {}, detail)."""
    ip = H.IP[t]
    port = DPS_TLS if ssl_on else DPS_PLAIN
    sa = (src, 0) if src else None
    try:
        if ssl_on:
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx_for(ident, tls_ver),
                                               source_address=sa)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout, source_address=sa)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", host)
        hdrs = list(headers)
        names = {k.lower() for k, _ in hdrs}
        for k, v in hdrs:
            conn.putheader(k, v)
        if isinstance(body, (bytes, bytearray)):
            if "content-length" not in names:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
        elif body is not None:  # iterable, Content-Length given by caller
            conn.endheaders()
            for ch in body:
                conn.send(ch)
        else:
            if method in ("POST", "PUT"):
                conn.putheader("Content-Length", "0")
            conn.endheaders()
        r = conn.getresponse()
        data = r.read()
        hd = {k.lower(): v for k, v in r.getheaders()}
        conn.close()
        return r.status, hd, data
    except ssl.SSLError as e:
        return "tls-reject", {}, str(e)
    except (ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected) as e:
        return ("tls-reject" if ssl_on else "conn-error"), {}, repr(e)
    except OSError as e:
        return "conn-error", {}, repr(e)


def multipart(fields, boundary="integ-s404-boundary"):
    """fields: [(name, filename|None, bytes, content_type|None)] -> (content_type, body)."""
    out = b""
    for name, fn, data, ct in fields:
        out += f"--{boundary}\r\n".encode()
        disp = f'form-data; name="{name}"'
        if fn is not None:
            disp += f'; filename="{fn}"'
        out += f"Content-Disposition: {disp}\r\n".encode("utf8")
        if ct:
            out += f"Content-Type: {ct}\r\n".encode()
        out += b"\r\n" + data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return f"multipart/form-data; boundary={boundary}", out


VER_RE = re.compile(rb"taky-(rs-)?[0-9A-Za-z.+-]*?(?=[\"<\s]|$)")
TS_RE = re.compile(rb'"SubmissionDateTime": ?"[^"]*"')


def norm(body):
    b = VER_RE.sub(b"taky-$VERSION", body)
    return TS_RE.sub(b'"SubmissionDateTime":"$TS"', b)


def par(fn):
    return H.par(fn)


# ----------------------------------------------------------------------------------------------- endpoints
VCM = ("<videoConnections><feed><uid> F1 </uid><alias>cam \u00e9</alias><address>1.2.3.4</address></feed>"
       "</videoConnections>").encode("utf8")


def endpoints():
    ct, mp = multipart([("assetfile", "up.zip", b"UPLOADED-DATA", "application/zip")])
    return [
        ("root", "GET", "/", (), None, False),
        ("version", "GET", "/Marti/api/version", (), None, False),
        ("vconfig", "GET", "/Marti/api/version/config", (), None, False),
        ("endpoints", "GET", "/Marti/api/clientEndPoints", (), None, True),
        ("search", "GET", "/Marti/sync/search?keywords=missionpackage&tool=public", (), None, True),
        ("upload", "POST", "/Marti/sync/missionupload?hash=hU&filename=up&creatorUid=U", (("Content-Type", ct),),
         mp, True),
        ("content", "GET", "/Marti/sync/content?hash=h1&receiver=R", (), None, True),
        ("mquery", "GET", "/Marti/sync/missionquery?hash=h1", (), None, True),
        ("tool", "PUT", "/Marti/api/sync/metadata/h1/tool", (), b"public", True),
        ("vcm-post", "POST", "/Marti/vcm", (("Content-Type", "application/xml"),), VCM, True),
        ("vcm-get", "GET", "/Marti/vcm", (), None, True),
        ("tracks", "POST", "/Marti/TracksKML", (("Content-Type", "text/plain"),), b"kml-body", True),
        ("kml", "GET", "/Marti/ExportMissionKML", (), None, True),
    ]


def cell(row, cid, desc, r, want):
    """r = {tgt: (status, hdrs, body)}; want = {tgt: status}. On equal 200 also compare Content-Type + body."""
    st = {t: r[t][0] for t in H.TGTS}
    ok = all(st[t] == want[t] for t in H.TGTS)
    note = ""
    if ok and st["py"] == st["rs"] == 200:
        cp, cr = r["py"][1].get("content-type"), r["rs"][1].get("content-type")
        bp, br = norm(r["py"][2]), norm(r["rs"][2])
        if cp != cr or bp != br:
            ok = False
            note = f"200 but differs: ct py={cp!r} rs={cr!r}; body py={bp[:120]!r} rs={br[:120]!r}"
    dev = "" if want["py"] == want["rs"] else f" (expected py={want['py']} rs={want['rs']})"
    H.rec(row, cid, desc + dev, st["py"], st["rs"], ok, note)


# ----------------------------------------------------------------------------------------------- groups
def g_start():
    row = "DPS-start"
    for ssl_on, port in ((True, DPS_TLS), (False, DPS_PLAIN)):
        case = f"dps-up-{'tls' if ssl_on else 'plain'}"
        srvs, ok = start_pair(case, ssl_on)
        H.both(row, f"{case}.listen", f"listens on bind_ip:{port}", ok, True)
        other = DPS_PLAIN if ssl_on else DPS_TLS
        H.both(row, f"{case}.only", f"nothing on :{other}", {t: H.listening(H.IP[t], other) for t in H.TGTS}, False)
        r = par(lambda t: req(t, "GET", "/", ssl_on=ssl_on, ident="alice" if ssl_on else None,
                              headers=(("User-Agent", "integ-ua"),)))
        time.sleep(0.5)
        # access log: gunicorn '%(t)s "%(r)s" %(s)s %(b)s "%(a)s"' on stdout (compat 1.3.11, S)
        pat = re.compile(r'^\[\d\d/\w{3}/\d{4}:\d\d:\d\d:\d\d [+-]\d{4}\] "GET / HTTP/1.1" 200 13 "integ-ua"$', re.M)
        H.both(row, f"{case}.accesslog", "access line on stdout in gunicorn format",
               {t: bool(pat.search(srvs[t].stdout())) for t in H.TGTS}, True,
               "lines: " + " | ".join(f"{t}={(srvs[t].stdout().strip().splitlines() or [''])[-1][:90]!r}"
                                      for t in H.TGTS))
        rcs = {t: srvs[t].stop() for t in H.TGTS}
        H.rec(row, f"{case}.stop", "SIGTERM -> exits (py gunicorn 0, rs 0)", rcs["py"], rcs["rs"],
              rcs["rs"] == 0 and rcs["py"] == 0)

    # D-27: `ssl.key =` (empty) with the key inside the cert file
    case = "dps-keyempty"
    over = {"ssl": {"cert": H.PKI.p("server-combined.pem"), "key": ""}}
    srvs, _ = start_pair(case, True, over, wait=False)
    time.sleep(0.2)
    rc_rs = srvs["rs"].wait_exit(15)
    up_py = H.wait_listen([srvs["py"]], DPS_TLS, 20)["py"]
    hs_py = req("py", "GET", "/", ident="alice")[0] if up_py else "down"
    v = {"py": (up_py, hs_py), "rs": (rc_rs, "D-27" if "DPS TLS configuration" in srvs["rs"].log() else srvs["rs"].log()[-200:])}
    H.expect(row, f"{case}", "`key =` empty: py starts, every TLS conn fails; rs exit 1 at startup", v,
             (True, "tls-reject"), (1, "D-27"), "D-27 (an01 S-A06 Q1); rs log: "
             + (srvs["rs"].log().strip().splitlines() or [""])[-1][:140])
    stop_pair(srvs)

    # valueless `key`: key from the cert file (parity)
    case = "dps-keyincrt"
    srvs, ok = start_pair(case, True, {"ssl": {"cert": H.PKI.p("server-combined.pem"), "key": None}})
    r = par(lambda t: req(t, "GET", "/Marti/api/clientEndPoints", ident="alice")[0])
    H.both(row, case, "valueless `key`, key inside cert file: starts, cert client 200", r, 200)
    stop_pair(srvs)

    # D-20: encrypted key + key_pw (Python DPS does not pass key_pw to gunicorn)
    case = "dps-keypw"
    srvs, _ = start_pair(case, True, {"ssl": {"key": H.PKI.p("server-pkcs8enc.key"), "key_pw": H.KEY_PW}},
                         wait=False)
    ok = H.wait_listen(srvs.values(), DPS_TLS, 20)
    r = {t: (req(t, "GET", "/", ident="alice", timeout=5)[0] if ok[t] else f"down rc={srvs[t].p.poll()}")
         for t in H.TGTS}
    H.rec(row, case, "encrypted PKCS#8 key + key_pw: rs serves 200 (D-20 superset); py cannot use it",
          r["py"], r["rs"], r["rs"] == 200 and r["py"] != 200, "D-20")
    stop_pair(srvs)

    # missing upload_path: warning, still starts
    case = "dps-noupload"
    srvs, ok = start_pair(case, False, {"dp_server": {"upload_path": "./missing"}}, plant=False)
    time.sleep(0.3)
    w = {t: (ok[t], "[ WARNING ] Datapackage directory does not exist!" in srvs[t].log()) for t in H.TGTS}
    H.both(row, case, "upload_path missing: WARNING block on stderr, server starts", w, (True, True))
    stop_pair(srvs)


IDENT_TLS = [
    # mode, ident, extra headers, want(public), want(auth)
    ("cert", "alice", (), 200, 200),
    ("nocert", None, (), 200, 401),
    ("revoked", "carol", (), 200, 403),
    ("expired", "expired", (), "tls-reject", "tls-reject"),
    ("notyet", "notyet", (), "tls-reject", "tls-reject"),
    ("foreignca", "foreign", (), "tls-reject", "tls-reject"),
]


def g_auth():
    row = "DPS-auth"
    eps = endpoints()
    srvs, ok = start_pair("dps-auth-tls", True)
    H.both(row, "tls.listen", "both up", ok, True)
    for mode, ident, xh, wpub, wauth in IDENT_TLS:
        for name, m, path, hd, body, auth in eps:
            r = par(lambda t: req(t, m, path, tuple(hd) + xh, body, ident=ident))
            w = wauth if auth else wpub
            cell(row, f"tls.{mode}.{name}", f"TLS {mode}: {m} {path.split('?')[0]}", r, {"py": w, "rs": w})
    for ver, vn in ((ssl.TLSVersion.TLSv1_2, "1.2"), (ssl.TLSVersion.TLSv1_3, "1.3")):
        r = par(lambda t: req(t, "GET", "/Marti/api/clientEndPoints", ident="alice", tls_ver=ver))
        cell(row, f"tls.ver{vn}", f"TLS {vn} with client cert: clientEndPoints", r, {"py": 200, "rs": 200})
    stop_pair(srvs)

    nl = non_loopback_ip()
    srvs, ok = start_pair("dps-auth-plain", False)
    H.both(row, "plain.listen", "both up", ok, True)
    modes = [
        ("none-lo", (), None, 200, {"py": 401, "rs": 401}),
        ("xuser-lo", (("X-USER", "alice"),), None, 200, {"py": 200, "rs": 200}),
        ("xuser-lower-lo", (("x-user", "alice"),), None, 200, {"py": 200, "rs": 200}),
        ("xuser+revoked-lo", (("X-USER", "alice"), ("X-REVOKED", "1")), None, 200, {"py": 403, "rs": 403}),
        ("revoked-only-lo", (("X-REVOKED", "1"),), None, 200, {"py": 401, "rs": 401}),
        ("xuser_underscore-lo", (("X_USER", "alice"),), None, 200, {"py": 401, "rs": 401}),
    ]
    if nl:
        modes += [
            ("none-nonlo", (), nl, 200, {"py": 401, "rs": 401}),
            ("xuser-nonlo", (("X-USER", "alice"),), nl, 200, {"py": 200, "rs": 401}),  # D-21
            ("xuser+revoked-nonlo", (("X-USER", "alice"), ("X-REVOKED", "1")), nl, 200, {"py": 403, "rs": 401}),
        ]
    else:
        H.rec(row, "plain.nonlo", "no local non-loopback address: non-loopback modes skipped", None, None, False,
              open_q="environment")
    for mode, xh, src, wpub, wauth in modes:
        for name, m, path, hd, body, auth in eps:
            r = par(lambda t: req(t, m, path, tuple(hd) + xh, body, ssl_on=False, src=src))
            w = wauth if auth else {"py": wpub, "rs": wpub}
            cell(row, f"plain.{mode}.{name}", f"plain {mode}: {m} {path.split('?')[0]}"
                 + (" [D-21]" if w["py"] != w["rs"] else ""), r, w)
    stop_pair(srvs)


def search_users(t, ssl_on=True, ident="alice", xh=()):
    st, _, b = req(t, "GET", "/Marti/sync/search", xh, ident=ident, ssl_on=ssl_on)
    if st != 200:
        return st
    return sorted((m["UID"], m["SubmissionUser"]) for m in json.loads(b)["results"] if m["UID"].startswith("S"))


def upload(t, uid, fname, data=b"x", ident=None, ssl_on=True, xh=(), h="hS"):
    ct, mp = multipart([("assetfile", fname, data, "application/octet-stream")])
    q = urllib.parse.quote(uid, safe="")
    return req(t, "POST", f"/Marti/sync/missionupload?hash={h}&creatorUid={q}", (("Content-Type", ct),) + xh, mp,
               ident=ident, ssl_on=ssl_on)


def g_spoof():
    row = "DPS-spoof"
    srvs, ok = start_pair("dps-spoof-tls", True)
    ep = "/Marti/api/clientEndPoints"
    cases = [
        ("nocert+X-USER", None, (("X-USER", "alice"),), 401),
        ("nocert+x-user", None, (("x-user", "alice"),), 401),
        ("nocert+X-User", None, (("X-User", "alice"),), 401),
        ("nocert+X_USER", None, (("X_USER", "alice"),), 401),
        ("revoked+X-USER", "carol", (("X-USER", "alice"),), 403),
        ("revoked+X-SERIAL_NUMBER", "carol", (("X-USER", "alice"), ("X-SERIAL_NUMBER", f"{H.PKI.serial['alice']:X}")),
         403),
        ("cert+X-REVOKED", "alice", (("X-REVOKED", "1"),), 200),
        ("cert+x-revoked", "alice", (("x-revoked", "1"),), 200),
        ("cert+X_REVOKED", "alice", (("X_REVOKED", "1"),), 200),
    ]
    for cid, ident, xh, want in cases:
        r = par(lambda t: req(t, "GET", ep, xh, ident=ident))
        cell(row, f"tls.{cid}", f"TLS spoof {cid}: clientEndPoints", r, {"py": want, "rs": want})
    # identity really is the cert CN: SubmissionUser in the stored meta
    r = par(lambda t: upload(t, "S1", "spoof.zip", ident="alice", xh=(("X-USER", "mallory"),))[0])
    H.both(row, "tls.upload-spoof", "upload as alice with X-USER: mallory -> 200", r, 200)
    r = par(lambda t: upload(t, "S2", "spoof.zip", ident="dave", xh=(("X_USER", "mallory"),), h="hS2")[0])
    H.both(row, "tls.upload-spoof-underscore", "upload as dave with X_USER: mallory -> 200", r, 200)
    for h in ("hS", "hS2"):
        par(lambda t: req(t, "PUT", f"/Marti/api/sync/metadata/{h}/tool", body=b"public", ident="alice"))
    r = par(lambda t: search_users(t))
    H.both(row, "tls.submissionuser", "SubmissionUser = cert CN (not the header)", r,
           [("S1_spoof.zip", "alice"), ("S2_spoof.zip", "dave")])
    stop_pair(srvs)

    srvs, ok = start_pair("dps-spoof-plain", False)
    r = par(lambda t: upload(t, "S3", "p.zip", ssl_on=False, xh=(("X-USER", "proxyuser"),))[0])
    H.both(row, "plain.upload-xuser-lo", "plain loopback upload with X-USER: proxyuser -> 200", r, 200)
    par(lambda t: req(t, "PUT", "/Marti/api/sync/metadata/hS/tool", (("X-USER", "x"),), b"public", ssl_on=False))
    r = par(lambda t: search_users(t, ssl_on=False, ident=None, xh=(("X-USER", "x"),)))
    H.both(row, "plain.submissionuser", "SubmissionUser = trusted loopback X-USER", r, [("S3_p.zip", "proxyuser")])
    stop_pair(srvs)


def g_http():
    row = "DPS-http"
    srvs, ok = start_pair("dps-http", True)
    A = "alice"

    def hdr(r, *names):
        return (r[0],) + tuple(r[1].get(n) for n in names)

    r = par(lambda t: req(t, "HEAD", "/", ident=A))
    H.same(row, "head.root", "HEAD /: status, Content-Type, Content-Length, empty body",
           {t: hdr(r[t], "content-type", "content-length") + (r[t][2],) for t in H.TGTS})
    r = par(lambda t: req(t, "HEAD", "/Marti/sync/content?hash=h1", ident=A))
    H.same(row, "head.content", "HEAD download: status, CT, CL, Content-Disposition, Accept-Ranges, empty body",
           {t: hdr(r[t], "content-type", "content-length", "content-disposition", "accept-ranges") + (r[t][2],)
            for t in H.TGTS})
    r = par(lambda t: req(t, "HEAD", "/Marti/sync/content?hash=h1"))
    H.both(row, "head.content-nocert", "HEAD download without cert -> 401", {t: r[t][0] for t in H.TGTS}, 401)

    def allow(r):
        return (r[0], tuple(sorted(x.strip() for x in r[1].get("allow", "").split(",") if x.strip())))
    for p in ("/", "/Marti/api/clientEndPoints", "/Marti/sync/missionupload", "/Marti/api/sync/metadata/h1/tool",
              "/Marti/vcm"):
        r = par(lambda t: req(t, "OPTIONS", p))
        H.same(row, f"options.{p}", f"OPTIONS {p} (no cert): status + Allow set", {t: allow(r[t]) for t in H.TGTS})

    for cid, m, p, ident in [("404.unknown", "GET", "/nope", A), ("404.unknown-nocert", "GET", "/Marti/nope", None),
                             ("404.trailing", "GET", "/Marti/api/version/", A),
                             ("405.post-root", "POST", "/", A), ("405.get-tool", "GET", "/Marti/api/sync/metadata/h1/tool", A),
                             ("405.get-upload", "GET", "/Marti/sync/missionupload", A),
                             ("405.delete-vcm", "DELETE", "/Marti/vcm", A), ("405.put-search", "PUT", "/Marti/sync/search", A)]:
        r = par(lambda t: req(t, m, p, ident=ident))
        H.same(row, cid, f"{m} {p}: status (+Allow on 405)", {t: allow(r[t]) for t in H.TGTS})

    n = len(PLANT_DATA)
    for cid, rng in [("range.first10", "bytes=0-9"), ("range.suffix", "bytes=-5"), ("range.open", f"bytes={n - 3}-"),
                     ("range.beyond", f"bytes={n + 10}-"), ("range.multi", "bytes=0-1,5-6"), ("range.bad", "bytes=x-y"),
                     ("range.overlong", f"bytes=0-{n + 100}")]:
        r = par(lambda t: req(t, "GET", "/Marti/sync/content?hash=h1", (("Range", rng),), ident=A))
        H.same(row, cid, f"Range {rng}: status, Content-Range, Content-Length, body sha",
               {t: hdr(r[t], "content-range", "content-length") + (hashlib.sha256(r[t][2]).hexdigest()[:16],)
                for t in H.TGTS})
    # conditional requests with each server's own validators
    base = par(lambda t: req(t, "GET", "/Marti/sync/content?hash=h1", ident=A))
    r = par(lambda t: req(t, "GET", "/Marti/sync/content?hash=h1", (("If-None-Match", base[t][1].get("etag", "")),),
                          ident=A))
    H.same(row, "cond.inm", "If-None-Match <own ETag> -> status, empty body", {t: (r[t][0], r[t][2]) for t in H.TGTS})
    r = par(lambda t: req(t, "GET", "/Marti/sync/content?hash=h1",
                          (("If-Modified-Since", base[t][1].get("last-modified", "")),), ident=A))
    H.same(row, "cond.ims", "If-Modified-Since <own Last-Modified> -> status", {t: r[t][0] for t in H.TGTS})
    r = par(lambda t: req(t, "GET", "/Marti/sync/content?hash=h1",
                          (("Range", "bytes=0-3"), ("If-Range", base[t][1].get("etag", ""))), ident=A))
    H.same(row, "cond.ifrange", "If-Range <own ETag> + Range -> 206", {t: hdr(r[t], "content-range") for t in H.TGTS})
    H.same(row, "dl.headers", "download: CT, CD, Cache-Control, ETag/Last-Modified present",
           {t: hdr(base[t], "content-type", "content-disposition", "cache-control")
            + ("etag" in base[t][1], "last-modified" in base[t][1]) for t in H.TGTS})
    stop_pair(srvs)


NAMES = [
    ("cyr", "U1", "Отчёт карта.zip"),
    ("umlaut", "U2", "grüße ü.kml"),
    ("cjk", "U3", "地图.zip"),
    ("path", "U4", "../../etc/passwd.zip"),
    ("spaces", "U5", "  my  pkg .zip"),
    ("uidcyr", "Иван", "pkg.zip"),
    ("emoji", "U6", "pin\U0001F4CD.zip"),
]


def g_names():
    row = "DPS-names"
    srvs, ok = start_pair("dps-names", True)
    for i, (cid, uid, fn) in enumerate(NAMES):
        h = f"hn{i}"
        r = par(lambda t: upload(t, uid, fn, data=f"payload-{cid}".encode(), ident="alice", h=h))
        cell(row, f"{cid}.upload", f"upload filename={fn!r} creatorUid={uid!r}", r, {"py": 200, "rs": 200})
        files = {t: sorted(x for x in os.listdir(os.path.join(srvs[t].d, "dp-user"))
                           if x not in ("meta", "C_pkg.zip")) for t in H.TGTS}
        H.same(row, f"{cid}.disk", "files on disk (secure_filename) equal", files)
        r = par(lambda t: req(t, "PUT", f"/Marti/api/sync/metadata/{h}/tool", body=b"public", ident="alice"))
        r = par(lambda t: req(t, "GET", f"/Marti/sync/content?hash={h}", ident="alice"))
        v = {t: (r[t][0], r[t][1].get("content-disposition"), r[t][2]) for t in H.TGTS}
        H.same(row, f"{cid}.download", "download: status, Content-Disposition, body", v)
        ctv = {t: r[t][1].get("content-type") for t in H.TGTS}
        if fn.endswith(".kml"):
            # py mimetypes merges the host /etc/mime.types; rs uses only the built-in table (compat 1.3.15, S)
            H.expect(row, f"{cid}.ctype", "download Content-Type for .kml", ctv,
                     "application/vnd.google-earth.kml+xml; charset=utf-8", "application/octet-stream",
                     "compat 1.3.15 (S, non-normative): host /etc/mime.types not merged by Rust")
        else:
            H.same(row, f"{cid}.ctype", "download Content-Type", ctv)
    r = par(lambda t: req(t, "GET", "/Marti/sync/search", ident="alice"))
    H.same(row, "search", "search JSON (ensure_ascii, sorted keys) equal after timestamp mask",
           {t: (r[t][0], norm(r[t][2])) for t in H.TGTS})
    stop_pair(srvs)


def write_db(path, revoke):
    lines = open(path).read().splitlines(keepends=True)
    out = []
    for ln in lines:
        f = ln.split("\t")
        if f[-1].strip() == revoke:
            f[0] = "R"
        out.append("\t".join(f))
    tmp = path + ".new"
    open(tmp, "w").writelines(out)
    os.replace(tmp, path)


def g_revoke():
    row = "DPS-revoke"
    srvs, ok = start_pair("dps-revoke", True)
    ep = "/Marti/api/clientEndPoints"
    warm = {t: [req(t, "GET", ep, ident="bob")[0] for _ in range(20)] for t in H.TGTS}
    H.both(row, "before", "bob 200 before revocation (20 requests, warms all gunicorn workers)",
           {t: set(warm[t]) for t in H.TGTS}, {200})
    time.sleep(1.1)
    for t in H.TGTS:
        write_db(os.path.join(srvs[t].d, "cert-db.txt"), "bob")
    after = {t: [req(t, "GET", ep, ident="bob")[0] for _ in range(10)] for t in H.TGTS}
    v = {t: (200 in after[t], set(after[t]) == {403}) for t in H.TGTS}
    H.expect(row, "after", "cert-db edited (bob -> R) without restart: py keeps 200 (per-worker cache), rs 403", v,
             (True, False), (False, True), f"D-11; py={after['py']} rs={after['rs']}")
    r = par(lambda t: req(t, "GET", ep, ident="alice")[0])
    H.both(row, "others", "alice unaffected -> 200", r, 200)
    stop_pair(srvs)


def g_large():
    row = "DPS-large"
    mb = int(os.environ.get("INTEG_LARGE_MB", "500"))
    if mb <= 0:
        H.rec(row, "large", "skipped (INTEG_LARGE_MB=0)", None, None, True)
        return
    srvs, ok = start_pair("dps-large", True)
    block = os.urandom(1 << 20)
    ct, _ = multipart([])
    boundary = "integ-s404-boundary"
    head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"assetfile\"; filename=\"big.bin\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    total = len(head) + mb * len(block) + len(tail)
    digest = hashlib.sha256()
    for i in range(mb):
        digest.update(i.to_bytes(4, "big") + block[4:])
    want_sha = digest.hexdigest()

    def gen():
        yield head
        for i in range(mb):
            yield i.to_bytes(4, "big") + block[4:]
        yield tail

    res = {}
    for t in H.TGTS:  # sequential: keep RSS/CPU measurements clean
        rss0 = rss(srvs[t].p.pid, "VmRSS")
        t0 = time.time()
        r = req(t, "POST", "/Marti/sync/missionupload?hash=hBig&creatorUid=L",
                (("Content-Type", ct), ("Content-Length", str(total))), gen(), ident="alice", timeout=600)
        dt_ = time.time() - t0
        hwm = rss(srvs[t].p.pid, "VmHWM")
        f = os.path.join(srvs[t].d, "dp-user", "L_big.bin")
        sha = sha_file(f) if os.path.exists(f) else None
        res[t] = {"status": r[0], "sha_ok": sha == want_sha, "secs": round(dt_, 1),
                  "rss0_mb": rss0 and round(rss0 / 1024, 1), "hwm_mb": hwm and round(hwm / 1024, 1),
                  "detail": r[2][:100] if r[0] != 200 else b""}
    rs = res["rs"]
    grow = (rs["hwm_mb"] or 0) - (rs["rss0_mb"] or 0)
    H.rec(row, f"large.{mb}MB.rs", f"{mb} MB upload over TLS: rs 200, file sha256 ok, peak RSS growth <= 32 MB (ADR-004)",
          None, rs, rs["status"] == 200 and rs["sha_ok"] and grow <= 32, f"rs growth {grow:.1f} MB")
    py = res["py"]
    H.rec(row, f"large.{mb}MB.py", f"{mb} MB upload over TLS: py (gunicorn) result (informational)", py, None, True,
          "Python reference only; gunicorn sync worker timeout 30 s may kill long requests")
    stop_pair(srvs)


def rss(pid, key):
    try:
        for ln in open(f"/proc/{pid}/status"):
            if ln.startswith(key + ":"):
                return int(ln.split()[1])
    except OSError:
        return None
    return None


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for ch in iter(lambda: f.read(1 << 20), b""):
            h.update(ch)
    return h.hexdigest()


SUB = {"start": g_start, "auth": g_auth, "spoof": g_spoof, "http": g_http, "names": g_names, "revoke": g_revoke,
       "large": g_large}


def g_dps(h):
    global H, DSRV
    H = h
    DSRV = make_dsrv_class()
    if not os.access(rs_dps_bin(), os.X_OK):
        H.rec("DPS", "dps.bin", f"taky_dps-rs not found: {rs_dps_bin()} (cargo build -p taky-dps)", None, None, False)
        return
    for ip in H.IP.values():
        for port in (DPS_TLS, DPS_PLAIN):
            if H.listening(ip, port):
                H.rec("DPS", "dps.ports", f"{ip}:{port} busy", None, None, False)
                return
    only = [s for s in os.environ.get("INTEG_DPS_ONLY", ",".join(SUB)).split(",") if s]
    for s in only:
        print(f"-- dps/{s}", flush=True)
        try:
            SUB[s]()
        except Exception as e:  # a crashed sub-group is a FAIL, the others still run
            traceback.print_exc()
            H.rec("DPS", f"dps/{s}.harness", "sub-group raised", repr(e), None, False)
        finally:
            H.stop_all()
