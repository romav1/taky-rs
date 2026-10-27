"""
difftest compat C8..C14 — data compatibility, part 2 (qa01, S-406 / T-33; test-strategy §1.5 L5).
Dispatched from compat.py (`tools/difftest/difftest compat C8 ...`); shares its redis-server, CHECKS, PROCS and Env.

  C8  video_feed: POST /Marti/vcm in one version, GET in the other (alternate | simultaneous); files == Python-only run
  C9  cert-db mixed writers: Python setup -> takyctl-rs build_client -> Python build_client while a Rust server runs ->
      Rust server kickban (takyctl-rs and Python takyctl as client) -> Python server (running, then restarted) rejects
  C10 cert-db: Python takyctl and takyctl-rs build_client alternately 100 times on one site
  C11 certificates: CA from Python / Rust x client from Python / Rust x server Python / Rust (CoT TLS + DPS TLS), revoked
  C12 taky.conf: setup confs both ways (loaded by both, servers start from the other's conf) + real-world configs
  C13 log_cot: Python and Rust CoT write alternately to one log_cot directory; files == Python-only run
  C14 drop-in: Python "production" site (/etc/taky, /var/taky in a private mount namespace with overlayfs) ->
      stop Python -> start Rust without migration (and back to Python)
TLS scenarios use their own addresses/ports: py 127.0.0.8, rs 127.0.0.9, CoT 18089 (monitor 18088), DPS 8443;
C14 binds 127.0.0.10 with the product defaults (8089/8087/8443).
"""
import configparser
import datetime as dt
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
try:
    from . import compat as C
except ImportError:  # run as a script inside the C14 mount namespace
    sys.path.insert(0, HERE)
    import compat as C  # type: ignore

check = C.check
RS_CTL = os.environ.get("TAKYCTL_RS_BIN", os.path.join(C.TAKYRS, "target", "debug", "takyctl-rs"))
RS_UNIT = os.path.join(C.TAKYRS, "target", "debug", "taky-rs-unit")
PYCTL = os.path.join(C.TAKYRS, "crates", "takyctl", "tests", "pyref", "takyctl.py")
VEC_TOOLS = os.path.join(C.OFFICE, "shared", "spec", "vectors", "tools")
TLS_COT, TLS_MON, TLS_DPS = 18089, 18088, 8443
P12_PW = "atakatak"
CERTDB_LINE = re.compile(r"^[VR]\t\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?\t\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?\t"
                         r"[0-9a-f]{40}\t[^\t\n]+\n$")


# ----------------------------------------------------------------------------------------------- processes / CLI
def env_for(tgt):
    env = dict(os.environ)
    env.pop("TAKY_CONFIG", None)
    if tgt == "py":
        env.update(PYTHONPATH=C.TAKY_SRC, PYTHONDONTWRITEBYTECODE="1")
    return env


def ctl(tgt, args, cwd, timeout=120):
    """Original takyctl (read-only source, wrapper of S-322) or takyctl-rs -> (rc, stdout, stderr)."""
    cmd = ([C.PY, "-I", "-B", "-W", "ignore", PYCTL, C.TAKY_SRC] if tgt == "py" else [RS_CTL]) + list(args)
    p = subprocess.run(cmd, cwd=cwd, env=env_for(tgt), capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def srv_cmd(kind, tgt, conf=None, level="info"):
    if tgt == "py":
        cmd = [C.PY, "-B", "-W", "ignore", "-c", C.PY_COT if kind == "cot" else C.PY_DPS]
    else:
        cmd = [C.RS_COT if kind == "cot" else C.RS_DPS]
    return cmd + (["-c", conf] if conf else []) + ["-l", level]


class Srv:
    """One server process (TLS scenarios): started in `cwd`, waits for ip:port."""

    def __init__(self, kind, tgt, cwd, ip, port, conf="taky.conf", logdir=None, level="info"):
        self.kind, self.tgt, self.ip, self.port = kind, tgt, ip, port
        logdir = logdir or cwd
        n = len([x for x in os.listdir(logdir) if x.startswith(f"{kind}-{tgt}-")])
        self.log = os.path.join(logdir, f"{kind}-{tgt}-{n}.log")
        self.p = subprocess.Popen(srv_cmd(kind, tgt, conf, level), cwd=cwd, env=env_for(tgt), stdin=subprocess.DEVNULL,
                                  stdout=open(self.log, "wb"), stderr=subprocess.STDOUT, start_new_session=True)
        C.PROCS.append(self.p)
        t0 = time.time()
        while not C.listening(ip, port):
            if self.p.poll() is not None or time.time() - t0 > 40:
                raise RuntimeError(f"{kind}-{tgt} did not start on {ip}:{port}:\n{self.text()[-2500:]}")
            time.sleep(0.05)
        if kind == "dps" and tgt == "py":
            time.sleep(1.0)  # gunicorn workers boot after the listener

    def text(self):
        return open(self.log, encoding="utf8", errors="replace").read()

    def stop(self):
        rc = C.stop_proc(self.p)
        t0 = time.time()
        while C.listening(self.ip, self.port) and time.time() - t0 < 10:
            time.sleep(0.05)
        return rc


def derive_conf(src, dst_dir, ip, root_dir, port=TLS_COT, mon_port=TLS_MON, extra=None):
    """Copy of a setup-written taky.conf for another 'host': absolute ssl/upload paths, own bind_ip/root_dir/ports."""
    cp = configparser.ConfigParser(allow_no_value=True, interpolation=None)
    cp.read(src)
    sdir = os.path.dirname(os.path.abspath(src))
    for sect, opt in [("ssl", o) for o in ("ca", "ca_key", "server_p12", "cert", "key", "cert_db")] + \
                     [("dp_server", "upload_path")]:
        v = cp.get(sect, opt, fallback=None)
        if v and not os.path.isabs(v):
            cp.set(sect, opt, os.path.normpath(os.path.join(sdir, v)))
    cp.set("taky", "bind_ip", ip)
    cp.set("taky", "root_dir", root_dir)
    cp.set("cot_server", "port", str(port))
    cp.set("cot_server", "mon_ip", ip)
    cp.set("cot_server", "mon_port", str(mon_port))
    for (s, k), v in (extra or {}).items():
        cp.set(s, k, v)
    os.makedirs(dst_dir, exist_ok=True)
    p = os.path.join(dst_dir, "taky.conf")
    with open(p, "w") as f:
        cp.write(f)
    return p


def certdb_lines(path):
    with open(path, encoding="utf8") as f:
        return f.readlines()


def py_certdb(conf, cwd):
    """The ORIGINAL CertificateDatabase reading the cert-db of `conf` -> [[status, name, serial hex], ...] in order."""
    code = ("import json, sys; from taky.config import load_config; load_config(sys.argv[1], explicit=True)\n"
            "from taky.util import anc; db = anc.CertificateDatabase()\n"
            "print(json.dumps([[r['status'], r['name'], '%040x' % r['serial_num']] for r in db.cert_db_sn.values()]))")
    p = subprocess.run([C.PY, "-B", "-W", "ignore", "-c", code, conf], cwd=cwd, env=env_for("py"),
                       capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        return {"error": p.stderr[-1500:]}
    return json.loads(p.stdout)


# ----------------------------------------------------------------------------------------------- TLS clients
def pem_from_zip(zp, out, pw=P12_PW):
    """Client key/cert PEM from the client p12 inside a build_client zip -> (crt, key, serial hex)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    z = zipfile.ZipFile(zp)
    n = [i for i in z.namelist() if i.endswith(".p12") and "server-" not in os.path.basename(i)][0]
    p = pkcs12.load_pkcs12(z.read(n), pw.encode())
    with open(out + ".crt", "wb") as f:
        f.write(p.cert.certificate.public_bytes(serialization.Encoding.PEM))
    fd = os.open(out + ".key", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, p.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    os.close(fd)
    return out + ".crt", out + ".key", f"{p.cert.certificate.serial_number:040x}"


def tls_ctx(ca, crt=None, key=None):
    c = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    c.check_hostname = False  # the server cert is for the setup hostname; the chain is verified
    if crt:
        c.load_cert_chain(crt, key)
    return c


def tls_conn(ip, port, ca, crt, key, timeout=5):
    return tls_ctx(ca, crt, key).wrap_socket(socket.create_connection((ip, port), timeout=timeout))


def now_s(off=0):
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=off)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def sa(uid, cs, n=0, etype="a-f-G-U-C", stale=120):
    return (f'<event version="2.0" uid="{uid}" type="{etype}" how="m-g" time="{now_s()}" start="{now_s()}" '
            f'stale="{now_s(stale)}"><point lat="1.{n}" lon="2.0" hae="0" ce="9999999" le="9999999"/>'
            f'<detail><contact callsign="{cs}" endpoint="*:-1:stcp"/><__group name="Cyan" role="Team Member"/>'
            '<takv device="qa" platform="ATAK-CIV" os="34" version="4.10"/></detail></event>').encode()


def read_until(s, needle, timeout):
    """-> (data, state) state in found|timeout|eof|error:<e>"""
    buf, end = b"", time.monotonic() + timeout
    while time.monotonic() < end:
        s.settimeout(max(0.05, end - time.monotonic()))
        try:
            ch = s.recv(65536)
        except (socket.timeout, TimeoutError):
            return buf, "timeout"
        except (ssl.SSLError, OSError) as e:
            return buf, f"error:{e.__class__.__name__}"
        if not ch:
            return buf, "eof"
        buf += ch
        if needle and needle in buf:
            return buf, "found"
    return buf, "timeout"


def cot_pair(ip, port, ca, a, b):
    """Two-way CoT delivery between clients a, b = (tag, crt, key) -> (a->b ok, b->a ok, detail)."""
    try:
        sb = tls_conn(ip, port, ca, b[1], b[2])
        sb.sendall(sa(f"{b[0]}-uid", b[0].upper()))
        time.sleep(0.3)
        sa_ = tls_conn(ip, port, ca, a[1], a[2])
        sa_.sendall(sa(f"{a[0]}-uid", a[0].upper()))
        _, st1 = read_until(sb, f'uid="{a[0]}-uid"'.encode(), 5)
        sb.sendall(sa(f"{b[0]}-uid", b[0].upper(), 1))
        _, st2 = read_until(sa_, f'uid="{b[0]}-uid"'.encode(), 5)
        sa_.close()
        sb.close()
        return st1 == "found", st2 == "found", [st1, st2]
    except Exception as e:  # noqa: BLE001
        return False, False, repr(e)


def refused(ip, port, ca, crt, key):
    """A TLS CoT connection must be refused (handshake error or closed after connect), not just silent."""
    try:
        s = tls_conn(ip, port, ca, crt, key)
    except (ssl.SSLError, OSError) as e:
        return True, f"handshake: {e.__class__.__name__}"
    try:
        s.sendall(sa("probe-uid", "PROBE"))
    except (ssl.SSLError, OSError) as e:
        return True, f"send: {e.__class__.__name__}"
    _, st = read_until(s, None, 3)
    s.close()
    return st != "timeout", st


def https(ip, port, ca, crt, key, method, path, body=None, ctype=None):
    """-> (status | 'tls', headers, body)"""
    try:
        conn = http.client.HTTPSConnection(ip, port, timeout=20, context=tls_ctx(ca, crt, key))
        hd = {"Content-Type": ctype} if ctype else {}
        conn.request(method, path, body=body, headers=hd)
        r = conn.getresponse()
        data = r.read()
        h = {k.lower(): v for k, v in r.getheaders()}
        conn.close()
        return r.status, h, data
    except (ssl.SSLError, OSError) as e:
        return "tls", {}, repr(e).encode()


def multipart(fname, data, mime="application/zip"):
    b = "s406-boundary"
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"assetfile\"; filename=\"{fname}\"\r\n"
            f"Content-Type: {mime}\r\n\r\n").encode() + data + f"\r\n--{b}--\r\n".encode()
    return body, f"multipart/form-data; boundary={b}"


# ----------------------------------------------------------------------------------------------- C8 video_feed
VCM_A = ("<?xml version='1.0' encoding='UTF-8'?>\n<videoConnections>\n"
         "  <feed>\n    <protocol>rtsp</protocol>\n    <alias>Cam ✓ Ünïcode &amp; &lt;more&gt; &#233;</alias>\n"
         "    <uid>feed-1</uid>\n    <address>10.0.0.1</address>\n    <port>554</port>\n    <roverPort>-1</roverPort>\n"
         "    <ignoreEmbeddedKLV>false</ignoreEmbeddedKLV>\n    <preferredMacAddress/>\n    <path>/live/1</path>\n"
         "    <buffer>-1</buffer>\n    <timeout>5000</timeout>\n    <rtspReliable>1</rtspReliable>\n  </feed>\n"
         "  <feed xmlns:x=\"urn:x-qa\" a='1' b=\"two &quot;q&quot;\"><uid> feed-2 </uid><x:extra k=\"v\"/>"
         "<!-- a comment --><alias>Two</alias><?pi data?></feed>\n"
         "  <feed><uid>../evil/feed 3</uid><alias>Three</alias></feed>\n"
         "  <feed><alias>no uid: skipped</alias></feed>\n"
         "</videoConnections>\n").encode()
VCM_B = ("<videoConnections><feed><protocol>raw</protocol><uid>feed-1</uid><alias>Cam one v2</alias>"
         "<address>10.0.0.2</address><port>1234</port></feed>"
         "<feed><uid>feed-4</uid><alias>Четыре</alias><url>udp://239.0.0.1:1234?x=1&amp;y=2</url></feed>"
         "</videoConnections>").encode()


def vcm_files(up):
    d = os.path.join(up, "video_feed")
    if not os.path.isdir(d):
        return None
    return {n: open(os.path.join(d, n), "rb").read().decode("utf8", "replace") for n in sorted(os.listdir(d))}


def vcm_get(env, tgt):
    st, hd, body = C.hreq(env, tgt, "GET", "/Marti/vcm")
    return {"status": st, "ctype": hd.get("content-type"), "body": body.decode("utf8", "replace")}


def vcm_post(env, tgt, data):
    st, _, body = C.hreq(env, tgt, "POST", "/Marti/vcm", data, "application/xml")
    return [st, body.decode("utf8", "replace")]


def sc_video(env):
    sc = env.sc
    # empty upload_path (no video_feed dir): both answer the same empty document
    env.start("dps", "rs")
    e_r = vcm_get(env, "rs")
    env.start("dps", "py")
    e_p = vcm_get(env, "py")
    check(f"{sc}.empty", "no video_feed dir: GET /Marti/vcm status/content-type/body equal", e_p == e_r, [e_p, e_r])
    r1 = vcm_post(env, "py", VCM_A)
    f_p1 = vcm_files(env.upload)
    check(f"{sc}.py.post", "P POST A -> 200, feed-1/feed-2/evil_feed_3 written (uid-less feed skipped)",
          r1[0] == 200 and sorted(f_p1 or {}) == ["evil_feed_3.xml", "feed-1.xml", "feed-2.xml"], [r1, sorted(f_p1 or {})])
    g_p1 = vcm_get(env, "py")
    env.start("dps", "rs")
    g_r1 = vcm_get(env, "rs")
    check(f"{sc}.R-reads-P", "R GET of the P-written feeds == P GET (status, content-type, bytes)", g_r1 == g_p1,
          [g_p1, g_r1])
    r2 = vcm_post(env, "rs", VCM_B)
    f_r2 = vcm_files(env.upload)
    g_r2 = vcm_get(env, "rs")
    env.start("dps", "py")
    g_p2 = vcm_get(env, "py")
    check(f"{sc}.rs.post", "R POST B -> 200 (overwrites feed-1, adds feed-4)", r2[0] == 200 and "feed-4.xml" in f_r2,
          [r2, sorted(f_r2)])
    check(f"{sc}.P-reads-R", "P GET of the R-written feeds == R GET (status, content-type, bytes)", g_p2 == g_r2,
          [g_r2, g_p2])
    # reference: Python alone, same POSTs, scratch upload_path
    ref = video_reference(env)
    check(f"{sc}.files", "video_feed/* after P(A)+R(B) byte-equal to the files Python alone writes for A+B",
          f_r2 == ref["files"], C.same_except(f_r2, ref["files"])[0])
    check(f"{sc}.get-ref", "final GET == Python-only final GET", g_p2 == ref["get"], [ref["get"], g_p2])
    env.stop_all()
    return {"empty": e_p, "files": f_r2, "get": g_p2}


def video_reference(env):
    saved = env.upload
    for k in list(env.srv):
        env.stop(*k)
    env.upload = os.path.join(env.base, "dp-ref")
    os.makedirs(os.path.join(env.upload, "meta"), exist_ok=True)
    try:
        env.start("dps", "py")
        vcm_post(env, "py", VCM_A)
        vcm_post(env, "py", VCM_B)
        out = {"files": vcm_files(env.upload), "get": vcm_get(env, "py")}
        env.stop("dps", "py")
    finally:
        env.upload = saved
    return out


# ----------------------------------------------------------------------------------------------- C9 cert-db mixed writers
def preserved(old, new, changed=()):
    """Every line of `old` is in `new` byte-for-byte, in the same order and at the same index (except indices in
    `changed`), and new lines are only appended."""
    if len(new) < len(old):
        return False
    return all(new[i] == old[i] for i in range(len(old)) if i not in changed)


def name_idx(lines, name):
    return [i for i, ln in enumerate(lines) if ln.rstrip("\n").split("\t")[-1] == name]


def sc_certdb_mixed(env):
    sc = env.sc
    base = env.base
    rc, out, err = ctl("py", ["setup", "--host", "srv1", "--public-ip", "127.0.0.1", "--bind-ip", C.IPS["rs"], "site"],
                       base)
    site = os.path.join(base, "site")
    db = os.path.join(site, "ssl", "cert-db.txt")
    check(f"{sc}.py.setup", "Python setup (SSL site) rc 0, cert-db 1 line srv1", rc == 0 and len(certdb_lines(db)) == 1,
          [rc, err[-500:]])
    l0 = certdb_lines(db)
    conf_rs = derive_conf(os.path.join(site, "taky.conf"), os.path.join(base, "rs"), C.IPS["rs"],
                          os.path.join(base, "rs"))
    conf_py = derive_conf(os.path.join(site, "taky.conf"), os.path.join(base, "py"), C.IPS["py"],
                          os.path.join(base, "py"))
    ca = os.path.join(site, "ssl", "ca.crt")
    rs = Srv("cot", "rs", os.path.dirname(conf_rs), C.IPS["rs"], TLS_COT, logdir=base)
    py = Srv("cot", "py", os.path.dirname(conf_py), C.IPS["py"], TLS_COT, logdir=base)
    cl = {}
    steps = []

    def build(tgt, name):
        before = certdb_lines(db)
        rc, out, err = ctl(tgt, ["-c", "site/taky.conf", "build_client", name], base)
        after = certdb_lines(db)
        ok = rc == 0 and preserved(before, after) and len(after) == len(before) + 1 and name_idx(after, name) == [
            len(before)]
        steps.append({"tool": tgt, "name": name, "rc": rc, "lines": len(after)})
        check(f"{sc}.build.{name}", f"{tgt} build_client {name} (Rust server running): rc 0, one line appended, earlier "
              "lines byte-identical", ok, {"rc": rc, "err": err[-400:], "before": before, "after": after})
        cl[name] = pem_from_zip(os.path.join(base, f"{name}.zip"), os.path.join(base, name))

    build("rs", "crs1")
    build("py", "cpy1")
    build("py", "victimpy")
    build("rs", "victimrs")
    l1 = certdb_lines(db)
    fmt_bad = [ln for ln in l1 if not CERTDB_LINE.match(ln)]
    check(f"{sc}.format", "all 5 lines in the DC §5 format (TAB, naive isoformat, %040x, CN, \\n)", not fmt_bad, fmt_bad)
    ser = {n: c[2] for n, c in cl.items()}
    check(f"{sc}.serials", "cert-db serials == the client certificates' serials",
          all(name_idx(l1, n) and l1[name_idx(l1, n)[0]].split("\t")[3] == s for n, s in ser.items()), ser)
    # Rust server: certificates added after its start connect (cert-db is a blacklist)
    for n in ("cpy1", "victimpy"):
        a, b, d = cot_pair(C.IPS["rs"], TLS_COT, ca, (n, *cl[n][:2]), ("crs1", *cl["crs1"][:2]))
        check(f"{sc}.rs.pre.{n}", f"before kickban: {n} <-> crs1 delivered on taky-rs", a and b, d)
    # kickban on the RUNNING Rust server: takyctl-rs for the Python-issued victim, Python takyctl for the Rust-issued one
    k = {}
    for tool, name in (("rs", "victimpy"), ("py", "victimrs")):
        rc, out, err = ctl(tool, ["kickban", "-U", os.path.join(base, "rs", "taky-mgmt.sock"), name], base)
        k[name] = out
        check(f"{sc}.kick.{name}", f"{tool} kickban {name} via the taky-rs mgmt socket: rc 0, 'Revoked certificate SNs for "
              f"{name}:' + its serial", rc == 0 and out.startswith(f"Revoked certificate SNs for {name}:\n - ") and
              ser[name] in out, [rc, out, err[-300:]])
    l2 = certdb_lines(db)
    vi = [name_idx(l2, "victimpy")[0], name_idx(l2, "victimrs")[0]] if name_idx(l2, "victimpy") and name_idx(
        l2, "victimrs") else []
    check(f"{sc}.kick.no-loss", "after the Rust server's kickban: all 5 lines kept in order (D-11: lines added after "
          "the server start are not lost), only the 2 victim lines changed", len(l2) == 5 and len(vi) == 2 and
          preserved(l1, l2, set(vi)), {"before": l1, "after": l2})
    bad = []
    for i in vi:
        o, n = l1[i].rstrip("\n").split("\t"), l2[i].rstrip("\n").split("\t")
        if not (n[0] == "R" and n[1] == o[1] and n[3:] == o[3:] and n[2] != o[2] and CERTDB_LINE.match(l2[i])):
            bad.append([l1[i], l2[i]])
    check(f"{sc}.kick.lines", "victim lines: status R, issued/serial/name unchanged, expires = revocation time "
          "(naive isoformat with microseconds)", vi and not bad, bad)
    pyv = py_certdb(conf_py, base)
    check(f"{sc}.py-reads", "the original CertificateDatabase reads the Rust-rewritten file: 5 records, victims R",
          isinstance(pyv, list) and [r[1] for r in pyv] == ["srv1", "crs1", "cpy1", "victimpy", "victimrs"] and
          [r[0] for r in pyv] == ["V", "V", "V", "R", "R"], pyv)
    # Rust server refuses the victims, keeps the others
    for n in ("victimpy", "victimrs"):
        r, d = refused(C.IPS["rs"], TLS_COT, ca, *cl[n][:2])
        check(f"{sc}.rs.refused.{n}", f"taky-rs refuses {n} after kickban", r, d)
    a, b, d = cot_pair(C.IPS["rs"], TLS_COT, ca, ("cpy1", *cl["cpy1"][:2]), ("crs1", *cl["crs1"][:2]))
    check(f"{sc}.rs.others", "taky-rs: cpy1 <-> crs1 still delivered", a and b, d)
    # Python server: running since before the kickban -> reads cert-db once (original behaviour), then restart rejects
    r, d = refused(C.IPS["py"], TLS_COT, ca, *cl["victimpy"][:2])
    check(f"{sc}.py.stale", "informational: the Python server started before the kickban still accepts victimpy "
          "(cert-db read once at startup, original behaviour)", True, {"refused": r, "state": d})
    rc = py.stop()
    check(f"{sc}.py.stop", "Python taky SIGTERM -> exit 0", rc == 0, rc)
    py = Srv("cot", "py", os.path.dirname(conf_py), C.IPS["py"], TLS_COT, logdir=base)
    for n in ("victimpy", "victimrs"):
        r, d = refused(C.IPS["py"], TLS_COT, ca, *cl[n][:2])
        check(f"{sc}.py.refused.{n}", f"restarted Python taky refuses {n} ('User banned')", r, d)
    a, b, d = cot_pair(C.IPS["py"], TLS_COT, ca, ("cpy1", *cl["cpy1"][:2]), ("crs1", *cl["crs1"][:2]))
    check(f"{sc}.py.others", "restarted Python taky: cpy1 <-> crs1 delivered", a and b, d)
    check(f"{sc}.py.banned-log", "Python log has 'User banned' for the victims", "User banned" in py.text(),
          [ln for ln in py.text().splitlines() if "ban" in ln.lower()][:4])
    # Python takyctl rewrites the file after the Rust revoke: the R lines survive byte-for-byte
    build("py", "cpy2")
    l3 = certdb_lines(db)
    check(f"{sc}.py-rewrite", "Python build_client after the Rust revoke rewrites the file: the 5 earlier lines (incl. the "
          "Rust-written R lines with microseconds) byte-identical", preserved(l2, l3) and len(l3) == 6, l3)
    # the Rust server re-reads the Python-rewritten file (mtime): cpy2 connects, victims still refused
    a, b, d = cot_pair(C.IPS["rs"], TLS_COT, ca, ("cpy2", *cl["cpy2"][:2]), ("crs1", *cl["crs1"][:2]))
    check(f"{sc}.rs.reread", "taky-rs after the Python rewrite: cpy2 connects; victims still refused",
          a and b and refused(C.IPS["rs"], TLS_COT, ca, *cl["victimpy"][:2])[0], d)
    # second kickban on the running Rust server after the Python rewrite: nothing lost
    rc, out, _ = ctl("rs", ["kickban", "-U", os.path.join(base, "rs", "taky-mgmt.sock"), "cpy2"], base)
    l4 = certdb_lines(db)
    check(f"{sc}.kick2", "takyctl-rs kickban cpy2 after the Python rewrite: 6 lines, only cpy2 changed to R",
          rc == 0 and len(l4) == 6 and preserved(l3, l4, {5}) and l4[5].startswith("R\t"), l4)
    # informational: the original's own race (Python server kickban writes its startup copy, B5/OQ-04, not D-11)
    build("rs", "late")
    rc, out, _ = ctl("rs", ["kickban", "-U", os.path.join(base, "py", "taky-mgmt.sock"), "crs1"], base)
    l5 = certdb_lines(db)
    check(f"{sc}.py-server-kick", "informational: kickban on the PYTHON server (started before 'late' and the cpy2 revoke) "
          "rewrites its startup copy (original B5; R5 'do not mix' rule)", True,
          {"rc": rc, "lines": len(l5), "late_kept": bool(name_idx(l5, "late")),
           "cpy2": [ln.split("\t")[0] for ln in l5 if ln.rstrip().endswith("\tcpy2")]})
    check(f"{sc}.rs.log", "taky-rs log: no ERROR/panic", not re.search(r"ERROR|panicked", rs.text()),
          [ln for ln in rs.text().splitlines() if "ERROR" in ln or "panick" in ln][:5])
    for s in (rs, py):
        rc = s.stop()
        check(f"{sc}.{s.kind}-{s.tgt}.stop", f"{s.kind} {s.tgt} SIGTERM -> exit 0", rc == 0, rc)
    return {"steps": steps, "certdb": {"l1": l1, "l2": l2, "l3": l3, "l4": l4, "l5": l5}, "kickban": k}


# ----------------------------------------------------------------------------------------------- C10 100 alternating writes
def sc_certdb_100(env, n=100):
    sc = env.sc
    base = env.base
    rc, _, err = ctl("rs", ["setup", "--host", "srv1", "--public-ip", "127.0.0.1", "--bind-ip", C.IPS["rs"], "site"],
                     base)
    db = os.path.join(base, "site", "ssl", "cert-db.txt")
    check(f"{sc}.rs.setup", "takyctl-rs setup rc 0", rc == 0, err[-400:])
    lines = certdb_lines(db)
    fails, names = [], ["srv1"]
    t0 = time.time()
    for i in range(n):
        tgt = "py" if i % 2 == 0 else "rs"
        name = f"u{i:03d}-{tgt}"
        rc, _, err = ctl(tgt, ["-c", "site/taky.conf", "build_client", name], base)
        new = certdb_lines(db)
        if not (rc == 0 and preserved(lines, new) and len(new) == len(lines) + 1 and
                new[-1].rstrip("\n").endswith("\t" + name) and CERTDB_LINE.match(new[-1])):
            fails.append({"i": i, "tool": tgt, "rc": rc, "err": err[-300:], "tail": new[-2:], "n": len(new)})
        lines = new
        names.append(name)
        try:
            os.unlink(os.path.join(base, f"{name}.zip"))
        except OSError:
            pass
    dur = time.time() - t0
    check(f"{sc}.writes", f"{n} alternating build_client (py, rs, py, ...): every call rc 0, appends exactly its line, "
          "all earlier lines byte-identical", not fails, fails[:5])
    final = certdb_lines(db)
    check(f"{sc}.count", f"{n + 1} lines, insertion order = call order", [ln.rstrip("\n").split("\t")[-1]
                                                                        for ln in final] == names, len(final))
    sers = [ln.split("\t")[3] for ln in final]
    check(f"{sc}.unique", "serials unique, every line in the DC §5 format",
          len(set(sers)) == len(sers) and all(CERTDB_LINE.match(ln) for ln in final), len(set(sers)))
    pyv = py_certdb(os.path.join(base, "site", "taky.conf"), base)
    check(f"{sc}.py-reads", "the original CertificateDatabase reads all records in order",
          isinstance(pyv, list) and [r[1] for r in pyv] == names, pyv if not isinstance(pyv, list) else len(pyv))
    # Rust server reads the 101-line file and revokes one in the middle; Python takyctl then appends: nothing lost
    conf_rs = derive_conf(os.path.join(base, "site", "taky.conf"), os.path.join(base, "rs"), C.IPS["rs"],
                          os.path.join(base, "rs"))
    srv = Srv("cot", "rs", os.path.dirname(conf_rs), C.IPS["rs"], TLS_COT, logdir=base)
    mid = names[51]
    rc, out, _ = ctl("rs", ["kickban", "-U", os.path.join(base, "rs", "taky-mgmt.sock"), mid], base)
    after = certdb_lines(db)
    check(f"{sc}.kick-mid", f"taky-rs kickban {mid}: {n + 1} lines kept, only line 51 changed (R)",
          rc == 0 and len(after) == n + 1 and preserved(final, after, {51}) and after[51].startswith("R\t"),
          [rc, out, len(after)])
    rc, _, _ = ctl("py", ["-c", "site/taky.conf", "build_client", "last-py"], base)
    last = certdb_lines(db)
    check(f"{sc}.py-after-kick", "Python build_client after the Rust revoke: all lines byte-identical + 1 appended",
          rc == 0 and preserved(after, last) and len(last) == n + 2, len(last))
    rc = srv.stop()
    check(f"{sc}.cot-rs.stop", "cot rs SIGTERM -> exit 0", rc == 0, rc)
    return {"duration_s": round(dur, 1), "lines": len(last), "head": last[:3], "tail": last[-3:]}


# ----------------------------------------------------------------------------------------------- C11 4x2 certificate matrix
def sc_cert_matrix(env):
    sc = env.sc
    base = env.base
    res = {}
    for ca_by in ("py", "rs"):
        sd = os.path.join(base, f"ca-{ca_by}")
        os.makedirs(sd)
        rc, _, err = ctl(ca_by, ["setup", "--host", "srv1", "--public-ip", "127.0.0.1", "--bind-ip", C.IPS["py"],
                                 "site"], sd)
        check(f"{sc}.{ca_by}.setup", f"CA/site by {ca_by} setup rc 0", rc == 0, err[-400:])
        site = os.path.join(sd, "site")
        ca = os.path.join(site, "ssl", "ca.crt")
        cl = {}
        for cl_by in ("py", "rs"):
            for role in ("ok", "rev"):
                name = f"{role}-{cl_by}"
                rc, _, err = ctl(cl_by, ["-c", "site/taky.conf", "build_client", name], sd)
                check(f"{sc}.{ca_by}.build.{name}", f"CA {ca_by}: client {name} by {cl_by} build_client rc 0", rc == 0,
                      err[-300:])
                cl[name] = pem_from_zip(os.path.join(sd, f"{name}.zip"), os.path.join(sd, name))
        confs = {t: derive_conf(os.path.join(site, "taky.conf"), os.path.join(sd, t), C.IPS[t], os.path.join(sd, t))
                 for t in ("py", "rs")}
        srv = {}
        for t in ("py", "rs"):
            for kind, port in (("cot", TLS_COT), ("dps", TLS_DPS)):
                srv[(kind, t)] = Srv(kind, t, os.path.dirname(confs[t]), C.IPS[t], port, logdir=sd)
        matrix = {}
        for t in ("py", "rs"):
            for cl_by in ("py", "rs"):
                for role in ("ok", "rev"):
                    name = f"{role}-{cl_by}"
                    peer = "ok-rs" if cl_by == "py" else "ok-py"
                    a, b, d = cot_pair(C.IPS[t], TLS_COT, ca, (name, *cl[name][:2]), (peer, *cl[peer][:2]))
                    st, _, _ = https(C.IPS[t], TLS_DPS, ca, *cl[name][:2], "GET", "/Marti/api/clientEndPoints")
                    matrix[f"{name}@{t}"] = {"cot": [a, b], "dps": st}
                    check(f"{sc}.{ca_by}.{name}@{t}", f"CA {ca_by} x client {cl_by} ({role}) x server {t}: TLS CoT two-way "
                          f"delivery with {peer} + DPS clientEndPoints 200", a and b and st == 200, [d, st])
        # foreign CA: a client of this site against the other site's servers is checked in the second pass
        res.setdefault("clients", {})[ca_by] = cl
        # revoke both rev-* via the RUNNING Rust server (takyctl-rs for rev-py, Python takyctl for rev-rs)
        for tool, name in (("rs", "rev-py"), ("py", "rev-rs")):
            rc, out, _ = ctl(tool, ["kickban", "-U", os.path.join(sd, "rs", "taky-mgmt.sock"), name], sd)
            check(f"{sc}.{ca_by}.kick.{name}", f"CA {ca_by}: {tool} kickban {name} on taky-rs rc 0, serial revoked",
                  rc == 0 and cl[name][2] in out, out)
        for kind, port in (("cot", TLS_COT), ("dps", TLS_DPS)):  # Python reads cert-db at startup: restart
            srv[(kind, "py")].stop()
            srv[(kind, "py")] = Srv(kind, "py", os.path.dirname(confs["py"]), C.IPS["py"], port, logdir=sd)
        time.sleep(0.3)
        for t in ("py", "rs"):
            for cl_by in ("py", "rs"):
                name = f"rev-{cl_by}"
                r, d = refused(C.IPS[t], TLS_COT, ca, *cl[name][:2])
                st, _, _ = https(C.IPS[t], TLS_DPS, ca, *cl[name][:2], "GET", "/Marti/api/clientEndPoints")
                matrix[f"{name}@{t}:revoked"] = {"cot_refused": [r, d], "dps": st}
                check(f"{sc}.{ca_by}.revoked.{name}@{t}", f"CA {ca_by}: revoked client by {cl_by} rejected by server {t} "
                      "(CoT refused, DPS 403)", r and st == 403, [d, st])
                name = f"ok-{cl_by}"
                peer = "ok-rs" if cl_by == "py" else "ok-py"
                a, b, d = cot_pair(C.IPS[t], TLS_COT, ca, (name, *cl[name][:2]), (peer, *cl[peer][:2]))
                check(f"{sc}.{ca_by}.after.{name}@{t}", f"CA {ca_by}: {name} still delivered on {t} after the revoke",
                      a and b, d)
        if ca_by == "rs":  # cross-site: clients of the Python CA against the Rust-CA servers -> unknown CA
            other = res["clients"]["py"]
            for t in ("py", "rs"):
                r, d = refused(C.IPS[t], TLS_COT, ca, *other["ok-rs"][:2])
                st, _, _ = https(C.IPS[t], TLS_DPS, ca, *other["ok-rs"][:2], "GET", "/Marti/api/clientEndPoints")
                check(f"{sc}.foreign-ca@{t}", f"client of the other site's CA rejected by server {t} (CoT + DPS TLS)",
                      r and st == "tls", [d, st])
        for (kind, t), s in srv.items():
            rc = s.stop()
            check(f"{sc}.{ca_by}.{kind}-{t}.stop", f"{kind} {t} SIGTERM -> exit 0", rc == 0, rc)
        res[ca_by] = matrix
    res.pop("clients", None)
    return res


# ----------------------------------------------------------------------------------------------- C12 taky.conf
ALL_KEYS = ["taky.hostname", "taky.node_id", "taky.bind_ip", "taky.public_ip", "taky.redis", "taky.root_dir",
            "cot_server.port", "cot_server.mon_ip", "cot_server.mon_port", "cot_server.log_cot",
            "cot_server.max_persist_ttl", "dp_server.upload_path", "ssl.enabled", "ssl.client_cert_required", "ssl.ca",
            "ssl.ca_key", "ssl.server_p12", "ssl.server_p12_pw", "ssl.cert", "ssl.key", "ssl.key_pw", "ssl.cert_db"]

REAL_CONFS = {
    "readme-deployment": None,  # filled from taky/doc/README_DEPLOYMENT.md
    "comments-mixed": "# taky site\n; semicolon comment\n[taky]\n  # indented comment\nhostname = tak.example.org\n"
                      "node_id:NODE-1\nbind_ip =   10.1.2.3   \npublic_ip=203.0.113.5\nredis = true\n\n[cot_server]\n"
                      "port = 8087\nlog_cot =\nmax_persist_ttl = 3600\n\n[dp_server]\nupload_path = ./dp-user\n\n[ssl]\n"
                      "enabled = no\n",
    "uppercase-keys": "[taky]\nHostName = UP.example\nNODE_ID = UpNode\n[cot_server]\nPort = 9000\n[ssl]\nEnabled = Off\n",
    "default-section": "[DEFAULT]\nbase = /srv/taky\nextra = shared\n[taky]\nroot_dir = /srv/taky\nhostname = dflt\n"
                       "[dp_server]\nupload_path = /srv/taky/dp\n[cot_server]\n[ssl]\n",
    "multiline": "[taky]\nhostname = multi\npublic_ip = 198.51.100.7\nnode_id = line one\n  line two\n\tline three\n"
                 "[cot_server]\nport = 8087\n[ssl]\nenabled = false\n",
    "ssl-relative": "[taky]\nhostname = rel\nroot_dir = ./var/../root/\n[cot_server]\nmon_port = 12345\nmon_ip = 127.0.0.1\n"
                    "log_cot = logs\n[dp_server]\nupload_path = dp\n[ssl]\nenabled = 1\nclient_cert_required = yes\n"
                    "ca = ssl/ca.crt\nca_key = ssl/ca.key\nserver_p12 = ssl/server.p12\nserver_p12_pw = p w\n"
                    "cert = /abs/server.crt\nkey = ssl/server.key\nkey_pw = secret\ncert_db = ssl/cert-db.txt\n",
    "crlf-utf8": "[taky]\r\nhostname = crlf.example\r\nnode_id = Узел-✓\r\n[cot_server]\r\nport = 8087\r\n[ssl]\r\n"
                 "enabled = false\r\n",
    "redis-url": "[taky]\nhostname = r\nredis = redis://:pw@10.0.0.5:6380/3\n[cot_server]\nmax_persist_ttl =\n[ssl]\n"
                 "enabled = FALSE\n",
    "extra-keys": "[taky]\nhostname = x\nunknown_key = kept\n[cot_server]\nport = 8087\n[custom]\nfoo = bar\n[ssl]\n"
                  "enabled = false\nserver_p12_key = atakatak\n",
    "empty-file": "",
    "dup-section": "[taky]\nhostname = a\n[taky]\nhostname = b\n",
    "dup-option": "[taky]\nhostname = a\nhostname = b\n",
    "no-section": "hostname = x\n[taky]\n",
    "bom": "\ufeff[taky]\nhostname = bom\n",
    "bad-port": "[cot_server]\nport = 80a\n",
    "bad-ttl": "[cot_server]\nmax_persist_ttl = 1.5\n",
    "bad-bool": "[ssl]\nenabled = maybe\n",
}
EXTRA_KEYS = ["taky.unknown_key", "custom.foo", "ssl.server_p12_key", "taky.base", "taky.extra", "ssl.extra"]


def readme_conf():
    txt = open(os.path.join(C.TAKY_SRC, "doc", "README_DEPLOYMENT.md"), encoding="utf8").read()
    m = re.search(r"cat /etc/taky/taky.conf\n(\[taky\].*?)```", txt, re.S)
    return m.group(1) if m else ""


def load_both(cases, workdir):
    """cases {label: conf text} -> ({label: py observation}, {label: rs observation}) via the unit adapters
    (pyunit.py = the original load_config; taky-rs-unit = taky_config::load_config_in, the code taky-rs runs)."""
    vec = {"id": "C12", "kind": "ini", "cases": [{"input": t, "keys": ALL_KEYS + EXTRA_KEYS} for t in cases.values()]}
    vp = os.path.join(workdir, "C12-vector.json")
    with open(vp, "w", encoding="utf8") as f:
        json.dump(vec, f, ensure_ascii=False)
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([VEC_TOOLS, C.TAKY_SRC]), PYTHONDONTWRITEBYTECODE="1")
    p = subprocess.run([C.PY, "-B", os.path.join(HERE, "pyunit.py"), vp], env=env, capture_output=True, text=True,
                       timeout=120)
    r = subprocess.run([RS_UNIT, vp], capture_output=True, text=True, timeout=120)
    if p.returncode or r.returncode:
        raise RuntimeError(f"unit adapters failed: py {p.stderr[-800:]} rs {r.stderr[-800:]}")
    po, ro = json.loads(p.stdout)["C12"], json.loads(r.stdout)["C12"]
    return dict(zip(cases, po)), dict(zip(cases, ro))


def norm_obs(o):
    """Python returns key_pw/redis etc. as None, both adapters map 'no value' to null; values compared as strings."""
    if "values" in o:
        return {"values": {k: (None if v is None else (v if isinstance(v, (str, dict)) else str(v)))
                           for k, v in o["values"].items()}}
    return {k: o.get(k) for k in ("error", "taky_exit", "taky_output")}


def sc_conf(env):
    sc = env.sc
    base = env.base
    confs = {}
    for tgt in ("py", "rs"):
        for ssl_on in (True, False):
            d = os.path.join(base, f"{tgt}-{'ssl' if ssl_on else 'nossl'}")
            os.makedirs(d)
            args = ["setup", "--host", "srv1", "--public-ip", "127.0.0.1", "--bind-ip", C.IPS["py"]] + \
                   ([] if ssl_on else ["--no-ssl"]) + ["site"]
            rc, _, err = ctl(tgt, args, d)
            check(f"{sc}.setup.{tgt}.{'ssl' if ssl_on else 'nossl'}", f"{tgt} setup {'' if ssl_on else '--no-ssl '}rc 0",
                  rc == 0, err[-300:])
            confs[f"{tgt}-{'ssl' if ssl_on else 'nossl'}"] = os.path.join(d, "site", "taky.conf")
    txt = {k: open(v, encoding="utf8").read() for k, v in confs.items()}
    for m in ("ssl", "nossl"):
        check(f"{sc}.bytes.{m}", f"setup-written taky.conf ({m}) byte-identical py vs rs", txt[f"py-{m}"] == txt[f"rs-{m}"],
              [txt[f"py-{m}"], txt[f"rs-{m}"]])
    cases = {f"setup-{k}": v for k, v in txt.items()}
    for n in ("taky.conf", "taky.conf.sample"):
        cases[f"repo-{n}"] = open(os.path.join(C.TAKY_SRC, n), encoding="utf8").read()
    for k, v in REAL_CONFS.items():
        cases[k] = readme_conf() if v is None else v
    po, ro = load_both(cases, base)
    diff, d13 = {}, {}
    for k in cases:
        a, b = norm_obs(po[k]), norm_obs(ro[k])
        ok = a == b
        if not ok and "error" in a and "error" in b and a["error"] == b["error"] and a["taky_exit"] == b["taky_exit"] \
                and a["taky_output"] == "traceback" and b["taky_output"] in ("message", "config_error_message"):
            ok, d13[k] = True, {"py": a, "rs": b}  # D-13: Python traceback -> Rust 'Configuration file error' line
        if not ok:
            diff[k] = {"py": a, "rs": b}
        check(f"{sc}.load.{k}", f"{k}: normalized config (22 keys + extras, $CFG_DIR-relative) or error class/exit equal"
              + (" (D-13 output)" if k in d13 else ""), ok, {"py": a, "rs": b} if not ok else d13.get(k))
    # servers start from the OTHER version's setup conf (unmodified, cwd = the site)
    starts = {}
    for k, path in confs.items():
        writer, m = k.split("-")
        reader = C.OTHER[writer]
        port = 8089 if m == "ssl" else 8087
        site = os.path.dirname(path)
        try:
            s = Srv("cot", reader, site, C.IPS["py"], port, logdir=base)
            ok = True
            if m == "ssl":  # a real handshake with a client built on that site
                rc, _, _ = ctl(writer, ["-c", "taky.conf", "build_client", "c12"], site)
                crt, key, _ = pem_from_zip(os.path.join(site, "c12.zip"), os.path.join(site, "c12"))
                c = tls_conn(C.IPS["py"], port, os.path.join(site, "ssl", "ca.crt"), crt, key)
                c.sendall(sa("C12-uid", "C12"))
                _, st = read_until(c, None, 1)
                c.close()
                ok = rc == 0 and st == "timeout"
            rc = s.stop()
            starts[k] = [ok, rc]
        except Exception as e:  # noqa: BLE001
            starts[k] = [False, repr(e)[-600:]]
        check(f"{sc}.start.{k}", f"{reader} CoT starts from the {writer}-setup conf ({m}), "
              f"{'TLS client accepted, ' if m == 'ssl' else ''}SIGTERM exit 0", starts[k] == [True, 0], starts[k])
    for k, path in confs.items():  # DPS of the other version too
        writer, m = k.split("-")
        reader = C.OTHER[writer]
        try:
            s = Srv("dps", reader, os.path.dirname(path), C.IPS["py"], 8443 if m == "ssl" else 8080, logdir=base)
            rc = s.stop()
            r = [True, rc == 0]
        except Exception as e:  # noqa: BLE001
            r = [False, repr(e)[-600:]]
        check(f"{sc}.dps.{k}", f"{reader} DPS starts from the {writer}-setup conf ({m})", r == [True, True], r)
    return {"cases": list(cases), "diff": diff, "d13": d13, "py": po, "rs": ro, "starts": starts}


# ----------------------------------------------------------------------------------------------- C13 log_cot
def c13_frames():
    t0 = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None, microsecond=0)
    sa_ev = C.ev("ANDROID-c13", "a-f-G-U-C", t0, 600,
                 '<contact callsign="Alpha" endpoint="*:-1:stcp"/><__group name="Cyan" role="Team Member"/>'
                 '<takv device="qa" platform="ATAK-CIV" os="34" version="4.10"/><track course="1.5" speed="0"/>')
    mk = [C.ev(f"M-c13-{i}", "a-u-G", t0, 600, f'<contact callsign="Маркер {i} &amp; &lt;x&gt;"/>'
               f'<remarks>line1\n  line2 ✓</remarks><link uid="ANDROID-c13" relation="p-p" type="a-f-G-U-C"/>')
          for i in range(3)]
    ping = C.ev("ANDROID-c13-ping", "t-x-c-t", t0, 20, "")
    chat = C.ev("GeoChat.ANDROID-c13.All Chat Rooms.x1", "b-t-f", t0, 600,
                '<__chat parent="RootContactGroup" groupOwner="false" chatroom="All Chat Rooms" id="All Chat Rooms" '
                'senderCallsign="Alpha"><chatgrp uid0="ANDROID-c13" uid1="All Chat Rooms" id="All Chat Rooms"/>'
                '</__chat><remarks source="BAO.F.ATAK.ANDROID-c13" time="2026-10-27T00:00:00.000Z">hi</remarks>')
    anon = [C.ev(f"M-c13-anon-{i}", "b-m-p-s-p-i", t0, 600, f'<contact callsign="P{i}"/>') for i in range(2)]
    return [sa_ev] + mk + [ping, chat], anon


def c13_phase(env, tgt, ident, anon):
    env.start("cot", tgt)
    C.write_events(env, tgt, ident, settle=0.5)
    C.write_events(env, tgt, anon, settle=0.5)
    env.stop("cot", tgt)


def c13_files(d):
    return {n: open(os.path.join(d, n), "rb").read().decode("utf8", "replace") for n in sorted(os.listdir(d))}


def sc_logcot(env):
    sc = env.sc
    ident, anon = c13_frames()
    runs = {}
    for label, seq in (("PRP", ("py", "rs", "py")), ("RPR", ("rs", "py", "rs")), ("PPP", ("py", "py", "py"))):
        d = os.path.join(env.base, f"cot-{label}")
        os.makedirs(d)
        env.extra["log_cot"] = d
        env.redis.c.flushdb()
        sizes = []
        prev = {}
        grow_ok = True
        for tgt in seq:
            c13_phase(env, tgt, ident, anon)
            cur = c13_files(d)
            grow_ok &= all(cur.get(n, "").startswith(v) and len(cur[n]) > len(v) for n, v in prev.items())
            prev = cur
            sizes.append({n: len(v) for n, v in cur.items()})
        runs[label] = {"files": prev, "sizes": sizes, "grow": grow_ok}
        if label != "PPP":
            check(f"{sc}.{label}.append", f"{label}: each later run appends to the files of the earlier run (no truncation, "
                  "earlier content kept as a prefix)", grow_ok, sizes)
    env.extra.pop("log_cot", None)
    ref = runs["PPP"]["files"]
    want_names = ["ANDROID-c13-Alpha.cot", "anonymous-127.0.0.1.cot"]  # client source address (loopback default)
    check(f"{sc}.names", "file names <uid>-<callsign>.cot and anonymous-<ip>.cot (Python-only run)",
          sorted(ref) == sorted(want_names), sorted(ref))
    for label in ("PRP", "RPR"):
        got = runs[label]["files"]
        check(f"{sc}.{label}.bytes", f"{label}: files byte-identical to the Python-only run PPP (lxml pretty-print, ping "
              "not logged)", got == ref, C.same_except(got, ref)[0])
    # simultaneous: both hosts log into one directory (shared NFS-like dir): own anonymous-<ip> files, same uid file
    return {k: {"sizes": v["sizes"], "files": v["files"]} for k, v in runs.items()}


def sc_logcot_sim(env):
    sc = env.sc
    ident, anon = c13_frames()
    d = os.path.join(env.base, "cot-sim")
    os.makedirs(d)
    env.extra["log_cot"] = d
    env.start("cot", "py")
    env.start("cot", "rs")
    C.write_events(env, "py", ident, settle=0.5)
    C.write_events(env, "rs", ident, settle=0.5)
    C.write_events(env, "py", anon, settle=0.5)
    C.write_events(env, "rs", anon, settle=0.5)
    env.stop_all()
    files = c13_files(d)
    one = None
    for k in list(env.srv):
        env.stop(*k)
    # reference: Python alone, same inputs, twice into one directory (alternate on its own ip)
    dr = os.path.join(env.base, "cot-sim-ref")
    os.makedirs(dr)
    env.extra["log_cot"] = dr
    env.start("cot", "py")
    C.write_events(env, "py", ident, settle=0.5)
    env.stop("cot", "py")
    env.start("cot", "py")
    C.write_events(env, "py", ident, settle=0.5)
    C.write_events(env, "py", anon, settle=0.5)
    env.stop("cot", "py")
    env.start("cot", "py")
    C.write_events(env, "py", anon, settle=0.5)
    env.stop("cot", "py")
    one = c13_files(dr)
    env.extra.pop("log_cot", None)
    check(f"{sc}.sim.uid-file", "simultaneous: the shared <uid>-<callsign>.cot holds P's then R's records == Python "
          "writing the same twice", files.get("ANDROID-c13-Alpha.cot") == one.get("ANDROID-c13-Alpha.cot"),
          [len(files.get("ANDROID-c13-Alpha.cot", "")), len(one.get("ANDROID-c13-Alpha.cot", ""))])
    check(f"{sc}.sim.all", "simultaneous: both hosts append to the same anonymous-<client ip>.cot too; whole directory "
          "== Python writing the same inputs twice", files == one, C.same_except(files, one)[0])
    return {"files": sorted(files)}


# ----------------------------------------------------------------------------------------------- C14 drop-in
C14_IP = "127.0.0.10"


def snap_tree(*roots):
    out = {}
    for root in roots:
        for d, dirs, files in os.walk(root):
            for n in sorted(dirs + files):
                p = os.path.join(d, n)
                st = os.lstat(p)
                if os.path.islink(p):
                    out[p] = ["l", os.readlink(p)]
                elif os.path.isdir(p):
                    out[p] = ["d", oct(st.st_mode & 0o7777)]
                elif os.path.isfile(p):
                    out[p] = ["f", oct(st.st_mode & 0o7777), hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]]
                else:
                    out[p] = ["s", oct(st.st_mode & 0o7777)]
    return out


def c14_worker(out_dir, redis_url):
    """Runs inside `unshare -m` (root): overlayfs over /etc and /var; results -> <out_dir>/result.json."""
    checks = []

    def ck(cid, desc, ok, detail=None):
        checks.append({"id": f"C14.{cid}", "desc": desc, "ok": bool(ok), "detail": detail})
        print(f"  {'PASS' if ok else 'FAIL'} C14.{cid}: {desc}", flush=True)
        return ok

    ov = os.path.join(out_dir, "ov")
    for d in ("etc-u", "etc-w", "var-u", "var-w"):
        os.makedirs(os.path.join(ov, d), exist_ok=True)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    for m in ("etc", "var"):
        subprocess.run(["mount", "-t", "overlay", "overlay", "-o",
                        f"lowerdir=/{m},upperdir={ov}/{m}-u,workdir={ov}/{m}-w", f"/{m}"], check=True)
    pre = os.path.exists("/etc/taky") or os.path.exists("/var/taky")
    ck("ns.clean", "inside the namespace /etc/taky and /var/taky start absent", not pre)
    work = os.path.join(out_dir, "work")  # cwd of the CLI (client zips land here)
    run = os.path.join(out_dir, "run")  # cwd of the servers: no taky.conf -> default lookup /etc/taky/taky.conf
    os.makedirs(work)
    os.makedirs(run)
    procs = []
    data = {}

    def up(tgt):
        s = {}
        for kind, port in (("cot", 8089), ("dps", 8443)):
            s[kind] = Srv(kind, tgt, run, C14_IP, port, conf=None, logdir=out_dir)
            procs.append(s[kind])
        return s

    try:
        # --- Python production install (system mode) + operator's Redis choice, as in README_DEPLOYMENT step 3
        rc, out, err = ctl("py", ["setup", "--host", "srv1", "--public-ip", "203.0.113.9", "--bind-ip", C14_IP], work)
        ck("py.setup", "Python `takyctl setup` (system mode) rc 0", rc == 0, err[-500:])
        conf = open("/etc/taky/taky.conf", encoding="utf8").read()
        conf = conf.replace("\nredis\n", f"\nredis = {redis_url}\n", 1)
        with open("/etc/taky/taky.conf", "w", encoding="utf8") as f:
            f.write(conf)
        ca = "/etc/taky/ssl/ca.crt"
        cl = {}
        for n in ("alpha", "bravo", "charlie"):
            rc, _, err = ctl("py", ["build_client", n], work)
            ck(f"py.build.{n}", f"Python build_client {n} (system cert-db, no -c) rc 0", rc == 0, err[-300:])
            cl[n] = pem_from_zip(os.path.join(work, f"{n}.zip"), os.path.join(work, n))
        py = up("py")
        a, b, d = cot_pair(C14_IP, 8089, ca, ("alpha", *cl["alpha"][:2]), ("bravo", *cl["bravo"][:2]))
        ck("py.cot", "Python taky (no -c): alpha <-> bravo delivered", a and b, d)
        s = tls_conn(C14_IP, 8089, ca, *cl["alpha"][:2])
        marker = C.ev("M-c14-marker", "a-u-G", dt.datetime.now(dt.timezone.utc).replace(tzinfo=None), 3600,
                      '<contact callsign="Marker C14"/>')
        s.sendall(sa("ANDROID-alpha", "ALPHA", stale=3600) + marker)
        time.sleep(0.8)
        s.close()
        pkg = os.urandom(5000) + b"c14"
        h = hashlib.sha256(pkg).hexdigest()
        body, ct = multipart("c14 pkg.zip", pkg)
        q = "/Marti/sync/missionupload?" + urllib.parse.urlencode({"hash": h, "filename": "c14 pkg",
                                                                  "creatorUid": "ANDROID-alpha"})
        r = https(C14_IP, 8443, ca, *cl["alpha"][:2], "POST", q, body, ct)
        r2 = https(C14_IP, 8443, ca, *cl["alpha"][:2], "PUT", f"/Marti/api/sync/metadata/{h}/tool", b"public")
        r3 = https(C14_IP, 8443, ca, *cl["alpha"][:2], "POST", "/Marti/vcm", VCM_B, "application/xml")
        ck("py.dps", "Python taky_dps (no -c): upload 200, tool public 200, vcm 200", r[0] == r2[0] == r3[0] == 200,
           [r[0], r[2][:200].decode("utf8", "replace"), r2[0], r3[0]])
        q_py = {"search": https(C14_IP, 8443, ca, *cl["bravo"][:2], "GET",
                                "/Marti/sync/search?keywords=missionpackage&tool=public"),
                "content": https(C14_IP, 8443, ca, *cl["bravo"][:2], "GET", f"/Marti/sync/content?hash={h}"),
                "vcm": https(C14_IP, 8443, ca, *cl["bravo"][:2], "GET", "/Marti/vcm")}
        rc, out, _ = ctl("py", ["kickban", "charlie"], work)
        ck("py.kickban", "Python takyctl kickban charlie (no -c, default socket) -> revoked", rc == 0 and
           out.startswith("Revoked certificate SNs for charlie:"), out)
        s = tls_conn(C14_IP, 8089, ca, *cl["bravo"][:2])
        _, st = read_until(s, b"M-c14-marker", 3)
        s.close()
        ck("py.persist", "Python: a new bravo connection gets the persisted marker (Redis)", st == "found", st)
        for k, sv in py.items():
            rc = sv.stop()
            ck(f"py.{k}.stop", f"Python {k} SIGTERM -> exit 0", rc == 0, rc)
        t1 = snap_tree("/etc/taky", "/var/taky")
        # --- drop-in: Rust binaries, same tree, no migration, no -c
        rs = up("rs")
        rep = tls_conn(C14_IP, 8089, ca, *cl["bravo"][:2])
        buf, st = read_until(rep, b"M-c14-marker", 4)
        buf2, _ = read_until(rep, None, 0.8)
        rep.close()
        allb = buf + buf2
        ck("rs.persist", "taky-rs: bravo (Python-issued p12) connects and gets the Python-persisted SA + marker replay",
           st == "found" and b'uid="ANDROID-alpha"' in allb, [st, len(allb)])
        a, b, d = cot_pair(C14_IP, 8089, ca, ("alpha", *cl["alpha"][:2]), ("bravo", *cl["bravo"][:2]))
        ck("rs.cot", "taky-rs: alpha <-> bravo delivered with the same p12", a and b, d)
        r_, d_ = refused(C14_IP, 8089, ca, *cl["charlie"][:2])
        ck("rs.banned", "taky-rs: charlie (revoked by the Python server) refused", r_, d_)
        q_rs = {"search": https(C14_IP, 8443, ca, *cl["bravo"][:2], "GET",
                                "/Marti/sync/search?keywords=missionpackage&tool=public"),
                "content": https(C14_IP, 8443, ca, *cl["bravo"][:2], "GET", f"/Marti/sync/content?hash={h}"),
                "vcm": https(C14_IP, 8443, ca, *cl["bravo"][:2], "GET", "/Marti/vcm")}

        def nsearch(x):
            j = json.loads(x[2])
            for m in j.get("results", []):
                m["SubmissionDateTime"] = "$TS"
            return x[0], j

        ck("rs.dps.search", "taky_dps-rs: search == Python's (package uploaded by Python, public)",
           nsearch(q_rs["search"]) == nsearch(q_py["search"]), [q_py["search"][2][:300], q_rs["search"][2][:300]])
        ck("rs.dps.content", "taky_dps-rs: content of the Python-uploaded package byte-exact",
           q_rs["content"][0] == 200 and q_rs["content"][2] == pkg, q_rs["content"][0])
        ck("rs.dps.vcm", "taky_dps-rs: /Marti/vcm == Python's", q_rs["vcm"][:1] + (q_rs["vcm"][2],) ==
           q_py["vcm"][:1] + (q_py["vcm"][2],), [q_py["vcm"][2][:300], q_rs["vcm"][2][:300]])
        st_c = https(C14_IP, 8443, ca, *cl["charlie"][:2], "GET", "/Marti/api/clientEndPoints")[0]
        ck("rs.dps.banned", "taky_dps-rs: charlie -> 403", st_c == 403, st_c)
        pkg2 = os.urandom(3000) + b"rs"
        h2 = hashlib.sha256(pkg2).hexdigest()
        body, ct = multipart("rs pkg.zip", pkg2)
        q = "/Marti/sync/missionupload?" + urllib.parse.urlencode({"hash": h2, "filename": "rs pkg",
                                                                  "creatorUid": "ANDROID-bravo"})
        ru = https(C14_IP, 8443, ca, *cl["bravo"][:2], "POST", q, body, ct)
        ck("rs.dps.upload", "taky_dps-rs: new upload into the Python upload_path 200", ru[0] == 200, ru[0])
        rc, out, err = ctl("rs", ["status"], work)
        ck("rs.status", "takyctl-rs status (no -c, default lookup + socket) rc 0", rc == 0 and "Uptime:" in out,
           [rc, out[-300:], err[-300:]])
        rc, _, err = ctl("rs", ["build_client", "delta"], work)
        cl["delta"] = pem_from_zip(os.path.join(work, "delta.zip"), os.path.join(work, "delta")) if rc == 0 else None
        a, b, d = cot_pair(C14_IP, 8089, ca, ("delta", *cl["delta"][:2]), ("alpha", *cl["alpha"][:2])) if cl[
            "delta"] else (False, False, err)
        ck("rs.build", "takyctl-rs build_client delta on the Python site; delta <-> alpha delivered on taky-rs",
           a and b, d)
        logs = {k: sv.text() for k, sv in rs.items()}
        ck("rs.logs", "taky-rs / taky_dps-rs logs: no ERROR/panic, no 'Purging key'",
           not any(re.search(r"ERROR|panicked|Purging key", t) for t in logs.values()),
           [ln for t in logs.values() for ln in t.splitlines() if re.search(r"ERROR|panicked|Purging", ln)][:6])
        for k, sv in rs.items():
            rc = sv.stop()
            ck(f"rs.{k}.stop", f"Rust {k} SIGTERM -> exit 0", rc == 0, rc)
        t2 = snap_tree("/etc/taky", "/var/taky")
        changed = sorted(p for p in set(t1) | set(t2) if t1.get(p) != t2.get(p))
        allowed = re.compile(r"^(/etc/taky/ssl/cert-db\.txt(\.lock)?|/var/taky/taky-mgmt\.sock|/var/taky/dp-user/(meta/)?[^/]*(rs pkg|rs_pkg|"
                             + h2 + r")[^/]*|/var/taky/dp-user/meta)$")
        unexpected = [p for p in changed if not allowed.match(p)]
        ck("tree", "only the expected files changed under /etc/taky + /var/taky (cert-db line for delta, its lock, "
           "the new upload); taky.conf, ssl/*, Python uploads, video_feed untouched", not unexpected,
           {"unexpected": [[p, t1.get(p), t2.get(p)] for p in unexpected], "changed": changed})
        db = certdb_lines("/etc/taky/ssl/cert-db.txt")
        ck("certdb", "cert-db: srv1, alpha, bravo, charlie(R), delta in order, DC §5 format",
           [ln.rstrip("\n").split("\t")[-1] for ln in db] == ["srv1", "alpha", "bravo", "charlie", "delta"] and
           [ln[0] for ln in db] == ["V", "V", "V", "R", "V"] and all(CERTDB_LINE.match(ln) for ln in db), db)
        # --- and back: Python again on the tree Rust used (rollback)
        py = up("py")
        a, b, d = cot_pair(C14_IP, 8089, ca, ("delta", *cl["delta"][:2]), ("bravo", *cl["bravo"][:2]))
        ck("back.cot", "rollback: Python taky accepts the Rust-issued delta (delta <-> bravo)", a and b, d)
        r_, d_ = refused(C14_IP, 8089, ca, *cl["charlie"][:2])
        ck("back.banned", "rollback: Python taky still refuses charlie", r_, d_)
        rs2 = https(C14_IP, 8443, ca, *cl["alpha"][:2], "GET", f"/Marti/sync/content?hash={h2}")
        ck("back.dps", "rollback: Python taky_dps serves the package uploaded by Rust", rs2[0] == 200 and rs2[2] == pkg2,
           rs2[0])
        for k, sv in py.items():
            sv.stop()
        data = {"t1": t1, "t2": t2, "changed": changed, "certdb": db}
    except Exception as e:  # noqa: BLE001
        import traceback

        ck("worker", "C14 worker ran without an exception", False, traceback.format_exc()[-3000:])
    finally:
        for sv in procs:
            C.stop_proc(sv.p, 5)
    with open(os.path.join(out_dir, "result.json"), "w", encoding="utf8") as f:
        json.dump({"checks": checks, "data": data}, f, default=str)


def sc_dropin(env):
    sc = env.sc
    if os.geteuid() != 0 or not shutil.which("unshare"):
        check(f"{sc}.env", "needs root + unshare (mount namespace + overlayfs)", False)
        return None
    for port in (8089, 8087, 8443):
        if C.listening(C14_IP, port):
            check(f"{sc}.ports", f"{C14_IP}:{port} busy", False)
            return None
    host_pre = os.path.exists("/etc/taky") or os.path.exists("/var/taky")
    cmd = ["unshare", "-m", C.PY, "-B", "-I", "-W", "ignore", os.path.abspath(__file__), "c14-worker", env.base,
           env.redis.url]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       env=dict(os.environ, PYTHONPATH=os.pathsep.join([C.TAKY_SRC, HERE])))
    print(p.stdout[-6000:], p.stderr[-3000:] if p.returncode else "", flush=True)
    try:
        res = json.load(open(os.path.join(env.base, "result.json")))
    except OSError as e:
        check(f"{sc}.worker", "namespace worker produced a result", False, [repr(e), p.stderr[-2000:]])
        return None
    C.CHECKS.extend(res["checks"])
    check(f"{sc}.host-untouched", "host /etc/taky and /var/taky still absent after the run",
          not host_pre and not os.path.exists("/etc/taky") and not os.path.exists("/var/taky"))
    return res["data"]


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "c14-worker":
        sys.exit(c14_worker(sys.argv[2], sys.argv[3]) or 0)
    sys.exit(2)
