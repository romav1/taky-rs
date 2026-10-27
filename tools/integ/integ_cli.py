"""S-404 (T-31 part 2) CLI integration group for tools/integ: system-mode site (no `path`) for Python takyctl vs
takyctl-rs, without touching the host's /etc and /var.

Each target runs in its own mount namespace (`unshare -m`, needs root) with overlayfs over /etc and /var (upper dirs in
$S403_TMP/cli/<tgt>), so `setup` really writes /etc/taky/taky.conf, /etc/taky/ssl/*, /var/taky/dp-user, and the servers
and CLI then find the config through the default lookup (./taky.conf -> /etc/taky/taky.conf, no -c, no TAKY_CONFIG).
Inside: setup, second setup (refusal), taky + taky_dps without -c, `status`/`status -j`/`kickban -j` without -c
(own server and cross: each CLI against the other language's server is not possible here - one namespace per
target - so it is own-language only; cross CLI x server is covered by takyctl/tests/pyref_mgmt.rs), `build_client`
(system cert-db), `systemd --no-install --path` (system-wide detection). Results are compared in the parent.
Not covered by S-322/S-323/S-324 (they use directory sites or a fake root inside the unit test).
"""

import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time

BIND = "127.0.0.6"  # both targets run sequentially on the same address so that taky.conf is byte-comparable
H = None


def _run(cmd, cwd, env, timeout=60):
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, timeout=timeout)
    return {"rc": p.returncode, "out": p.stdout.decode("utf8", "replace"), "err": p.stderr.decode("utf8", "replace")}


def _tree(*roots):
    rows = []
    for root in roots:
        for dp, dns, fns in os.walk(root):
            for n in sorted(dns + fns):
                p = os.path.join(dp, n)
                st = os.lstat(p)
                kind = "d" if os.path.isdir(p) else ("l" if os.path.islink(p) else "f")
                rows.append(f"{p} {kind} {oct(st.st_mode & 0o7777)}")
    return sorted(rows)


def _listening(port, t=0.3):
    try:
        socket.create_connection((BIND, port), t).close()
        return True
    except OSError:
        return False


def _wait(pred, timeout=30):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if pred():
            return True
        time.sleep(0.1)
    return False


def worker(tgt, out_dir, rs_root, taky_src, py):
    """Runs inside `unshare -m` as root. Writes <out_dir>/result.json."""
    up = os.path.join(out_dir, "ov")
    for d in ("etc-u", "etc-w", "var-u", "var-w"):
        os.makedirs(os.path.join(up, d), exist_ok=True)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    for m in ("etc", "var"):
        subprocess.run(["mount", "-t", "overlay", "overlay", "-o",
                        f"lowerdir=/{m},upperdir={up}/{m}-u,workdir={up}/{m}-w", f"/{m}"], check=True)
    res = {"pre_exists": os.path.exists("/etc/taky") or os.path.exists("/var/taky")}
    cwd = os.path.join(out_dir, "cwd")
    os.makedirs(cwd, exist_ok=True)
    env = dict(os.environ)
    env.pop("TAKY_CONFIG", None)
    env["TZ"] = "UTC"
    if tgt == "py":
        env["PYTHONPATH"] = taky_src
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        ctl = [py, "-I", "-B", "-W", "ignore", os.path.join(rs_root, "crates/takyctl/tests/pyref/takyctl.py"),
               taky_src]
        cot = [py, "-B", "-W", "ignore", "-c",
               'import sys; sys.argv[0] = "taky"; from taky.cot.__main__ import main; main()']
        dps = [py, "-B", "-W", "ignore", "-c",
               'import sys; sys.argv[0] = "taky_dps"; from taky.dps.__main__ import main; main()']
    else:
        b = os.path.join(rs_root, "target", "debug")
        ctl, cot, dps = [os.path.join(b, "takyctl-rs")], [os.path.join(b, "taky-rs")], [os.path.join(b, "taky_dps-rs")]
    procs = []
    try:
        res["setup"] = _run(ctl + ["setup", "--public-ip", "203.0.113.9", "--host", "srv1", "--bind-ip", BIND], cwd, env)
        res["tree"] = _tree("/etc/taky", "/var/taky")
        try:
            res["conf"] = open("/etc/taky/taky.conf").read()
        except OSError as e:
            res["conf"] = repr(e)
        try:
            res["certdb_lines"] = len(open("/etc/taky/ssl/cert-db.txt").read().splitlines())
        except OSError:
            res["certdb_lines"] = None
        res["setup2"] = _run(ctl + ["setup", "--public-ip", "203.0.113.9", "--host", "srv1"], cwd, env)

        # servers without -c: default lookup must find /etc/taky/taky.conf (cwd has no taky.conf)
        for name, cmd, port in (("cot", cot, 8089), ("dps", dps, 8443)):
            lf = open(os.path.join(out_dir, f"{name}.log"), "wb")
            p = subprocess.Popen(cmd + ["-l", "info"], cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=lf,
                                 stderr=subprocess.STDOUT, start_new_session=True)
            procs.append(p)
            res[f"{name}_up"] = _wait(lambda: _listening(port) or p.poll() is not None) and _listening(port)
        res["mgmt_sock"] = _wait(lambda: os.path.exists("/var/taky/taky-mgmt.sock"), 10)
        time.sleep(0.6)  # Python: let it reap the readiness probes (B3/V046)
        res["status"] = _run(ctl + ["status"], cwd, env)
        res["status_j"] = _run(ctl + ["status", "-j"], cwd, env)
        res["build_client"] = _run(ctl + ["build_client", "alice"], cwd, env)
        res["zips"] = sorted(x for x in os.listdir(cwd) if x.endswith(".zip"))
        try:
            res["certdb_after"] = [ln.split("\t")[0] + ":" + ln.split("\t")[-1].strip()
                                   for ln in open("/etc/taky/ssl/cert-db.txt").read().splitlines()]
        except OSError:
            res["certdb_after"] = None
        # DPS over TLS with the system server cert, unauthenticated endpoint
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.load_verify_locations("/etc/taky/ssl/ca.crt")
        c.check_hostname = False
        try:
            import http.client
            h = http.client.HTTPSConnection(BIND, 8443, timeout=10, context=c)
            h.request("GET", "/Marti/api/version/config")
            r = h.getresponse()
            res["dps_vconfig"] = [r.status, r.read().decode()]
        except Exception as e:  # noqa: BLE001 - recorded as the observation
            res["dps_vconfig"] = [repr(e)]
        res["kickban_j"] = _run(ctl + ["kickban", "-j", "alice"], cwd, env)
        try:
            res["certdb_kick"] = [ln.split("\t")[0] + ":" + ln.split("\t")[-1].strip()
                                  for ln in open("/etc/taky/ssl/cert-db.txt").read().splitlines()]
        except OSError:
            res["certdb_kick"] = None
        # systemd: system-wide detection from the real config path; log_cot set (Python needs it, D-16)
        conf = open("/etc/taky/taky.conf").read()
        open("/etc/taky/taky.conf", "w").write(conf.replace("log_cot\n", "log_cot = /var/taky/cot.log\n"))
        units = os.path.join(out_dir, "units")
        shutil.rmtree(units, ignore_errors=True)
        os.makedirs(units)
        res["systemd"] = _run(ctl + ["systemd", "--no-install", "--path", units], cwd, env)
        res["units"] = {n: open(os.path.join(units, n)).read() for n in sorted(os.listdir(units))}
    finally:
        for p in procs:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGTERM)
                try:
                    p.wait(10)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait(5)
        res["exit"] = [p.returncode for p in procs]
        res["sock_after_stop"] = os.path.exists("/var/taky/taky-mgmt.sock")
        json.dump(res, open(os.path.join(out_dir, "result.json"), "w"), indent=1)


# ----------------------------------------------------------------------------------------------- parent side
def _mask(s):
    s = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<UUID>", s)
    s = re.sub(r"\d+\.\d+", "<F>", s)
    return s


def _unit_shape(text):
    """Keys present per section (values differ by design: names, ExecStart, Conflicts - S-324 §4)."""
    out, sec = [], None
    for ln in text.splitlines():
        if ln.startswith("["):
            sec = ln
            out.append(sec)
        elif "=" in ln:
            out.append(f"  {ln.split('=', 1)[0]}")
    return out


def g_cli(h):
    global H
    H = h
    row = "CLI-system"
    if os.geteuid() != 0 or not shutil.which("unshare"):
        H.rec(row, "cli.env", "needs root + unshare (mount namespace + overlayfs)", None, None, False)
        return
    for port in (8089, 8443):
        if H.listening(BIND, port):
            H.rec(row, "cli.ports", f"{BIND}:{port} busy", None, None, False)
            return
    res = {}
    for t in H.TGTS:  # sequential: same bind address
        d = os.path.join(H.TMP, "cli", t)
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
        cmd = ["unshare", "-m", H.PY, "-B", "-I", os.path.abspath(__file__), "worker", t, d, H.RS_ROOT, H.TAKY_SRC,
               H.PY]
        p = subprocess.run(cmd, capture_output=True, timeout=300)
        if p.returncode != 0:
            print(p.stdout.decode()[-2000:], p.stderr.decode()[-2000:], flush=True)
        try:
            res[t] = json.load(open(os.path.join(d, "result.json")))
        except OSError as e:
            H.rec(row, f"cli.{t}.worker", "namespace worker produced no result", repr(e), None, False)
            return
    P, R = res["py"], res["rs"]
    host_clean = not os.path.exists("/etc/taky") and not os.path.exists("/var/taky")
    H.rec(row, "host-untouched", "host /etc/taky and /var/taky still absent; overlay started empty",
          P["pre_exists"], R["pre_exists"], host_clean and not P["pre_exists"] and not R["pre_exists"])
    o = {t: (res[t]["setup"]["rc"], res[t]["setup"]["out"], res[t]["setup"]["err"]) for t in H.TGTS}
    H.same(row, "setup.output", "system setup: rc, stdout, stderr", o)
    H.both(row, "setup.rc", "system setup rc 0", {t: o[t][0] for t in H.TGTS}, 0)
    H.same(row, "setup.conf", "/etc/taky/taky.conf byte-identical", {t: res[t]["conf"] for t in H.TGTS})
    tree = {t: [x for x in res[t]["tree"] if not x.startswith("/etc/taky/ssl/cert-db.txt.lock")] for t in H.TGTS}
    H.same(row, "setup.tree", "/etc/taky + /var/taky tree (type, mode), minus cert-db.txt.lock (ADR-003)", tree)
    H.both(row, "setup.certdb", "cert-db.txt has 1 line (server)", {t: res[t]["certdb_lines"] for t in H.TGTS}, 1)
    o = {t: (res[t]["setup2"]["rc"], res[t]["setup2"]["out"], res[t]["setup2"]["err"]) for t in H.TGTS}
    H.same(row, "setup.again", "second system setup: refusal rc/stdout/stderr", o)
    H.both(row, "lookup.cot", "taky without -c finds /etc/taky/taky.conf, listens :8089",
           {t: res[t]["cot_up"] for t in H.TGTS}, True)
    H.both(row, "lookup.mgmt", "mgmt socket at /var/taky/taky-mgmt.sock (root_dir default)",
           {t: res[t]["mgmt_sock"] for t in H.TGTS}, True)
    H.both(row, "lookup.dps", "taky_dps without -c listens :8443", {t: res[t]["dps_up"] for t in H.TGTS}, True)
    H.same(row, "dps.vconfig", "DPS TLS (system server cert verifies vs /etc/taky/ssl/ca.crt): version/config",
           {t: [res[t]["dps_vconfig"][0], re.sub(r"taky-(rs-)?[^\"]*", "taky-$V", "".join(
               map(str, res[t]["dps_vconfig"][1:])))] for t in H.TGTS})
    o = {t: (res[t]["status"]["rc"], _mask(res[t]["status"]["out"]), res[t]["status"]["err"]) for t in H.TGTS}
    H.same(row, "status", "status without -c (socket from /etc/taky/taky.conf root_dir)", o)
    o = {t: (res[t]["status_j"]["rc"], _mask(res[t]["status_j"]["out"])) for t in H.TGTS}
    H.same(row, "status.json", "status -j without -c: rc + JSON text (floats masked)", o)
    o = {t: (res[t]["build_client"]["rc"], _mask(res[t]["build_client"]["out"]), res[t]["build_client"]["err"])
         for t in H.TGTS}
    H.same(row, "build_client", "build_client alice (system site): rc/stdout/stderr", o)
    H.same(row, "build_client.zip", "one alice-<uuid>? zip in cwd", {t: [_mask(z) for z in res[t]["zips"]] for t in H.TGTS})
    H.same(row, "build_client.certdb", "cert-db after build_client", {t: res[t]["certdb_after"] for t in H.TGTS})
    # Python's CoT server reads cert-db once at startup (B5): a client issued later by build_client is unknown to it
    o = {t: (res[t]["kickban_j"]["rc"], re.sub(r"\d+", "<N>", res[t]["kickban_j"]["out"]), res[t]["certdb_kick"])
         for t in H.TGTS}
    H.expect(row, "kickban.after-build_client", "kickban -j alice (cert issued after server start): rc, JSON, cert-db",
             o, (0, '{"revoked_sns": []}\n', ["V:srv1", "V:alice"]),
             (0, '{"revoked_sns": [<N>]}\n', ["V:srv1", "R:alice"]),
             "D-11 (B5 closed): Rust re-reads cert-db by mtime; Python keeps the startup copy and revokes nothing")
    so = {t: res[t]["systemd"] for t in H.TGTS}
    H.both(row, "systemd.rc", "systemd --no-install rc 0", {t: so[t]["rc"] for t in H.TGTS}, 0)
    H.same(row, "systemd.stderr", "systemd: root warning on stderr", {t: so[t]["err"] for t in H.TGTS})
    mode = {t: ([ln.strip() for ln in so[t]["out"].splitlines() if "Detected" in ln and "virtualenv" not in ln],
                sorted(res[t]["units"]),
                [ln for v in res[t]["units"].values() for ln in v.splitlines() if ln.startswith("WorkingDirectory")])
            for t in H.TGTS}
    H.expect(row, "systemd.mode", "system site (/etc/taky/taky.conf): mode line, unit names, WorkingDirectory", mode,
             (["- Detected site install: /var/taky"], ["taky-srv1-cot.service", "taky-srv1-dps.service",
                                                      "taky-srv1.service"],
              ["WorkingDirectory=/var/taky", "WorkingDirectory=/var/taky"]),
             (["- Detected system-wide site install"], ["taky-rs-cot.service", "taky-rs-dps.service", "taky-rs.service"],
              []),
             "D-16 / OQ-L1: Python cfg_path = log_cot value (DC 1.5) -> never system mode, WorkingDirectory=dirname(log_cot)")
    H.both(row, "stop", "servers stopped (SIGTERM rc 0), mgmt socket removed",
           {t: (res[t]["exit"], res[t]["sock_after_stop"]) for t in H.TGTS}, ([0, 0], False))


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "worker":
    worker(*sys.argv[2:7])
