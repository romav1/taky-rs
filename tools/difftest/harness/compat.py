"""
difftest compat — data compatibility scenarios (qa01, S-405 / S-406, T-33; test-strategy §1.5 L5).

    tools/difftest/difftest compat C1                 # one scenario, default mode
    tools/difftest/difftest compat all                # C1..C14
    tools/difftest/difftest compat C6 --mode simultaneous

The ORIGINAL Python taky / taky_dps (read-only ../taky, `python -B`, DPS through the gunicorn path exactly like
`python -m taky.dps`) and the shipped taky-rs / taky_dps-rs binaries (default target/debug, TAKY_RS_BIN /
TAKY_DPS_RS_BIN override) work on the SAME data: one real redis-server (127.0.0.8:16380, db 0) and one upload_path.
Modes (test-strategy §1.5):
  alternate     the processes run one after the other on the same host: same bind_ip (127.0.0.8), same root_dir,
                same taky.conf file (ADR-000 item 1). Starting one version stops the other.
  simultaneous  both run at once as two "hosts": Python 127.0.0.8, Rust 127.0.0.9, own root_dir each, shared Redis
                and upload_path, same `hostname` (= same Redis keyspace).
CoT runs plain TCP (ssl.enabled = false, port 18087), DPS plain HTTP (product port 8080, X-USER from loopback).
Scenarios:
  C1 Redis replay P->R      C2 Redis replay R->P      C3 alternating P->R->P on the same uids + TTL (+ max_persist_ttl)
  C4 P and R simultaneously, same hostname (+ MONITOR: D-4 SET EX / D-5 SCAN)  [always simultaneous]
  C5 foreign keyspace + broken values: purge only the own keyspace (V043); hostname with glob characters
  C6 DPS upload_path P -> R -> P: search/content/missionquery/tool, meta JSON + symlinks rewritten by the other
  C7 DPS upload_path R -> P incl. re-upload with the same UID and a new hash (PP/RR/RP/PR file trees)
  C8..C14 (video_feed, cert-db mixed writers / 100 alternating writes, certificate 4x2 matrix, taky.conf both ways,
  log_cot alternating, drop-in of a Python system site): compat2.py (S-406). C9-C12/C14 run once (mode "single"),
  C13 alternate (simultaneous = both hosts log into one directory), C8 both modes.
Opt-in (not part of scripts/check.sh). Results: <taky-rs>/target/qa/difftest/compat-<scenario>.json; exit 1 on FAIL.
Every started server and the redis-server are stopped (SIGTERM to the process group, then SIGKILL).
"""
import argparse
import datetime as dt
import hashlib
import http.client
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TAKYRS = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
OFFICE = os.path.dirname(TAKYRS)
TAKY_SRC = os.path.abspath(os.environ.get("TAKY_SRC", os.path.join(OFFICE, "taky")))
RS_COT = os.environ.get("TAKY_RS_BIN", os.path.join(TAKYRS, "target", "debug", "taky-rs"))
RS_DPS = os.environ.get("TAKY_DPS_RS_BIN", os.path.join(TAKYRS, "target", "debug", "taky_dps-rs"))
TMP = os.environ.get("S405_TMP", "/tmp/s405-compat")
REPORT = os.path.join(TAKYRS, "target", "qa", "difftest")
PY = sys.executable
IPS = {"py": "127.0.0.8", "rs": "127.0.0.9"}
COT_PORT, DPS_PORT, REDIS_PORT = 18087, 8080, 16380
HOSTNAME = "compat.example"
HOST_HDR = "taky.example:8080"
PY_COT = 'import sys; sys.argv[0] = "taky"; from taky.cot.__main__ import main; main()'
PY_DPS = 'import sys; sys.argv[0] = "taky_dps"; from taky.dps.__main__ import main; main()'
SCENARIOS = ("C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13", "C14")
SINGLE = ("C9", "C10", "C11", "C12", "C14")  # no alternate/simultaneous variant (own process layout)
OTHER = {"py": "rs", "rs": "py"}

CHECKS = []
PROCS = []


def check(cid, desc, ok, detail=None):
    CHECKS.append({"id": cid, "desc": desc, "ok": bool(ok), "detail": detail})
    print(f"  {'PASS' if ok else 'FAIL'} {cid}: {desc}" + ("" if ok or detail is None else f"\n       {_short(detail)}"),
          flush=True)
    return ok


def _short(v, n=900):
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str)
    return s if len(s) <= n else s[:n] + "..."


def diff_lists(a, b):
    """First differences of two sorted lists (for check details)."""
    sa, sb = sorted(a), sorted(b)
    if sa == sb:
        return None
    return {"only_a": [x for x in sa if x not in sb][:5], "only_b": [x for x in sb if x not in sa][:5],
            "len": [len(sa), len(sb)]}


# ----------------------------------------------------------------------------------------------- processes
def listening(ip, port, timeout=0.3):
    try:
        socket.create_connection((ip, port), timeout).close()
        return True
    except OSError:
        return False


def stop_proc(p, timeout=12):
    if p is None or p.poll() is not None:
        return None if p is None else p.poll()
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        rc = p.wait(timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait(5)
        rc = "killed"
    try:
        os.killpg(p.pid, signal.SIGKILL)  # gunicorn worker stragglers
    except (ProcessLookupError, PermissionError):
        pass
    return rc


class Redis:
    def __init__(self, d):
        self.d = d
        os.makedirs(d, exist_ok=True)
        exe = shutil.which("redis-server")
        if not exe:
            raise SystemExit("redis-server not found")
        self.p = subprocess.Popen([exe, "--bind", IPS["py"], "--port", str(REDIS_PORT), "--save", "",
                                   "--appendonly", "no", "--dir", d],
                                  stdout=open(os.path.join(d, "redis.log"), "wb"), stderr=subprocess.STDOUT,
                                  start_new_session=True)
        PROCS.append(self.p)
        t0 = time.time()
        while not listening(IPS["py"], REDIS_PORT):
            if time.time() - t0 > 10 or self.p.poll() is not None:
                raise SystemExit("redis-server did not start")
            time.sleep(0.05)
        import redis

        self.c = redis.StrictRedis(host=IPS["py"], port=REDIS_PORT, db=0)
        self.url = f"redis://{IPS['py']}:{REDIS_PORT}/0"

    def snapshot(self, prefix="taky:"):
        """{key: {"value": str|type, "ttl": int}} of every key under prefix."""
        out = {}
        for k in sorted(self.c.keys(prefix + "*")):
            t = self.c.type(k).decode()
            ks = k.decode("utf8", "replace")
            v = self.c.get(k).decode("utf8", "replace") if t == "string" else f"<{t}>"
            out[ks] = {"value": v, "ttl": self.c.ttl(k)}
        return out

    def stop(self):
        stop_proc(self.p)


class Monitor:
    """Raw MONITOR connection; lines collected by a thread (`+ts [db ip:port] "CMD" "arg" ...`)."""

    def __init__(self):
        self.s = socket.create_connection((IPS["py"], REDIS_PORT), 5)
        self.s.sendall(b"MONITOR\r\n")
        self.lines = []
        self.stop_ev = threading.Event()
        self.th = threading.Thread(target=self._run, daemon=True)
        self.th.start()
        time.sleep(0.2)

    def _run(self):
        buf = b""
        self.s.settimeout(0.2)
        while not self.stop_ev.is_set():
            try:
                b = self.s.recv(65536)
                if not b:
                    break
                buf += b
            except socket.timeout:
                continue
            except OSError:
                break
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                self.lines.append(line.decode("utf8", "replace"))

    def mark(self):
        time.sleep(0.3)
        return len(self.lines)

    def window(self, start):
        """Commands since `start`: [(cmd upper, [args...])] (MONITOR line, quoting simplified)."""
        out = []
        for ln in self.lines[start:]:
            if not ln.startswith("+") or ln.startswith("+OK"):
                continue
            parts = re.findall(r'"((?:[^"\\]|\\.)*)"', ln)
            if parts:
                out.append((parts[0].upper(), parts[1:]))
        return out

    def close(self):
        self.stop_ev.set()
        try:
            self.s.close()
        except OSError:
            pass


class Env:
    """One scenario run: directories, shared Redis/upload_path, servers per (kind, tgt)."""

    def __init__(self, sc, mode, redis):
        self.sc, self.mode, self.redis = sc, mode, redis
        self.base = os.path.join(TMP, f"{sc}-{mode}")
        shutil.rmtree(self.base, ignore_errors=True)
        os.makedirs(self.base)
        self.upload = os.path.join(self.base, "dp-user")
        os.makedirs(os.path.join(self.upload, "meta"))  # as `takyctl setup` lays it out
        self.srv = {}
        self.extra = {}
        self.logs = []

    def ip(self, tgt):
        return IPS["py"] if self.mode == "alternate" else IPS[tgt]

    def root(self, tgt):
        d = os.path.join(self.base, "site" if self.mode == "alternate" else tgt)
        os.makedirs(d, exist_ok=True)
        return d

    def write_conf(self, tgt):
        root = self.root(tgt)
        conf = {
            "taky": {"hostname": self.extra.get("hostname", HOSTNAME), "node_id": "TAKY", "bind_ip": self.ip(tgt),
                     "root_dir": root, "redis": self.redis.url},
            "cot_server": {"port": str(COT_PORT), "max_persist_ttl": str(self.extra.get("max_ttl", -1)),
                           **({"log_cot": self.extra["log_cot"]} if self.extra.get("log_cot") else {})},
            "dp_server": {"upload_path": self.upload},
            "ssl": {"enabled": "false", "cert_db": os.path.join(root, "cert-db.txt")},
        }
        p = os.path.join(root, "taky.conf")
        with open(p, "w") as f:
            for s, kv in conf.items():
                f.write(f"[{s}]\n" + "".join(f"{k} = {v}\n" for k, v in kv.items()) + "\n")
        return root

    def start(self, kind, tgt):
        """Ensure `kind` (cot|dps) of `tgt` runs; alternate mode stops the other version's same kind first."""
        cur = self.srv.get((kind, tgt))
        if cur and cur["p"].poll() is None:
            return cur
        if self.mode == "alternate":
            self.stop(kind, OTHER[tgt])
        root = self.write_conf(tgt)
        log = os.path.join(root, f"{kind}-{tgt}-{len(self.logs)}.log")
        if tgt == "py":
            cmd = [PY, "-B", "-W", "ignore", "-c", PY_COT if kind == "cot" else PY_DPS]
            env = dict(os.environ, PYTHONPATH=TAKY_SRC, PYTHONDONTWRITEBYTECODE="1")
        else:
            cmd = [RS_COT if kind == "cot" else RS_DPS]
            env = dict(os.environ)
        env.pop("TAKY_CONFIG", None)
        cmd += ["-c", "taky.conf", "-l", "debug" if kind == "cot" else "info"]
        p = subprocess.Popen(cmd, cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=open(log, "wb"),
                             stderr=subprocess.STDOUT, start_new_session=True)
        PROCS.append(p)
        self.logs.append(log)
        port = COT_PORT if kind == "cot" else DPS_PORT
        t0 = time.time()
        while not listening(self.ip(tgt), port):
            if p.poll() is not None or time.time() - t0 > 30:
                raise RuntimeError(f"{kind}-{tgt} did not start:\n{open(log, errors='replace').read()[-2000:]}")
            time.sleep(0.05)
        self.srv[(kind, tgt)] = {"p": p, "log": log}
        return self.srv[(kind, tgt)]

    def stop(self, kind, tgt):
        cur = self.srv.pop((kind, tgt), None)
        if cur:
            rc = stop_proc(cur["p"])
            check(f"{self.sc}.{kind}-{tgt}.stop", f"{kind} {tgt} SIGTERM -> exit 0", rc == 0, {"rc": rc})
            # the port must be free before the other version binds it (alternate mode, same ip)
            t0 = time.time()
            while listening(self.ip(tgt), COT_PORT if kind == "cot" else DPS_PORT) and time.time() - t0 < 10:
                time.sleep(0.05)

    def stop_all(self):
        for kind, tgt in list(self.srv):
            self.stop(kind, tgt)

    def log_text(self, kind, tgt):
        """Concatenated logs of every start of (kind, tgt) in this env."""
        out = ""
        for p in self.logs:
            if os.path.basename(p).startswith(f"{kind}-{tgt}-"):
                out += open(p, encoding="utf8", errors="replace").read()
        return out


# ----------------------------------------------------------------------------------------------- CoT client
def split_events(data):
    from lxml import etree

    out, acc = [], b""
    parts = data.split(b"<event ")
    if parts[0].strip():
        out.append(parts[0].decode("utf8", "replace"))
    for part in parts[1:]:
        acc += b"<event " + part
        try:
            etree.fromstring(acc)
        except etree.XMLSyntaxError:
            continue
        out.append(acc.decode("utf8"))
        acc = b""
    if acc:
        out.append(acc.decode("utf8", "replace"))
    return out


class Peer:
    def __init__(self, ip):
        self.s = socket.create_connection((ip, COT_PORT), 5)
        self.s.settimeout(0.05)
        self.buf = b""

    def pump(self, quiet=0.5, limit=8.0):
        t0 = last = time.time()
        while time.time() - last < quiet and time.time() - t0 < limit:
            try:
                b = self.s.recv(65536)
                if not b:
                    break
                self.buf += b
                last = time.time()
            except socket.timeout:
                pass
            except OSError:
                break
        return self

    def send(self, frames, gap=0.05):
        for f in frames:
            self.s.sendall(f)
            time.sleep(gap)
        return self

    def events(self):
        return split_events(self.buf)

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def replay(env, tgt, quiet=0.8):
    """A NEW client connects to tgt and records what it gets on connect (persistence replay)."""
    p = Peer(env.ip(tgt)).pump(quiet)
    ev = p.events()
    p.close()
    return ev


def write_events(env, tgt, frames, settle=0.8):
    p = Peer(env.ip(tgt)).pump(0.3)
    p.send(frames)
    p.pump(settle)
    p.close()
    time.sleep(0.2)


def ts(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def ev(uid, etype, t0, stale_s, detail="", how="m-g", point='lat="1.5" lon="-2.25" hae="10" ce="9999999" le="9999999"',
       tfmt=ts):
    return (f'<event version="2.0" uid="{uid}" type="{etype}" how="{how}" time="{tfmt(t0)}" start="{tfmt(t0)}" '
            f'stale="{tfmt(t0 + dt.timedelta(seconds=stale_s))}"><point {point}/>'
            f'<detail>{detail}</detail></event>').encode()


def input_set(tag, stale=600, variant=""):
    """The common CoT input: kept types (a-, b-m-p, u-d-*, b-r-f-h-c) + not kept / negative TTL ones.
    Returns (frames, kept_uids). `variant` changes detail content (C3 rewrites)."""
    t0 = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None, microsecond=0)
    sec = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731  (no fractional part)
    micro = lambda t: t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"  # noqa: E731
    v = variant
    frames = [
        ev(f"ANDROID-{tag}-sa", "a-f-G-U-C", t0, stale,
           f'<contact callsign="Alpha{v}" endpoint="*:-1:stcp"/><__group name="Cyan" role="Team Member"/>'
           f'<takv device="qa" platform="ATAK-CIV" os="34" version="4.10"/><track course="90.5" speed="1.25"/>'),
        ev(f"M-{tag}-marker", "a-u-G", t0, stale,
           f'<contact callsign="Маркер ✓ &amp; &lt;x&gt; &quot;q&quot;{v}"/><remarks>héllo\n  wörld{v}</remarks>'
           f'<link uid="ANDROID-{tag}-sa" relation="p-p" type="a-f-G-U-C"/>', tfmt=sec),
        ev(f"M:{tag} with:colons", "a-h-G", t0, stale, f'<contact callsign="Hostile{v}"/><color argb="-1"/>',
           tfmt=micro),
        ev(f"D-{tag}-drawing", "u-d-f", t0, stale,
           f'<link point="1.0,2.0"/><link point="1.5,2.5"/><strokeColor value="-65536"/><labels_on value="false"/>'
           f'<contact callsign="Line {v}"/>'),
        ev(f"P-{tag}-pointer", "b-m-p-s-p-i", t0, stale, f'<contact callsign="Pointer{v}"/>'),
        ev(f"E-{tag}-evac", "b-r-f-h-c", t0, stale, f'<contact callsign="Evac{v}"/><_medevac_ title="m{v}"/>'),
        ev(f"C-{tag}-circle", "u-d-c", t0, stale, f'<shape><ellipse major="100" minor="50" angle="0"/></shape>'),
        ev(f"R-{tag}-rect", "u-d-r", t0, stale, '<contact callsign="Rect"/>'),
        ev(f"M-{tag}-empty", "a-n-G", t0, stale, "", point='lat="0" lon="0" hae="0" ce="0" le="0"'),
        # not kept: chat-like bit, ping, picture request; negative TTL marker
        ev(f"GeoChat.{tag}.x", "b-t-f", t0, stale, '<remarks>hi</remarks>'),
        ev(f"PING-{tag}", "t-x-c-t", t0, 20, ""),
        ev(f"F-{tag}-file", "b-f-t-r", t0, stale, ""),
        ev(f"M-{tag}-past", "a-u-G", t0 - dt.timedelta(seconds=7200), 3600, '<contact callsign="Old"/>'),
    ]
    kept = [f"ANDROID-{tag}-sa", f"M-{tag}-marker", f"M:{tag} with:colons", f"D-{tag}-drawing", f"P-{tag}-pointer",
            f"E-{tag}-evac", f"C-{tag}-circle", f"R-{tag}-rect", f"M-{tag}-empty"]
    return frames, kept, t0


def ks(uid, host=HOSTNAME):
    return f"taky:{host}:persist:{uid}"


def stale_epoch(xml):
    m = re.search(r'stale="([^"]+)"', xml)
    s = m.group(1).rstrip("Z")
    fmt = "%Y-%m-%dT%H:%M:%S.%f" if "." in s else "%Y-%m-%dT%H:%M:%S"
    return dt.datetime.strptime(s, fmt).replace(tzinfo=dt.timezone.utc).timestamp()


def ttl_ok(snap):
    """TTL of every key within ±2 s of (stale - now) (whole seconds, test-strategy C3)."""
    bad = {}
    now = time.time()
    for k, v in snap.items():
        if not v["value"].startswith("<event"):
            continue
        want = stale_epoch(v["value"]) - now
        if abs(v["ttl"] - want) > 2:
            bad[k] = {"ttl": v["ttl"], "want": round(want, 1)}
    return bad


def mask_stale(s):
    return re.sub(r'(stale="[^"]*")', lambda m: re.sub(r"\d", "D", m.group(1)), s)


# ----------------------------------------------------------------------------------------------- C1 / C2
def sc_replay(env, writer):
    sc, reader = env.sc, OTHER[writer]
    frames, kept, _ = input_set(sc.lower())
    env.start("cot", writer)
    if env.mode == "simultaneous":
        env.start("cot", reader)
    write_events(env, writer, frames)
    snap1 = env.redis.snapshot()
    check(f"{sc}.keys", f"{writer} stored exactly the kept uids (types a-/b-m-p/b-r-f-h-c/u-d-*; not b-t-f/t-x-c-t/"
          "b-f-t-r/negative TTL)", sorted(snap1) == sorted(ks(u) for u in kept),
          diff_lists(list(snap1), [ks(u) for u in kept]))
    check(f"{sc}.ttl", f"{writer} TTL = stale - now (±2 s)", not ttl_ok(snap1), ttl_ok(snap1))
    base = replay(env, writer)  # what the writer itself replays to a new client
    check(f"{sc}.self-replay", f"{writer} replays all {len(kept)} kept events", len(base) == len(kept),
          {"n": len(base)})
    if env.mode == "alternate":
        env.stop("cot", writer)
    env.start("cot", reader)
    got = replay(env, reader)
    check(f"{sc}.replay", f"{reader} replays the {writer}-written events byte-exact (= what {writer} delivers)",
          sorted(got) == sorted(base), diff_lists(got, base))
    check(f"{sc}.order", f"replay order {reader} == {writer} (informational: KEYS vs SCAN order is not normative)",
          True, {"same_order": got == base})
    got2 = replay(env, reader)
    check(f"{sc}.replay-2", f"{reader} second replay identical (nothing purged/rewritten by reading)",
          sorted(got2) == sorted(base), diff_lists(got2, base))
    snap2 = env.redis.snapshot()
    check(f"{sc}.no-purge", f"Redis keys/values unchanged after {reader} read them (no purge)",
          {k: v["value"] for k, v in snap2.items()} == {k: v["value"] for k, v in snap1.items()},
          diff_lists(list(snap2), list(snap1)))
    log = env.log_text("cot", reader)
    check(f"{sc}.log-no-purge", f"{reader} log has no 'Purging key' / persistence-store warnings",
          "Purging key" not in log and "persistence store" not in log,
          [ln for ln in log.splitlines() if "Purging" in ln or "persistence store" in ln][:5])
    # simultaneous: the reader started before the writes, so its startup count is 0
    want = f"Tracking {len(kept) if env.mode == 'alternate' else 0} items"
    check(f"{sc}.log-tracking", f"{reader} startup log '{want}'", want in log,
          [ln for ln in log.splitlines() if "Tracking" in ln][:3])
    env.stop_all()
    return {"values": {k: v["value"] for k, v in snap1.items()}, "replay": sorted(base)}


# ----------------------------------------------------------------------------------------------- C3
def sc_alternating(env):
    sc = env.sc
    env.extra["max_ttl"] = 900
    frames_x, kept, t0 = input_set("c3", stale=600)
    frames_y, _, _ = input_set("c3", stale=650, variant="-v2")
    clamp = ev("M-c3-clamped", "a-u-G", t0, 86400, '<contact callsign="Clamped"/>')
    snaps, replays = {}, {}

    def phase(label, tgt, frames, extra=()):
        env.start("cot", tgt)
        write_events(env, tgt, frames + list(extra))
        s = env.redis.snapshot()
        snaps[label] = s
        replays[label] = sorted(replay(env, tgt))
        bad = ttl_ok({k: v for k, v in s.items() if "clamped" not in k and "short" not in k})
        check(f"{sc}.{label}.ttl", f"{label}: {tgt} TTLs = stale - now (±2 s)", not bad, bad)
        ck = ks("M-c3-clamped")
        if extra:  # only the phase that (re)wrote the clamped event
            check(f"{sc}.{label}.clamp-ttl", f"{label}: {tgt} max_persist_ttl=900 clamps TTL (±2 s)",
                  abs(s[ck]["ttl"] - 900) <= 2, s[ck]["ttl"])
        return s

    vals = lambda s, mask=False: {k: (mask_stale(v["value"]) if mask else v["value"])  # noqa: E731
                                  for k, v in s.items()}
    # P writes X
    sp = phase("P-X", "py", frames_x, [clamp])
    # R writes the identical input X over Python's keys
    sr = phase("R-X", "rs", frames_x, [clamp])
    plain = lambda s: {k: v for k, v in vals(s).items() if "clamped" not in k}  # noqa: E731
    check(f"{sc}.X.values", "identical input X: Rust-written values byte-exact = Python-written values",
          plain(sr) == plain(sp), [k for k in plain(sp) if plain(sp).get(k) != plain(sr).get(k)][:5])
    ck = ks("M-c3-clamped")
    check(f"{sc}.X.clamp-value", "clamped event: values equal with stale digits masked (stale = now + 900, same format)",
          vals(sr, True).get(ck) == vals(sp, True).get(ck), [vals(sp).get(ck), vals(sr).get(ck)])
    check(f"{sc}.X.replay", "replay after R-X == replay after P-X (except clamped stale)",
          [mask_stale(x) for x in replays["R-X"]] == [mask_stale(x) for x in replays["P-X"]],
          diff_lists(replays["R-X"], replays["P-X"]))
    # R writes Y (same uids, changed content), then P reads and writes Y
    sry = phase("R-Y", "rs", frames_y)
    env.start("cot", "py")
    got = sorted(replay(env, "py"))
    check(f"{sc}.Y.read-by-py", "P replays the R-written Y values exactly as R does",
          got == replays["R-Y"], diff_lists(got, replays["R-Y"]))
    spy = phase("P-Y", "py", frames_y)
    check(f"{sc}.Y.values", "identical input Y: Python-written values byte-exact = Rust-written values",
          plain(spy) == plain(sry), [k for k in plain(sry) if plain(sry).get(k) != plain(spy).get(k)][:5])
    # short TTL: written by P, expires in Redis, R does not replay it
    t1 = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    short = ev("M-c3-short", "a-u-G", t1, 4, '<contact callsign="Short"/>')
    write_events(env, "py", [short])
    ttl = env.redis.c.ttl(ks("M-c3-short"))
    check(f"{sc}.short.ttl", "P: short-lived event TTL 3..4 s (round half-even of stale - now)", ttl in (3, 4), ttl)
    env.start("cot", "rs")
    got = replay(env, "rs")
    check(f"{sc}.short.live", "R replays the short-lived event while it lives",
          any('uid="M-c3-short"' in x for x in got), len(got))
    time.sleep(4.5)
    got = replay(env, "rs")
    check(f"{sc}.short.expired", "after expiry: key gone and R no longer replays it",
          env.redis.c.exists(ks("M-c3-short")) == 0 and not any('uid="M-c3-short"' in x for x in got), len(got))
    # P -> R -> P final: P reads after R's last start
    env.start("cot", "py")
    got = sorted(replay(env, "py"))
    want = sorted(x for x in replays["P-Y"] if 'uid="M-c3-short"' not in x)
    check(f"{sc}.final.py", "final P replay (after R ran) == P-Y replay", [mask_stale(x) for x in got] ==
          [mask_stale(x) for x in want], diff_lists(got, want))
    for t in ("py", "rs"):
        log = env.log_text("cot", t)
        check(f"{sc}.{t}.no-purge", f"{t} log has no 'Purging key'", "Purging key" not in log)
    env.stop_all()
    return {"P-X": vals(sp), "R-X": vals(sr), "R-Y": vals(sry), "P-Y": vals(spy)}


# ----------------------------------------------------------------------------------------------- C4
def sc_simultaneous(env):
    sc = env.sc
    mon = Monitor()
    try:
        m = mon.mark()
        env.start("cot", "py")
        win_py_start = mon.window(m)
        m = mon.mark()
        env.start("cot", "rs")
        win_rs_start = mon.window(m)
        fp, kp, _ = input_set("c4p")
        fr, kr, _ = input_set("c4r")
        m = mon.mark()
        write_events(env, "py", fp)
        win_py_w = mon.window(m)
        m = mon.mark()
        write_events(env, "rs", fr)
        win_rs_w = mon.window(m)
        snap = env.redis.snapshot()
        want = sorted(ks(u) for u in kp + kr)
        check(f"{sc}.keys", "one keyspace taky:compat.example:persist holds the kept events of both hosts",
              sorted(snap) == want, diff_lists(list(snap), want))
        m = mon.mark()
        gp = sorted(replay(env, "py"))
        win_py_r = mon.window(m)
        m = mon.mark()
        gr = sorted(replay(env, "rs"))
        win_rs_r = mon.window(m)
        check(f"{sc}.replay.count", f"new client on P and on R each get all {len(want)} events (own + other host's)",
              len(gp) == len(want) and len(gr) == len(want), [len(gp), len(gr)])
        check(f"{sc}.replay.exact", "P replay == R replay (byte-exact, as multisets)", gp == gr, diff_lists(gp, gr))
        # same uid written by both: last writer wins, both replay the last value
        t0 = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None, microsecond=0)
        write_events(env, "py", [ev("SHARED-1", "a-u-G", t0, 600, '<contact callsign="from-py"/>')])
        write_events(env, "rs", [ev("SHARED-1", "a-u-G", t0, 600, '<contact callsign="from-rs"/>')])
        v = env.redis.c.get(ks("SHARED-1")).decode()
        sp = [x for x in replay(env, "py") if 'uid="SHARED-1"' in x]
        sr = [x for x in replay(env, "rs") if 'uid="SHARED-1"' in x]
        check(f"{sc}.shared-uid", "same uid from both hosts: last writer (rs) wins, both replay it",
              "from-rs" in v and sp == sr and len(sp) == 1 and "from-rs" in sp[0], {"redis": v, "py": sp, "rs": sr})
        write_events(env, "py", [ev("SHARED-1", "a-u-G", t0, 600, '<contact callsign="from-py-2"/>')])
        sr = [x for x in replay(env, "rs") if 'uid="SHARED-1"' in x]
        check(f"{sc}.shared-uid-2", "then py overwrites: rs replays py's value", len(sr) == 1 and "from-py-2" in sr[0],
              sr)
        # MONITOR (D-4 / D-5): resulting state is the same; commands differ
        cmds = lambda w: [c for c, _ in w]  # noqa: E731
        set_py = [a for c, a in win_py_w if c == "SET"]
        set_rs = [[c] + a for c, a in win_rs_w if c in ("SET", "SETEX")]
        check(f"{sc}.monitor.py-set", "Python write: SET key value (no EX) + EXPIRE key ttl",
              set_py and all(len(a) == 2 for a in set_py) and "EXPIRE" in cmds(win_py_w),
              {"cmds": sorted(set(cmds(win_py_w)))})
        # D-4 says `SET … EX`; redis-rs `set_ex` sends the equivalent atomic `SETEX key ttl value` (same state;
        # spec wording question to an01, S-405). Both forms are accepted, the form seen is recorded.
        one_cmd = lambda a: ((a[0] == "SET" and len(a) == 5 and a[3].upper() == "EX") or  # noqa: E731
                             (a[0] == "SETEX" and len(a) == 4 and a[2].isdigit()))
        check(f"{sc}.monitor.rs-set", "Rust write: one atomic command with TTL (D-4: SET key value EX ttl | SETEX key "
              "ttl value), no EXPIRE", set_rs and all(one_cmd(a) for a in set_rs) and "EXPIRE" not in cmds(win_rs_w),
              {"cmds": sorted(set(cmds(win_rs_w))), "form": sorted({a[0] for a in set_rs})})
        check(f"{sc}.monitor.py-read", "Python replay: KEYS taky:compat.example:persist:* + GET",
              ("KEYS", [f"taky:{HOSTNAME}:persist:*"]) in win_py_r and "GET" in cmds(win_py_r),
              sorted(set(cmds(win_py_r))))
        scans = [a for c, a in win_rs_r if c == "SCAN"]
        check(f"{sc}.monitor.rs-read", "Rust replay: SCAN <cursor> MATCH taky:compat.example:persist:* COUNT n (D-5) + "
              "GET, no KEYS", scans and all(a[1].upper() == "MATCH" and a[2] == f"taky:{HOSTNAME}:persist:*"
                                            for a in scans) and "KEYS" not in cmds(win_rs_r) and "GET" in cmds(win_rs_r),
              {"cmds": sorted(set(cmds(win_rs_r))), "scan": scans[:1]})
        check(f"{sc}.monitor.start", "startup count: Python KEYS, Rust SCAN (informational: other commands)",
              "KEYS" in cmds(win_py_start) and "SCAN" in cmds(win_rs_start),
              {"py": sorted(set(cmds(win_py_start))), "rs": sorted(set(cmds(win_rs_start)))})
        mutating = {"DEL", "UNLINK", "FLUSHDB", "FLUSHALL", "RENAME"}
        allw = win_py_start + win_rs_start + win_py_w + win_rs_w + win_py_r + win_rs_r
        check(f"{sc}.monitor.no-delete", "no DEL/UNLINK/FLUSH* from either version", not (mutating & set(cmds(allw))),
              sorted(mutating & set(cmds(allw))))
        mon_dump = {"py_write": sorted(set(cmds(win_py_w))), "rs_write": sorted(set(cmds(win_rs_w))),
                    "py_read": sorted(set(cmds(win_py_r))), "rs_read": sorted(set(cmds(win_rs_r))),
                    "rs_set_example": set_rs[:1] and [x if len(x) < 60 else "<value>" for x in set_rs[0]],
                    "py_set_example": set_py[:1] and [set_py[0][0], "<value>"],
                    "rs_scan_example": scans[:1]}
    finally:
        mon.close()
    env.stop_all()
    return mon_dump


# ----------------------------------------------------------------------------------------------- C5
BROKEN = {
    "BAD-xml": "<event><not closed",
    "BAD-root": '<foo version="2.0"/>',
    "BAD-date": '<event version="2.0" uid="BAD-date" type="a-u-G" how="h-e" time="yesterday" start="x" stale="y"/>',
    "BAD-empty": "",
}


def seed_c5(rds, host, valid):
    rds.c.flushdb()
    for uid, val in BROKEN.items():
        rds.c.set(ks(uid, host), val, ex=600)
    rds.c.set(ks("SEED-1", host), valid, ex=600)
    rds.c.rpush(ks("BAD-list", host), "x")  # WRONGTYPE for GET
    rds.c.expire(ks("BAD-list", host), 600)
    # foreign keyspaces: other hostname, empty hostname, other app, prefix-alike, nested
    for k in ("taky:other.example:persist:X", "taky:persist:Y", "other:compat.example:persist:Z",
              f"taky:{host}x:persist:W", f"taky:{host}:persistX:V", f"xtaky:{host}:persist:U"):
        rds.c.set(k, "<event><not closed", ex=600)
    rds.c.set("taky:other.example:persist:OK", valid, ex=600)


def sc_foreign(env):
    sc = env.sc
    t0 = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None, microsecond=0)
    valid = ev("SEED-1", "a-u-G", t0, 600, '<contact callsign="S"/>').decode()
    res = {}
    for host_case, host, cfg_host in (("plain", HOSTNAME, HOSTNAME), ("glob", HOSTNAME, "c?mpat.exampl[e]")):
        env.extra["hostname"] = cfg_host
        for tgt in ("py", "rs"):
            seed_c5(env.redis, host, valid)
            before = env.redis.snapshot("")
            env.start("cot", tgt)
            got = replay(env, tgt)
            after = env.redis.snapshot("")
            env.stop("cot", tgt)
            gone = sorted(set(before) - set(after))
            res[(host_case, tgt)] = {"gone": gone, "replay": sorted(got), "log": env.log_text("cot", tgt)}
            if host_case == "plain":
                want_gone = sorted(ks(u, host) for u in list(BROKEN) + ["BAD-list"])
                check(f"{sc}.{tgt}.purged", f"{tgt}: own broken keys purged (xml/root/date/empty/WRONGTYPE), "
                      "foreign keyspaces untouched", gone == want_gone, {"gone": gone, "want": want_gone})
                check(f"{sc}.{tgt}.replay", f"{tgt}: only the valid own key replayed", len(got) == 1 and
                      'uid="SEED-1"' in got[0], got)
        # parity between versions
        a, b = res[(host_case, "py")], res[(host_case, "rs")]
        check(f"{sc}.{host_case}.parity", f"hostname {cfg_host!r}: py and rs purge the same keys and replay the same "
              "events", a["gone"] == b["gone"] and a["replay"] == b["replay"],
              {"py_gone": a["gone"], "rs_gone": b["gone"], "py_n": len(a["replay"]), "rs_n": len(b["replay"])})
        if host_case == "glob":
            check(f"{sc}.glob.note", "informational: a hostname with glob characters is used as a KEYS/SCAN pattern "
                  "in both versions (matches foreign keyspaces)", True,
                  {"gone": a["gone"], "replayed": len(a["replay"])})
        env.extra.pop("hostname", None)
    pl = res[("plain", "py")]["log"].count("Purging key"), res[("plain", "rs")]["log"].count("Purging key")
    check(f"{sc}.log", "both log one 'Purging key' WARNING per purged key", pl[0] == pl[1] == len(BROKEN) + 1, pl)
    env.stop_all()
    return {f"{k[0]}-{k[1]}": {"gone": v["gone"], "replay_n": len(v["replay"])} for k, v in res.items()}


# ----------------------------------------------------------------------------------------------- DPS client
def hreq(env, tgt, method, path, body=None, ctype=None, user="alice"):
    conn = http.client.HTTPConnection(env.ip(tgt), DPS_PORT, timeout=20)
    conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", HOST_HDR)
    if user:
        conn.putheader("X-USER", user)
    if ctype:
        conn.putheader("Content-Type", ctype)
    if body is not None or method in ("POST", "PUT"):
        body = body or b""
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
    else:
        conn.endheaders()
    r = conn.getresponse()
    data = r.read()
    hd = {k.lower(): v for k, v in r.getheaders()}
    conn.close()
    return r.status, hd, data


def upload(env, tgt, creator, fname, data, f_hash, mime="application/zip"):
    b = "s405-boundary"
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"assetfile\"; filename=\"{fname}\"\r\n"
            f"Content-Type: {mime}\r\n\r\n").encode() + data + f"\r\n--{b}--\r\n".encode()
    import urllib.parse

    q = "/Marti/sync/missionupload?" + urllib.parse.urlencode(
        {"hash": f_hash, "filename": fname.rsplit(".", 1)[0], "creatorUid": creator})
    return hreq(env, tgt, "POST", q, body, f"multipart/form-data; boundary={b}")


def norm_resp(r):
    st, hd, body = r
    try:
        j = json.loads(body)
        if isinstance(j, dict) and "results" in j:
            for m in j["results"]:
                m["SubmissionDateTime"] = "$TS"
            j["results"].sort(key=lambda m: str(m.get("UID")))
        body = j
    except ValueError:
        body = hashlib.sha256(body).hexdigest()[:16] + f":{len(body)}" if len(body) > 200 else body.decode(
            "utf8", "replace")
    keep = {k: hd.get(k) for k in ("content-type", "content-disposition") if hd.get(k)}
    return {"status": st, "body": body, "hdr": keep}


def queries(env, tgt, hashes):
    out = {"search": norm_resp(hreq(env, tgt, "GET", "/Marti/sync/search?keywords=missionpackage&tool=public"))}
    for h in hashes:
        out[f"content:{h}"] = norm_resp(hreq(env, tgt, "GET", f"/Marti/sync/content?hash={h}&receiver=X"))
        out[f"query:{h}"] = norm_resp(hreq(env, tgt, "GET", f"/Marti/sync/missionquery?hash={h}"))
    return out


def tree(up):
    """{relpath: ("file", sha/masked-json) | ("link", target)} of upload_path (SubmissionDateTime masked)."""
    out = {}
    for d, dirs, files in os.walk(up):
        for n in sorted(files + [x for x in dirs if os.path.islink(os.path.join(d, x))]):
            p = os.path.join(d, n)
            rel = os.path.relpath(p, up)
            if os.path.islink(p):
                out[rel] = ["link", os.readlink(p)]
            else:
                data = open(p, "rb").read()
                if rel.startswith("meta" + os.sep):
                    # masked only if it has Python's format: isoformat() + "Z" (microseconds omitted when 0)
                    out[rel] = ["meta", re.sub(rb'"SubmissionDateTime": "\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?Z"',
                                               b'"SubmissionDateTime": "$TS"', data).decode("utf8", "replace")]
                else:
                    out[rel] = ["file", hashlib.sha256(data).hexdigest()[:16], len(data)]
    return out


def meta_format_ok(up):
    """compat 1.2.7: every meta/*.json byte-equal to Python json.dump of its parsed content."""
    bad = {}
    md = os.path.join(up, "meta")
    for n in sorted(os.listdir(md)):
        p = os.path.join(md, n)
        if os.path.islink(p):
            continue
        raw = open(p, encoding="utf8").read()
        if json.dumps(json.loads(raw)) != raw:
            bad[n] = raw
    return bad


def same_except(a, b, allow=()):
    """Response dict equality; keys in `allow` are documented deviations (returned separately)."""
    diffs = {k: [a.get(k), b.get(k)] for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)}
    return {k: v for k, v in diffs.items() if k not in allow}, {k: v for k, v in diffs.items() if k in allow}


# ----------------------------------------------------------------------------------------------- C6
def sc_dps_prp(env):
    sc = env.sc
    da, db = os.urandom(3000) + b"alpha", os.urandom(5000) + b"beta"
    ha, hb = hashlib.sha256(da).hexdigest(), hashlib.sha256(db).hexdigest()
    hashes = [ha, hb, "0" * 64]
    d15 = {f"content:{'0' * 64}"}  # D-15: unknown hash -> Rust 404 instead of Python 500
    env.start("dps", "py")
    r1 = upload(env, "py", "ANDROID-1", "alpha.zip", da, ha)
    r2 = upload(env, "py", "ANDROID-1", "beta pkg.zip", db, hb, "application/x-zip-compressed")
    check(f"{sc}.py.upload", "P uploads 2 packages (200 + content URL)", r1[0] == r2[0] == 200, [r1[2], r2[2]])
    r = hreq(env, "py", "PUT", f"/Marti/api/sync/metadata/{ha}/tool", b"public")
    check(f"{sc}.py.tool", "P sets alpha public", r[0] == 200, r[2])
    q_p1 = queries(env, "py", hashes)
    env.start("dps", "rs")
    q_r1 = queries(env, "rs", hashes)
    bad, dev = same_except(q_p1, q_r1, d15)
    check(f"{sc}.R1", "R reads the P-written upload_path: search/content/missionquery responses equal to P's", not bad,
          bad)
    check(f"{sc}.R1.d15", "documented deviation D-15 only (unknown hash content: py 500, rs 404)",
          all(v[0]["status"] == 500 and v[1]["status"] == 404 for v in dev.values()), dev)
    # R toggles visibility both ways
    ra = hreq(env, "rs", "PUT", f"/Marti/api/sync/metadata/{ha}/tool", b"private")
    rb = hreq(env, "rs", "PUT", f"/Marti/api/sync/metadata/{hb}/tool", b"public")
    check(f"{sc}.rs.tool", "R toggles alpha private, beta public (200)", ra[0] == rb[0] == 200, [ra[2], rb[2]])
    q_r2, t_r2 = queries(env, "rs", hashes), tree(env.upload)
    check(f"{sc}.R2.search", "R search after toggle shows only beta",
          [m["UID"] for m in q_r2["search"]["body"]["results"]] == ["ANDROID-1_beta_pkg.zip"], q_r2["search"])
    mf = meta_format_ok(env.upload)
    check(f"{sc}.R2.meta-format", "meta JSON rewritten by R is byte-equal to Python json.dump (compat 1.2.7)", not mf,
          mf)
    check(f"{sc}.R2.symlinks", "symlinks meta/<hash>.json -> <UID>.json intact after R rewrite",
          t_r2.get(f"meta/{ha}.json") == ["link", "ANDROID-1_alpha.zip.json"] and
          t_r2.get(f"meta/{hb}.json") == ["link", "ANDROID-1_beta_pkg.zip.json"],
          {k: v for k, v in t_r2.items() if v[0] == "link"})
    env.start("dps", "py")
    q_p2 = queries(env, "py", hashes)
    bad, dev = same_except(q_r2, q_p2, d15)
    check(f"{sc}.P2", "P reads the R-rewritten meta: responses equal to R's", not bad, bad)
    # P toggles back, R reads again
    hreq(env, "py", "PUT", f"/Marti/api/sync/metadata/{ha}/tool", b"public")
    q_p3, t_p3 = queries(env, "py", hashes), tree(env.upload)
    env.start("dps", "rs")
    q_r3 = queries(env, "rs", hashes)
    bad, dev = same_except(q_p3, q_r3, d15)
    check(f"{sc}.R3", "after P toggles alpha public again, R responses equal P's", not bad, bad)
    # file tree written by R for the same operations as P: P-only reference run on a scratch copy
    ref = sc_dps_reference(env, da, db, ha, hb)
    check(f"{sc}.tree", "upload_path tree after R's toggles == the tree Python alone produces for the same "
          "operations (except SubmissionDateTime)", t_r2 == ref, same_except(t_r2, ref)[0])
    env.stop_all()
    return {"q_p1": q_p1, "q_r2": q_r2, "tree_r2": t_r2, "tree_p3": t_p3}


def sc_dps_reference(env, da, db, ha, hb):
    """Python-only run of C6's P1 + R toggles in a scratch upload_path (alternate: restart on the same ip)."""
    saved, mode = env.upload, env.mode
    for k in list(env.srv):
        if k[0] == "dps":
            env.stop(*k)
    env.upload = os.path.join(env.base, "dp-ref")
    os.makedirs(os.path.join(env.upload, "meta"), exist_ok=True)
    try:
        env.start("dps", "py")
        upload(env, "py", "ANDROID-1", "alpha.zip", da, ha)
        upload(env, "py", "ANDROID-1", "beta pkg.zip", db, hb, "application/x-zip-compressed")
        hreq(env, "py", "PUT", f"/Marti/api/sync/metadata/{ha}/tool", b"public")
        hreq(env, "py", "PUT", f"/Marti/api/sync/metadata/{ha}/tool", b"private")
        hreq(env, "py", "PUT", f"/Marti/api/sync/metadata/{hb}/tool", b"public")
        t = tree(env.upload)
        env.stop("dps", "py")
    finally:
        env.upload, env.mode = saved, mode
    return t


# ----------------------------------------------------------------------------------------------- C7
def sc_dps_reupload(env):
    sc = env.sc
    d1, d2 = os.urandom(4000) + b"v1", os.urandom(6000) + b"v2"
    h1, h2 = hashlib.sha256(d1).hexdigest(), hashlib.sha256(d2).hexdigest()
    trees, resp = {}, {}
    base_upload = env.upload
    for first, second in (("py", "py"), ("rs", "rs"), ("rs", "py"), ("py", "rs")):
        seq = f"{first[0].upper()}{second[0].upper()}"
        env.upload = os.path.join(env.base, f"dp-{seq}")
        os.makedirs(os.path.join(env.upload, "meta"), exist_ok=True)
        for k in list(env.srv):
            env.stop(*k)
        env.start("dps", first)
        r = upload(env, first, "ANDROID-7", "pkg.zip", d1, h1)
        hreq(env, first, "PUT", f"/Marti/api/sync/metadata/{h1}/tool", b"public")
        env.start("dps", second)
        a = queries(env, second, [h1])
        r2 = upload(env, second, "ANDROID-7", "pkg.zip", d2, h2)  # same UID, new hash: old symlink removed
        t_after = tree(env.upload)
        env.start("dps", first)
        b = queries(env, first, [h1, h2])
        hreq(env, first, "PUT", f"/Marti/api/sync/metadata/{h2}/tool", b"public")
        c = queries(env, first, [h2])
        trees[seq], resp[seq] = t_after, {"up1": r[0], "up2": [r2[0], r2[2].decode()], "read1": a, "read2": b,
                                          "read3": c}
        check(f"{sc}.{seq}.old-link", f"{seq}: after re-upload meta/<h1>.json removed, meta/<h2>.json -> UID.json",
              f"meta/{h1}.json" not in t_after and t_after.get(f"meta/{h2}.json") == ["link", "ANDROID-7_pkg.zip.json"],
              {k: v for k, v in t_after.items() if k.startswith("meta")})
        check(f"{sc}.{seq}.content", f"{seq}: {first} serves the re-uploaded bytes for h2",
              b[f"content:{h2}"]["status"] == 200 and b[f"content:{h2}"]["body"] ==
              hashlib.sha256(d2).hexdigest()[:16] + f":{len(d2)}", b[f"content:{h2}"])
        mf = meta_format_ok(env.upload)
        check(f"{sc}.{seq}.meta-format", f"{seq}: meta JSON byte-equal to Python json.dump", not mf, mf)
        for k in list(env.srv):
            env.stop(*k)
    env.upload = base_upload
    ref = trees["PP"]
    for seq in ("RR", "RP", "PR"):
        bad = same_except(trees[seq], ref)[0]
        check(f"{sc}.{seq}.tree", f"{seq} file tree after re-upload == PP (except SubmissionDateTime)", not bad, bad)
    d15 = {f"content:{h1}"}  # read2 content of the removed hash h1: py 500 (KeyError), rs 404 (D-15)
    for seq in ("RR", "RP", "PR"):
        for step in ("read1", "read2", "read3"):
            bad, dev = same_except(resp[seq][step], resp["PP"][step], d15 if step == "read2" else ())
            ok_dev = all(v[0]["status"] in (404, 500) and v[1]["status"] in (404, 500) for v in dev.values())
            check(f"{sc}.{seq}.{step}", f"{seq} {step} responses == PP (D-15 allowed for the removed hash)",
                  not bad and ok_dev, bad or dev)
        check(f"{sc}.{seq}.upload", f"{seq} upload/re-upload status+URL == PP",
              [resp[seq]["up1"], resp[seq]["up2"]] == [resp["PP"]["up1"], resp["PP"]["up2"]],
              [resp[seq]["up2"], resp["PP"]["up2"]])
    env.stop_all()
    return {"trees": trees, "resp": resp}


# ----------------------------------------------------------------------------------------------- main
def run(sc, mode, redis):
    env = Env(sc, mode, redis)
    redis.c.flushdb()
    try:
        if sc == "C1":
            return sc_replay(env, "py")
        if sc == "C2":
            return sc_replay(env, "rs")
        if sc == "C3":
            return sc_alternating(env)
        if sc == "C4":
            return sc_simultaneous(env)
        if sc == "C5":
            return sc_foreign(env)
        if sc == "C6":
            return sc_dps_prp(env)
        if sc == "C7":
            return sc_dps_reupload(env)
        from . import compat2

        if sc == "C8":
            return compat2.sc_video(env)
        if sc == "C9":
            return compat2.sc_certdb_mixed(env)
        if sc == "C10":
            return compat2.sc_certdb_100(env)
        if sc == "C11":
            return compat2.sc_cert_matrix(env)
        if sc == "C12":
            return compat2.sc_conf(env)
        if sc == "C13":
            return compat2.sc_logcot(env) if mode == "alternate" else compat2.sc_logcot_sim(env)
        if sc == "C14":
            return compat2.sc_dropin(env)
    finally:
        env.stop_all()


def main(argv):
    ap = argparse.ArgumentParser(prog="difftest compat", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", nargs="+", help="C1..C14 or all")
    ap.add_argument("--mode", choices=["alternate", "simultaneous", "both"], default=None,
                    help="default: simultaneous for C4, alternate otherwise; 'both' runs C1-C3/C6-C8/C13 in both modes")
    args = ap.parse_args(argv)
    scs = list(SCENARIOS) if "all" in args.scenario else [s.upper() for s in args.scenario]
    for s in scs:
        if s not in SCENARIOS:
            ap.error(f"unknown scenario {s}")
    from . import compat2

    need = [RS_COT, RS_DPS] + ([compat2.RS_CTL] if set(scs) & {"C9", "C10", "C11", "C12", "C14"} else []) + \
        ([compat2.RS_UNIT] if "C12" in scs else [])
    for exe in need:
        if not os.access(exe, os.X_OK):
            print(f"{exe} not found (cargo build -p taky-server --bin taky-rs -p taky-dps --bin taky_dps-rs -p takyctl "
                  "--bin takyctl-rs; C12: cargo build -p taky-testkit --features difftest --bin taky-rs-unit)")
            return 2
    for ip in IPS.values():
        for port in (COT_PORT, DPS_PORT, REDIS_PORT, 18089, 18088, 8443, 8089, 8087):
            if listening(ip, port):
                print(f"{ip}:{port} is busy")
                return 2
    os.makedirs(TMP, exist_ok=True)
    os.makedirs(REPORT, exist_ok=True)
    redis = Redis(os.path.join(TMP, "redis"))
    total_fail = 0
    try:
        for sc in scs:
            if sc == "C4":
                modes = ["simultaneous"]
            elif sc == "C5":
                modes = ["alternate"]
            elif sc in SINGLE:
                modes = ["single"]
            elif args.mode == "both":
                modes = ["alternate", "simultaneous"]
            else:
                modes = [args.mode or "alternate"]
            for mode in modes:
                del CHECKS[:]
                t0 = time.time()
                print(f"== {sc} ({mode})", flush=True)
                try:
                    data = run(sc, mode, redis)
                except Exception as exc:  # pylint: disable=broad-except
                    import traceback

                    check(f"{sc}.harness", "scenario ran without a harness exception", False,
                          f"{exc}\n{traceback.format_exc()}")
                    data = None
                n_fail = sum(not c["ok"] for c in CHECKS)
                total_fail += n_fail
                verdict = "PASS" if n_fail == 0 else "FAIL"
                print(f"{verdict} {sc} ({mode}): {len(CHECKS) - n_fail}/{len(CHECKS)} checks, {time.time() - t0:.0f}s",
                      flush=True)
                with open(os.path.join(REPORT, f"compat-{sc}-{mode}.json"), "w", encoding="utf8") as f:
                    json.dump({"scenario": sc, "mode": mode, "verdict": verdict, "checks": CHECKS, "data": data}, f,
                              indent=1, ensure_ascii=False, default=str)
    finally:
        redis.stop()
        for p in PROCS:
            stop_proc(p, 5)
    return 0 if total_fail == 0 else 1
