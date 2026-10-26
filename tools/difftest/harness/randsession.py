"""
Seeded random session generator (qa01, S-402; test-strategy §1.3 scenario source (c)).

    tools/difftest/difftest random --sessions 1000 --seed 1 [--clients 2..6] [--ops 10..18]
                                   [--target rs|py] [--rs-bin DIR] [--out DIR] [--resume] [--notes FILE]
    tools/difftest/difftest random --seed 4711 --sessions 1 -v      # reproduce one session

Session i uses seed `--seed + i`; everything (config, clients, operations, payloads) is derived
from `random.Random(seed)` only, so a seed reproduces a session exactly. A session is turned into
a synthetic format-2 "cot" vector WITHOUT expectations (oracle-free) and replayed by the normal
CoT driver (cot.CotRun) against the Python baseline (127.0.0.2) and the target (127.0.0.3) at the
same time; the observations are compared with compare.diff_cot (exact; connect replay as a
multiset; Redis TTL +-1 s). Both servers run with a frozen clock at the session's `now`
(pylaunch_cot.py / taky-rs-difftest), so pong/persist/TTL values are deterministic.

Generated traffic: N devices (uid/callsign/team) connect, then a random mix of SA updates,
markers (random stale: already stale .. 1 day), GeoChat (All Chat Rooms / team / direct, incl.
unknown targets), <marti><dest callsign> (known/unknown/several), pings (t-x-c-t), garbage
(broken XML -> disconnect, non-event root, bad time / point / missing uid, text noise), split and
batched sends, disconnects and reconnects. Config axes: memory or Redis persistence,
max_persist_ttl, log_cot, TLS with client certificates. No mgmt operations (Python drops CoT
while a mgmt connection is open; mgmt is covered by V044-V046, V051, V052).

Results: <out>/sessions.jsonl (one line per seed: params, status, divergences), divergent
sessions also as <out>/div-<seed>.json (the generated vector + both observations).
"""
import argparse
import json
import os
import random
import sys
import threading
import time
import traceback
from datetime import datetime, timedelta

from . import bench, compare
from .cot import CotRun
from .targets import PyTarget, RsTarget

TEAMS = ["Cyan", "Red", "Blue", "Green", "White"]
ROLES = ["Team Member", "Team Lead", "HQ", "Sniper", "Medic", "RTO"]
SETUP_LOCK = threading.Lock()  # CotRun.setup uses taky's global app_config (load_config, anc)


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


class Gen:
    def __init__(self, seed, clients, ops):
        self.seed = seed
        self.r = random.Random(seed)
        self.n_clients = self.r.randint(*clients)
        self.n_ops = self.r.randint(*ops)
        self.now = datetime(2030, 1, 1) + timedelta(seconds=self.r.randrange(0, 86400 * 365))
        self.msg = 0

    # ---------------------------------------------------------------- payloads
    def stale(self):
        return self.now + timedelta(seconds=self.r.choice([-60, -1, 5, 30, 600, 3600, 86400]))

    def decl(self):
        return self.r.choice(['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
                              '<?xml version="1.0"?>', ""])

    def coord(self, lo, hi):
        x = self.r.uniform(lo, hi)
        return self.r.choice([f"{x:.6f}", f"{x:.9f}", repr(round(x, 3)), f"{x:.1f}"])

    def head(self, uid, typ, how, stale=None):
        n = iso(self.now)
        return (f'<event version="2.0" uid="{uid}" type="{typ}" time="{n}" start="{n}" '
                f'stale="{iso(stale or self.stale())}" how="{how}">')

    def point(self, zero=False):
        if zero:
            return '<point lat="0.0" lon="0.0" hae="9999999.0" ce="9999999.0" le="9999999.0"/>'
        return (f'<point lat="{self.coord(-89, 89)}" lon="{self.coord(-179, 179)}" '
                f'hae="{self.coord(-100, 3000)}" ce="{self.r.choice(["9.9", "9999999.0", "3"])}" '
                f'le="9999999.0"/>')

    def sa(self, d, extra=""):
        det = (f'<takv os="29" version="4.10.0" device="PIXEL {d["i"]}" platform="ATAK-CIV"/>'
               f'<contact endpoint="*:-1:stcp" callsign="{d["cs"]}"/><uid Droid="{d["cs"]}"/>'
               f'<__group role="{d["role"]}" name="{d["team"]}"/>'
               f'<status battery="{self.r.randint(1, 100)}"/>'
               f'<track course="{self.coord(0, 359)}" speed="{self.coord(0, 30)}"/>')
        return (self.decl() + self.head(d["uid"], "a-f-G-U-C", "m-g") + self.point()
                + f"<detail>{det}{extra}</detail></event>")

    def marker(self, d, extra=""):
        uid = f"M-{self.r.randint(1, 6)}"
        return (self.decl() + self.head(uid, self.r.choice(["a-u-G", "a-h-G", "b-m-p-s-m"]), "h-g-i-g-o")
                + self.point() + f'<detail><contact callsign="Marker {uid}"/>'
                + (f'<link uid="{d["uid"]}" type="a-f-G-U-C" relation="p-p"/>' if self.r.random() < .5 else "")
                + f"{extra}</detail></event>")

    def chat(self, d, kind, devs):
        self.msg += 1
        n = iso(self.now)
        text = self.r.choice(["hello", "hi &lt;3 &amp; more", "ok", "roger", "привет"])
        if kind == "all":
            room = cid = "All Chat Rooms"
            parent, grp = "RootContactGroup", ""
        elif kind == "team":
            room = cid = self.r.choice([d["team"]] * 3 + TEAMS)
            parent = "TeamGroups"
            grp = f'<chatgrp uid0="{d["uid"]}" uid1="{room}" id="{room}"/>'
        else:
            if self.r.random() < 0.85:
                t = self.r.choice(devs)
            else:
                t = {"uid": "ANDROID-Z", "cs": "ZULU"}
            room, cid, parent = t["cs"], t["uid"], "RootContactGroup"
            grp = f'<chatgrp uid0="{d["uid"]}" uid1="{t["uid"]}" id="{t["uid"]}"/>'
        uid = f"GeoChat.{d['uid']}.{cid}.{self.msg:04d}"
        return (self.decl() + self.head(uid, "b-t-f", "h-g-i-g-o", self.now + timedelta(days=1))
                + self.point(zero=True)
                + f'<detail><__chat parent="{parent}" groupOwner="false" chatroom="{room}" id="{cid}" '
                  f'senderCallsign="{d["cs"]}">{grp}</__chat>'
                  f'<link uid="{d["uid"]}" type="a-f-G-U-C" relation="p-p"/>'
                  f'<remarks source="BAO.F.ATAK.{d["uid"]}" to="{cid}" time="{n}">{text}</remarks>'
                  f'<__serverdestination destinations="1.2.3.4:4242:tcp:{d["uid"]}"/></detail></event>')

    def marti(self, devs):
        k = self.r.choice([1, 1, 2])
        cs = [self.r.choice(devs)["cs"] if self.r.random() < 0.8 else "NOBODY" for _ in range(k)]
        return "<marti>" + "".join(f'<dest callsign="{c}"/>' for c in cs) + "</marti>"

    def ping(self, d):
        n = self.now
        return (self.decl() + self.head(f"{d['uid']}-ping", "t-x-c-t", "m-g", n + timedelta(seconds=10))
                + '<point lat="0.0" lon="0.0" hae="0.0" ce="9999999.0" le="9999999.0"/><detail/></event>')

    def garbage(self, d):
        kind = self.r.choice(["broken", "non_event", "bad_time", "bad_point", "no_uid", "noise"])
        if kind == "broken":
            return kind, '<event version="2.0" uid="X"><point></event>'
        if kind == "non_event":
            return kind, '<foo bar="1"><baz/></foo>'
        if kind == "bad_time":
            return kind, self.sa(d).replace(f'time="{iso(self.now)}"', 'time="not-a-time"', 1)
        if kind == "bad_point":
            return kind, self.sa(d).replace('<point lat="', '<point lat="abc', 1)
        if kind == "no_uid":
            return kind, self.sa(d).replace(f' uid="{d["uid"]}"', "", 1)
        return kind, "this is not xml at all\n"

    def split(self, s):
        b = s.encode("utf8")
        cuts = sorted(self.r.sample(range(1, len(b)), k=min(len(b) - 1, self.r.randint(1, 3))))
        parts, last = [], 0
        for c in cuts + [len(b)]:
            parts.append(b[last:c])
            last = c
        return parts

    # ---------------------------------------------------------------- session
    def build(self):
        r = self.r
        ssl_on = r.random() < 0.10
        cfg = {"taky": {}, "cot_server": {}, "ssl": {}}
        backend = "redis" if r.random() < 0.3 else "memory"
        if backend == "redis":
            cfg["taky"]["redis"] = "true"
            cfg["taky"]["hostname"] = r.choice(["srv1", "taky"])
        if r.random() < 0.2:
            cfg["cot_server"]["max_persist_ttl"] = str(r.choice([1, 30, 60, 3600]))
        if r.random() < 0.15:
            cfg["cot_server"]["log_cot"] = "AUTO"
        if ssl_on:
            cfg["ssl"]["enabled"] = "true"
        devs = []
        for i in range(self.n_clients):
            devs.append({"i": i, "uid": f"ANDROID-{i:02d}", "cs": f"CS{i}",
                         "team": r.choice(TEAMS[:3]), "role": r.choice(ROLES)})
        clients, steps = {}, []
        cid_of = {}  # device index -> current client id
        connected = set()

        def new_client(i):
            cid = f"C{i}" if i not in cid_of else f"{cid_of[i]}r"
            cid_of[i] = cid
            clients[cid] = {"kind": "cot"}
            if ssl_on:
                clients[cid]["cert"] = devs[i]["cs"]
            return cid

        def send(cid, payload, op_kind):
            if isinstance(payload, list):
                steps.append({"op": "send", "client": cid,
                              "chunks_b64": [__import__("base64").b64encode(p).decode() for p in payload],
                              "gen": op_kind})
            else:
                steps.append({"op": "send", "client": cid, "chunks": [payload], "gen": op_kind})

        first = r.randint(2, self.n_clients)
        for i in range(first):
            steps.append({"op": "connect", "client": new_client(i), "gen": "connect"})
            connected.add(i)
        weights = [("sa", 26), ("marker", 12), ("chat_all", 8), ("chat_team", 8), ("chat_direct", 8),
                   ("marti", 7), ("ping", 5), ("garbage", 6), ("split", 6), ("batch", 5),
                   ("close", 5), ("connect", 6)]
        names = [w[0] for w in weights]
        ws = [w[1] for w in weights]
        for _ in range(self.n_ops):
            op = r.choices(names, ws)[0]
            if op == "connect":
                idle = [i for i in range(self.n_clients) if i not in connected]
                if not idle:
                    op = "sa"
                else:
                    i = r.choice(idle)
                    steps.append({"op": "connect", "client": new_client(i), "gen": "connect"})
                    connected.add(i)
                    continue
            if not connected:
                i = r.randrange(self.n_clients)
                steps.append({"op": "connect", "client": new_client(i), "gen": "connect"})
                connected.add(i)
            i = r.choice(sorted(connected))
            d, cid = devs[i], cid_of[i]
            if op == "close":
                steps.append({"op": "close", "client": cid, "gen": "close"})
                connected.discard(i)
            elif op == "sa":
                send(cid, self.sa(d), op)
            elif op == "marker":
                send(cid, self.marker(d), op)
            elif op.startswith("chat_"):
                send(cid, self.chat(d, op[5:], devs), op)
            elif op == "marti":
                body = self.marker(d, self.marti(devs)) if r.random() < .6 else self.sa(d, self.marti(devs))
                send(cid, body, op)
            elif op == "ping":
                send(cid, self.ping(d), op)
            elif op == "garbage":
                kind, body = self.garbage(d)
                send(cid, body, f"garbage:{kind}")
                if kind in ("broken", "noise"):
                    connected.discard(i)  # server closes the connection (XML syntax error)
            elif op == "split":
                send(cid, self.split(r.choice([self.sa, self.marker])(d)), op)
            elif op == "batch":
                send(cid, "".join(r.choice([self.sa, self.marker, self.ping])(d) for _ in range(r.randint(2, 3))), op)
        # observer: a fresh client sees the persisted events as replay (multiset)
        obs_cid = "OBS"
        clients[obs_cid] = {"kind": "cot"}
        if ssl_on:
            clients[obs_cid]["cert"] = "OBSERVER"
        steps.append({"op": "connect", "client": obs_cid, "gen": "observer"})
        for st in steps:
            st["expect"] = {}
        vec = {"id": f"R{self.seed}", "runner": "cot", "format": 2, "now": iso(self.now),
               "config": cfg, "clients": clients, "steps": steps,
               "requires": ["clock"] + (["redis"] if backend == "redis" else []) + (["tls"] if ssl_on else [])}
        params = {"clients": self.n_clients, "ops": self.n_ops, "steps": len(steps), "backend": backend,
                  "ssl": ssl_on, "ttl": cfg["cot_server"].get("max_persist_ttl"),
                  "log_cot": "log_cot" in cfg["cot_server"]}
        return vec, params


class LockedRun(CotRun):
    def setup(self):
        with SETUP_LOCK:
            super().setup()


def run_one(vec, target, workdir, redis, quiet, taky_src, out):
    try:
        run = LockedRun(vec, target, workdir, redis, quiet, taky_src)
        obs, serials = run.run(lambda step: step.get("expect"))
        out["obs"] = compare.masked(obs, serials)
    except Exception as exc:  # pylint: disable=broad-except
        out["error"] = f"{exc}\n{traceback.format_exc()}"


def rng(s):
    a, _, b = s.partition("..")
    return int(a), int(b or a)


def main(argv):
    ap = argparse.ArgumentParser(prog="difftest random")
    ap.add_argument("--sessions", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--clients", default="2..6")
    ap.add_argument("--ops", default="10..18")
    ap.add_argument("--target", default="rs", choices=["py", "rs"])
    ap.add_argument("--rs-bin")
    ap.add_argument("--quiet", type=float, default=0.2)
    ap.add_argument("--py-ip", default=os.environ.get("PYREF_BIND_IP", "127.0.0.2"))
    ap.add_argument("--rs-ip", default="127.0.0.3")
    ap.add_argument("--taky-src", default=os.environ.get("TAKY_SRC"))
    ap.add_argument("--vectors-tools", default=None)
    ap.add_argument("--state", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--resume", action="store_true", help="skip seeds already in <out>/sessions.jsonl")
    ap.add_argument("--notes", help="append a checkpoint line to this file every --every sessions")
    ap.add_argument("--every", type=int, default=100)
    ap.add_argument("--dump", action="store_true", help="print the generated vector and exit")
    ap.add_argument("--mutate-control", action="store_true",
                    help="negative control: alter the first delivered event of the target; every session "
                         "with a delivery must then be DIVERGENT")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    here = os.path.dirname(os.path.abspath(__file__))
    tool_dir = os.path.dirname(here)
    takyrs = os.path.abspath(os.path.join(tool_dir, "..", ".."))
    office = os.path.dirname(takyrs)
    taky_src = os.path.abspath(args.taky_src or os.path.join(office, "taky"))
    tools = args.vectors_tools or os.path.join(office, "shared", "spec", "vectors", "tools")
    state = args.state or os.path.join(tool_dir, ".state", "random")
    out = args.out or os.path.join(takyrs, "target", "qa", "difftest-random")
    os.makedirs(out, exist_ok=True)
    clients, ops = rng(args.clients), rng(args.ops)

    if args.dump:
        vec, params = Gen(args.seed, clients, ops).build()
        print(json.dumps({"params": params, "vector": vec}, indent=1, ensure_ascii=False))
        return 0

    import logging

    logging.disable(logging.CRITICAL)
    jsonl = os.path.join(out, "sessions.jsonl")
    done = set()
    if args.resume and os.path.exists(jsonl):
        with open(jsonl, encoding="utf8") as fp:
            for line in fp:
                done.add(json.loads(line)["seed"])
    elif os.path.exists(jsonl):
        os.remove(jsonl)
    tmp = bench.fresh_dir(os.path.join(state, "tmp"))
    py = PyTarget(args.py_ip, sys.executable, taky_src, tools, tmp)
    if args.target == "rs":
        bin_dir = args.rs_bin or os.path.join(takyrs, "target", "release")
        tb = RsTarget(args.rs_ip, bin_dir, "launcher")
    else:
        tb = PyTarget(args.rs_ip, sys.executable, taky_src, tools, tmp)
        tb.redis_db = 2
    redis = bench.RedisServer(state, args.py_ip)
    redis.start()
    counts = {"PASS": 0, "DIVERGENT": 0, "ERROR": 0}
    t0 = time.monotonic()
    seeds = [args.seed + k for k in range(args.sessions)]
    n_run = 0
    try:
        for seed in seeds:
            if seed in done:
                continue
            vec, params = Gen(seed, clients, ops).build()
            ts = time.monotonic()
            ra, rb = {}, {}
            wa = bench.fresh_dir(os.path.join(state, "py"))
            wb = bench.fresh_dir(os.path.join(state, "tg"))
            th = [threading.Thread(target=run_one, args=(vec, py, wa, redis, args.quiet, taky_src, ra)),
                  threading.Thread(target=run_one, args=(vec, tb, wb, redis, args.quiet, taky_src, rb))]
            for t in th:
                t.start()
            for t in th:
                t.join()
            if args.mutate_control and "obs" in rb:
                for st in rb["obs"]["steps"]:
                    hit = next((c for c, evs in st["deliveries"].items() if evs), None)
                    if hit:
                        st["deliveries"][hit][0] = st["deliveries"][hit][0].replace('version="2.0"', 'version="2.1"', 1)
                        break
            if "error" in ra or "error" in rb:
                status, divs = "ERROR", [{"where": "run", "class": "harness",
                                          "a": ra.get("error"), "b": rb.get("error")}]
            else:
                divs = compare.diff_cot(vec, ra["obs"], rb["obs"], True)
                status = "DIVERGENT" if divs else "PASS"
            counts[status] += 1
            n_run += 1
            n_ev = sum(len(e) for st in ra.get("obs", {}).get("steps", []) for e in st["deliveries"].values())
            n_cl = sum(len(st["server_closed"]) for st in ra.get("obs", {}).get("steps", []))
            params = dict(params, delivered=n_ev, server_closed=n_cl)
            rec = {"seed": seed, "status": status, "params": params,
                   "seconds": round(time.monotonic() - ts, 2),
                   "divergences": [{"where": d["where"], "class": d["class"]} for d in divs]}
            with open(jsonl, "a", encoding="utf8") as fp:
                fp.write(json.dumps(rec) + "\n")
            if divs:
                with open(os.path.join(out, f"div-{seed}.json"), "w", encoding="utf8") as fp:
                    json.dump({"params": params, "divergences": divs, "vector": vec,
                               "obs_py": ra.get("obs"), "obs_target": rb.get("obs")},
                              fp, indent=1, ensure_ascii=False, default=str)
            line = f"{status:9} seed {seed} {params} {rec['seconds']}s"
            if args.verbose or divs:
                print(line, flush=True)
                for d in divs[:3]:
                    print(f"     {d['where']} [{d['class']}]\n       py: {str(d['a'])[:400]}\n"
                          f"       {tb.name}: {str(d['b'])[:400]}", flush=True)
            total_done = len(done) + n_run
            if total_done % args.every == 0:
                msg = (f"random sessions {total_done}/{len(seeds)} (seeds {args.seed}..{seed}): "
                       f"{counts}, {time.monotonic() - t0:.0f}s this run")
                print(msg, flush=True)
                if args.notes:
                    with open(args.notes, "a", encoding="utf8") as fp:
                        fp.write(f"- {datetime.now():%Y-%m-%d}: S-402 checkpoint: {msg}; resume with --resume\n")
    finally:
        redis.stop()
    summary = {"seed0": args.seed, "sessions": args.sessions, "clients": args.clients, "ops": args.ops,
               "quiet": args.quiet, "target": tb.name, "this_run": counts, "elapsed_s": round(time.monotonic() - t0, 1)}
    with open(os.path.join(out, f"summary-{args.seed}.json"), "w", encoding="utf8") as fp:
        json.dump(summary, fp, indent=1)
    print(f"\ndifftest random: {summary}")
    return 0 if counts["DIVERGENT"] == 0 and counts["ERROR"] == 0 else 1
