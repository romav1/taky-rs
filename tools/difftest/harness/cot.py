"""
CoT vector driver: replays one "cot" vector against a live target instance over real sockets and
returns observations in the same shape as an01's run_python.Runner (observed_steps / final), so the
oracle comparison can reuse run_python.Runner.check() unchanged.

Settle (format 2 rule 3) for a black-box process: after each operation the client sockets are read
until no byte arrives for `quiet` seconds (default 0.2 s; the Python launcher loops every 20 ms).
"""
import base64
import json
import os
import select
import socket
import ssl
import time

from . import bench

import run_python as rp  # an01: split_events, norm_log, Runner (certs), persist_equal


class Client:
    def __init__(self, cid, spec):
        self.cid = cid
        self.kind = spec.get("kind", "cot")
        self.sock = None
        self.buf = b""
        self.closed = False


class CotRun:
    def __init__(self, vec, target, workdir, redis, quiet, taky_src):
        self.vec, self.t, self.workdir, self.redis, self.quiet = vec, target, workdir, redis, quiet
        self.taky_src = taky_src
        self.inst = None
        self.held = []
        self.reported_closed = set()
        self.serials = {}
        self.client_ctx = {}
        self.notes = []

    # ------------------------------------------------------------ setup
    def setup(self):
        root = self.workdir
        redis_url = self.redis.url(self.t.redis_db) if self.redis else "redis://127.0.0.1:1/0"
        self.sections = bench.cot_sections(self.vec, self.t.ip, root, redis_url)
        self.conf = os.path.join(root, "taky.conf")
        bench.write_conf(self.conf, self.sections)
        self.ssl_on = bench.is_true(self.sections["ssl"].get("enabled", "false"))
        self.log_dir = self.sections["cot_server"].get("log_cot")
        self.redis_on = self.sections["taky"].get("redis") == redis_url
        from taky.config import load_config

        load_config(self.conf)  # anc.CertificateDatabase() follows ssl.cert_db of this vector
        if self.ssl_on:
            # an01's certificate setup (CA, server CN=localhost, client CNs, not_in_cert_db, revoked_before_start)
            r = rp.Runner(self.vec, self.taky_src, "exact")
            r.sections = self.sections
            r.make_certs()
            self.serials, self.client_ctx = r.serials, r.client_ctx
        if self.redis_on:
            rds = self.redis.client(self.t.redis_db)
            rds.flushdb()
            for key, val in self.vec.get("initial_redis", {}).items():
                rds.set(key, val["value"].encode())
                if val.get("ttl"):
                    rds.expire(key, val["ttl"])
            self.rds = rds
        self.clients = {cid: Client(cid, s) for cid, s in self.vec.get("clients", {}).items()}
        self.inst = self.t.cot(self.workdir)
        self.inst.start(self.conf, self.vec)

    # ------------------------------------------------------------ io
    def drain(self):
        """Read every open client socket until `quiet` seconds pass without data."""
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            socks = {c.sock: c for c in self.clients.values() if c.sock and not c.closed}
            if not socks:
                time.sleep(self.quiet)
                return
            pending = [s for s in socks if isinstance(s, ssl.SSLSocket) and s.pending()]
            ready = pending or select.select(list(socks), [], [], self.quiet)[0]
            if not ready:
                return
            for s in ready:
                self._recv(socks[s])

    def _recv(self, c):
        while True:
            try:
                data = c.sock.recv(65536)
            except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                return
            except (ConnectionResetError, BrokenPipeError, ssl.SSLError, OSError):
                c.closed = True
                return
            if not data:
                c.closed = True
                return
            c.buf += data

    def connect(self, c, raw=False):
        port = bench.MON_PORT if c.kind == "monitor" else bench.COT_PORT
        try:
            s = socket.create_connection((self.t.ip, port), timeout=5)
        except OSError:
            c.closed = True
            return
        if self.ssl_on and c.kind == "cot" and not raw:
            ctx = self.client_ctx.get(c.cid)
            if ctx is None:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            try:
                s = ctx.wrap_socket(s)  # blocking handshake against the live server
            except (ssl.SSLError, OSError):
                c.closed = True
        s.setblocking(False)
        c.sock = s

    def send(self, c, chunks):
        for ch in chunks:
            if isinstance(ch, dict):
                ch = ch.get("prefix", "") + ch["repeat"] * int(ch["count"]) + ch.get("suffix", "")
            data = ch if isinstance(ch, bytes) else ch.encode("utf8")
            if c.closed or c.sock is None:
                break
            c.sock.setblocking(True)
            c.sock.settimeout(10)
            try:
                c.sock.sendall(data)
            except OSError:
                c.closed = True
            c.sock.setblocking(False)
            # chunk boundary = server recv boundary: let the server consume this chunk first
            self.drain()

    def mgmt(self, request, n_expected=1):
        path = os.path.join(self.workdir, "taky-mgmt.sock")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect(path)
        except OSError:
            return {"_no_response": True}
        reqs = request if isinstance(request, list) and n_expected > 1 else [request]
        payload = b"".join((r if isinstance(r, str) else json.dumps(r)).encode() + b"\0" for r in reqs)
        data = b""
        try:
            s.sendall(payload)
            while data.count(b"\0") < n_expected:
                d = s.recv(65536)
                if not d:
                    break
                data += d
        except OSError:  # timeout: no (complete) response
            pass
        s.close()
        if n_expected > 1:
            return [json.loads(x.decode()) for x in data.split(b"\0")[:-1]]
        if b"\0" not in data:
            return {"_no_response": True}
        return json.loads(data[: data.index(b"\0")].decode())

    # ------------------------------------------------------------ observation
    def snapshot_persist(self):
        hook = self.inst.persist_hook()
        if hook is None:
            return None
        if hook.get("backend") == "redis":
            out = {}
            for key in sorted(self.rds.keys("*")):
                v = self.rds.get(key)
                if v is not None:
                    out[key.decode()] = {"value": v.decode(), "ttl": self.rds.ttl(key)}
            return {"backend": "redis", "keys": out}
        return hook

    def run_step(self, step, exp):
        op = step["op"]
        for c in self.clients.values():
            c.buf = b""
        obs = {}
        if op == "connect":
            self.connect(self.clients[step["client"]])
        elif op == "connect_raw":
            self.connect(self.clients[step["client"]], raw=True)
        elif op == "send":
            chunks = step.get("chunks")
            if chunks is None:
                chunks = [base64.b64decode(b) for b in step["chunks_b64"]]
            self.send(self.clients[step["client"]], chunks)
        elif op == "close":
            c = self.clients[step["client"]]
            try:
                c.sock.close()
            except (OSError, AttributeError):
                pass
            c.closed = True
        elif op == "advance":
            self.inst.advance(float(step["seconds"]))
        elif op == "mgmt":
            obs["mgmt_response"] = self.mgmt(step["request"])
        elif op == "mgmt_multi":
            obs["mgmt_response"] = self.mgmt(step["requests"], n_expected=len(step["requests"]))
        elif op == "mgmt_hold":
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(os.path.join(self.workdir, "taky-mgmt.sock"))
            self.held.append(s)
        elif op == "mgmt_release":
            for s in self.held:
                s.close()
            self.held = []
        elif op == "issue_cert":
            from taky.util import anc

            sd = self.sections["ssl"]
            cert = anc.make_cert(path=os.path.dirname(sd["cert"]), f_name=f"issued-{step['cn']}",
                                 hostname=step["cn"], cert_pw=bench.P12_PW,
                                 cert_auth=(sd["ca"], sd["ca_key"]), dump_pem=True,
                                 key_in_pem=True, is_server_cert=False)
            anc.CertificateDatabase().add_certificate(cert)
            self.serials[step["cn"]] = cert.serial_number
        else:
            raise ValueError(f"unknown op {op}")
        self.drain()
        deliveries, closed = {}, []
        for cid, c in self.clients.items():
            if c.buf:
                deliveries[cid] = rp.split_events(c.buf)
            if c.closed and op != "close" and cid not in self.reported_closed:
                closed.append(cid)
        self.reported_closed.update(closed)
        if op == "close":
            self.reported_closed.add(step["client"])
        obs["deliveries"] = deliveries
        obs["server_closed"] = sorted(closed)
        if not self.inst.alive():
            obs["server_crash"] = self.inst.crash_reason()
        elif "persist" in (exp or {}):
            obs["persist"] = self.snapshot_persist()
        return obs

    def final(self):
        final = {}
        persist = self.snapshot_persist()
        if persist is not None:
            final["persist"] = persist
        if self.log_dir:
            files = {}
            for f in sorted(os.listdir(self.log_dir)):
                with open(os.path.join(self.log_dir, f), encoding="utf8") as fp:
                    files[f] = rp.norm_log(fp.read())
            # D-12 (an01 rule): *.cot that escaped log_cot into root_dir, keyed relative to log_cot
            for dirpath, _dirs, filenames in os.walk(self.workdir):
                if os.path.abspath(dirpath) == os.path.abspath(self.log_dir):
                    continue
                for f in sorted(filenames):
                    if f.endswith(".cot"):
                        full = os.path.join(dirpath, f)
                        with open(full, encoding="utf8") as fp:
                            files[os.path.relpath(full, self.log_dir)] = rp.norm_log(fp.read())
            final["log_files"] = files
        if self.ssl_on:
            st = {}
            with open(self.sections["ssl"]["cert_db"], encoding="utf8") as fp:
                for line in fp:
                    parts = line.rstrip("\n").split("\t")
                    st[parts[4]] = parts[0]
            final["cert_db_status"] = st
        return final

    def run(self, expect_for):
        """expect_for(step) -> the expectation this target is checked against (or None)."""
        steps_obs = []
        self.setup()
        try:
            for step in self.vec["steps"]:
                exp = expect_for(step)
                if exp is None:  # Rust-only step: never executed against Python (format 2)
                    break
                obs = self.run_step(step, exp)
                steps_obs.append(obs)
                if obs.get("server_crash"):
                    break
            final = self.final()
        finally:
            for s in self.held:
                s.close()
            for c in self.clients.values():
                try:
                    if c.sock:
                        c.sock.close()
                except OSError:
                    pass
            self.inst.stop()
        return normalize({"steps": steps_obs, "final": final}, self.t.ip), self.serials


def normalize(obs, ip):
    """Map the target's bind_ip to the reference address space of the vectors:
    ip -> 127.0.0.1 everywhere, then log_cot file names 127.0.0.1 -> $IP (an01's rule)."""
    obs = json.loads(json.dumps(obs).replace(ip, "127.0.0.1"))
    lf = obs["final"].get("log_files")
    if lf is not None:
        obs["final"]["log_files"] = {k.replace("127.0.0.1", "$IP"): v for k, v in lf.items()}
    return obs
