"""
Targets = the servers under test. A target knows how to start/stop its processes for one vector and
offers the test hooks; everything on the wire is driven by cot.py / dps.py, identically for all targets.

  py  — the ORIGINAL Python taky 0.9 (read-only ../taky, venv from tools/pyref), bind_ip 127.0.0.2
  rs  — taky-rs / taky_dps-rs, bind_ip 127.0.0.3 — DPS wired (S-319); CoT/unit N/A until T-30

Instance contract (CoT):  start(conf, vec, ctl_dir) / stop() / alive() / crash_reason()
                          advance(seconds) / persist_hook() -> {"backend": "memory", "uids": [...]} | {"backend": "redis"}
Instance contract (DPS):  start(conf, workdir) / stop(); port, scheme
Unit:                     run_unit(paths) -> {vector_id: [observation per case]}
"""
import json
import os
import subprocess
import sys
import time

from . import bench

HERE = os.path.dirname(os.path.abspath(__file__))


class TargetUnavailable(RuntimeError):
    pass


class PyCot:
    def __init__(self, target, workdir):
        self.t, self.workdir = target, workdir
        self.proc = None
        self.seq = 0

    def start(self, conf, vec):
        self.ctl = bench.fresh_dir(os.path.join(self.workdir, "ctl"))
        log = open(os.path.join(self.workdir, "server.log"), "wb")
        self.proc = subprocess.Popen(
            [self.t.python, os.path.join(HERE, "pylaunch_cot.py"), "--conf", conf,
             "--now", vec.get("now", "2030-01-01T00:00:00Z"), "--ctl", self.ctl, "--log-level", "info"],
            cwd=self.workdir, env=self.t.env, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True)
        end = time.monotonic() + 20
        while time.monotonic() < end:
            if os.path.exists(os.path.join(self.ctl, "ready")):
                return
            if self.proc.poll() is not None:
                break
            time.sleep(0.02)
        raise RuntimeError(f"python taky did not start (see {self.workdir}/server.log)")

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def crash_reason(self):
        p = os.path.join(self.ctl, "crash.txt")
        if os.path.exists(p):
            with open(p, encoding="utf8") as fp:
                return fp.read()
        return f"exit {self.proc.poll()}"

    def _ctl(self, **cmd):
        import signal

        self.seq += 1
        cmd["seq"] = self.seq
        p = os.path.join(self.ctl, "cmd.json")
        with open(p + ".tmp", "w", encoding="utf8") as fp:
            json.dump(cmd, fp)
        os.replace(p + ".tmp", p)
        os.kill(self.proc.pid, signal.SIGUSR1)
        ack = os.path.join(self.ctl, "ack.json")
        end = time.monotonic() + 10
        while time.monotonic() < end:
            try:
                with open(ack, encoding="utf8") as fp:
                    data = json.load(fp)
                if data.get("seq") == self.seq:
                    return data
            except (OSError, ValueError):
                pass
            if not self.alive():
                return None
            time.sleep(0.01)
        raise RuntimeError("control hook timed out")

    def advance(self, seconds):
        return self._ctl(advance=seconds)

    def persist_hook(self):
        if not self.alive():  # crashed: post-mortem snapshot written by the launcher
            p = os.path.join(self.ctl, "persist-at-exit.json")
            if os.path.exists(p):
                with open(p, encoding="utf8") as fp:
                    return json.load(fp)
            return None
        ack = self._ctl(persist=True)
        return None if ack is None else ack["persist"]

    def stop(self):
        bench.stop_proc(self.proc)


class PyDps:
    def __init__(self, target, workdir):
        self.t, self.workdir = target, workdir
        self.proc = None

    def start(self, conf, ssl_on):
        self.port = bench.DPS_TLS_PORT if ssl_on else bench.DPS_TCP_PORT
        if bench.port_busy(self.t.ip, self.port):
            raise RuntimeError(f"{self.t.ip}:{self.port} is busy (pyref bench up? run tools/pyref/down.sh)")
        log = open(os.path.join(self.workdir, "server.log"), "wb")
        env = dict(self.t.env, TAKY_CONFIG=conf)
        self.proc = subprocess.Popen(
            [self.t.python, "-m", "taky.dps", "-c", conf, "-l", "info"],
            cwd=self.workdir, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        if not bench.wait_port(self.t.ip, self.port, 30, self.proc):
            raise RuntimeError(f"taky_dps did not start (see {self.workdir}/server.log)")

    def stop(self):
        bench.stop_proc(self.proc)


class PyTarget:
    name = "py"
    redis_db = 1

    def __init__(self, ip, python, taky_src, vectors_tools, tmpdir):
        self.ip = ip
        self.python = python
        self.env = dict(os.environ)
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.env["PYTHONPATH"] = os.pathsep.join([taky_src, vectors_tools])
        self.env["TMPDIR"] = tmpdir
        self.env.pop("TAKY_CONFIG", None)

    def cot(self, workdir):
        return PyCot(self, workdir)

    def dps(self, workdir):
        return PyDps(self, workdir)

    def run_unit(self, paths):
        out = subprocess.run([self.python, os.path.join(HERE, "pyunit.py"), *paths],
                             env=self.env, capture_output=True, check=True)
        return json.loads(out.stdout)


class RsDps:
    """taky_dps-rs as a live process (same taky.conf/cert layout as PyDps; bind_ip 127.0.0.3).

    No testkit hooks: SubmissionDateTime is masked ($TIMESTAMP, dps.observe), like the Python side."""

    def __init__(self, target, workdir):
        self.t, self.workdir = target, workdir
        self.proc = None

    def start(self, conf, ssl_on):
        self.port = bench.DPS_TLS_PORT if ssl_on else bench.DPS_TCP_PORT
        if bench.port_busy(self.t.ip, self.port):
            raise RuntimeError(f"{self.t.ip}:{self.port} is busy")
        log = open(os.path.join(self.workdir, "server.log"), "wb")
        env = dict(os.environ, TAKY_CONFIG=conf)
        self.proc = subprocess.Popen(
            [self.t.dps_exe, "-c", conf, "-l", "info"],
            cwd=self.workdir, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        if not bench.wait_port(self.t.ip, self.port, 30, self.proc):
            raise RuntimeError(f"taky_dps-rs did not start (see {self.workdir}/server.log)")

    def stop(self):
        bench.stop_proc(self.proc)


class RsTarget:
    """Rust target (taky-rs, taky_dps-rs) — bind_ip 127.0.0.3.

    DPS: taky_dps-rs from --rs-bin (default <taky-rs>/target/debug; `cargo build -p taky-dps --bin taky_dps-rs`).
    CoT / unit: not wired yet (T-30 needs the testkit hooks of qa01/handoff/T-11.md and a unit adapter);
    such vectors are reported N/A, not run.
    """

    name = "rs"
    redis_db = 2

    def __init__(self, ip, bin_dir=None):
        self.ip = ip
        self.bin_dir = bin_dir or os.path.abspath(os.path.join(HERE, "..", "..", "..", "target", "debug"))
        self.dps_exe = os.path.join(self.bin_dir, "taky_dps-rs")

    def dps(self, workdir):
        if not os.access(self.dps_exe, os.X_OK):
            raise TargetUnavailable(f"{self.dps_exe} not found (cargo build -p taky-dps --bin taky_dps-rs)")
        return RsDps(self, workdir)

    def _na(self, *_a, **_k):
        raise TargetUnavailable("rust CoT server / unit adapter not wired into difftest yet (T-30)")

    cot = run_unit = _na


def local_non_loopback_ip():
    """A local non-loopback address to use as the client source for `remote_addr` DPS steps."""
    import socket

    env = os.environ.get("DIFFTEST_REMOTE_IP")
    if env:
        return env
    for probe in ("192.0.2.1", "10.255.255.255", "8.8.8.8"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((probe, 9))
            ip = s.getsockname()[0]
        except OSError:
            continue
        finally:
            s.close()
        if not ip.startswith("127."):
            return ip
    return None


def python_exe():
    return sys.executable
