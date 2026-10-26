"""
Targets = the servers under test. A target knows how to start/stop its processes for one vector and
offers the test hooks; everything on the wire is driven by cot.py / dps.py, identically for all targets.

  py  — the ORIGINAL Python taky 0.9 (read-only ../taky, venv from tools/pyref), bind_ip 127.0.0.2
  rs  — taky-rs / taky_dps-rs, bind_ip 127.0.0.3 — DPS (S-319), CoT (S-315), unit (S-402: taky-rs-unit)
        CoT runs one of two Rust processes (--rs-cot):
          launcher  taky-rs-difftest (crates/taky-testkit, feature difftest): the real server code
                    (taky_server::start on Listeners::bind) + FakeClock at the vector's `now` + the
                    pylaunch_cot.py control channel (advance, persist snapshot). Default; full checks.
          bin       the shipped `taky-rs -c taky.conf` binary as is: no frozen clock and no persist
                    hook, so vectors that require `clock` are N/A and memory-persist checks are skipped.

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

    hooks = True

    def cot(self, workdir, vec=None):
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


class RsCot(PyCot):
    """taky-rs CoT server as a live process on 127.0.0.3.

    mode "launcher": taky-rs-difftest with the same ctl contract as pylaunch_cot.py (ready marker,
    cmd.json + SIGUSR1 -> ack.json; crash.txt). mode "bin": the shipped taky-rs binary; readiness =
    the CoT port accepts, no control channel (advance/persist are unavailable, see RsTarget)."""

    def start(self, conf, vec):
        self.ctl = bench.fresh_dir(os.path.join(self.workdir, "ctl"))
        log = open(os.path.join(self.workdir, "server.log"), "wb")
        env = dict(os.environ)
        env.pop("TAKY_CONFIG", None)
        if self.t.cot_mode == "bin":
            cmd = [self.t.cot_exe, "-c", conf, "-l", "info"]
        else:
            cmd = [self.t.cot_exe, "--conf", conf, "--now", vec.get("now", "2030-01-01T00:00:00Z"),
                   "--ctl", self.ctl, "--log-level", "info"]
        self.proc = subprocess.Popen(cmd, cwd=self.workdir, env=env, stdout=log,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        end = time.monotonic() + 20
        while time.monotonic() < end:
            if self.proc.poll() is not None:
                break
            if self.t.cot_mode == "bin":
                if bench.port_busy(self.t.ip, bench.COT_PORT):
                    return
            elif os.path.exists(os.path.join(self.ctl, "ready")):
                return
            time.sleep(0.02)
        raise RuntimeError(f"{os.path.basename(self.t.cot_exe)} did not start (see {self.workdir}/server.log)")

    def advance(self, seconds):
        if self.t.cot_mode == "bin":
            raise RuntimeError("advance needs the frozen clock (--rs-cot launcher)")
        return super().advance(seconds)

    def persist_hook(self):
        if self.t.cot_mode == "bin":
            # black box: Redis is dumped by the harness; memory persistence is not observable
            return {"backend": "redis"} if self.redis_on else None
        if not self.alive():
            return None  # no post-mortem snapshot in Rust (a crash is a FAIL anyway)
        return super().persist_hook()


class RsTarget:
    """Rust target (taky-rs, taky_dps-rs) — bind_ip 127.0.0.3.

    Binaries from --rs-bin (default <taky-rs>/target/debug):
      DPS  taky_dps-rs         (cargo build -p taky-dps --bin taky_dps-rs)
      CoT  taky-rs-difftest    (cargo build -p taky-testkit --features difftest --bin taky-rs-difftest)
           or taky-rs with --rs-cot bin (cargo build -p taky-server --bin taky-rs)
    Unit: taky-rs-unit (cargo build -p taky-testkit --features difftest --bin taky-rs-unit), same
          contract as pyunit.py (argv: vector paths, stdout: {id: [observation per case]}).
    """

    name = "rs"
    redis_db = 2

    def __init__(self, ip, bin_dir=None, cot_mode="launcher"):
        self.ip = ip
        self.bin_dir = os.path.abspath(bin_dir or os.path.join(HERE, "..", "..", "..", "target", "debug"))
        self.dps_exe = os.path.join(self.bin_dir, "taky_dps-rs")
        self.cot_mode = cot_mode
        self.cot_exe = os.path.join(self.bin_dir, "taky-rs" if cot_mode == "bin" else "taky-rs-difftest")
        # without the launcher there is no frozen clock and no memory persist hook
        self.hooks = cot_mode != "bin"

    def dps(self, workdir):
        if not os.access(self.dps_exe, os.X_OK):
            raise TargetUnavailable(f"{self.dps_exe} not found (cargo build -p taky-dps --bin taky_dps-rs)")
        return RsDps(self, workdir)

    def cot(self, workdir, vec=None):
        if not os.access(self.cot_exe, os.X_OK):
            how = ("cargo build -p taky-server --bin taky-rs" if self.cot_mode == "bin" else
                   "cargo build -p taky-testkit --features difftest --bin taky-rs-difftest")
            raise TargetUnavailable(f"{self.cot_exe} not found ({how})")
        if vec is not None and not self.hooks and "clock" in vec.get("requires", []):
            raise TargetUnavailable("vector requires a frozen clock; the plain taky-rs binary has none "
                                    "(use --rs-cot launcher)")
        return RsCot(self, workdir)

    def run_unit(self, paths):
        exe = os.path.join(self.bin_dir, "taky-rs-unit")
        if not os.access(exe, os.X_OK):
            raise TargetUnavailable(f"{exe} not found "
                                    "(cargo build -p taky-testkit --features difftest --bin taky-rs-unit)")
        out = subprocess.run([exe, *paths], capture_output=True, check=True)
        return json.loads(out.stdout)


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
