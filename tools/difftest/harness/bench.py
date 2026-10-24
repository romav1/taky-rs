"""
Per-vector bench preparation shared by all targets: taky.conf, test-only PKI, upload_path, Redis.

A target gets the SAME taky.conf for a vector (only bind_ip/root_dir differ), so Python and Rust
are compared on identical configuration (taky-rs reads the original taky.conf, ADR-000).
"""
import copy
import os
import shutil
import socket
import subprocess
import time

COT_PORT = 8089  # fixed per target IP (Python 127.0.0.2, Rust 127.0.0.3)
MON_PORT = 8088
DPS_TLS_PORT = 8443  # hard-coded in taky_dps
DPS_TCP_PORT = 8080
P12_PW = "atakatak"  # test-only

TRUE = ("1", "yes", "true", "on")


def is_true(v):
    return str(v).lower() in TRUE


def write_conf(path, sections):
    with open(path, "w", encoding="utf8") as fp:
        for sect, vals in sections.items():
            fp.write(f"[{sect}]\n")
            for k, v in vals.items():
                fp.write(f"{k}\n" if v is None else f"{k} = {v}\n")
            fp.write("\n")


def fresh_dir(path):
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path)
    return path


def cot_sections(vec, ip, root, redis_url):
    """taky.conf for a CoT vector (mirrors run_python.Runner.write_config, live addresses)."""
    sections = {"taky": {}, "cot_server": {}, "dp_server": {}, "ssl": {}}
    for sect, vals in copy.deepcopy(vec.get("config", {})).items():
        sections.setdefault(sect, {}).update(vals)
    sections["taky"]["bind_ip"] = ip
    sections["taky"]["root_dir"] = root
    redis_v = sections["taky"].get("redis")
    if redis_v not in (None, "", "false", "no", "off", "0"):
        # "true" (localhost:6379) and explicit URLs both go to the bench redis-server, own DB per target
        sections["taky"]["redis"] = redis_url
    sections["dp_server"]["upload_path"] = os.path.join(root, "dp-user")
    sections["cot_server"]["port"] = str(COT_PORT)
    if sections["cot_server"].get("mon_ip"):
        sections["cot_server"]["mon_ip"] = ip
        sections["cot_server"]["mon_port"] = str(MON_PORT)
    if sections["cot_server"].get("log_cot") == "AUTO":
        sections["cot_server"]["log_cot"] = os.path.join(root, "cotlog")
        os.mkdir(sections["cot_server"]["log_cot"])
    ssl_paths(sections, root)
    return sections


def ssl_paths(sections, root):
    if is_true(sections["ssl"].get("enabled", "false")):
        sd = os.path.join(root, "ssl")
        os.makedirs(sd, exist_ok=True)
        for k, f in [("ca", "ca.crt"), ("ca_key", "ca.key"), ("cert", "server.crt"),
                     ("key", "server.key"), ("server_p12", "server.p12"), ("cert_db", "cert-db.txt")]:
            sections["ssl"][k] = os.path.join(sd, f)
    else:
        sections["ssl"]["cert_db"] = os.path.join(root, "cert-db.txt")


def dps_sections(vec, ip, root):
    sections = {"taky": {}, "cot_server": {}, "dp_server": {}, "ssl": {}}
    for sect, vals in copy.deepcopy(vec.get("config", {})).items():
        sections.setdefault(sect, {}).update(vals)
    sections["taky"]["bind_ip"] = ip
    sections["taky"]["root_dir"] = root
    sections["dp_server"]["upload_path"] = os.path.join(root, "dp-user")
    ssl_paths(sections, root)
    return sections


def make_dps_pki(sections, identities):
    """CA + server cert + one client cert per distinct (cn, revoked); returns {(cn, revoked): (crt, key)}."""
    from taky.util import anc

    s = sections["ssl"]
    d = os.path.dirname(s["cert"])
    anc.make_ca(s["ca"], s["ca_key"])
    cdb = anc.CertificateDatabase()
    srv = anc.make_cert(path=d, f_name="server", hostname="localhost", cert_pw=P12_PW,
                        cert_auth=(s["ca"], s["ca_key"]), dump_pem=True, key_in_pem=False,
                        is_server_cert=True)
    cdb.add_certificate(srv)
    out = {}
    for i, (cn, revoked) in enumerate(sorted(identities)):
        f = f"client-{i}"
        cert = anc.make_cert(path=d, f_name=f, hostname=cn, cert_pw=P12_PW,
                             cert_auth=(s["ca"], s["ca_key"]), dump_pem=True, key_in_pem=True,
                             is_server_cert=False)
        cdb.add_certificate(cert)
        if revoked:
            cdb.revoke_certificate(cert.serial_number)
        out[(cn, revoked)] = (os.path.join(d, f + ".crt"), os.path.join(d, f + ".key"))
    return out


def plant_files(upload_path, initial_files):
    os.makedirs(os.path.join(upload_path, "meta"), exist_ok=True)
    for rel, spec in initial_files.items():
        full = os.path.join(upload_path, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        if "symlink_to" in spec:
            os.symlink(spec["symlink_to"], full)
        else:
            with open(full, "wb") as fp:
                fp.write(spec["content"].encode("utf8"))


def port_busy(ip, port):
    s = socket.socket()
    try:
        s.settimeout(0.3)
        return s.connect_ex((ip, port)) == 0
    finally:
        s.close()


def wait_port(ip, port, timeout, proc=None):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if proc is not None and proc.poll() is not None:
            return False
        if port_busy(ip, port):
            return True
        time.sleep(0.05)
    return False


def stop_proc(proc, timeout=10):
    """SIGTERM the whole process group (gunicorn workers too), SIGKILL after timeout."""
    import signal

    if proc is None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(5)
    # reap stragglers of the group (gunicorn workers)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


class RedisServer:
    """One redis-server for the whole difftest run (no persistence); each target uses its own DB."""

    def __init__(self, state_dir, ip, port=16379):
        self.ip, self.port, self.dir = ip, port, fresh_dir(os.path.join(state_dir, "redis"))
        self.proc = None

    def start(self):
        exe = shutil.which("redis-server")
        if not exe:
            raise RuntimeError("redis-server not found (needed by vectors that require 'redis')")
        self.proc = subprocess.Popen(
            [exe, "--bind", self.ip, "--port", str(self.port), "--save", "", "--appendonly", "no",
             "--dir", self.dir],
            stdout=open(os.path.join(self.dir, "redis.log"), "wb"), stderr=subprocess.STDOUT,
            start_new_session=True)
        if not wait_port(self.ip, self.port, 10, self.proc):
            raise RuntimeError(f"redis-server did not start on {self.ip}:{self.port}")

    def url(self, db):
        return f"redis://{self.ip}:{self.port}/{db}"

    def client(self, db):
        import redis

        return redis.StrictRedis(host=self.ip, port=self.port, db=db)

    def stop(self):
        stop_proc(self.proc)
