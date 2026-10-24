"""
DPS vector driver: replays one "dps" vector against a live taky_dps (gunicorn, real TLS) and returns
observations in the shape of an01's run_python_dps (status, content_type, body / body_json / body_b64 /
body_is_framework_page, headers; final files of upload_path).

Live differences from an01's Flask-test-client runner (by design, this is the real path):
  * identity -> a real client certificate with that CN (revoked -> 'R' line in cert-db), no injected headers;
  * request headers go through gunicorn + ClientCertificateWorker as is (case variants sent verbatim);
  * remote_addr -> the request is sent from a local non-loopback source address (any; the exact value
    in the vector is not reproducible). Without such an address the step is reported as SKIP.
Normalisation (same as an01): SubmissionDateTime -> $TIMESTAMP, taky-unknown -> taky-$VERSION,
absolute upload_path -> $UPLOAD_PATH.
"""
import base64
import http.client
import io
import json
import os
import ssl
import urllib.parse

from . import bench
from .targets import local_non_loopback_ip

import run_python_dps as rpd  # an01: norm_json, norm_text, snapshot_files


class DpsRun:
    def __init__(self, vec, target, workdir):
        self.vec, self.t, self.workdir = vec, target, workdir
        self.skipped = []

    def setup(self):
        self.sections = bench.dps_sections(self.vec, self.t.ip, self.workdir)
        self.up = self.sections["dp_server"]["upload_path"]
        bench.plant_files(self.up, self.vec.get("initial_files", {}))
        self.conf = os.path.join(self.workdir, "taky.conf")
        bench.write_conf(self.conf, self.sections)
        self.ssl_on = bench.is_true(self.sections["ssl"].get("enabled", "false"))
        self.certs = {}
        if self.ssl_on:
            from taky.config import load_config

            load_config(self.conf)
            idents = {(st["request"]["identity"]["cn"], bool(st["request"]["identity"].get("revoked")))
                      for st in self.vec["steps"] if st["request"].get("identity")}
            self.certs = bench.make_dps_pki(self.sections, idents)
        self.inst = self.t.dps(self.workdir)
        self.inst.start(self.conf, self.ssl_on)

    def request(self, rq):
        base = urllib.parse.urlsplit(self.vec.get("base_url", "https://taky.example:8443/"))
        src = None
        if rq.get("remote_addr"):
            ip = local_non_loopback_ip()
            if ip is None:
                return None
            src = (ip, 0)
        if self.ssl_on:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ident = rq.get("identity")
            if ident:
                crt, key = self.certs[(ident["cn"], bool(ident.get("revoked")))]
                ctx.load_cert_chain(crt, key)
            conn = http.client.HTTPSConnection(self.t.ip, self.inst.port, timeout=15, context=ctx,
                                               source_address=src)
        else:
            conn = http.client.HTTPConnection(self.t.ip, self.inst.port, timeout=15, source_address=src)
            ident = rq.get("identity")
        headers = list(rq.get("headers", {}).items())
        if not self.ssl_on and ident:
            # plain mode: identity is what a trusted front end would set (an01 runner semantics)
            headers.append(("X-USER", ident["cn"]))
            if ident.get("revoked"):
                headers.append(("X-REVOKED", "1"))
        body = None
        if "multipart" in rq:
            from werkzeug.datastructures import FileStorage
            from werkzeug.test import encode_multipart

            fields = {}
            for f in rq["multipart"]:
                payload = base64.b64decode(f["data_b64"]) if "data_b64" in f else f["data"].encode()
                fields[f["name"]] = FileStorage(io.BytesIO(payload), filename=f["filename"],
                                                content_type=f.get("content_type"))
            boundary, body = encode_multipart(fields, boundary="difftest-boundary-7f3a")
            headers.append(("Content-Type", f'multipart/form-data; boundary="{boundary}"'))
        elif "body" in rq:
            body = rq["body"].encode("utf8")
        path = rq["path"]
        if rq.get("query"):
            path += "?" + urllib.parse.urlencode(rq["query"])
        conn.putrequest(rq["method"], path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", base.netloc)
        for k, v in headers:
            conn.putheader(k, v)
        if body is not None or rq["method"] in ("POST", "PUT"):
            conn.putheader("Content-Length", str(len(body or b"")))
        conn.endheaders(body)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def observe(self, step, resp, data):
        ctype = resp.getheader("Content-Type")
        obs = {"status": resp.status, "content_type": ctype}
        if (ctype or "").startswith("application/json"):
            obs["body_json"] = rpd.norm_json(json.loads(data))
        else:
            try:
                obs["body"] = data.decode("utf8")
            except UnicodeDecodeError:
                obs["body_b64"] = base64.b64encode(data).decode()
        if "body" in obs:
            obs["body"] = obs["body"].replace("taky-unknown", "taky-$VERSION").replace(self.up, "$UPLOAD_PATH")
            if resp.status >= 400 and obs["body"].lower().startswith("<!doctype html>"):
                del obs["body"]
                obs["body_is_framework_page"] = True
        if "body_json" in obs:
            obs["body_json"] = json.loads(json.dumps(obs["body_json"]).replace("taky-unknown", "taky-$VERSION"))
        names = sorted(set(step.get("expect", {}).get("headers", {})) | set(step.get("record_headers", [])))
        if names:
            obs["headers"] = {h: resp.getheader(h) for h in names}
        return obs

    def run(self, expect_for):
        steps_obs = []
        self.setup()
        try:
            for idx, step in enumerate(self.vec["steps"]):
                if expect_for(step) is None:
                    break
                r = self.request(step["request"])
                if r is None:
                    self.skipped.append(f"step {idx}: remote-addr (no local non-loopback address)")
                    steps_obs.append({"skipped": "remote-addr"})
                    continue
                steps_obs.append(self.observe(step, *r))
            files = rpd.snapshot_files(self.up)
        finally:
            self.inst.stop()
        return {"steps": steps_obs, "final": {"files": files}}
