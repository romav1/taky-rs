#!/usr/bin/env python3
"""Build the seed corpora of taky-rs/fuzz (qa01, S-407, test-strategy §1.6).

    python3 tools/fuzz/seeds.py            # writes fuzz/corpus/<target>/seed-<sha1[:16]>

Sources: every an01 vector (CoT `send` chunks / expected deliveries, mgmt requests, DPS requests,
unit U001-U003 inputs), the XML string literals of taky/tests/*.py, taky/taky.conf{,.sample}.
Stream seeds are written twice: mode 0 (the whole client stream as one chunk) and mode 2 (the exact
vector chunk boundaries) — the framing of fuzz/common/src/lib.rs `split_chunks`.
Seeds larger than MAX_SEED bytes (the D-2 limit vectors with `repeat` chunks) are skipped: they would
raise libFuzzer's -max_len for every input; the limits are covered by the vectors themselves.
Idempotent; only adds files. Stdlib only.
"""
import ast
import base64
import glob
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TAKYRS = os.path.abspath(os.path.join(HERE, "..", ".."))
OFFICE = os.path.dirname(TAKYRS)
VECTORS = os.path.join(OFFICE, "shared", "spec", "vectors")
TAKY = os.path.join(OFFICE, "taky")
CORPUS = os.path.join(TAKYRS, "fuzz", "corpus")
MAX_SEED = 64 * 1024
BOUNDARY = b"taky"


def chunk_bytes(c):
    if isinstance(c, dict):  # {"prefix", "repeat", "count", "suffix"}
        return (c.get("prefix", "") + c["repeat"] * c["count"] + c.get("suffix", "")).encode()
    return c.encode("utf8")


def step_chunks(step):
    if "chunks_b64" in step:
        return [base64.b64decode(c) for c in step["chunks_b64"]]
    return [chunk_bytes(c) for c in step.get("chunks", [])]


def mode0(chunks):
    return b"\x00" + b"".join(chunks)


def mode2(chunks):
    out = b"\x02"
    for c in chunks:
        for i in range(0, max(len(c), 1), 0xFFFF):
            part = c[i:i + 0xFFFF]
            out += struct.pack(">H", len(part)) + part
    return out


class Corpus:
    def __init__(self):
        self.seeds = {}

    def add(self, target, data):
        if isinstance(data, str):
            data = data.encode("utf8")
        if len(data) > MAX_SEED:
            return
        self.seeds.setdefault(target, set()).add(data)

    def write(self):
        total = 0
        for target, items in sorted(self.seeds.items()):
            d = os.path.join(CORPUS, target)
            os.makedirs(d, exist_ok=True)
            for data in items:
                name = "seed-" + hashlib.sha1(data).hexdigest()[:16]
                p = os.path.join(d, name)
                if not os.path.exists(p):
                    with open(p, "wb") as fp:
                        fp.write(data)
            total += len(items)
            print(f"{target}: {len(items)} seeds")
        return total


def walk_strings(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for v in o.values():
            yield from walk_strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from walk_strings(v)


def multipart(parts):
    out = b""
    for p in parts:
        data = base64.b64decode(p["data_b64"]) if "data_b64" in p else p.get("data", "").encode()
        disp = f'form-data; name="{p["name"]}"'
        if "filename" in p:
            disp += f'; filename="{p["filename"]}"'
        out += b"--" + BOUNDARY + b"\r\nContent-Disposition: " + disp.encode() + b"\r\n"
        out += b"Content-Type: " + p.get("content_type", "application/octet-stream").encode() + b"\r\n\r\n"
        out += data + b"\r\n"
    return out + b"--" + BOUNDARY + b"--\r\n"


def main():
    c = Corpus()
    xml_docs = set()
    # --- CoT vectors -------------------------------------------------------------------------
    for p in sorted(glob.glob(os.path.join(VECTORS, "cot", "*.json"))):
        v = json.load(open(p, encoding="utf8"))
        streams = {}
        for s in v.get("steps", []):
            if s.get("op") == "send":
                ch = step_chunks(s)
                streams.setdefault(s["client"], []).extend(ch)
                for one in ch:
                    if one.strip().startswith((b"<event", b"<?xml")):
                        xml_docs.add(one)
            elif s.get("op") == "mgmt":
                req = s["request"]
                raw = req if isinstance(req, str) else json.dumps(req)
                c.add("mgmt_frame", raw.encode() + b"\x00")
            for exp in (s.get("expect", {}), s.get("rust_expect", {})):
                for msgs in (exp.get("deliveries") or {}).values():
                    for m in msgs:
                        if isinstance(m, str) and m.startswith("<"):
                            xml_docs.add(m.encode())
        for ch in streams.values():
            c.add("cot_decoder_stream", mode0(ch))
            c.add("cot_decoder_stream", mode2(ch))
        for s in walk_strings(v):
            for tok in s.replace('"', " ").replace("'", " ").split():
                if len(tok) >= 10 and tok[:4].isdigit() and "T" in tok:
                    c.add("isoparse", tok.split("=")[-1])
    # --- taky/tests string literals (real ATAK/WinTAK/iTAK samples) ---------------------------
    for p in sorted(glob.glob(os.path.join(TAKY, "tests", "*.py"))):
        tree = ast.parse(open(p, encoding="utf8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
                b = node.value.encode() if isinstance(node.value, str) else node.value
                if b"<event" in b or b"<?xml" in b or b"<detail" in b:
                    xml_docs.add(b.strip())
                    c.add("cot_decoder_stream", mode0([b]))
    for d in xml_docs:
        c.add("parse_element", d)
        c.add("serialize_roundtrip", d)
        if not d.startswith(b"<?xml"):
            c.add("cot_decoder_stream", mode0([d]))
    # Byte-by-byte / cycling splits of a few real events (split properties of test_xmldeclstrip).
    for d in sorted(xml_docs, key=len)[:8]:
        c.add("cot_decoder_stream", b"\x03\x00" + d)
        c.add("cot_decoder_stream", b"\x01\x02\x06\x00\x0d" + d + d)
    # --- unit vectors ---------------------------------------------------------------------------
    for uid, target in (("U001", "isoparse"), ("U002", "py_float"), ("U003", "ini_parse")):
        v = json.load(open(os.path.join(VECTORS, "unit", f"{uid}.json"), encoding="utf8"))
        for case in v["cases"]:
            if isinstance(case.get("input"), str):
                c.add(target, case["input"])
    for name in ("taky.conf", "taky.conf.sample"):
        p = os.path.join(TAKY, name)
        if os.path.exists(p):
            c.add("ini_parse", open(p, "rb").read())
    # --- mgmt -----------------------------------------------------------------------------------
    for raw in (b'{"cmd": "status"}\x00', b'{"cmd": "ping"}\x00{"cmd": "status"}\x00',
                b'{"cmd": "kickban", "user": "bob"}\x00', b'{"cmd": 1e400}\x00', b'{not json\x00',
                b'{"cmd": [1, {"a": null}, true, 1.5]}\x00', b'"\\ud800"\x00', b'{"cmd": "status"}'):
        c.add("mgmt_frame", raw)
    # --- DPS ------------------------------------------------------------------------------------
    for p in sorted(glob.glob(os.path.join(VECTORS, "dps", "*.json"))):
        v = json.load(open(p, encoding="utf8"))
        for s in v.get("steps", []):
            r = s.get("request")
            if not r:
                continue
            q = "&".join(f"{k}={val}" for k, val in (r.get("query") or {}).items())
            for part in r.get("multipart") or []:
                if "filename" in part:
                    c.add("secure_filename", part["filename"])
            for val in (r.get("query") or {}).values():
                c.add("secure_filename", str(val))
            body = r.get("body", "").encode() if "body" in r else b""
            if "body_b64" in r:
                body = base64.b64decode(r["body_b64"])
            path = r["path"]
            if path == "/Marti/sync/missionupload":
                body = multipart(r["multipart"]) if r.get("multipart") else body
                c.add("dps_multipart", b"\x00" + q.encode() + b"\n" + body)
            elif path == "/Marti/vcm" and r["method"] == "POST":
                c.add("dps_multipart", b"\x01" + q.encode() + b"\n" + body)
                c.add("parse_element", body)
            elif path.endswith("/tool"):
                c.add("dps_multipart", b"\x02" + path.split("/")[-2].encode() + b"\n" + body)
            elif path == "/Marti/TracksKML":
                c.add("dps_multipart", b"\x03" + q.encode() + b"\n" + body)
    for name in ("My cool movie.mov", "../../../etc/passwd", "i contain cool \xfcml\xe4uts.txt",
                 "COM1.txt", "..", "._.a", "\u00e9t\u00e9", "a/b\\c", "  ", "con"):
        c.add("secure_filename", name)
    n = c.write()
    print(f"total {n} seeds in {CORPUS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
