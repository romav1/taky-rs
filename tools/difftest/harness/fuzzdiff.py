"""
difftest fuzzdiff — differential fuzzing of the CoT stream decoder (qa01, S-407, test-strategy §1.6).

    tools/difftest/difftest fuzzdiff [--corpus DIR ...] [--decoder-dump PATH] [--allowlist FILE] [--out DIR]

Every corpus file is turned into socket chunks by `split_chunks` (byte-for-byte the framing of
fuzz/common/src/lib.rs) and run through
  * Rust:   `decoder-dump` (fuzz workspace; CotDecoder exactly as conn::read_half drives it), and
  * Python: the oracle — a real `XMLPullParser(tag="event", resolve_entities=False)` pre-fed `<root>`
            behind `XMLDeclStrip`, fed chunk by chunk like TAKClient.feed (feed raises ⇒ the stream is
            dead, events of that chunk are never read); per event `tostring(elm, with_tail=False)`,
            `Event.from_elm` ⇒ `tostring(evt.as_element)`, then `elm.clear(keep_tail=True)`.
Compared (exact): whether the stream errored, the number of events, each element's bytes, the model
outcome kind (frame / unmarshal / serialize) and the frame bytes. A divergence matching an entry of
fuzz/allowlist.toml (each one tied to a D-n / OQ / parity reference) is "allowed"; anything else is a
defect. Default corpora: fuzz/corpus/{cot_decoder_stream,regressions/cot_decoder_stream} as streams, and
fuzz/corpus/{parse_element,serialize_roundtrip} as single-chunk streams.
Report: <out>/fuzzdiff.json (+ minimized-by-hand repros are kept under fuzz/corpus/regressions/fuzzdiff/).
Exit: 0 = no unallowed divergence, 1 = defects, 2 = harness error.
"""
import argparse
import base64
import collections
import json
import os
import re
import subprocess
import sys
import time
import tomllib
import traceback

from lxml import etree

from taky.cot import models
from taky.util import XMLDeclStrip

HERE = os.path.dirname(os.path.abspath(__file__))
TAKYRS = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FUZZ = os.path.join(TAKYRS, "fuzz")
# Appended to a divergent stream to tell "reported one read later" from a real difference: libxml2's
# push parser reports many errors only once more input arrives (`<!x` waits for the next bytes, a
# trailing invalid UTF-8 byte waits for the rest of the sequence), the Rust decoder reports them at once.
PROBE = b'\n<event uid="fuzzdiff-probe"/>\n'


def split_chunks(data):
    """Mirror of fuzz/common/src/lib.rs `split_chunks` (keep in sync)."""
    out = []
    if not data:
        return out
    h, rest = data[0], data[1:]
    mode = h & 3
    if mode == 0:
        out.append(rest)
    elif mode == 1:
        n = (rest[0] % 8) + 1 if rest else 1
        if len(rest) < 1 + n:
            out.append(rest)
        else:
            sizes, body, i = rest[1:1 + n], rest[1 + n:], 0
            while body:
                sz = min(sizes[i % n] + 1, len(body))
                out.append(body[:sz])
                body = body[sz:]
                i += 1
    elif mode == 2:
        body = rest
        while body:
            if len(body) < 2:
                out.append(body)
                break
            ln = int.from_bytes(body[:2], "big")
            take = min(ln, len(body) - 2)
            out.append(body[2:2 + take])
            body = body[2 + take:]
    else:
        sz = (rest[0] % 16) + 1 if rest else 1
        body = rest[1:]
        out.extend(body[i:i + sz] for i in range(0, len(body), sz))
    return [c for c in out if c]


def py_stream(chunks):
    parser = etree.XMLPullParser(tag="event", resolve_entities=False)
    parser.feed(b"<root>")
    xdc = XMLDeclStrip(parser)
    events, error, error_chunk, error_text = [], False, None, None
    for i, c in enumerate(chunks):
        try:
            xdc.feed(c)
        except etree.XMLSyntaxError as exc:
            error, error_chunk, error_text = True, i, str(exc)
            break
        for _, elm in xdc.read_events():
            raw = etree.tostring(elm, with_tail=False)
            try:
                evt = models.Event.from_elm(elm)
                try:
                    outcome = {"frame": etree.tostring(evt.as_element)}
                except Exception as exc:  # pylint: disable=broad-except
                    outcome = {"serialize": f"{type(exc).__name__}: {exc}"}
            except models.UnmarshalError as exc:
                outcome = {"unmarshal": str(exc)}
            except Exception as exc:  # pylint: disable=broad-except  (client.py: "Unhandled exception", dropped)
                outcome = {"unmarshal": f"{type(exc).__name__}: {exc}", "unhandled": True}
            finally:
                elm.clear(keep_tail=True)
            events.append({"elm": raw, "evt": outcome})
    return {"events": events, "error": error, "error_chunk": error_chunk, "error_text": error_text}


def rs_decode(line):
    evs = []
    for e in line["events"]:
        ev = e["evt"]
        if "frame_b64" in ev:
            outcome = {"frame": base64.b64decode(ev["frame_b64"])}
        else:
            outcome = dict(ev)
        evs.append({"elm": base64.b64decode(e["elm_b64"]), "evt": outcome})
    return {"events": evs, "error": line["error"], "error_chunk": line["error_chunk"],
            "error_text": line["error_text"]}


def kind(o):
    return next(k for k in ("frame", "unmarshal", "serialize") if k in o)


def compare(py, rs):
    """List of divergence classes (empty = equal)."""
    out = []
    if py["error"] != rs["error"]:
        out.append("error-flag:" + ("rust-only" if rs["error"] else "python-only"))
    if len(py["events"]) != len(rs["events"]):
        out.append("event-count")
    for a, b in zip(py["events"], rs["events"]):
        if a["elm"] != b["elm"]:
            out.append("elm-bytes")
        ka, kb = kind(a["evt"]), kind(b["evt"])
        if ka != kb:
            out.append(f"evt-kind:{ka}->{kb}")
        elif ka == "frame" and a["evt"]["frame"] != b["evt"]["frame"]:
            out.append("frame-bytes")
    return sorted(set(out))


def first_bad_utf8(stream):
    try:
        stream.decode("utf8")
        return None
    except UnicodeDecodeError as exc:
        return exc.start


def cut_chunks(chunks, n):
    """The chunk sequence truncated to its first `n` bytes (boundaries kept)."""
    out = []
    for c in chunks:
        if n <= 0:
            break
        out.append(c[:n])
        n -= len(c)
    return [c for c in out if c]


class Allowlist:
    """fuzz/allowlist.toml. An [[entry]] matches a divergence when every given key holds:
    classes          the divergence classes (after the probe) are a subset of this list
    requires         ... and contain all of these
    input_regex      re.search on the concatenated stream (latin-1)
    rust_error_regex / python_error_regex   on the error texts
    clean_before     triggers (regexes on the latin-1 stream, or "@badutf8"): the stream must contain one,
                     and the stream truncated just before the earliest trigger (+ probe) must show NO
                     divergence — i.e. both sides agree up to the construct the D-n/OQ is about.
    Required: id, ref (D-n / OQ / parity reference), reason."""

    def __init__(self, path, dump_exe):
        with open(path, "rb") as fp:
            self.entries = tomllib.load(fp).get("entry", [])
        for e in self.entries:
            for k in ("id", "ref", "reason"):
                if k not in e:
                    raise ValueError(f"allowlist entry without {k!r}: {e}")
        self.dump_exe = dump_exe

    def prefix_clean(self, chunks, triggers):
        stream = b"".join(chunks)
        text = stream.decode("latin-1")
        pos = []
        for t in triggers:
            if t == "@badutf8":
                b = first_bad_utf8(stream)
                if b is not None:
                    pos.append(b)
            else:
                m = re.search(t, text, re.S)
                if m:
                    pos.append(m.start())
        if not pos:
            return False
        pre = cut_chunks(chunks, min(pos)) + [PROBE]
        rs = run_dump(self.dump_exe, [pre])
        return rs is not None and not compare(py_stream(pre), rs[0])

    def match(self, classes, data, py, rs):
        chunks = split_chunks(data)
        text = b"".join(chunks).decode("latin-1")
        for e in self.entries:
            if "classes" in e and not set(classes) <= set(e["classes"]):
                continue
            if "requires" in e and not set(e["requires"]) <= set(classes):
                continue
            if "input_regex" in e and not re.search(e["input_regex"], text, re.S):
                continue
            if "rust_error_regex" in e and not re.search(e["rust_error_regex"], rs["error_text"] or ""):
                continue
            if "python_error_regex" in e and not re.search(e["python_error_regex"], py["error_text"] or ""):
                continue
            if "clean_before" in e and not self.prefix_clean(chunks, e["clean_before"]):
                continue
            return e["id"]
        return None


def run_dump(exe, streams):
    proc = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    lines = "".join(json.dumps({"id": i, "chunks_b64": [base64.b64encode(c).decode() for c in ch]}) + "\n"
                    for i, ch in enumerate(streams))
    out, _ = proc.communicate(lines.encode())
    if proc.returncode != 0:
        print(f"decoder-dump exited {proc.returncode}", file=sys.stderr)
        return None
    res = [json.loads(x) for x in out.decode().splitlines() if x.strip()]
    if len(res) != len(streams):
        print(f"decoder-dump returned {len(res)} lines for {len(streams)} inputs", file=sys.stderr)
        return None
    for r in res:
        if "harness_error" in r:
            print(f"decoder-dump: {r['harness_error']}", file=sys.stderr)
            return None
    return [rs_decode(r) for r in res]


def iter_inputs(dirs):
    seen = set()
    for d, as_stream in dirs:
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            if not os.path.isfile(p):
                continue
            with open(p, "rb") as fp:
                data = fp.read()
            if not as_stream:
                data = b"\x00" + data
            if data in seen:
                continue
            seen.add(data)
            yield os.path.relpath(p, FUZZ), data


def main(argv):
    ap = argparse.ArgumentParser(prog="difftest fuzzdiff", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", action="append", help="stream corpus dir (repeatable); default: see above")
    ap.add_argument("--docs", action="append", help="document corpus dir, fed as one chunk (repeatable)")
    ap.add_argument("--decoder-dump", default=os.path.join(FUZZ, "target", "release", "decoder-dump"))
    ap.add_argument("--allowlist", default=os.path.join(FUZZ, "allowlist.toml"))
    ap.add_argument("--out", default=os.path.join(TAKYRS, "target", "qa", "fuzzdiff"))
    ap.add_argument("--show", type=int, default=5, help="examples per divergence class in the summary")
    args = ap.parse_args(argv)
    if args.corpus is None and args.docs is None:
        args.corpus = [os.path.join(FUZZ, "corpus", "cot_decoder_stream"),
                       os.path.join(FUZZ, "corpus", "regressions", "cot_decoder_stream"),
                       os.path.join(FUZZ, "corpus", "regressions", "fuzzdiff")]
        args.docs = [os.path.join(FUZZ, "corpus", "parse_element"),
                     os.path.join(FUZZ, "corpus", "serialize_roundtrip")]
    if not os.access(args.decoder_dump, os.X_OK):
        print(f"decoder-dump not found: {args.decoder_dump} "
              "(cargo build --release --manifest-path fuzz/Cargo.toml -p taky-fuzz-decoder-dump)", file=sys.stderr)
        return 2
    allow = Allowlist(args.allowlist, args.decoder_dump)
    dirs = [(d, True) for d in args.corpus or []] + [(d, False) for d in args.docs or []]
    inputs = list(iter_inputs(dirs))
    t0 = time.monotonic()
    rs_lines = run_dump(args.decoder_dump, [split_chunks(d) for _, d in inputs])
    if rs_lines is None:
        return 2
    stats = collections.Counter()
    by_class = collections.defaultdict(list)
    results = []
    pending = []
    for (name, data), rs in zip(inputs, rs_lines):
        try:
            py = py_stream(split_chunks(data))
        except Exception:  # pylint: disable=broad-except
            print(f"{name}: oracle exception\n{traceback.format_exc()}", file=sys.stderr)
            return 2
        stats["events_py"] += len(py["events"])
        stats["events_rs"] += len(rs["events"])
        classes = compare(py, rs)
        if not classes:
            stats["equal"] += 1
        else:
            pending.append((name, data, py, rs, classes))
    probed = run_dump(args.decoder_dump, [split_chunks(d) + [PROBE] for _, d, _, _, _ in pending])
    if probed is None:
        return 2
    for (name, data, py, rs, classes), rs2 in zip(pending, probed):
        py2 = py_stream(split_chunks(data) + [PROBE])
        classes2 = compare(py2, rs2) or ["late-error"]
        py_alive = any(b"fuzzdiff-probe" in e["elm"] for e in py2["events"])
        rs_alive = any(b"fuzzdiff-probe" in e["elm"] for e in rs2["events"])
        if not py2["error"] and not py_alive and (rs2["error"] or not rs_alive):
            # libxml2 went silent (no error, nothing parsed any more: the "zombie" of D-23 / OQ-05);
            # the connection is dead in Python too, only the way it dies differs.
            classes2 = sorted(set(classes2) | {"python-zombie"})
        aid = allow.match(classes2, data, py2, rs2)
        status = "allowed" if aid else "defect"
        stats[status] += 1
        if aid:
            stats["allow:" + aid] += 1
        rec = {"input": name, "status": status, "allow": aid, "classes": classes2, "classes_unprobed": classes,
               "py_error": py2["error_text"], "rs_error": rs2["error_text"],
               "py_events": len(py2["events"]), "rs_events": len(rs2["events"]),
               "py_alive": py_alive, "rs_alive": rs_alive,
               "stream_b64": base64.b64encode(b"".join(split_chunks(data))[:4096]).decode()}
        results.append(rec)
        by_class[(status, tuple(classes2))].append(rec)
    secs = round(time.monotonic() - t0, 1)
    os.makedirs(args.out, exist_ok=True)
    report = {"inputs": len(inputs), "seconds": secs, "stats": dict(stats), "divergences": results}
    with open(os.path.join(args.out, "fuzzdiff.json"), "w", encoding="utf8") as fp:
        json.dump(report, fp, indent=1)
    print(f"fuzzdiff: {len(inputs)} inputs, {secs} s: equal {stats['equal']}, allowed {stats['allowed']}, "
          f"defect {stats['defect']} (events py {stats['events_py']} / rs {stats['events_rs']})")
    for k, v in sorted(stats.items()):
        if k.startswith("allow:"):
            print(f"  {k}: {v}")
    for (status, classes), recs in sorted(by_class.items()):
        print(f"  [{status}] {','.join(classes)}: {len(recs)}")
        if status == "defect":
            for r in recs[:args.show]:
                print(f"     {r['input']}: py_err={r['py_error']!r} rs_err={r['rs_error']!r} "
                      f"events py={r['py_events']} rs={r['rs_events']}")
    print(f"report: {os.path.join(args.out, 'fuzzdiff.json')}")
    return 1 if stats["defect"] else 0
