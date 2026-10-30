"""
Comparison: (1) oracle — a target's observations vs the vector expectation for that target
(py: expect / final_expect; rs: rust_expect ?? expect, final_rust_expect ?? final_expect);
(2) differential — observations of run A vs run B (py vs py now, py vs rs later).

Rules (test-strategy L2/L3, vectors README format 2):
  * XML deliveries: exact by default (`--mode c14n` = diagnostics only); per-client order, except a
    `connect` step (persist replay) = multiset; when exact differs but c14n matches the finding is
    classified "serialization", otherwise "behaviour".
  * Redis TTL: |a - b| <= 1 (differential) / expect-1 <= ttl <= expect (oracle, an01 persist_equal).
  * Masks applied before comparing: certificate serials -> $SERIAL_INT:<cn> (unsubst), bind_ip ->
    127.0.0.1 / $IP (cot.normalize), DPS SubmissionDateTime/taky-unknown/upload_path (dps.observe).
  * Differential py-vs-rs skips the steps / finals that carry a rust_expect (approved divergence D-n);
    those are covered by the rs oracle check instead. py-vs-py compares everything.
"""
import copy
import json

import run_python as rp  # an01: Runner.check, c14n, unsubst, persist_equal

from .dps import sort_unordered


def rust_view(vec):
    """The vector as a Rust runner sees it: rust_expect replaces expect (format 2)."""
    v = copy.deepcopy(vec)
    for s in v.get("steps", []) + v.get("cases", []):
        if "rust_expect" in s:
            s["expect"] = s.pop("rust_expect")
    if "final_rust_expect" in v:
        v["final_expect"] = v.pop("final_rust_expect")
    return v


def _is_memory_persist(p):
    return isinstance(p, dict) and p.get("backend") == "memory"


def strip_memory_persist(vec):
    """Vector view for a target without the memory persist hook (plain taky-rs binary):
    memory `persist` expectations are removed (reported as skipped checks)."""
    v = copy.deepcopy(vec)
    for s in v.get("steps", []):
        for k in ("expect", "rust_expect"):
            if _is_memory_persist((s.get(k) or {}).get("persist")):
                del s[k]["persist"]
    for k in ("final_expect", "final_rust_expect"):
        if _is_memory_persist(v.get(k, {}).get("persist")):
            del v[k]["persist"]
    return v


def strip_memory_persist_obs(obs):
    """Drop memory persist observations (the other side has none) for the differential check."""
    o = copy.deepcopy(obs)
    for s in o.get("steps", []):
        if s.get("persist") is None or _is_memory_persist(s.get("persist")):
            s.pop("persist", None)
    if o.get("final", {}).get("persist") is None or _is_memory_persist(o["final"].get("persist")):
        o.get("final", {}).pop("persist", None)
    return o


def expect_fn(target_name):
    if target_name == "py":
        return lambda step: step.get("expect")
    return lambda step: step.get("rust_expect", step.get("expect"))


# ---------------------------------------------------------------- oracle
def oracle_cot(vec, obs, serials, mode, target_name, taky_src):
    v = vec if target_name == "py" else rust_view(vec)
    r = rp.Runner(v, taky_src, mode)
    r.observed_steps = obs["steps"]
    r.final = obs["final"]
    r.serials = serials
    r.check()
    return r.errors


def oracle_dps(vec, obs, target_name):
    v = vec if target_name == "py" else rust_view(vec)
    errs = []
    for idx, (step, o) in enumerate(zip(v["steps"], obs["steps"])):
        if "skipped" in o:
            continue
        exp = step.get("expect", {})
        rq = step["request"]
        for k, val in exp.items():
            if k == "unordered":
                continue
            if k == "body_json":
                val = sort_unordered(val, exp.get("unordered", []))
            if k == "body_is_framework_page":
                if bool(o.get(k)) != bool(val):
                    errs.append(f"{v['id']} step {idx} {rq['method']} {rq['path']}: framework page expected {val}")
                continue
            if k == "body" and exp.get("body_is_framework_page"):
                continue
            if k == "headers":
                got = {h: o.get("headers", {}).get(h) for h in val}
                if got != val:
                    errs.append(f"{v['id']} step {idx}: headers expected {val!r} observed {got!r}")
                continue
            if o.get(k) != val:
                errs.append(f"{v['id']} step {idx} {rq['method']} {rq['path']}: {k} expected {val!r} observed {o.get(k)!r}")
    exp_files = v.get("final_expect", {}).get("files")
    if exp_files is not None and exp_files != obs["final"]["files"]:
        errs.append(f"{v['id']} final files:\n  expected {exp_files}\n  observed {obs['final']['files']}")
    return errs


def oracle_unit(vec, obs, target_name):
    v = vec if target_name == "py" else rust_view(vec)
    errs = []
    for i, (case, o) in enumerate(zip(v["cases"], obs)):
        if case.get("expect") != o:
            errs.append(f"{v['id']} case {i} {case.get('input')!r}: expected {case.get('expect')} observed {o}")
    if len(obs) != len(v["cases"]):
        errs.append(f"{v['id']}: {len(obs)} observations for {len(v['cases'])} cases")
    return errs


# ---------------------------------------------------------------- differential
def _xml_diff(where, a, b, unordered):
    if unordered:
        a, b = sorted(a), sorted(b)
    if a == b:
        return None
    ca, cb = [rp.c14n(x) for x in a], [rp.c14n(x) for x in b]
    if unordered:
        ca, cb = sorted(ca), sorted(cb)
    kind = "serialization" if ca == cb else "behaviour"
    return {"where": where, "class": kind, "a": a, "b": b}


def _persist_close(a, b):
    if not isinstance(a, dict) or not isinstance(b, dict) or a.get("backend") != "redis":
        return a == b
    if b.get("backend") != "redis" or set(a.get("keys", {})) != set(b.get("keys", {})):
        return False
    return all(a["keys"][k]["value"] == b["keys"][k]["value"]
               and abs(a["keys"][k]["ttl"] - b["keys"][k]["ttl"]) <= 1 for k in a["keys"])


def diff_cot(vec, a, b, skip_divergent):
    out = []
    steps = vec["steps"]
    n_a, n_b = len(a["steps"]), len(b["steps"])
    # py-vs-rs: Python stops at a crash step / before a Rust-only step (format 2); the extra Rust
    # steps all carry rust_expect and are covered by the rs oracle, so a longer rs run is expected.
    extra_rust_only = (skip_divergent and n_b > n_a
                       and all("rust_expect" in st for st in steps[max(n_a - 1, 0):n_b]))
    if n_a != n_b and not extra_rust_only:
        out.append({"where": "steps", "class": "behaviour",
                    "a": f"{len(a['steps'])} steps executed", "b": f"{len(b['steps'])} steps executed"})
    for idx, (sa, sb) in enumerate(zip(a["steps"], b["steps"])):
        step = steps[idx]
        if skip_divergent and "rust_expect" in step:
            continue
        where = f"step {idx} ({step['op']})"
        for cid in sorted(set(sa["deliveries"]) | set(sb["deliveries"])):
            d = _xml_diff(f"{where} deliveries to {cid}", sa["deliveries"].get(cid, []),
                          sb["deliveries"].get(cid, []), step["op"] == "connect")
            if d:
                out.append(d)
        for key in ("server_closed", "mgmt_response"):
            if sa.get(key) != sb.get(key):
                out.append({"where": f"{where} {key}", "class": "behaviour", "a": sa.get(key), "b": sb.get(key)})
        if bool(sa.get("server_crash")) != bool(sb.get("server_crash")):
            out.append({"where": f"{where} server_crash", "class": "behaviour",
                        "a": sa.get("server_crash"), "b": sb.get("server_crash")})
        if "persist" in sa and "persist" in sb and not _persist_close(sa["persist"], sb["persist"]):
            out.append({"where": f"{where} persist", "class": "behaviour", "a": sa["persist"], "b": sb["persist"]})
    if not (skip_divergent and "final_rust_expect" in vec):
        fa, fb = a["final"], b["final"]
        for key in sorted(set(fa) | set(fb)):
            same = _persist_close(fa.get(key), fb.get(key)) if key == "persist" else fa.get(key) == fb.get(key)
            if not same:
                out.append({"where": f"final {key}", "class": "behaviour", "a": fa.get(key), "b": fb.get(key)})
    return out


def diff_plain(vec, a, b, skip_divergent, items_key):
    out = []
    items = vec.get(items_key, [])
    la, lb = (a["steps"], b["steps"]) if items_key == "steps" else (a, b)
    # py-vs-rs: Rust-only trailing steps (DPS `python_skip`, all with rust_expect) are not run on Python
    extra_rust_only = (skip_divergent and len(lb) > len(la)
                       and all("rust_expect" in it for it in items[len(la):len(lb)]))
    if len(la) != len(lb) and not extra_rust_only:
        out.append({"where": items_key, "class": "behaviour", "a": len(la), "b": len(lb)})
    for idx, (oa, ob) in enumerate(zip(la, lb)):
        if skip_divergent and "rust_expect" in items[idx]:
            continue
        if "skipped" in oa or "skipped" in ob:
            continue
        if oa != ob:
            out.append({"where": f"{items_key[:-1]} {idx}", "class": "behaviour", "a": oa, "b": ob})
    if items_key == "steps" and not (skip_divergent and "final_rust_expect" in vec):
        if a["final"] != b["final"]:
            out.append({"where": "final files", "class": "behaviour", "a": a["final"], "b": b["final"]})
    return out


def masked(obs, serials):
    """Certificate serials differ between runs/targets: replace them by $SERIAL_INT:<cn>."""
    return rp.unsubst(json.loads(json.dumps(obs)), serials) if serials else obs
