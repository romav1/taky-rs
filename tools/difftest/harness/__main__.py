"""
difftest — differential test harness Python taky <-> taky-rs (qa01, T-11; test-strategy §1.3, §4.1).

    tools/difftest/difftest --target py --all            # Python vs Python (self-check of the harness)
    tools/difftest/difftest --target rs --only D         # Python vs Rust DPS (taky_dps-rs)
    tools/difftest/difftest --target rs --only V         # Python vs Rust CoT (taky-rs-difftest launcher)
    tools/difftest/difftest --target rs --rs-cot bin --only V   # ... vs the plain taky-rs binary
    tools/difftest/difftest --target py --only V04,D01   # subset by id prefix
    tools/difftest/difftest --target py shared/spec/vectors/cot/V001.json ...
    tools/difftest/difftest random --sessions 1000 --seed 1   # seeded random sessions (randsession.py)
    tools/difftest/difftest compat C1 [--mode alternate|simultaneous|both]   # data compatibility C1..C14 (compat.py, compat2.py)

For every selected vector the baseline (Python) and the target are each started as LIVE processes
(Python on 127.0.0.2, Rust on 127.0.0.3) and driven over real sockets. Two kinds of checks:
  oracle        each run vs the vector expectation for that target (format 2: rust_expect ?? expect)
  differential  baseline observations vs target observations (masks: serials, bind_ip, DPS timestamps/version)
Report: <taky-rs>/target/qa/difftest/{report.json,junit.xml,obs-<run>.json} + a summary on stdout.
Exit: 0 green, 1 oracle failure or divergence, 2 target unavailable / harness error.
"""
import argparse
import glob
import json
import os
import shutil
import sys
import time
import traceback

from . import bench, compare
from .cot import CotRun
from .dps import DpsRun
from .targets import PyTarget, RsTarget, TargetUnavailable

import vecfmt  # an01: format-2 lint

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL_DIR = os.path.dirname(HERE)
TAKYRS = os.path.abspath(os.path.join(TOOL_DIR, "..", ".."))
OFFICE = os.path.dirname(TAKYRS)
SUPPORTED_FORMATS = (2,)


def load_vectors(args):
    paths = list(args.vectors)
    if args.all or not paths:
        for sub in ("cot", "dps", "unit"):
            paths += sorted(glob.glob(os.path.join(args.vectors_dir, sub, "*.json")))
    out, errors = [], []
    seen = set()
    for p in paths:
        p = os.path.abspath(p)
        if p in seen:
            continue
        seen.add(p)
        with open(p, encoding="utf8") as fp:
            vec = json.load(fp)
        if args.only and not any(vec["id"].startswith(x) for x in args.only.split(",")):
            continue
        if vec.get("format") not in SUPPORTED_FORMATS:  # README: a runner MUST reject unknown formats
            errors.append(f"{vec.get('id', p)}: unsupported vector format {vec.get('format')!r}")
            continue
        vec["_path"] = p
        out.append(vec)
    return out, errors


def run_pass(label, target, vectors, args, redis):
    """Run every vector once against `target`; returns {id: {"obs", "serials", "error", "skipped"}}."""
    results = {}
    state = os.path.join(args.state, label)
    bench.fresh_dir(state)
    expect_for = compare.expect_fn(target.name)
    units = [v for v in vectors if v["runner"] == "unit"]
    if units:
        try:
            uobs = target.run_unit([v["_path"] for v in units])
            for v in units:
                results[v["id"]] = {"obs": uobs.get(v["id"], []), "serials": {}}
        except TargetUnavailable as exc:
            for v in units:
                results[v["id"]] = {"unavailable": str(exc)}
        except Exception as exc:  # pylint: disable=broad-except
            for v in units:
                results[v["id"]] = {"error": f"unit adapter failed: {exc}"}
    for vec in vectors:
        if vec["runner"] == "unit":
            continue
        vid = vec["id"]
        workdir = bench.fresh_dir(os.path.join(state, vid))
        t0 = time.monotonic()
        try:
            if vec["runner"] == "cot":
                run = CotRun(vec, target, workdir, redis, args.quiet, args.taky_src)
                obs, serials = run.run(expect_for)
                results[vid] = {"obs": obs, "serials": serials}
            elif vec["runner"] == "dps":
                run = DpsRun(vec, target, workdir)
                results[vid] = {"obs": run.run(expect_for), "serials": {}, "skipped": run.skipped}
            else:
                results[vid] = {"error": f"unknown runner {vec['runner']!r}"}
        except TargetUnavailable as exc:  # e.g. rs CoT before T-30: N/A for this vector, not a failure
            results[vid] = {"unavailable": str(exc)}
        except Exception as exc:  # pylint: disable=broad-except
            results[vid] = {"error": f"harness exception: {exc}\n{traceback.format_exc()}"}
        results[vid]["seconds"] = round(time.monotonic() - t0, 2)
        if args.verbose:
            print(f"  [{label}] {vid} {results[vid]['seconds']}s", file=sys.stderr)
    return results


def oracle(vec, res, target_name, args, hooks=True):
    if "error" in res:
        return [res["error"]]
    if vec["runner"] == "cot":
        if not hooks:
            vec = compare.strip_memory_persist(vec)
        return compare.oracle_cot(vec, res["obs"], res["serials"], args.mode, target_name, args.taky_src)
    if vec["runner"] == "dps":
        return compare.oracle_dps(vec, res["obs"], target_name)
    return compare.oracle_unit(vec, res["obs"], target_name)


def differential(vec, ra, rb, skip_divergent, hooks=True):
    if "error" in ra or "error" in rb:
        return [{"where": "run", "class": "harness", "a": ra.get("error"), "b": rb.get("error")}]
    a = compare.masked(ra["obs"], ra["serials"])
    b = compare.masked(rb["obs"], rb["serials"])
    if vec["runner"] == "cot" and not hooks:
        a, b = compare.strip_memory_persist_obs(a), compare.strip_memory_persist_obs(b)
    if vec["runner"] == "cot":
        return compare.diff_cot(vec, a, b, skip_divergent)
    if vec["runner"] == "dps":
        return compare.diff_plain(vec, a, b, skip_divergent, "steps")
    return compare.diff_plain(vec, a, b, skip_divergent, "cases")


def junit(path, rows, elapsed):
    from xml.sax.saxutils import escape, quoteattr

    fails = sum(1 for r in rows if r["status"] == "FAIL")
    lines = [f'<?xml version="1.0" encoding="UTF-8"?>',
             f'<testsuite name="difftest" tests="{len(rows)}" failures="{fails}" time="{elapsed:.1f}">']
    for r in rows:
        lines.append(f'  <testcase classname="difftest.{r["runner"]}" name={quoteattr(r["id"])}>')
        if r["status"] == "FAIL":
            body = "\n".join(r["oracle_a"] + r["oracle_b"] + [json.dumps(d, ensure_ascii=False) for d in r["divergences"]])
            lines.append(f'    <failure message="oracle/differential mismatch">{escape(body)}</failure>')
        lines.append("  </testcase>")
    lines.append("</testsuite>")
    with open(path, "w", encoding="utf8") as fp:
        fp.write("\n".join(lines) + "\n")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "random":  # seeded random sessions (S-402)
        from . import randsession

        return randsession.main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "compat":  # data compatibility scenarios C1..C14 (S-405, S-406)
        from . import compat

        return compat.main(sys.argv[2:])
    ap = argparse.ArgumentParser(prog="difftest", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("vectors", nargs="*", help="vector files (default with --all: cot/ dps/ unit/)")
    ap.add_argument("--all", action="store_true", help="all vectors under --vectors-dir")
    ap.add_argument("--target", default="py", choices=["py", "rs"], help="target compared with the Python baseline")
    ap.add_argument("--only", help="comma-separated id prefixes, e.g. V04,D01")
    ap.add_argument("--mode", default="exact", choices=["exact", "c14n"], help="oracle XML comparison")
    ap.add_argument("--quiet", type=float, default=0.2, help="settle window in seconds (default 0.2)")
    ap.add_argument("--py-ip", default=os.environ.get("PYREF_BIND_IP", "127.0.0.2"))
    ap.add_argument("--rs-ip", default="127.0.0.3")
    ap.add_argument("--rs-bin", help="directory with taky-rs binaries (default <taky-rs>/target/debug)")
    ap.add_argument("--rs-cot", default="launcher", choices=["launcher", "bin"],
                    help="Rust CoT process: launcher = taky-rs-difftest (frozen clock + hooks, default); "
                         "bin = the plain taky-rs binary (vectors needing a clock are N/A)")
    ap.add_argument("--vectors-dir", default=os.path.join(OFFICE, "shared", "spec", "vectors"))
    ap.add_argument("--taky-src", default=os.environ.get("TAKY_SRC", os.path.join(OFFICE, "taky")))
    ap.add_argument("--state", default=os.path.join(TOOL_DIR, ".state"))
    ap.add_argument("--report", default=os.path.join(TAKYRS, "target", "qa", "difftest"))
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    args.taky_src = os.path.abspath(args.taky_src)
    import logging

    logging.disable(logging.CRITICAL)

    vectors, load_errors = load_vectors(args)
    for e in load_errors:
        print(f"ERROR {e}")
    if not vectors:
        print("no vectors selected")
        return 2
    tmp = bench.fresh_dir(os.path.join(args.state, "tmp"))
    tools = os.path.join(args.vectors_dir, "tools")
    py = PyTarget(args.py_ip, sys.executable, args.taky_src, tools, tmp)
    if args.target == "py":
        runs = [("py-1", py), ("py-2", PyTarget(args.py_ip, sys.executable, args.taky_src, tools, tmp))]
    else:
        runs = [("py-1", py), ("rs-1", RsTarget(args.rs_ip, args.rs_bin, args.rs_cot))]

    redis = None
    if any("redis" in v.get("requires", []) for v in vectors):
        redis = bench.RedisServer(args.state, args.py_ip)
        redis.start()
    t0 = time.monotonic()
    results = {}
    try:
        for label, target in runs:
            print(f"== run {label}: {len(vectors)} vectors against target '{target.name}' ({target.ip})", flush=True)
            try:
                results[label] = run_pass(label, target, vectors, args, redis)
            except TargetUnavailable as exc:
                print(f"TARGET UNAVAILABLE ({label}): {exc}")
                return 2
    finally:
        if redis:
            redis.stop()
    elapsed = time.monotonic() - t0

    (la, ta), (lb, tb) = runs
    skip_div = ta.name != tb.name
    rows = []
    for vec in vectors:
        ra, rb = results[la][vec["id"]], results[lb][vec["id"]]
        if "unavailable" in ra or "unavailable" in rb:
            why = ra.get("unavailable") or rb.get("unavailable")
            rows.append({"id": vec["id"], "runner": vec["runner"], "status": "N/A", "oracle_a": [],
                         "oracle_b": [], "divergences": [], "skipped_checks": [], "unavailable": why,
                         "seconds": [ra.get("seconds"), rb.get("seconds")]})
            print(f"N/A  {vec['id']:5} target unavailable: {why}")
            continue
        hooks = getattr(tb, "hooks", True)
        oa = oracle(vec, ra, ta.name, args)
        ob = oracle(vec, rb, tb.name, args, hooks)
        lint = vecfmt.lint(vec)
        divs = differential(vec, ra, rb, skip_div, hooks)
        skipped = sorted(set(ra.get("skipped", []) + rb.get("skipped", [])))
        if vec["runner"] == "cot" and not hooks and "persist-hook" in vec.get("requires", []):
            skipped.append("memory persist (no hook in the plain taky-rs binary)")
        status = "PASS" if not (oa or ob or divs or lint) else "FAIL"
        rows.append({"id": vec["id"], "runner": vec["runner"], "status": status, "oracle_a": oa + lint,
                     "oracle_b": ob, "divergences": divs, "skipped_checks": skipped,
                     "seconds": [ra.get("seconds"), rb.get("seconds")]})
        mark = f"oracle {la}:{'ok' if not oa else len(oa)} {lb}:{'ok' if not ob else len(ob)}, divergences {len(divs)}"
        extra = f"  (skipped: {'; '.join(skipped)})" if skipped else ""
        print(f"{status} {vec['id']:5} {mark}{extra}")
        for e in (oa + lint)[:5]:
            print(f"     {la}: {e}")
        for e in ob[:5]:
            print(f"     {lb}: {e}")
        for d in divs[:5]:
            print(f"     DIVERGENCE {d['where']} [{d['class']}]\n       {la}: {d['a']}\n       {lb}: {d['b']}")

    os.makedirs(args.report, exist_ok=True)
    for label in results:
        with open(os.path.join(args.report, f"obs-{label}.json"), "w", encoding="utf8") as fp:
            json.dump({k: v for k, v in results[label].items()}, fp, indent=1, ensure_ascii=False, default=str)
    n_fail = sum(r["status"] == "FAIL" for r in rows)
    n_na = sum(r["status"] == "N/A" for r in rows)
    n_div = sum(len(r["divergences"]) for r in rows)
    by_runner = {}
    for r in rows:
        by_runner[r["runner"]] = by_runner.get(r["runner"], 0) + 1
    summary = {"target": args.target, "runs": [la, lb], "vectors": len(rows), "by_runner": by_runner,
               "passed": len(rows) - n_fail - n_na, "failed": n_fail, "unavailable": n_na, "divergences": n_div,
               "load_errors": load_errors, "mode": args.mode, "quiet": args.quiet,
               "elapsed_s": round(elapsed, 1), "skipped_checks": sum(len(r["skipped_checks"]) for r in rows)}
    with open(os.path.join(args.report, "report.json"), "w", encoding="utf8") as fp:
        json.dump({"summary": summary, "vectors": rows}, fp, indent=1, ensure_ascii=False, default=str)
    junit(os.path.join(args.report, "junit.xml"), rows, elapsed)
    green = n_fail == 0 and not load_errors
    print(f"\ndifftest --target {args.target}: {len(rows)} vectors {by_runner} x 2 runs ({la}, {lb}), "
          f"{len(rows) - n_fail - n_na} PASS, {n_fail} FAIL, {n_na} N/A, {n_div} divergences, "
          f"{summary['skipped_checks']} skipped checks, {elapsed:.0f}s -> {'N/A' if n_na == len(rows) else 'GREEN' if green else 'RED'}")
    print(f"report: {os.path.relpath(args.report, TAKYRS)}/{{report.json,junit.xml,obs-*.json}}")
    if os.environ.get("DIFFTEST_CLEAN"):
        shutil.rmtree(args.state, ignore_errors=True)
    if n_na == len(rows):
        return 2  # nothing could be run against the target
    return 0 if green else 1


if __name__ == "__main__":
    sys.exit(main())
