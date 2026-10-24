#!/usr/bin/env python3
"""
Unit-vector adapter for the "py" target: reads unit vectors (runner "unit"), evaluates every case
with the ORIGINAL Python taky and prints {vector_id: [observation, ...]} as JSON on stdout.

The evaluation functions are imported from an01's runner (shared/spec/vectors/tools/run_python_unit.py),
so this adapter observes exactly what the oracle runner observes. It runs as a separate process
(black box, like the live servers); the Rust target will provide the same contract with a small
testkit binary (stdin: vector paths, stdout: the same JSON).
"""
import sys

sys.dont_write_bytecode = True

import json  # noqa: E402
import logging  # noqa: E402


def main():
    import run_python_unit as ru

    logging.disable(logging.CRITICAL)
    out = {}
    for path in sys.argv[1:]:
        with open(path, encoding="utf8") as fp:
            vec = json.load(fp)
        obs = []
        for case in vec["cases"]:
            kind = vec["kind"]
            if kind == "isoparse":
                obs.append(ru.run_isoparse(case["input"]))
            elif kind == "float":
                obs.append(ru.run_float(case["input"]))
            elif kind == "ini":
                obs.append(ru.run_ini(case))
            else:
                obs.append({"adapter_error": f"unknown kind {kind}"})
        out[vec["id"]] = obs
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
