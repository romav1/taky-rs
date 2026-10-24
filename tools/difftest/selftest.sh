#!/usr/bin/env bash
# Negative controls for difftest: the harness must go RED (exit 1) when an expectation is wrong.
#   1. a CoT vector whose expected delivery is altered by one attribute value  -> oracle FAIL
#   2. a DPS vector whose expected status is altered                           -> oracle FAIL
#   3. a vector with an unknown "format"                                        -> rejected (exit 2)
# Tampered copies live in tools/difftest/.state/selftest (git-ignored); the real vectors are untouched.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VEC="$DIR/../../../shared/spec/vectors"
WORK="$DIR/.state/selftest"
rm -rf "$WORK" && mkdir -p "$WORK"

python3 - "$VEC" "$WORK" <<'EOF'
import json, sys
vec, work = sys.argv[1:]
v = json.load(open(f"{vec}/cot/V001.json"))
step = next(s for s in v["steps"] if s["expect"].get("deliveries"))
cid = next(iter(step["expect"]["deliveries"]))
step["expect"]["deliveries"][cid][0] = step["expect"]["deliveries"][cid][0].replace('version="2.0"', 'version="2.1"', 1)
v["id"] = "X001"; json.dump(v, open(f"{work}/X001.json", "w"))
d = json.load(open(f"{vec}/dps/D001.json"))
d["steps"][0]["expect"]["status"] = 299
d["id"] = "X002"; json.dump(d, open(f"{work}/X002.json", "w"))
f = json.load(open(f"{vec}/cot/V002.json"))
f["format"] = 99; f["id"] = "X003"; json.dump(f, open(f"{work}/X003.json", "w"))
EOF

rc=0
expect_rc() {  # expect_rc WANT DESCRIPTION ARGS...
    local want="$1" what="$2"; shift 2
    local got=0
    "$DIR/difftest" --target py --report "$WORK/report" "$@" >"$WORK/out.txt" 2>&1 || got=$?
    if [[ "$got" == "$want" ]]; then
        echo "[selftest] ok   $what (exit $got)"
    else
        echo "[selftest] FAIL $what (exit $got, want $want)"; cat "$WORK/out.txt"; rc=1
    fi
}
expect_rc 1 "tampered CoT delivery is detected" "$WORK/X001.json"
grep -q "deliveries to" "$WORK/out.txt" || { echo "[selftest] FAIL: no delivery mismatch reported"; rc=1; }
expect_rc 1 "tampered DPS status is detected" "$WORK/X002.json"
expect_rc 2 "unknown vector format is rejected" "$WORK/X003.json"
[[ $rc == 0 ]] && echo "[selftest] RESULT: PASS" || echo "[selftest] RESULT: FAIL"
exit $rc
