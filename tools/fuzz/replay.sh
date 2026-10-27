#!/usr/bin/env bash
# Replay every committed regression repro and the corpus of each target once (-runs=0): exit != 0 if
# any input crashes/times out again (qa01, S-407). Usage: tools/fuzz/replay.sh [target…]
set -euo pipefail
cd "$(dirname "$0")/../../fuzz"
export RUSTC_BOOTSTRAP="${RUSTC_BOOTSTRAP:-1}"
targets=("$@"); [[ ${#targets[@]} -gt 0 ]] || mapfile -t targets < <(cargo fuzz list)
for t in "${targets[@]}"; do
    dirs=("corpus/$t"); [[ -d "corpus/regressions/$t" ]] && dirs+=("corpus/regressions/$t")
    cargo fuzz run -O -s "${FUZZ_SANITIZER:-none}" "$t" "${dirs[@]}" -- -runs=0 -rss_limit_mb=256 -malloc_limit_mb=64 -timeout=1 -close_fd_mask=1 >/dev/null 2>"artifacts/replay-$t.log" \
        && echo "$t: OK" || { echo "$t: FAIL (see fuzz/artifacts/replay-$t.log)"; exit 1; }
done
