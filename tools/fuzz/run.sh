#!/usr/bin/env bash
# Run one taky-rs fuzz target with the S-407 / test-strategy §1.6 limits (qa01).
#   tools/fuzz/run.sh <target> <seconds> [extra libFuzzer args…]
# Corpus: fuzz/corpus/<target>/ (seeds + new inputs, minimize later with tools/fuzz/merge.sh);
# crashes/timeouts/OOMs: fuzz/artifacts/<target>/ (git-ignored; minimized repros are committed under
# fuzz/corpus/regressions/<target>/). Stable toolchain + RUSTC_BOOTSTRAP=1 locally, nightly in CI.
# Sanitizer: FUZZ_SANITIZER=none (default; safe Rust, ~2x execs on 2 cores) or address.
# Log with final stats: fuzz/artifacts/<target>.log
set -euo pipefail
cd "$(dirname "$0")/../../fuzz"
t="$1"; secs="$2"; shift 2
mkdir -p "corpus/$t" "artifacts/$t"
export RUSTC_BOOTSTRAP="${RUSTC_BOOTSTRAP:-1}"
cargo fuzz run -O -s "${FUZZ_SANITIZER:-none}" "$t" "corpus/$t" -- \
    -rss_limit_mb=256 -malloc_limit_mb=64 -timeout=1 \
    -max_total_time="$secs" -print_final_stats=1 -close_fd_mask=1 \
    -artifact_prefix="artifacts/$t/" "$@" 2>&1 | tee "artifacts/$t.log" | grep -E "INITED|DONE|ERROR|SUMMARY|panicked|stat::"
