#!/usr/bin/env bash
# Minimize fuzz/corpus/<target>/ in place with libFuzzer -merge=1 (qa01, S-407).
#   tools/fuzz/merge.sh <target>...
set -euo pipefail
cd "$(dirname "$0")/../../fuzz"
export RUSTC_BOOTSTRAP="${RUSTC_BOOTSTRAP:-1}"
for t in "$@"; do
    tmp="corpus/.merge-$t"; rm -rf "$tmp"; mkdir -p "$tmp"
    cargo fuzz run -O -s "${FUZZ_SANITIZER:-none}" "$t" "$tmp" "corpus/$t" -- -merge=1 -rss_limit_mb=256 -malloc_limit_mb=64 -timeout=1 -close_fd_mask=1 2>&1 | grep -E "MERGE-OUTER: [0-9]+ new files" || true
    rm -rf "corpus/$t"; mv "$tmp" "corpus/$t"
    echo "$t: $(ls "corpus/$t" | wc -l) files, $(du -sh "corpus/$t" | cut -f1)"
done
