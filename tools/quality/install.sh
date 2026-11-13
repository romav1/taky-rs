#!/usr/bin/env bash
# Pinned install of the ub-mode quality tools (S-805, ub01 §5). Idempotent: re-running with the
# same pins changes nothing.
#   crapper, dryer — unclebob, Python, from GitHub at a fixed commit, into one venv
#                    ($UB_VENV, default tools/quality/.state/venv; git-ignored);
#   cargo-tarpaulin — coverage, ptrace engine (llvm-cov needs llvm-tools: blocked by the office proxy);
#   cargo-mutants  — mutation testing (CI `quality` job, pull requests).
# Bump a pin here only together with tools/quality/baseline.toml (scores may change).
set -euo pipefail

CRAPPER_SHA=c757ec79a6c15dc815238bbd9c2f4601eb54d3cc   # github.com/unclebob/crapper
DRYER_SHA=66ff6d21a42c04afcad89c78a80066176d1294b0     # github.com/unclebob/dryer
TREE_SITTER=0.26.1
TREE_SITTER_LANGUAGE_PACK=1.25.0
TARPAULIN=0.37.6
MUTANTS=27.1.0

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
venv="${UB_VENV:-$here/.state/venv}"
log() { printf '[quality] %s\n' "$*" >&2; }

pins="crapper@$CRAPPER_SHA dryer@$DRYER_SHA tree-sitter==$TREE_SITTER tree-sitter-language-pack==$TREE_SITTER_LANGUAGE_PACK"
if [[ -x "$venv/bin/crapper" && -x "$venv/bin/dryer" && "$(cat "$venv/.ub-pins" 2>/dev/null)" == "$pins" ]]; then
    log "venv up to date: $venv"
else
    log "creating venv: $venv"
    rm -rf "$venv"
    mkdir -p "$(dirname "$venv")"
    python3 -m venv "$venv"
    "$venv/bin/pip" install -q --disable-pip-version-check \
        "crapper @ git+https://github.com/unclebob/crapper@$CRAPPER_SHA" \
        "dryer @ git+https://github.com/unclebob/dryer@$DRYER_SHA" \
        "tree-sitter==$TREE_SITTER" "tree-sitter-language-pack==$TREE_SITTER_LANGUAGE_PACK"
    printf '%s' "$pins" > "$venv/.ub-pins"
fi

cargo_tool() { # <crate> <version> <version-probe command...>
    local crate="$1" want="$2"; shift 2
    if "$@" 2>/dev/null | grep -q " $want\$"; then
        log "$crate $want present"
    else
        log "cargo install $crate $want"
        cargo install --locked "$crate" --version "$want"
    fi
}
cargo_tool cargo-tarpaulin "$TARPAULIN" cargo tarpaulin --version
cargo_tool cargo-mutants "$MUTANTS" cargo mutants --version
log "ok: $venv/bin/{crapper,dryer}, cargo-tarpaulin $TARPAULIN, cargo-mutants $MUTANTS"
