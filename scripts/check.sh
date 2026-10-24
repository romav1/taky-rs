#!/usr/bin/env bash
# Local / CI quality gate for taky-rs (PROTOCOL §8, ARCHITECTURE §16.3).
# Runs: rustfmt check, clippy (-D warnings, all targets, all features), tests, cargo-deny.
# If cargo-deny is not installed, that stage is skipped with a WARNING locally, but FAILS when
# CI is set to a truthy value (GitHub Actions sets CI=true; review-T-10 N-4).
set -euo pipefail

cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }

step "cargo fmt --all -- --check"
cargo fmt --all -- --check

step "cargo clippy --workspace --all-targets --all-features -- -D warnings"
cargo clippy --workspace --all-targets --all-features -- -D warnings

step "cargo test --workspace --all-features"
cargo test --workspace --all-features

step "cargo deny check"
if cargo deny --version >/dev/null 2>&1; then
    cargo deny check
elif [[ -n "${CI:-}" && "${CI}" != "false" && "${CI}" != "0" ]]; then
    echo "ERROR: cargo-deny is not installed and CI=${CI}; refusing to skip 'cargo deny check'" >&2
    echo "ERROR: install it with: cargo install cargo-deny --locked" >&2
    exit 1
else
    echo "WARNING: cargo-deny is not installed; skipping 'cargo deny check'" >&2
    echo "WARNING: install it with: cargo install cargo-deny --locked" >&2
fi

printf '\ncheck.sh: all checks passed\n'
