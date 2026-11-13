#!/usr/bin/env bash
# ub-mode quality gate (S-805, ub01 §5), called by `scripts/check.sh --ub`.
#   1. cargo tarpaulin (ptrace) -> LCOV            target/quality/target/coverage/rust/lcov.info
#   2. crapper --use-existing-coverage crates       target/quality/crap.txt, .metrics/crap.edn
#   3. dryer --threshold 0.8 crates                 target/quality/dry.txt, .metrics/dry.edn
#   4. ratchet.py vs tools/quality/baseline.toml: FAIL when a count rises (new offenders listed).
# Options: --write-baseline (rewrite the baseline from this run), --no-coverage-run (reuse the
# LCOV of a previous run). Env: UB_KEEP_TARPAULIN=1 keeps target/tarpaulin (instrumented build,
# ~10 GB; removed by default because the office disk is small — the next run rebuilds it).
set -euo pipefail

# Coverage must not depend on the machine: without redis/openssl their tests would SKIP, lose
# coverage and give false CRAP results (S-807 M-4). Override with e.g. TAKY_REQUIRE_REDIS=0.
export TAKY_REQUIRE_REDIS="${TAKY_REQUIRE_REDIS:-1}" TAKY_REQUIRE_OPENSSL="${TAKY_REQUIRE_OPENSSL:-1}"

cd "$(dirname "$0")/../.."
root="$PWD"
q="$root/target/quality"
venv="${UB_VENV:-$root/tools/quality/.state/venv}"
write=() run_cov=1
for a in "$@"; do
    case "$a" in
        --write-baseline) write=(--write-baseline) ;;
        --no-coverage-run) run_cov=0 ;;
        *) echo "ub.sh: unknown option $a" >&2; exit 2 ;;
    esac
done
step() { printf '\n==> %s\n' "$*"; }
t0=$SECONDS

step "tools/quality/install.sh (pinned tools)"
tools/quality/install.sh

step "ratchet self-test"
python3 -I -B -m unittest discover -s tools/quality -q

mkdir -p "$q/target/coverage/rust"
if (( run_cov )); then
    step "cargo tarpaulin --engine ptrace (LCOV)"
    rm -f "$q/target/coverage/rust/lcov.info"
    # Same flags as the ub01 audit (REPORT §3); a failing test fails the gate.
    # Own --target-dir: tarpaulin's RUSTFLAGS would otherwise add a second full build to
    # target/debug (~10 GB here). pipefail: a failing test fails the gate.
    cargo tarpaulin --workspace --all-features --engine ptrace --skip-clean --timeout 300 \
        --target-dir "$root/target/tarpaulin" \
        --out Lcov --output-dir "$q/target/coverage/rust" \
        --exclude-files 'crates/*/tests/*' 'fuzz/*' 2>&1 | tail -n 25
    if [[ -z "${UB_KEEP_TARPAULIN:-}" ]]; then rm -rf "$root/target/tarpaulin"; fi
fi
lcov="$q/target/coverage/rust/lcov.info"
test -s "$lcov" || { echo "ub.sh: no LCOV at $lcov" >&2; exit 1; }
if (( ! run_cov )); then
    newer="$(find crates -name '*.rs' -newer "$lcov" | head -n 3)"
    if [[ -n "$newer" ]]; then # S-807 N-5: stale coverage gives wrong CRAP names/scores
        echo "WARNING: --no-coverage-run: LCOV is older than these sources (CRAP results may be" >&2
        echo "WARNING: wrong; run without --no-coverage-run):" >&2
        sed 's/^/WARNING:   /' <<<"$newer" >&2
    fi
fi

step "crapper --use-existing-coverage crates"
"$venv/bin/crapper" --root "$q" --use-existing-coverage "$root/crates" > "$q/crap.txt"
echo "report: $q/crap.txt"

step "dryer --threshold 0.8 crates"
"$venv/bin/dryer" --root "$q" --threshold 0.8 "$root/crates" > "$q/dry.txt"
echo "report: $q/dry.txt"

step "ratchet vs tools/quality/baseline.toml"
python3 -I -B tools/quality/ratchet.py --baseline tools/quality/baseline.toml \
    --crap "$q/.metrics/crap.edn" --dry "$q/.metrics/dry.edn" --root "$root" "${write[@]}"
printf '\nub.sh: quality gate passed (%ss)\n' "$((SECONDS - t0))"
