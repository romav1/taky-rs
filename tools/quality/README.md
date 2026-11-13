# tools/quality — ub-mode quality ratchet (S-805)

`scripts/check.sh --ub` runs **only** this gate (plain `scripts/check.sh` is unchanged):

1. `cargo tarpaulin` (ptrace engine — `cargo llvm-cov` needs llvm-tools, blocked by the office
   proxy) → LCOV in `target/quality/target/coverage/rust/lcov.info`. All tests run; a failing
   test fails the gate.
2. unclebob `crapper --use-existing-coverage crates` → functions with **CRAP ≥ 10**.
3. unclebob `dryer --threshold 0.8 crates` → **duplicate pairs**.
4. `ratchet.py` compares with `baseline.toml` and **fails** when a count rises, when any offender
   is not in `[known]` (a swap — one fixed, one new — fails too), or when a `[known.crap]` score
   rises by more than `score_tolerance` (0.5; absorbs ptrace coverage noise). A missing, empty or
   unparsable report fails (exit 2). A count that drops passes with a hint to lower the baseline.

Reports: `target/quality/{crap.txt,dry.txt,.metrics/*.edn}` (CI artifact `quality-reports`).

## Run locally

```sh
tools/quality/install.sh             # once; pinned crapper/dryer SHAs, tarpaulin, mutants
bash scripts/check.sh --ub           # ~6 min on 2 cores (tarpaulin is most of it)
bash scripts/check.sh --ub --no-coverage-run   # reuse the last LCOV: seconds, for dryer
```

`target/tarpaulin` (instrumented build, ~10 GB) is deleted after each run; set
`UB_KEEP_TARPAULIN=1` to keep it for faster reruns. With `--no-coverage-run` after editing code,
CRAP names can be off (LCOV lines no longer match); trust a full run.

## Lower the baseline (after fixing offenders)

```sh
bash scripts/check.sh --ub --write-baseline     # rewrites counts + [known], keeps [exceptions]
git diff tools/quality/baseline.toml            # only removals / lower scores expected
```

Never raise a count to make CI green: fix the function, or add an exception (below) with a reason.

## Accepted exceptions

`[exceptions] crap` in `baseline.toml` lists crapper keys (`namespace::name`) that do not count.
Only Python lookup tables written as `match`, which mirror Python names or messages and must stay
byte-exact (ub01 REPORT §6): `Teams::as_str`, `IniError::fmt`, `IniError::py_class`. Control-flow
functions get no exemption. A table that scores high only because it is untested (e.g.
`PyLevel::as_py_str`) is not exempt: add a test.

## CI

Job `quality` in `.github/workflows/ci.yml`: redis + openssl, `TAKY_REQUIRE_REDIS/OPENSSL=1`,
`check.sh --ub`. On pull requests also `cargo mutants --in-diff <PR diff> --timeout 60`
(20 min cap, **report-only** for now: `continue-on-error`), output in the artifact.

## Pins (`install.sh`)

crapper `c757ec79a6c15dc815238bbd9c2f4601eb54d3cc`, dryer `66ff6d21a42c04afcad89c78a80066176d1294b0`
(tree-sitter 0.26.1, tree-sitter-language-pack 1.25.0), cargo-tarpaulin 0.37.6,
cargo-mutants 27.1.0. Bumping a pin can change scores: refresh `baseline.toml` in the same commit.
