# tools/pyref — Python taky reference bench

Scripts that run the **original Python taky** (`../taky`, read-only) next to taky-rs:
`venv.sh` (venv from `requirements.lock`), `certs.sh`, `up.sh` / `down.sh`, `smoke.sh`.
State goes to `tools/pyref/.state/` (git-ignored).

## Test prerequisites (`taky_common::testenv`, S-802)

Tests that need an external tool never pass silently. When the tool is missing they print one
line `SKIP(<KIND>) <test>: <reason>` — or, if `TAKY_REQUIRE_<KIND>=1` (or `TAKY_REQUIRE_ALL=1`)
is set, they **fail** with that reason.

| Kind | Needs | CI (`check` job) |
|---|---|---|
| `REDIS` | `redis-server` on `PATH` (tests spawn their own) | required |
| `OPENSSL` | `openssl` CLI on `PATH` | required |
| `PYREF` | the original at `../taky` + Python with its deps | not run: the tests are `#[ignore]`d (below) |

The Python cross-checks (`taky-pki/tests/pyref_*.rs`, `takyctl/tests/pyref_*.rs`) are
`#[ignore = "needs the Python original (taky/)"]` (S-823, PROTOCOL §8.8.1), so a plain
`cargo test` / `check.sh` reports them as **ignored**, never as passed. Run them with `--ignored`;
a missing original or Python is then an assertion failure:

```sh
# taky-rs/ checked out next to the original: <dir>/taky (Python, v0.9) and <dir>/taky-rs
tools/pyref/venv.sh                   # or: export TAKY_PYREF_PYTHON=/path/to/python
export TAKY_REQUIRE_ALL=1             # a missing openssl fails too
cargo test --no-fail-fast --all-features -p takyctl --test pyref_cli --test pyref_datapackage \
    --test pyref_mgmt --test pyref_systemd -- --ignored
cargo test --no-fail-fast --all-features -p taky-pki --test pyref_x509 --test pyref_p12 -- --ignored
```

Expect `9 passed` in total (cli 1, datapackage 1, mgmt 3, systemd 2, x509 1, p12 1) and no
`SKIP(` line in `-- --nocapture` output. The rest of the workspace (Redis, OpenSSL tests) still
runs with `TAKY_REQUIRE_ALL=1 cargo test --workspace --all-features`.
