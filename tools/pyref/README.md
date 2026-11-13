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
| `PYREF` | the original at `../taky` + Python with its deps | optional (original not vendored) |

Run the Python cross-checks (`taky-pki/tests/pyref_*.rs`, `takyctl/tests/pyref_*.rs`) for real:

```sh
# taky-rs/ checked out next to the original: <dir>/taky (Python, v0.9) and <dir>/taky-rs
tools/pyref/venv.sh                   # or: export TAKY_PYREF_PYTHON=/path/to/python
TAKY_REQUIRE_ALL=1 cargo test --workspace --all-features
```

With `TAKY_REQUIRE_ALL=1` a missing original, venv, Redis or OpenSSL is a test failure, so a
green run proves every cross-check ran. Expect no `SKIP(` line in `-- --nocapture` output.
