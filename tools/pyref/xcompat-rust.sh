#!/usr/bin/env bash
# Rust leg of the S-309 Redis cross-compat harness (S-807 N-6): runs the #[ignore]d entry points
# taky-cot/tests/redis_live.rs::xcompat_rust_{writes,reads} with --ignored against a private
# redis-server: Rust writes N events, Rust reads them back; the replayed frames must carry the
# same uids. The Python leg (taky RedisPersistence on the same DB) plugs in between the two
# steps with the same TAKY_XCOMPAT_* env (dev01 S-309 script; not in the repo yet).
# Usage: tools/pyref/xcompat-rust.sh   (needs redis-server on PATH)
set -euo pipefail
cd "$(dirname "$0")/../.."
work="$(mktemp -d)"
port=$(( 20000 + RANDOM % 20000 ))
redis-server --port "$port" --bind 127.0.0.1 --save "" --appendonly no --dir "$work" \
    --daemonize yes --pidfile "$work/redis.pid" >/dev/null
trap 'redis-cli -p "$port" shutdown nosave >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
for _ in $(seq 50); do redis-cli -p "$port" ping >/dev/null 2>&1 && break; sleep 0.1; done

ev() { printf '<event version="2.0" uid="%s" type="a-f-G" how="m-g" time="2030-01-01T00:00:00.000Z" start="2030-01-01T00:00:00.000Z" stale="2030-01-01T01:00:00.000Z"><point lat="1.0" lon="2.0" hae="3.0" ce="4.0" le="5.0"/><detail/></event>\n' "$1"; }
{ ev XC-1; ev XC-2; ev XC-3; } > "$work/in.xml"

export TAKY_XCOMPAT_REDIS_URL="redis://127.0.0.1:$port/0" TAKY_XCOMPAT_HOST=xc \
    TAKY_XCOMPAT_NOW=2030-01-01T00:00:00Z TAKY_XCOMPAT_IN="$work/in.xml" TAKY_XCOMPAT_OUT="$work/out.xml"
t() { cargo test -q -p taky-cot --test redis_live -- --ignored --exact "$1" 2>&1 | tail -n 3; }
t xcompat_rust_writes
echo "redis keys: $(redis-cli -p "$port" --scan --pattern 'taky:xc:persist:*' | sort | tr '\n' ' ')"
t xcompat_rust_reads
got="$(grep -o 'uid="[^"]*"' "$work/out.xml" | sort | tr '\n' ' ')"
want='uid="XC-1" uid="XC-2" uid="XC-3" '
[[ "$got" == "$want" ]] || { echo "xcompat-rust: FAIL replay uids: $got" >&2; exit 1; }
echo "xcompat-rust: OK (3 events written and replayed through Redis)"
