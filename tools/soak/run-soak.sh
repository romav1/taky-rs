#!/usr/bin/env bash
# run-soak.sh - long-run memory check of a RUNNING taky-rs (qa01, S-506; ADR-012 G3-2, test-strategy §1.8 / §3.4 item 5).
#
# Samples the memory (RSS) and open files of taky-rs and taky_dps-rs with tools/memwatch every 10 s for N hours,
# optionally drives the CoT server with the project's load generator (loadgen), then checks the thresholds
# (RSS <= 128 MB, growth <= 1 MB/h after a 30 min warm-up, final <= 1.1 x hour 1) and packs everything into
# ONE archive to send back: taky-rs-soak-<host>-<date>.tar.gz.
#
#   sudo tools/soak/run-soak.sh --hours 24 --detach         # typical: real devices connected, runs in background
#   sudo tools/soak/run-soak.sh --hours 0.1                 # 6-minute trial run first
#   sudo tools/soak/run-soak.sh --hours 24 --detach --load --loadgen ./loadgen \
#        --target 127.0.0.1:8089 --tls --certs ./lg-pem      # with synthetic load (see doc/ACCEPTANCE.md D3)
#
# Needs: bash, python3 (3.8+), Linux /proc. Run with sudo so that the open-file count of the service user's
# processes is readable (without sudo only RSS is recorded). It never starts, stops or changes taky-rs.
# Exit code: 0 PASS, 1 FAIL (a threshold violated), 2 not enough data / setup error.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MEMWATCH="${MEMWATCH:-$HERE/../memwatch/memwatch}"

usage() {
    cat <<'EOF'
usage: run-soak.sh --hours N [options]
  --hours N            how long to sample (decimals allowed: 0.1 = 6 min); required (or --minutes N)
  --minutes N          the same in minutes
  --out DIR            result directory (default ./taky-rs-soak-<host>-<YYYYmmdd-HHMM>); the archive is DIR.tar.gz
  --interval S         seconds between samples (default 10)
  --names "A B"        process names to watch (default "taky-rs taky_dps-rs")
  --max-rss SIZE       default 128MB          --max-slope RATE   default 1MB/h
  --warmup DUR         default 30m (runs shorter than 2 h: 1/6 of the run)
  --detach             keep running in the background after you log out; prints the log path and exits
  --load               also run loadgen for the whole run (stops 2 min before the end of sampling)
    --loadgen PATH     loadgen binary (or $LOADGEN)
    --target HOST:PORT CoT address (default 127.0.0.1:8089 with --tls, else 127.0.0.1:8087)
    --tls --certs DIR  TLS; DIR holds one client <name>.crt + <name>.key (takyctl-rs build_client --dump_pem)
    --clients N        default 100            --rate EV_PER_S    default 300 (30 % of the 1000 ev/s target)
    --loadgen-args "…" extra loadgen arguments, e.g. "--churn-per-min 2 --slow-clients 1"
EOF
}

die() { echo "run-soak: $*" >&2; exit 2; }
log() { echo "[$(date '+%F %T')] $*"; }

HOURS="" OUT="" INTERVAL=10 NAMES="taky-rs taky_dps-rs" MAX_RSS=128MB MAX_SLOPE=1MB/h WARMUP="" DETACH=0
LOAD=0 LOADGEN="${LOADGEN:-}" TARGET="" TLS=0 CERTS="" CLIENTS=100 RATE=300 LG_ARGS=""
ORIG_ARGS=("$@")
while [[ $# -gt 0 ]]; do
    case "$1" in
        --hours) HOURS="${2:-}"; shift 2 ;;
        --minutes) HOURS="$(awk -v m="${2:-x}" 'BEGIN { if (m+0 > 0) printf "%.6f", m / 60 }')"; shift 2 ;;
        --out) OUT="${2:-}"; shift 2 ;;
        --interval) INTERVAL="${2:-}"; shift 2 ;;
        --names) NAMES="${2:-}"; shift 2 ;;
        --max-rss) MAX_RSS="${2:-}"; shift 2 ;;
        --max-slope) MAX_SLOPE="${2:-}"; shift 2 ;;
        --warmup) WARMUP="${2:-}"; shift 2 ;;
        --detach) DETACH=1; shift ;;
        --load) LOAD=1; shift ;;
        --loadgen) LOADGEN="${2:-}"; shift 2 ;;
        --target) TARGET="${2:-}"; shift 2 ;;
        --tls) TLS=1; shift ;;
        --certs) CERTS="${2:-}"; shift 2 ;;
        --clients) CLIENTS="${2:-}"; shift 2 ;;
        --rate) RATE="${2:-}"; shift 2 ;;
        --loadgen-args) LG_ARGS="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
done

[[ -n "$HOURS" ]] || { usage >&2; die "--hours is required"; }
DUR_S="$(awk -v h="$HOURS" 'BEGIN { s = int(h * 3600 + 0.5); if (s >= 60) print s }')"
[[ -n "$DUR_S" ]] || die "--hours must be at least 1 minute (0.017)"
command -v python3 >/dev/null || die "python3 not found (sudo apt install python3)"
[[ -f "$MEMWATCH" ]] || die "memwatch not found at $MEMWATCH (keep tools/memwatch next to tools/soak, or set MEMWATCH=)"
if [[ -z "$WARMUP" ]]; then
    if (( DUR_S >= 7200 )); then WARMUP=30m; else WARMUP="$(( DUR_S / 6 ))s"; fi
fi
HOST="$(hostname -s 2>/dev/null || hostname)"
[[ -n "$OUT" ]] || OUT="$PWD/taky-rs-soak-$HOST-$(date +%Y%m%d-%H%M)"
mkdir -p "$OUT" || die "cannot create $OUT"
OUT="$(cd "$OUT" && pwd)"

# ---- processes
declare -A PIDS=()
for n in $NAMES; do
    p="$(pgrep -x "$n" | tr '\n' ' ')"
    [[ -n "$p" ]] || die "process '$n' is not running. Start the service first (sudo systemctl start taky-rs, or docker compose up -d) or pass --names"
    PIDS[$n]="$p"
done

# ---- loadgen settings
if (( LOAD )); then
    [[ -n "$LOADGEN" && -x "$LOADGEN" ]] || die "--load needs --loadgen PATH to a built loadgen binary"
    [[ -n "$TARGET" ]] || { (( TLS )) && TARGET=127.0.0.1:8089 || TARGET=127.0.0.1:8087; }
    (( TLS == 0 )) || [[ -d "$CERTS" ]] || die "--tls needs --certs DIR with <name>.crt and <name>.key"
    (( DUR_S > 300 )) || die "--load needs a run of more than 5 minutes"
    LOADGEN="$(cd "$(dirname "$LOADGEN")" && pwd)/$(basename "$LOADGEN")"
    [[ -z "$CERTS" ]] || CERTS="$(cd "$CERTS" && pwd)"
fi

# ---- background mode: re-run ourselves detached from the terminal
if (( DETACH )); then
    args=()
    for a in "${ORIG_ARGS[@]}"; do [[ "$a" == --detach ]] || args+=("$a"); done
    [[ " ${args[*]} " == *" --out "* ]] || args+=(--out "$OUT")
    [[ -z "$LOADGEN" ]] || args+=(--loadgen "$LOADGEN")
    [[ -z "$CERTS" ]] || args+=(--certs "$CERTS")
    setsid nohup bash "$HERE/run-soak.sh" "${args[@]}" >"$OUT/run-soak.log" 2>&1 </dev/null &
    echo "$!" >"$OUT/run-soak.pid"
    echo "run-soak: running in the background (pid $!) for $HOURS h."
    echo "  progress:  tail -f $OUT/run-soak.log"
    echo "  stop early (still writes the archive):  sudo kill $!"
    echo "  result:    $OUT.tar.gz"
    exit 0
fi

# ---- run
START_ISO="$(date '+%Y-%m-%d %H:%M:%S')"
EXTRA_TAIL=0; (( LOAD )) && EXTRA_TAIL=120
SAMPLE_S=$DUR_S
LOAD_S=$(( DUR_S - EXTRA_TAIL ))
log "taky-rs soak: $HOURS h ($DUR_S s), every ${INTERVAL}s, warm-up $WARMUP -> $OUT"
for n in $NAMES; do log "  watching $n (pid ${PIDS[$n]% })"; done
[[ "$(id -u)" == 0 ]] || log "  note: not root - open-file counts of other users' processes are not readable (use sudo)"

{
    echo "start: $START_ISO ($(date -u '+%FT%TZ'))"
    echo "host: $HOST"; uname -a
    [[ -r /etc/os-release ]] && grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
    grep -m1 -E '^(model name|Model|Hardware)' /proc/cpuinfo 2>/dev/null; grep -m1 '^Model' /proc/cpuinfo 2>/dev/null
    echo "cpus: $(nproc 2>/dev/null)"
    free -m 2>/dev/null
    echo "duration_s: $DUR_S interval_s: $INTERVAL warmup: $WARMUP max_rss: $MAX_RSS max_slope: $MAX_SLOPE"
    echo "load: $LOAD target: $TARGET tls: $TLS clients: $CLIENTS rate: $RATE extra: $LG_ARGS"
    for n in $NAMES; do
        for p in ${PIDS[$n]}; do
            exe="$(readlink "/proc/$p/exe" 2>/dev/null)"
            echo "process $n pid $p exe ${exe:-?} user $(ps -o user= -p "$p" 2>/dev/null)"
            echo "  cmdline: $(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)"
            [[ -n "$exe" && -x "$exe" ]] && echo "  version: $("$exe" --version 2>&1 | head -1)"
        done
    done
    if command -v systemctl >/dev/null; then
        echo; systemctl --no-pager status 'taky-rs*' 2>&1 | head -40
    fi
} >"$OUT/info.txt" 2>&1

MW_ARGS=()
for n in $NAMES; do MW_ARGS+=(--name "$n"); done
python3 "$MEMWATCH" sample "${MW_ARGS[@]}" --interval "$INTERVAL" --duration "$SAMPLE_S" --out "$OUT/rss.csv" \
    2>"$OUT/memwatch.log" &
MW_PID=$!

LG_PID=""
if (( LOAD )); then
    cot_pid="$(pgrep -x taky-rs | head -1)"
    lg=("$LOADGEN" --target "$TARGET" --clients "$CLIENTS" --rate "$RATE" --warmup 0 --duration "$LOAD_S"
        --drain 5 --label "soak-$HOST" --out "$OUT/loadgen.json")
    [[ -n "$cot_pid" ]] && lg+=(--server-pid "$cot_pid")
    (( TLS )) && lg+=(--tls --certs "$CERTS")
    # shellcheck disable=SC2206
    [[ -n "$LG_ARGS" ]] && lg+=($LG_ARGS)
    log "  load: ${lg[*]}"
    "${lg[@]}" >"$OUT/loadgen.log" 2>&1 &
    LG_PID=$!
fi

STOPPED=0
on_signal() {
    STOPPED=1
    log "stopped early - packing what was recorded"
    [[ -n "$LG_PID" ]] && kill -INT "$LG_PID" 2>/dev/null
    kill -TERM "$MW_PID" 2>/dev/null
}
trap on_signal INT TERM HUP

# progress line every 30 minutes (every 1/6 of a short run)
STEP=$(( DUR_S >= 10800 ? 1800 : (DUR_S / 6 > 10 ? DUR_S / 6 : 10) ))
t0=$SECONDS
while kill -0 "$MW_PID" 2>/dev/null; do
    sleep 5 &
    wait $! 2>/dev/null
    if (( SECONDS - t0 >= STEP )); then
        t0=$SECONDS
        last="$(tail -n "$(wc -w <<<"$NAMES")" "$OUT/rss.csv" 2>/dev/null | awk -F, '{ printf "%s rss=%.1fMB fds=%s  ", $3, $6/1024, $10 }')"
        log "  $last"
    fi
done
wait "$MW_PID" 2>/dev/null
if [[ -n "$LG_PID" ]]; then
    kill -INT "$LG_PID" 2>/dev/null
    wait "$LG_PID" 2>/dev/null
    LG_RC=$?
    log "  loadgen exit code $LG_RC"
fi
trap - INT TERM HUP

# ---- logs of the services during the run
if command -v journalctl >/dev/null; then
    journalctl --no-pager -u taky-rs -u taky-rs-cot -u taky-rs-dps --since "$START_ISO" 2>/dev/null | tail -n 20000 \
        >"$OUT/journal.log"
    {
        echo "journal lines: $(wc -l <"$OUT/journal.log")"
        echo "WARNING lines: $(grep -c 'WARNING' "$OUT/journal.log")"
        echo "ERROR/CRITICAL lines: $(grep -cE 'ERROR|CRITICAL|panicked' "$OUT/journal.log")"
        echo "service (re)starts: $(grep -cE 'Started taky-rs|Starting taky-rs' "$OUT/journal.log")"
    } >>"$OUT/info.txt"
fi
echo "end: $(date '+%F %T') stopped_early: $STOPPED" >>"$OUT/info.txt"
for n in $NAMES; do echo "pids at end: $n $(pgrep -x "$n" | tr '\n' ' ')" >>"$OUT/info.txt"; done

# ---- verdict
AN_ARGS=(--warmup "$WARMUP" --max-rss "$MAX_RSS" --max-slope "$MAX_SLOPE" --json "$OUT/analysis.json")
(( LOAD )) && AN_ARGS+=(--max-fd-growth 10)
python3 "$MEMWATCH" analyze "$OUT/rss.csv" "${AN_ARGS[@]}" >"$OUT/analysis.txt" 2>&1
RC=$?
cat "$OUT/analysis.txt"
if [[ -f "$OUT/loadgen.json" ]]; then
    python3 - "$OUT/loadgen.json" <<'EOF' 2>&1 | tee -a "$OUT/analysis.txt"
import json, sys
r = json.load(open(sys.argv[1]))
lat = r.get("latency", {})
print("loadgen: in %.0f ev/s, out %.0f ev/s, sent %s, expected %s, received %s, lost %s (%.4f %%), disconnects %s, "
      "latency p50 %.1f ms p99 %.1f ms max %.1f ms" % (
          r.get("in_rate", 0), r.get("out_rate", 0), r.get("sent"), r.get("expected"), r.get("received"),
          r.get("lost"), 100 * r.get("loss_ratio", 0), r.get("disconnects"),
          lat.get("p50_ms", 0), lat.get("p99_ms", 0), lat.get("max_ms", 0)))
EOF
fi

ARCHIVE="$OUT.tar.gz"
tar -czf "$ARCHIVE" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>/dev/null
[[ -n "${SUDO_USER:-}" ]] && chown "$SUDO_USER" "$ARCHIVE" 2>/dev/null
echo
case $RC in
    0) echo "RESULT: PASS" ;;
    1) echo "RESULT: FAIL (see the [FAIL] lines above)" ;;
    *) echo "RESULT: NOT ENOUGH DATA (run longer, or the process was not running)" ;;
esac
echo "Send this file back: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"
exit $RC
