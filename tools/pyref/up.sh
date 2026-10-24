#!/usr/bin/env bash
# Bring up the Python taky reference bench on $PYREF_BIND_IP (default 127.0.0.2):
#   taky     (CoT, TLS)  :8089   mgmt socket: .state/site/taky-mgmt.sock
#   taky_dps (gunicorn)  :8443
# Re-runnable: stops a running bench, regenerates site + test PKI, keeps the venv.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

"$PYREF_DIR/down.sh" >/dev/null 2>&1 || true
"$PYREF_DIR/venv.sh"
"$PYREF_DIR/certs.sh"

mkdir -p "$PYREF_RUN"
conf="$PYREF_SITE/taky.conf"

# start NAME CMD... : own session/process group so down.sh can stop the whole tree
start() {
    local name="$1"; shift
    (cd "$PYREF_SITE" && exec setsid "$@" >"$PYREF_RUN/$name.log" 2>&1 </dev/null) &
    echo $! >"$PYREF_RUN/$name.pid"
    log "started $name (pgid $(cat "$PYREF_RUN/$name.pid"))"
}

start taky "$PY" -m taky.cot -c "$conf" -l info
start taky_dps "$PY" -m taky.dps -c "$conf" -l info

check() {
    local name="$1" port="$2"
    if ! wait_port "$PYREF_BIND_IP" "$port" 30 || ! pid_alive "$name"; then
        tail -n 30 "$PYREF_RUN/$name.log" >&2 || true
        "$PYREF_DIR/down.sh" >/dev/null 2>&1 || true
        die "$name did not come up on $PYREF_BIND_IP:$port"
    fi
    log "$name listening on $PYREF_BIND_IP:$port"
}
check taky "$PYREF_COT_PORT"
check taky_dps "$PYREF_DPS_PORT"
log "bench UP (state: $PYREF_STATE)"
