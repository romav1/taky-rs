# Shared settings for the Python taky reference bench (sourced, not executed).
# All generated state (venv, site, test-only keys, logs, pids) lives under $PYREF_STATE
# and is git-ignored (tools/pyref/.gitignore). Nothing here writes into taky/ (read-only original).

PYREF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAKYRS_ROOT="$(cd "$PYREF_DIR/../.." && pwd)"
TAKY_SRC="${TAKY_SRC:-$(cd "$TAKYRS_ROOT/../taky" && pwd)}"

PYREF_STATE="${PYREF_STATE:-$PYREF_DIR/.state}"
PYREF_VENV="${PYREF_VENV:-$PYREF_STATE/venv}"
PYREF_SITE="$PYREF_STATE/site"          # takyctl setup output: taky.conf, ssl/, dp-user/
PYREF_CLIENTS="$PYREF_STATE/clients"    # build_client output (--dump_pem)
PYREF_RUN="$PYREF_STATE/run"            # pid files, process logs

PYREF_BIND_IP="${PYREF_BIND_IP:-127.0.0.2}"   # Rust bench uses 127.0.0.3 (test-strategy L3)
PYREF_COT_PORT=8089                           # TLS CoT (takyctl setup default)
PYREF_DPS_PORT=8443                           # TLS DPS (hard-coded in taky_dps)
PYREF_P12_PW="atakatak"                       # test-only password
PYREF_CLIENT_NAMES="${PYREF_CLIENT_NAMES:-pyref-alpha pyref-bravo}"

PY="$PYREF_VENV/bin/python"

export PYTHONDONTWRITEBYTECODE=1   # never write __pycache__ into taky/
export PYTHONPATH="$TAKY_SRC"

log() { printf '[pyref] %s\n' "$*" >&2; }
die() { printf '[pyref] ERROR: %s\n' "$*" >&2; exit 1; }

# wait_port HOST PORT TIMEOUT_S
wait_port() {
    local host="$1" port="$2" timeout="$3" i
    for ((i = 0; i < timeout * 10; i++)); do
        if "$PY" -c "import socket,sys; s=socket.create_connection(('$host',$port),0.5); s.close()" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# pid_alive NAME -> 0 if the process group recorded in run/NAME.pid is alive
pid_alive() {
    local f="$PYREF_RUN/$1.pid"
    [[ -f "$f" ]] && kill -0 -- "-$(cat "$f")" 2>/dev/null
}
