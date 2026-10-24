#!/usr/bin/env bash
# Stop the Python taky reference bench (SIGTERM to each process group, SIGKILL after 10 s).
#   down.sh          stop processes, keep site/logs for inspection
#   down.sh --purge  also delete the generated state except the venv
#   down.sh --all    delete everything under .state (including the venv)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

stop() {
    local name="$1" f="$PYREF_RUN/$1.pid" pgid i
    [[ -f "$f" ]] || return 0
    pgid=$(cat "$f")
    if kill -0 -- "-$pgid" 2>/dev/null; then
        kill -TERM -- "-$pgid" 2>/dev/null || true
        for ((i = 0; i < 100; i++)); do
            kill -0 -- "-$pgid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 -- "-$pgid" 2>/dev/null; then
            log "$name did not stop on SIGTERM, sending SIGKILL"
            kill -KILL -- "-$pgid" 2>/dev/null || true
        fi
        log "stopped $name (pgid $pgid)"
    fi
    rm -f "$f"
}

stop taky_dps
stop taky
rm -f "$PYREF_SITE/taky-mgmt.sock"

case "${1:-}" in
    --purge) rm -rf "$PYREF_SITE" "$PYREF_CLIENTS" "$PYREF_RUN" "$PYREF_STATE/setup.log"; log "state purged (venv kept)" ;;
    --all) rm -rf "$PYREF_STATE"; log "state purged (including venv)" ;;
    "") ;;
    *) die "unknown option: $1" ;;
esac
log "bench DOWN"
