#!/usr/bin/env bash
# Smoke test against a running bench (up.sh): CoT broadcast between two TLS clients, mgmt ping, DPS version.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
pid_alive taky && pid_alive taky_dps || die "bench is not running, run up.sh first"
"$PY" -I "$PYREF_DIR/smoke.py" "$PYREF_STATE" "$PYREF_BIND_IP" "$PYREF_COT_PORT" "$PYREF_DPS_PORT"
pid_alive taky || die "taky died during the smoke test (see $PYREF_RUN/taky.log)"
