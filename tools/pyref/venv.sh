#!/usr/bin/env bash
# Create (or reuse) the reference venv from requirements.lock.
# Re-created only when the lock file changes (stamp = copy of the lock inside the venv).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

stamp="$PYREF_VENV/.pyref-lock"
if [[ -x "$PY" && -f "$stamp" ]] && cmp -s "$stamp" "$PYREF_DIR/requirements.lock"; then
    log "venv up to date: $PYREF_VENV"
    exit 0
fi

log "creating venv: $PYREF_VENV"
rm -rf "$PYREF_VENV"
mkdir -p "$(dirname "$PYREF_VENV")"
python3 -m venv "$PYREF_VENV"
"$PY" -m pip install -q --disable-pip-version-check -r "$PYREF_DIR/requirements.lock"
cp "$PYREF_DIR/requirements.lock" "$stamp"
"$PY" -c "import lxml.etree as e, flask, cryptography, sys; print('[pyref] python', sys.version.split()[0], 'lxml', e.__version__, 'libxml2', e.LIBXML_VERSION, 'flask', flask.__version__ if hasattr(flask,'__version__') else '?', 'cryptography', cryptography.__version__)" >&2
