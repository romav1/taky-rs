#!/usr/bin/env bash
# Generate a fresh bench site with test-only PKI, using the original tooling:
#   takyctl setup        -> taky.conf, ssl/ca.{crt,key}, ssl/server.{crt,key,p12}, ssl/cert-db.txt, dp-user/
#   takyctl build_client -> clients/<name>-<uuid>.{crt,key,p12} + clients/<name>.zip (cert-db updated)
# Then applies the bench config overrides. Keys are generated at runtime and never committed.
# Wipes the previous site (the bench must be down; up.sh takes care of that).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
[[ -x "$PY" ]] || die "venv missing, run venv.sh first"

rm -rf "$PYREF_SITE" "$PYREF_CLIENTS"
mkdir -p "$PYREF_STATE" "$PYREF_CLIENTS"

log "takyctl setup -> $PYREF_SITE"
"$PY" -m taky.cli setup --host pyref.local --bind-ip "$PYREF_BIND_IP" \
    --public-ip "$PYREF_BIND_IP" --p12_pw "$PYREF_P12_PW" "$PYREF_SITE" >"$PYREF_STATE/setup.log" 2>&1 \
    || { cat "$PYREF_STATE/setup.log" >&2; die "takyctl setup failed"; }

# Bench overrides (appended sections would duplicate keys, so edit with configparser).
mkdir -p "$PYREF_SITE/cot-log"
"$PY" - "$PYREF_SITE/taky.conf" <<'EOF'
import configparser, sys
path = sys.argv[1]
cfg = configparser.ConfigParser(allow_no_value=True)
cfg.read(path)
cfg.set("cot_server", "log_cot", "./cot-log")
cfg.set("ssl", "client_cert_required", "true")
with open(path, "w", encoding="utf8") as fp:
    cfg.write(fp)
EOF

for name in $PYREF_CLIENT_NAMES; do
    log "takyctl build_client $name"
    (cd "$PYREF_CLIENTS" && "$PY" -m taky.cli -c "$PYREF_SITE/taky.conf" build_client \
        --p12_pw "$PYREF_P12_PW" --dump_pem "$name") >>"$PYREF_STATE/setup.log" 2>&1 \
        || { cat "$PYREF_STATE/setup.log" >&2; die "build_client $name failed"; }
    crt=$(ls "$PYREF_CLIENTS"/"$name"-*.crt)
    ln -sf "$(basename "$crt")" "$PYREF_CLIENTS/$name.crt"
    ln -sf "$(basename "${crt%.crt}.key")" "$PYREF_CLIENTS/$name.key"
done
log "PKI ready: $(wc -l <"$PYREF_SITE/ssl/cert-db.txt") cert-db entries"
