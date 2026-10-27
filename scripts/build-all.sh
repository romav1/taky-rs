#!/usr/bin/env bash
# Release builds of taky-rs for all ADR-007 targets (local builds and CI share this script).
#
# Usage: scripts/build-all.sh [--strict] [--out DIR] [TARGET...]
#   TARGET   Rust target triple(s); default: all six ADR-007 targets (see ALL_TARGETS).
#   --strict Fail (exit 2) when a target has to be skipped because a tool is missing (CI uses it).
#   --out    Output directory (default: dist/ in the workspace root).
#
# Output per built target:
#   dist/<target>/                         staged archive tree:
#       taky-rs taky_dps-rs takyctl-rs     release binaries (0755)
#       LICENSE README.md CHANGELOG.md
#       doc/*.md                           operator docs (QUICKSTART, DEPLOYMENT, MIGRATION, ...)
#       packaging/systemd/                 reference units taky-rs{,-cot,-dps}.service + README.md
#   dist/taky-rs-<target>.tar.gz           release artifact (ADR-007): the tree above, top-level
#                                          directory <target>/
#   dist/SHA256SUMS                        sha256sum of every dist/taky-rs-*.tar.gz
#   dist/docker/<arch>/...                 (musl targets only: binaries + LICENSE, Docker build
#                                           context, see packaging/docker/Dockerfile;
#                                           arch = amd64|arm64|armv7)
#
# Tools: rustup (with the target installed), and for anything but a plain host build:
#   zig + cargo-zigbuild, e.g. `pip install ziglang cargo-zigbuild`.
# glibc targets are built with the `.2.28` suffix (minimum glibc 2.28, ADR-007).
# Each binary is built in its own cargo invocation (-p), so the taky-pki `gen` feature (rsa) that
# takyctl enables is not unified into taky-rs / taky_dps-rs (review-T-10 N-2).
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

ALL_TARGETS=(
    x86_64-unknown-linux-gnu
    x86_64-unknown-linux-musl
    aarch64-unknown-linux-gnu
    aarch64-unknown-linux-musl
    armv7-unknown-linux-gnueabihf
    armv7-unknown-linux-musleabihf
)
# package:binary (ADR-000 names)
BINARIES=(taky-server:taky-rs taky-dps:taky_dps-rs takyctl:takyctl-rs)
GLIBC_MIN="2.28"
HOST_TARGET="x86_64-unknown-linux-gnu"

STRICT=0
OUT="$ROOT/dist"
TARGETS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --strict) STRICT=1 ;;
        --out) OUT="$(mkdir -p "$2" && cd "$2" && pwd)"; shift ;;
        -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) echo "build-all.sh: unknown option $1" >&2; exit 64 ;;
        *) TARGETS+=("$1") ;;
    esac
    shift
done
[[ ${#TARGETS[@]} -eq 0 ]] && TARGETS=("${ALL_TARGETS[@]}")

say() { printf '==> %s\n' "$*"; }
hint() { printf '    hint: %s\n' "$*"; }

docker_arch() {
    case "$1" in
        x86_64-*-musl) echo amd64 ;;
        aarch64-*-musl) echo arm64 ;;
        armv7-*-musleabihf) echo armv7 ;;
        *) echo "" ;;
    esac
}

# --- tool detection -------------------------------------------------------------------------
have_zigbuild=0
if command -v cargo-zigbuild >/dev/null 2>&1; then
    if command -v zig >/dev/null 2>&1 || python3 -m ziglang version >/dev/null 2>&1; then
        have_zigbuild=1
    fi
fi
installed_targets=""
if command -v rustup >/dev/null 2>&1; then
    installed_targets="$(rustup target list --installed 2>/dev/null || true)"
else
    # No rustup: only the compiler's own host target is available.
    installed_targets="$(rustc -vV | sed -n 's/^host: //p')"
fi

built=()
skipped=()
failed=()

for T in "${TARGETS[@]}"; do
    known=0
    for k in "${ALL_TARGETS[@]}"; do [[ "$k" == "$T" ]] && known=1; done
    if [[ $known -eq 0 ]]; then
        echo "build-all.sh: unsupported target '$T' (supported: ${ALL_TARGETS[*]})" >&2
        exit 64
    fi

    say "target $T"
    if ! grep -qx "$T" <<<"$installed_targets"; then
        echo "    SKIP: Rust standard library for $T is not installed"
        hint "rustup target add $T"
        if [[ $have_zigbuild -eq 0 && "$T" != "$HOST_TARGET" ]]; then
            hint "pip install ziglang cargo-zigbuild   (also needed for $T)"
        fi
        skipped+=("$T"); continue
    fi

    if [[ $have_zigbuild -eq 1 ]]; then
        build_cmd=(cargo zigbuild)
        if [[ "$T" == *-gnu || "$T" == *-gnueabihf ]]; then
            cargo_target="$T.$GLIBC_MIN"
        else
            cargo_target="$T"
        fi
    elif [[ "$T" == "$HOST_TARGET" && "$(uname -m)" == "x86_64" ]]; then
        build_cmd=(cargo build)
        cargo_target="$T"
        echo "    NOTE: zig/cargo-zigbuild not found; plain 'cargo build' for the host target"
        echo "          (minimum glibc is that of this machine, not $GLIBC_MIN)"
        hint "pip install ziglang cargo-zigbuild   # for the glibc $GLIBC_MIN baseline and cross targets"
    else
        echo "    SKIP: cross-compiling $T needs zig and cargo-zigbuild"
        hint "pip install ziglang cargo-zigbuild   (or: cargo install --locked cargo-zigbuild + zig from ziglang.org)"
        skipped+=("$T"); continue
    fi

    ok=1
    for pb in "${BINARIES[@]}"; do
        pkg="${pb%%:*}"; bin="${pb##*:}"
        echo "    ${build_cmd[*]} --release --locked --target $cargo_target -p $pkg --bin $bin"
        if ! "${build_cmd[@]}" --release --locked --target "$cargo_target" -p "$pkg" --bin "$bin"; then
            ok=0; break
        fi
    done
    if [[ $ok -eq 0 ]]; then
        echo "    FAIL: build for $T failed" >&2
        failed+=("$T"); continue
    fi

    # --- stage artifacts ---
    dest="$OUT/$T"
    rm -rf "$dest"; mkdir -p "$dest/doc" "$dest/packaging/systemd"
    for pb in "${BINARIES[@]}"; do
        install -m 0755 "target/$T/release/${pb##*:}" "$dest/"
    done
    install -m 0644 LICENSE README.md CHANGELOG.md "$dest/"
    install -m 0644 doc/*.md "$dest/doc/"
    install -m 0644 packaging/systemd/*.service packaging/systemd/README.md "$dest/packaging/systemd/"
    # Reproducible-ish archive: sorted names, root-owned entries, mtime of the last commit.
    mtime="$(git log -1 --format=%ct 2>/dev/null || date +%s)"
    tar -C "$OUT" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$mtime" \
        -czf "$OUT/taky-rs-$T.tar.gz" "$T"

    arch="$(docker_arch "$T")"
    if [[ -n "$arch" ]]; then
        rm -rf "$OUT/docker/$arch"; mkdir -p "$OUT/docker/$arch"
        for pb in "${BINARIES[@]}"; do cp -p "$dest/${pb##*:}" "$OUT/docker/$arch/"; done
        cp -p "$dest/LICENSE" "$OUT/docker/$arch/"
    fi
    echo "    OK: $dest (+ taky-rs-$T.tar.gz)"
    built+=("$T")
done

if [[ ${#built[@]} -gt 0 ]]; then
    (cd "$OUT" && sha256sum taky-rs-*.tar.gz > SHA256SUMS)
fi

echo
say "summary: built ${#built[@]}, skipped ${#skipped[@]}, failed ${#failed[@]}"
for t in "${built[@]}"; do echo "    built:   $t"; done
for t in "${skipped[@]}"; do echo "    skipped: $t"; done
for t in "${failed[@]}"; do echo "    failed:  $t"; done

[[ ${#failed[@]} -gt 0 ]] && exit 1
[[ $STRICT -eq 1 && ${#skipped[@]} -gt 0 ]] && exit 2
exit 0
