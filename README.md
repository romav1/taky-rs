# taky-rs

A Rust port of [taky](https://github.com/tkuester/taky), a small TAK server for
ATAK, WinTAK and iTAK: a Cursor-on-Target (CoT) router, a Data Package Server and the
`takyctl` admin tool.

taky-rs is a **drop-in replacement** for taky 0.9. It uses the same `taky.conf`, the same
ports, the same CoT protocol, Redis keys, Data Package storage, `cert-db.txt` and
certificates, so you can switch from the Python version without migrating any data.
The few places where it behaves differently on purpose (security and robustness fixes)
are listed in [doc/DEVIATIONS.md](doc/DEVIATIONS.md).

> **Status: 1.0 release candidate.** Feature-complete and tested against the Python
> original. Not yet measured: sustained load and long-run memory use — see
> [Known limitations](#known-limitations).

## Binaries

Every name has an `-rs` suffix, so taky-rs can be installed next to the Python taky.
Command-line flags and subcommands are the same as in the original.

| taky-rs       | Python taky | What it does                                                     |
|---------------|-------------|------------------------------------------------------------------|
| `taky-rs`     | `taky`      | CoT server: TCP 8087 or TLS 8089, optional monitor port, management socket |
| `taky_dps-rs` | `taky_dps`  | Data Package Server (Marti API) on HTTPS 8443 or HTTP 8080        |
| `takyctl-rs`  | `takyctl`   | `setup`, `build_client`, `systemd`, `status`, `kickban`          |

systemd units are named `taky-rs.service`, `taky-rs-cot.service`, `taky-rs-dps.service`.

## Supported platforms

| Platform | Release archive | Notes |
|---|---|---|
| Linux x86_64 | `taky-rs-x86_64-unknown-linux-gnu.tar.gz` | glibc 2.28 or newer (Debian 10+, Ubuntu 18.10+, RHEL 8+) |
| Raspberry Pi, 64-bit OS (Pi 3/4/5, Zero 2 W) | `taky-rs-aarch64-unknown-linux-gnu.tar.gz` | `uname -m` prints `aarch64` |
| Raspberry Pi, 32-bit OS (Pi 2/3/4, Zero 2 W) | `taky-rs-armv7-unknown-linux-gnueabihf.tar.gz` | `uname -m` prints `armv7l` |
| Static (any Linux, also Alpine) | `taky-rs-{x86_64,aarch64,armv7}-unknown-linux-musl*.tar.gz` | no libc dependency |
| Docker | image `taky-rs` for amd64, arm64, arm/v7 | see `packaging/docker/` |

Pi Zero / Pi 1 (ARMv6) are not supported.

## Install from a release

Download the archive for your platform and `SHA256SUMS` from the project's GitHub
Releases page, then:

```sh
sha256sum --ignore-missing -c SHA256SUMS
tar xzf taky-rs-aarch64-unknown-linux-gnu.tar.gz
sudo install -m 0755 aarch64-unknown-linux-gnu/taky-rs \
                     aarch64-unknown-linux-gnu/taky_dps-rs \
                     aarch64-unknown-linux-gnu/takyctl-rs /usr/local/bin/
takyctl-rs --version
```

Put all three binaries in the same directory: `takyctl-rs systemd` then writes their
absolute paths into the service files.

## Build from source

Needs Rust 1.88 or newer (the CI uses 1.97). No OpenSSL is needed; TLS uses rustls.

```sh
cd taky-rs
cargo build --release --locked -p taky-server --bin taky-rs
cargo build --release --locked -p taky-dps    --bin taky_dps-rs
cargo build --release --locked -p takyctl     --bin takyctl-rs
ls target/release/taky-rs target/release/taky_dps-rs target/release/takyctl-rs
```

Building on a Raspberry Pi works but is slow; prefer the release archives.
For cross builds of all targets see `scripts/build-all.sh` (needs `zig` and `cargo-zigbuild`).

## Documentation

- [doc/QUICKSTART.md](doc/QUICKSTART.md) — from zero to a connected ATAK device in ten minutes
- [doc/DEPLOYMENT.md](doc/DEPLOYMENT.md) — system and site installs, systemd, ports, Redis,
  TLS and client certificates, banning users, Raspberry Pi notes
- [doc/DEVIATIONS.md](doc/DEVIATIONS.md) — what behaves differently from the Python taky
- [doc/MIGRATION.md](doc/MIGRATION.md) — switching an existing Python taky server to taky-rs
- `packaging/systemd/` — reference systemd units (what `takyctl-rs systemd --user taky` writes)
- `packaging/docker/` — Docker image and compose example

## Known limitations

- **Load and memory are not measured for 1.0.** The design target is the same as the
  original (about 1000 events/s, about 100 clients, under 128 MB RAM, no memory growth),
  but no load test or 24-hour memory test has been run for this release. Before you
  rely on it in production, watch memory use (`systemctl status taky-rs-cot`, `ps`) for a
  day on your own hardware.
- TLS 1.2 and 1.3 with ECDHE ciphers only. Very old clients that need TLS 1.0/1.1 or RSA
  key exchange cannot connect (current ATAK, WinTAK and iTAK are fine).
- The Python taky and taky-rs cannot **run** at the same time with the same config:
  they use the same ports and management socket. They can be installed side by side.

## Development

```sh
scripts/check.sh   # fmt --check, clippy -D warnings, tests, cargo deny check
```

`cargo deny` is optional locally (`cargo install cargo-deny --locked`); the script skips it
with a warning when it is not installed. See `ARCHITECTURE.md` for the crate layout.

## License

MIT — see `LICENSE`. taky-rs includes the copyright notice of the original taky (MIT).
