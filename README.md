# taky-rs

A Rust port of [taky](https://github.com/tkuester/taky) — a simple TAK server
(Cursor-on-Target router, Data Package Server and the `takyctl` CLI) for ATAK / WinTAK / iTAK.

taky-rs is intended as a **drop-in replacement**: the same `taky.conf`, ports, CoT protocol,
management socket, Redis keys, DPS storage layout, `cert-db.txt` and certificates, so the Python
and Rust versions can work on the same data. Deliberate deviations (security and robustness only)
are listed in `ARCHITECTURE.md` §17.

> **Status:** early skeleton (v0.1.0). The binaries build and parse their command lines,
> but the server functionality is not implemented yet.

## Binaries

| Binary        | Original    | Purpose                                              |
|---------------|-------------|------------------------------------------------------|
| `taky-rs`     | `taky`      | CoT server (TCP/TLS, monitor port, mgmt socket)      |
| `taky_dps-rs` | `taky_dps`  | Data Package Server (Marti API over HTTPS)           |
| `takyctl-rs`  | `takyctl`   | `setup`, `build_client`, `systemd`, `status`, `kickban` |

## Building

Requires Rust 1.88 or newer (edition 2024). No OpenSSL; TLS uses rustls with `ring`.

```sh
cargo build --workspace
cargo run --bin taky-rs -- --version
```

## Checks

```sh
scripts/check.sh   # fmt --check, clippy -D warnings, tests, cargo deny check
```

`cargo deny` is optional locally (`cargo install cargo-deny --locked`); the script prints a
warning and skips it when it is not installed.

## Layout

See `ARCHITECTURE.md` for the crate structure, async model and compatibility notes.

## License

MIT — see `LICENSE`. taky-rs includes the copyright notice of the original taky (MIT).
