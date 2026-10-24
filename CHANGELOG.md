# Changelog

All notable changes to taky-rs are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Cargo workspace (`crates/*`): `taky-common`, `taky-config`, `taky-xml`, `taky-cot`, `taky-pki`,
  `taky-server`, `taky-dps`, `takyctl`.
- Stub binaries `taky-rs`, `taky_dps-rs`, `takyctl-rs` with command-line flags matching the
  original taky; `--version` prints `<prog> version 0.1.0`, other commands report "not implemented".
- Public API seams between the core and the server/PKI crates (ARCHITECTURE §14), bodies pending.
- `testkit` feature: injectable clock (`FakeClock`), `TestOutbox`, `HubHandle::settle`,
  `Router::persist_snapshot` / `find_clients`, bindable `start()` for server and DPS.
- `scripts/check.sh` (fmt, clippy `-D warnings`, tests, cargo-deny) and `deny.toml`.
- MIT `LICENSE` including the original taky notice.
