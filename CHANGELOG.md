# Changelog

All notable changes to taky-rs are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0-rc.1] - 2026-10-27

First release candidate: a drop-in replacement for the Python taky 0.9 (same `taky.conf`,
ports, CoT protocol, Redis keys, Data Package storage, `cert-db.txt`, certificates and client
data packages). Intentional differences are listed in `doc/DEVIATIONS.md` (D-1..D-30).

### Added
- `taky-rs`: CoT server — TCP or TLS with client certificates, monitor port, management
  socket (`status`, `kickban`), broadcast / GeoChat / `<marti><dest>` routing, persistence in
  memory or Redis, `log_cot`.
- `taky_dps-rs`: Data Package Server — Marti API upload/download/search/metadata,
  public/private packages, KML, video, version; client-certificate authentication.
  Logs `Listening at: https://<bind_ip>:8443` (`http://…:8080` without SSL) at startup.
- `takyctl-rs`: `setup`, `build_client` (ATAK/iTAK data packages, `.p12`), `systemd`,
  `status`, `kickban`, with the original flags and subcommands.
- Release archives `taky-rs-<target>.tar.gz` for x86_64, aarch64 and armv7 (glibc ≥ 2.28 and
  static musl), each with the three binaries, `LICENSE`, `README.md`, `CHANGELOG.md`, `doc/`
  and the reference systemd units in `packaging/systemd/`; `SHA256SUMS`.
- Documentation: `doc/QUICKSTART.md`, `doc/DEPLOYMENT.md`, `doc/MIGRATION.md`,
  `doc/DEVIATIONS.md`.

### Known limitations
- Sustained load and long-run memory use are not measured for this release (see README,
  "Known limitations").
