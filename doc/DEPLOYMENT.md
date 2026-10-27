# Deploying taky-rs

This guide covers a production install of taky-rs: where files live, how to run it under
systemd as a non-root user, ports, Redis, the Data Package Server, TLS and client
certificates, banning users, and notes for the Raspberry Pi. For a ten-minute walkthrough
see [QUICKSTART.md](QUICKSTART.md). Moving an existing Python taky server over is covered in
[MIGRATION.md](MIGRATION.md).

## Contents

1. [What runs](#what-runs)
2. [Install the binaries](#install-the-binaries)
3. [Choose a layout: system or site](#choose-a-layout-system-or-site)
4. [Configuration file](#configuration-file)
5. [Run as a non-root user](#run-as-a-non-root-user)
6. [systemd services](#systemd-services)
7. [Ports and firewall](#ports-and-firewall)
8. [Redis (persistent map items)](#redis-persistent-map-items)
9. [Data Package Server](#data-package-server)
10. [TLS and client certificates](#tls-and-client-certificates)
11. [Banning a user (kickban)](#banning-a-user-kickban)
12. [Status, logs and the CoT log](#status-logs-and-the-cot-log)
13. [Docker](#docker)
14. [Raspberry Pi notes](#raspberry-pi-notes)
15. [Backups](#backups)
16. [Known limitations](#known-limitations)

## What runs

| Process | Binary | Default port | Purpose |
|---|---|---|---|
| CoT server | `taky-rs` | 8089 TLS (8087 without TLS) | Routes position reports, chat, markers between clients |
| Data Package Server | `taky_dps-rs` | 8443 HTTPS (8080 without TLS) | File and data-package sharing (Marti API) |
| Admin tool | `takyctl-rs` | — | Creates config and certificates, systemd units, shows status, bans users |

The two servers are independent processes that read the same `taky.conf`. The DPS is
optional (`takyctl-rs systemd --no-dps`), but ATAK's file sharing needs it.

## Install the binaries

From a release archive (see the platform table in the [README](../README.md#supported-platforms)):

```sh
sha256sum --ignore-missing -c SHA256SUMS
tar xzf taky-rs-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 x86_64-unknown-linux-gnu/taky-rs \
                     x86_64-unknown-linux-gnu/taky_dps-rs \
                     x86_64-unknown-linux-gnu/takyctl-rs /usr/local/bin/
```

Keep the three binaries in one directory. When `takyctl-rs systemd` finds `taky-rs` and
`taky_dps-rs` next to itself it writes their absolute paths into the units; otherwise it
writes the bare names and systemd must find them in its `PATH`.

Upgrading = replace the binaries and `sudo systemctl restart taky-rs`. Config, certificates
and data stay as they are.

Check the version with `taky-rs --version`, `taky_dps-rs --version`, `takyctl-rs --version`.

## Choose a layout: system or site

`takyctl-rs setup` creates one of two layouts.

**System install** (recommended; needs root): no path argument.

```sh
sudo takyctl-rs setup --host myserver --public-ip 203.0.113.10 --user taky
```

| Path | Contents |
|---|---|
| `/etc/taky/taky.conf` | configuration |
| `/etc/taky/ssl/` | `ca.crt`, `ca.key`, `server.crt`, `server.key`, `server.p12`, `cert-db.txt` |
| `/var/taky/` | runtime directory (`taky-mgmt.sock`) |
| `/var/taky/dp-user/` | uploaded data packages (`meta/` holds their metadata) |

**Site install** (no root needed; several servers per machine): give a directory that does
not exist yet. Everything goes inside it, with relative paths in the config.

```sh
takyctl-rs setup --host team-a --public-ip 203.0.113.10 /srv/team-a
```

```
/srv/team-a/taky.conf
/srv/team-a/ssl/{ca.crt,ca.key,server.crt,server.key,server.p12,cert-db.txt}
/srv/team-a/dp-user/meta/
```

In a site install run every command (`taky-rs`, `taky_dps-rs`, `takyctl-rs build_client`, …)
**from inside that directory**, or pass `-c /srv/team-a/taky.conf`. Two sites on one machine
need different ports (edit `[cot_server] port`). The DPS port is fixed, so two sites can each
run a DPS only with different `bind_ip` addresses.

`setup` options (`takyctl-rs setup --help`):

| Option | Meaning |
|---|---|
| `--public-ip IP` | **required.** Address clients connect to; written into every client package |
| `--host NAME` | server hostname (default: the machine's hostname); certificate name and Redis key prefix |
| `--bind-ip IP` | listen address (default `0.0.0.0`) |
| `--user USER` | `chown` the created files to `USER:USER` (user and group must exist) |
| `--p12_pw PW` | password of `server.p12` (default `atakatak`) |
| `--no-ssl` | plain TCP 8087 / HTTP 8080, no certificates (testing only) |
| `PATH` | site directory; omit for a system install |

`setup` refuses to overwrite an existing config or CA.

## Configuration file

`taky.conf` is the same INI file as the Python taky uses; existing files work unchanged.
Lookup order when no `-c` is given: `./taky.conf` in the current directory, then
`/etc/taky/taky.conf`. Relative paths inside the file are relative to the file's directory.

The keys you are most likely to change:

| Section | Key | Default | Meaning |
|---|---|---|---|
| `[taky]` | `hostname` | `taky.local` | server name; also the Redis key prefix `taky:<hostname>:persist` |
| `[taky]` | `bind_ip` | all IPv4 | listen address of both servers |
| `[taky]` | `public_ip` | — | address put into client packages |
| `[taky]` | `redis` | off | `true` = local Redis; or a URL `redis://host:6379/0` |
| `[taky]` | `root_dir` | `/var/taky` | where `taky-mgmt.sock` is created |
| `[cot_server]` | `port` | 8089 with TLS, else 8087 | CoT port |
| `[cot_server]` | `mon_ip`, `mon_port` | off, 8087 | monitor port (TLS mode only) |
| `[cot_server]` | `log_cot` | off | directory for raw CoT logs |
| `[cot_server]` | `max_persist_ttl` | -1 (off) | cap, in seconds, on how long an item is kept for late joiners |
| `[dp_server]` | `upload_path` | `/var/taky/dp-user` | data package storage |
| `[ssl]` | `enabled` | false | TLS on/off |
| `[ssl]` | `client_cert_required` | True | CoT clients must present a certificate signed by `ca` |
| `[ssl]` | `ca`, `ca_key`, `cert`, `key`, `key_pw`, `server_p12`, `server_p12_pw`, `cert_db` | files under `/etc/taky/ssl/` | certificate files |

A value containing `%` must be written as `%%` (INI interpolation). `takyctl-rs setup`
does this for you. A broken config makes the server exit with code 1 and a one-line
error message.

## Run as a non-root user

Neither server needs root: all default ports are above 1024. Create a system user and let
`setup` give it the files:

```sh
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin taky
sudo takyctl-rs setup --host myserver --public-ip 203.0.113.10 --user taky
```

Run the admin commands that touch the CA or the management socket as that user:

```sh
sudo -u taky takyctl-rs status
sudo -u taky takyctl-rs build_client JENNY      # writes JENNY.zip to the current directory
sudo -u taky takyctl-rs kickban JENNY
```

Private keys (`ca.key`, `server.key`, client `.p12` files) are created with mode 0600.

## systemd services

```sh
sudo takyctl-rs systemd --user taky
```

This writes three units to `/etc/systemd/system`, runs `systemctl daemon-reload`, enables
and starts them:

| System install | Site install (`--host team-a`) | Runs |
|---|---|---|
| `taky-rs.service` | `taky-rs-team-a.service` | umbrella unit; start/stop this one |
| `taky-rs-cot.service` | `taky-rs-team-a-cot.service` | `taky-rs -l "${LOG_LEVEL}"` |
| `taky-rs-dps.service` | `taky-rs-team-a-dps.service` | `taky_dps-rs` |

The mode is chosen from the config path: `/etc/taky/taky.conf` → system units; any other
config → site units with `WorkingDirectory=` set to the site directory. For a site install run
the command from the site directory (or `sudo takyctl-rs -c /srv/team-a/taky.conf systemd --user taky`).

Options (`takyctl-rs systemd --help`):

| Option | Meaning |
|---|---|
| `-u`, `--user USER` | run the services as `USER` (without it they run as root and a warning is printed) |
| `--no-dps` | do not create/start the Data Package Server unit |
| `--no-install` | only write the files; do not reload, enable or start |
| `--path DIR` | write the units to `DIR` instead of `/etc/systemd/system` |

`systemd` refuses to overwrite existing unit files; delete them first to regenerate.

Day-to-day:

```sh
sudo systemctl stop taky-rs          # stops CoT and DPS
sudo systemctl start taky-rs
sudo systemctl restart taky-rs
systemctl status taky-rs-cot taky-rs-dps
```

Environment file: both service units read `/etc/default/taky-rs` (site:
`/etc/default/taky-rs-<host>`) if it exists. Neither `setup` nor `systemd` creates it. Example:

```sh
# /etc/default/taky-rs
LOG_LEVEL=debug          # CoT server log level: debug, info, warning, error, critical
#RUST_LOG=debug          # overrides -l for both servers
```

Python taky units: every `taky-rs*` unit declares `Conflicts=` and `After=` on the Python
`taky*.service` units of the same mode. Starting `taky-rs` therefore stops a running Python
taky first, and the two never fight over the ports.

## Ports and firewall

| Port | Protocol | When | Who connects |
|---|---|---|---|
| 8089 | TCP + TLS | `[ssl] enabled = true` (default after `setup`) | ATAK / WinTAK / iTAK |
| 8087 | TCP | `--no-ssl` | clients, without encryption |
| 8443 | HTTPS | TLS mode | clients (data packages) |
| 8080 | HTTP | `--no-ssl` | clients (data packages) |
| `mon_port` (8087) | TCP | TLS mode **and** `mon_ip` set | local tools that read all traffic |

The DPS port is fixed (8443/8080). Open the ports clients use, for example with ufw:

```sh
sudo ufw allow 8089/tcp
sudo ufw allow 8443/tcp
```

The monitor port is plain TCP without authentication and receives a copy of every event:
bind it to `127.0.0.1` (`mon_ip = 127.0.0.1`) and do not open it in the firewall.

## Redis (persistent map items)

Without Redis, items that late joiners receive (markers, last positions) are kept in memory
and lost on restart. With Redis they survive restarts and can be shared between servers.

```sh
sudo apt install redis-server
```

In `taky.conf`:

```ini
[taky]
redis = true                          # localhost:6379, database 0
#redis = redis://10.0.0.5:6379/1      # or a URL: redis://, rediss://, unix://
```

then `sudo systemctl restart taky-rs`. Keys are `taky:<hostname>:persist:<uid>`, the same as in
the Python taky, so both versions can use the same Redis data.
If Redis goes away, the CoT server keeps routing traffic, logs `Lost connection to redis`
and skips storing items until it logs `Connection to redis restored`.

## Data Package Server

`taky_dps-rs` serves the Marti data-package API that ATAK uses for "Send to server" and
for downloading packages. Files go to `[dp_server] upload_path` (`/var/taky/dp-user`), one
file per package plus a JSON metadata file in `meta/`; the layout is identical to the Python
version.

- TLS mode: clients authenticate with their client certificate. Revoked certificates get
  `403`.
- Plain mode (`--no-ssl`): the server trusts an `X-USER` header only from a reverse proxy on
  the same host (127.0.0.1 / ::1); other requests to protected endpoints get `401`.
- Config path: the `TAKY_CONFIG` environment variable, then `-c`, then the normal lookup.
- It runs as one process (no worker pool) and stops gracefully on SIGTERM.

Quick check from the server:

```sh
curl -k https://127.0.0.1:8443/Marti/api/version
```

prints `taky-rs-<version>`.

## TLS and client certificates

`setup` creates a private CA (`ca.crt`, `ca.key`, valid 10 years), a server certificate
signed by it (valid 2 years, like client certificates), and `cert-db.txt`, the list of issued certificates.

**Client packages** — one per user/device:

```sh
sudo -u taky takyctl-rs build_client JENNY                  # ATAK / WinTAK: JENNY.zip
sudo -u taky takyctl-rs build_client --is_itak JENNY-ITAK   # iTAK: JENNY-ITAK.zip
```

| Option | Meaning |
|---|---|
| `--is_itak` | iTAK package layout instead of ATAK |
| `--p12_pw PW` | password of the client `.p12` (default `atakatak`) |
| `--dump_pem` | also save the client `.p12`, `.crt` and `.key` in the current directory |

The zip holds the client certificate, the server CA and the connection
(`public_ip:port:ssl`). Each call adds a `V` line to `cert-db.txt`. Names must not
contain `/`. The running CoT server and DPS notice new and revoked certificates
without a restart.

**How clients are checked**: with `client_cert_required = True` (default) a CoT client
without a certificate from your CA is rejected during the TLS handshake. A certificate marked
revoked (`R`) in `cert-db.txt` is disconnected.

**TLS versions**: TLS 1.2 and 1.3 with ECDHE. Current ATAK, WinTAK and iTAK work; clients
that only speak TLS 1.0/1.1 or RSA key exchange do not.

**Your own certificate files**: `cert` / `key` may point to any PEM certificate chain and
key (RSA PKCS#1, PKCS#8 or EC). An encrypted key works when `key_pw` is set — in both
servers. The DPS refuses to start if `key =` is empty.

Clients only see the server as `public_ip`, so if the server's public address changes, rebuild
the client packages (or edit the server address on each device).

## Banning a user (kickban)

```sh
sudo -u taky takyctl-rs kickban JENNY
```

```
Revoked certificate SNs for JENNY:
 - 359c39ea1bbc6d7d9aab9f921b57816321b03fb1
```

All certificates issued to the name `JENNY` are marked revoked (`R`) in `cert-db.txt` and
the devices using them are disconnected; they cannot reconnect, and the DPS answers them
with `403`. `-j` prints the result as JSON.

The command talks to the running CoT server over its management socket
(`<root_dir>/taky-mgmt.sock`); if the server is not running it fails with
`ERROR: Unable to connect to mgmt socket`. Use `-U /path/to/taky-mgmt.sock` for a
non-default socket. To let a banned user back in, build a new package for them.

## Status, logs and the CoT log

```sh
sudo -u taky takyctl-rs status        # uptime and connected clients
sudo -u taky takyctl-rs status -j     # the same as JSON
journalctl -u taky-rs-cot -f          # CoT server log
journalctl -u taky-rs-dps -f          # DPS log; one access-log line per request
```

Run by hand (for testing), from the directory with `taky.conf` or with `-c`:

```sh
taky-rs -l debug -c /etc/taky/taky.conf
taky_dps-rs -l debug -c /etc/taky/taky.conf
```

Stop with Ctrl+C. A second `taky-rs` with the same config refuses to start
(`Taky already appears to be running`).

**CoT log**: set `[cot_server] log_cot = /var/taky/cot-log` (the directory must exist and be
writable by `taky`). Every client's traffic is appended to `<uid>-<callsign>.cot`. This grows
without limit — rotate or clean it, especially on an SD card.

## Docker

A multi-arch image (`taky-rs`, linux/amd64, linux/arm64, linux/arm/v7) is built from the
static release binaries. It runs as a non-root user, with volumes for `/etc/taky` and
`/var/taky`. First-run setup, `build_client`, upgrades and a compose file with Redis are
described in `packaging/docker/README.md`.

## Raspberry Pi notes

- **Which archive**: `uname -m` → `aarch64` (64-bit Raspberry Pi OS) uses
  `taky-rs-aarch64-unknown-linux-gnu.tar.gz`; `armv7l` (32-bit OS) uses
  `taky-rs-armv7-unknown-linux-gnueabihf.tar.gz`. Pi Zero / Pi 1 (ARMv6) are not supported.
  If the glibc archive does not start (very old OS), use the `-musl` archive of the same CPU.
- **Clock**: certificates and CoT stale times depend on the correct time. The Pi has no
  real-time clock — keep `systemd-timesyncd` (or chrony) enabled and set up `setup` /
  `build_client` only after the clock is synchronised (`timedatectl` shows
  `System clock synchronized: yes`).
- **SD card**: leave `log_cot` off unless you need it, and keep `upload_path` on reliable
  storage (a USB SSD if users share large files). With Redis, consider its own persistence
  settings; the default snapshots are fine for a small team.
- **Memory**: the servers are single processes with no worker pool; on a Pi 3 or later with
  1 GB RAM there is plenty of headroom for a small team. Load and long-run memory use are not
  measured for 1.0 — see below.
- **Network**: give the Pi a fixed address (DHCP reservation) and use it as `--public-ip`;
  client packages contain that address.
- **Building on the Pi** is possible (`cargo build --release …`, see the README) but takes a
  long time; use the release archives.

## Backups

Back up these, ideally while the services are stopped:

| What | Why |
|---|---|
| `/etc/taky/` (especially `ssl/ca.key` and `ssl/cert-db.txt`) | without the CA key you must re-issue every client package |
| `/var/taky/dp-user/` | uploaded data packages and their metadata |
| Redis dump (`/var/lib/redis/dump.rdb`) | persisted map items, if Redis is used |

`ca.key` is the key to your whole network: keep the backup private.

## Known limitations

- **Not measured for 1.0**: throughput (design target ≥ 1000 events/s with about 100 clients)
  and memory over time (target under 128 MB, no growth). Before relying on taky-rs in
  production, run it for a day on your hardware and watch memory, for example
  `systemctl status taky-rs-cot` (the `Memory:` line) or `ps -o rss,cmd -C taky-rs`.
- TLS 1.2/1.3 with ECDHE only (see above).
- The Python taky and taky-rs cannot run at the same time on one host with the same config
  (same ports and management socket); the systemd units stop the other one for you.
- Differences from the Python taky that you might notice are listed in
  [DEVIATIONS.md](DEVIATIONS.md).
