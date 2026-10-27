# Migrating from the Python taky to taky-rs

This guide switches an existing Python taky 0.9 server to taky-rs on the same machine. taky-rs
reads the same `taky.conf`, certificates, `cert-db.txt`, Data Package storage and Redis data,
so **nothing is converted or copied**: you stop the Python services, install three binaries,
create the `taky-rs` systemd units and start them. Devices keep their client packages and
reconnect on their own. Going back to Python is the same steps the other way round.

New installs: see [QUICKSTART.md](QUICKSTART.md) and [DEPLOYMENT.md](DEPLOYMENT.md).

## Contents

1. [What stays the same](#what-stays-the-same)
2. [What changes for the operator](#what-changes-for-the-operator)
3. [Before you start](#before-you-start)
4. [Switch-over](#switch-over)
5. [Check the result](#check-the-result)
6. [Mixing Python and Rust tools](#mixing-python-and-rust-tools)
7. [Rollback to Python](#rollback-to-python)
8. [Recommended checks before production](#recommended-checks-before-production)

## What stays the same

| Item | Where (system install) | After the switch |
|---|---|---|
| Configuration | `/etc/taky/taky.conf` | read unchanged, same keys and lookup (`./taky.conf`, then `/etc/taky/taky.conf`) |
| CA, server certificate, `server.p12` | `/etc/taky/ssl/` | used as they are |
| Issued and revoked clients | `/etc/taky/ssl/cert-db.txt` | read as is; new lines in the same format |
| Client packages on devices | ATAK / WinTAK / iTAK | keep working, no re-import |
| Uploaded data packages + metadata | `/var/taky/dp-user/`, `meta/` | served unchanged; new uploads in the same layout |
| Persisted map items | Redis keys `taky:<hostname>:persist:<uid>` | replayed to clients as before |
| Ports | 8089 (TLS) / 8087, DPS 8443 / 8080 | the same |
| Management socket | `/var/taky/taky-mgmt.sock` | the same path and protocol |

A site install (`/srv/team-a/taky.conf` with relative paths) works the same way: taky-rs uses
the site directory as it is.

## What changes for the operator

| | Python taky 0.9 | taky-rs |
|---|---|---|
| Binaries | `taky`, `taky_dps`, `takyctl` | `taky-rs`, `taky_dps-rs`, `takyctl-rs` (same options and subcommands) |
| System units | `taky.service`, `taky-cot.service`, `taky-dps.service` | `taky-rs.service`, `taky-rs-cot.service`, `taky-rs-dps.service` |
| Site units (`hostname = team-a`) | `taky-team-a[-cot\|-dps].service` | `taky-rs-team-a[-cot\|-dps].service` |
| Environment file | `/etc/default/taky[-<host>]`, CoT unit only | `/etc/default/taky-rs[-<host>]`, CoT and DPS units |
| DPS | gunicorn, `2 × CPUs + 1` worker processes | one `taky_dps-rs` process (D-6) |
| Version string | `taky v…` | `taky-rs v…` in the log, `taky-rs-<version>` from `/Marti/api/version` |
| `cert-db.txt` changes | Python CoT server reads it at start, Python DPS on its first request | picked up by both running servers without a restart (D-11) |
| Lock file | — | `cert-db.txt.lock` (empty) appears next to `cert-db.txt` on the first write |
| New cert-db dates | local time | real UTC (D-18): with a non-UTC time zone new lines look shifted by your UTC offset |
| `takyctl systemd` | fails in 0.9 (`TypeError`, D-16) | works and detects system vs site install |
| TLS | whatever the host's Python/OpenSSL allows | TLS 1.2/1.3 with ECDHE only |

Behaviour differences you might notice in daily use are listed, one line each, in
[DEVIATIONS.md](DEVIATIONS.md). The ones most likely to matter on switch-over:

- **D-21** — plain-HTTP DPS behind a reverse proxy: `X-USER` is trusted only from a proxy on the
  same host (127.0.0.1/::1). A proxy on another machine gets `401`.
- **D-25** — `build_client` refuses names with `/`.
- **D-19** — new client `.p12` and key files are mode 0600.
- **D-13** — a broken config gives a one-line error instead of a traceback.
- Very old clients that only speak TLS 1.0/1.1 or RSA key exchange cannot connect.

## Before you start

1. **Find the config the Python server uses.** System install: `/etc/taky/taky.conf`. Site
   install: the `taky.conf` in the directory the units use as `WorkingDirectory=`.

2. **Find the Python units.** taky 0.9's own `takyctl systemd` fails, so your units may have
   been written by hand or by an older taky and can have other names. List them:

   ```sh
   systemctl list-unit-files 'taky*'
   systemctl list-units --all 'taky*'
   ```

   The taky-rs units automatically stop **only** the default Python names
   (`taky.service`, `taky-cot.service`, `taky-dps.service`, or `taky-<host>*.service` for a
   site). Write down any other name: you stop and disable it yourself in step 1 of the
   switch-over. (If a Python *site* has `hostname = rs`, its unit is `taky-rs.service`, the
   same name as the taky-rs system unit: rename one of them first.)

3. **Check the service user and ownership.** taky-rs must be able to write `cert-db.txt`
   **and create `cert-db.txt.lock` in the same directory**:

   ```sh
   grep -h '^User=' /etc/systemd/system/taky*.service
   ls -ld /etc/taky/ssl /var/taky /var/taky/dp-user
   ls -l /etc/taky/ssl/cert-db.txt
   ```

   The directories should belong to the service user (`takyctl setup --user taky` does this).

4. **Note the Python environment file**, if any: `/etc/default/taky` (site:
   `/etc/default/taky-<host>`). taky-rs reads `/etc/default/taky-rs[-<host>]` instead.

5. **Redis** (only if `[taky] redis` is set): count the stored items, to compare after the
   switch. Use the same server and database as in `taky.conf` (`redis-cli -u redis://host:6379/0`
   for a URL):

   ```sh
   redis-cli --scan --pattern 'taky:*:persist:*' | wc -l
   ```

6. **Back up** `/etc/taky/`, `/var/taky/` and the Redis dump, as in
   [DEPLOYMENT.md — Backups](DEPLOYMENT.md#backups). Nothing is converted, but a backup makes
   any rollback trivial.

7. **Plan a short outage.** Clients disconnect when the Python server stops and reconnect to
   taky-rs a few seconds later.

## Switch-over

The commands below are for a system install with the service user `taky`. Site install
differences are noted after each step.

**1. Stop and disable the Python services**

```sh
sudo systemctl disable --now taky.service taky-cot.service taky-dps.service
```

Add any other Python unit names you found. Site install: `taky-team-a.service
taky-team-a-cot.service taky-team-a-dps.service`. Leave the Python package installed for
now — you need it for a rollback.

Make sure nothing is left running (no output expected):

```sh
pgrep -af 'taky'
```

**2. Install the binaries**

```sh
sha256sum --ignore-missing -c SHA256SUMS
tar xzf taky-rs-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 x86_64-unknown-linux-gnu/taky-rs \
                     x86_64-unknown-linux-gnu/taky_dps-rs \
                     x86_64-unknown-linux-gnu/takyctl-rs /usr/local/bin/
takyctl-rs --version
```

Pick the archive for your CPU as in [DEPLOYMENT.md — Install the binaries](DEPLOYMENT.md#install-the-binaries)
(Raspberry Pi: `aarch64` or `armv7`).

**3. Carry over the environment file** (only if the Python one exists)

```sh
sudo cp -n /etc/default/taky /etc/default/taky-rs
```

Site install: `sudo cp -n /etc/default/taky-team-a /etc/default/taky-rs-team-a`.
`LOG_LEVEL` means the same; Python-only settings in it have no effect.

**4. Create and start the taky-rs units**

Run it from a directory that has **no** `taky.conf` (a `./taky.conf` would be used first):

```sh
cd /
sudo takyctl-rs systemd --user taky
```

```
Building systemd services
 - Detected system-wide site install
 - Writing services to /etc/systemd/system
   - Writing taky-rs-cot.service
   - Writing taky-rs-dps.service
   - Writing taky-rs.service
 - Reloading systemctl services
 - Enabling service
 - Starting service
```

Site install: `sudo takyctl-rs -c /srv/team-a/taky.conf systemd --user taky` (or run it
from inside the site directory); it prints `Detected site install` and writes
`taky-rs-team-a*.service` with `WorkingDirectory=/srv/team-a`.

Use the same `--user` as the Python units (step 3 of the pre-checks); add `--no-dps` if you
did not run the Python DPS. To look at the units before installing them:
`mkdir /tmp/units && takyctl-rs systemd --user taky --no-install --path /tmp/units`
(the directory must exist).

Each `taky-rs*` unit has `Conflicts=` and `After=` on the default Python units, so even if a
Python unit was left enabled, starting taky-rs stops it first.

## Check the result

```sh
systemctl status taky-rs-cot taky-rs-dps
journalctl -u taky-rs-cot -b | head -20
sudo -u taky takyctl-rs status
curl -k https://127.0.0.1:8443/Marti/api/version        # prints taky-rs-<version>
```

In the CoT log look for:

- `Loading config file from /etc/taky/taky.conf` — the same config as before;
- `Listening for ssl on <bind_ip>:8089` and `Management socket at /var/taky/taky-mgmt.sock`;
- with Redis: `Tracking N items` — N should match the count from the pre-checks (items that
  expired in the meantime are gone in both versions).

Then, on devices:

- existing devices reconnect without changes and see the persisted markers again;
- chat and positions pass between two devices;
- a data package shared before the switch can be downloaded; a new one can be uploaded;
- `sudo -u taky takyctl-rs build_client TEST` produces a package that connects;
- a user banned before the switch stays banned.

The data tree is not rewritten: after the switch the only changes are new lines in
`cert-db.txt`, the new `cert-db.txt.lock` and new uploads.

## Mixing Python and Rust tools

**One server per config.** The Python taky and taky-rs cannot run at the same time on the
same config (same ports and management socket). A second taky-rs refuses with
`Taky already appears to be running via /var/taky/taky-mgmt.sock`. The `Conflicts=` lines
cover the default unit names only.

**Python `takyctl` against a running taky-rs** works (same files, same socket protocol):
`build_client`, `status` and `kickban` give the same results. The Python tool does not take
the `cert-db.txt` lock, so do not run a Python `takyctl build_client` at the same moment as a
`kickban`; prefer `takyctl-rs` once you have switched.

**`takyctl-rs` against a running Python server** (for example after a rollback) has the
limits of the Python server, not of taky-rs:

- the Python CoT server reads `cert-db.txt` once, at start (the Python DPS on its first
  request). A ban written by `takyctl-rs` or by taky-rs takes effect on a running Python
  server only after `systemctl restart taky`;
- a `kickban` executed by a **running Python server** writes back the copy it read at start:
  clients added since then by any `build_client` (Python or Rust) lose their line, and bans
  written by others are undone. After a rollback, restart the Python services after every
  `build_client` and before every `kickban`.

**Shared Redis between a Python and a Rust server** (two hosts, the same `hostname`, so the same
keys): both read and write the same items. A Python server may delete items that taky-rs keeps
(rare XML namespace cases, D-30). Give each server its own `hostname` unless you want them to
share map items.

## Rollback to Python

Everything taky-rs wrote can be read by the Python taky: clients issued by `takyctl-rs` connect,
bans made by taky-rs are respected, uploaded packages are served.

```sh
sudo systemctl disable --now taky-rs.service taky-rs-cot.service taky-rs-dps.service
sudo systemctl enable --now taky.service
```

(Use your own Python unit names; site install: `taky-rs-team-a*.service` and
`taky-team-a.service`.) If the Python services are hand-made, start each one as before.

Optionally remove the taky-rs units:

```sh
sudo rm /etc/systemd/system/taky-rs.service /etc/systemd/system/taky-rs-cot.service \
        /etc/systemd/system/taky-rs-dps.service
sudo systemctl daemon-reload
```

`cert-db.txt.lock` and `/etc/default/taky-rs` can stay; the Python taky ignores them. Read
[Mixing Python and Rust tools](#mixing-python-and-rust-tools) before issuing or banning clients
on the Python server again. To switch forward later, repeat steps 1 and 4 of the switch-over
(`takyctl-rs systemd` refuses to overwrite existing unit files; if you kept them, just run
`sudo systemctl enable --now taky-rs.service`).

## Recommended checks before production

Throughput and long-run memory are **not measured for 1.0** (design targets: ≥ 1000 events/s
with about 100 clients, under 128 MB, no growth). Before the production switch:

1. **Rehearse on a spare machine** (ideally the same hardware, e.g. the Raspberry Pi): restore the
   backup of `/etc/taky` and `/var/taky` to the same paths and run the switch-over there. Point
   `[taky] redis` at a separate Redis database so the rehearsal does not touch the production
   items.
2. **Load**: drive the rehearsal server with the project's load generator (`loadgen`, kept
   by the QA team, not part of the release archive) or with your own client fleet, at the
   number of clients and the message rate you expect.
3. **24 hours of memory**: leave the rehearsal server running with clients connected for at
   least a day and record the memory of both processes, for example every 5 minutes:

   ```sh
   while true; do
     echo "$(date -Is) cot=$(ps -o rss= -C taky-rs) dps=$(ps -o rss= -C taky_dps-rs)"
     sleep 300
   done >> /var/tmp/taky-rs-rss.log
   ```

   Values are in KiB. They should level off after the first hour and stay below 128 MB.
   `systemctl status taky-rs-cot` shows the current value on its `Memory:` line.
4. **Devices**: connect each client type you use (ATAK, WinTAK, iTAK) and go through the
   [Check the result](#check-the-result) list.

Only then switch the production server.
