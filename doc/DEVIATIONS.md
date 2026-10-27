# Differences from the Python taky

taky-rs keeps everything that clients and stored data depend on: the protocol, `taky.conf`,
Redis keys and values, Data Package storage, `cert-db.txt`, certificates and client packages.
It differs from taky 0.9 only where the original crashes, loses traffic or is insecure.
These 30 differences (D-1..D-30) are approved; each line says what an operator may notice.

Obvious differences not counted below: the `-rs` names of binaries and systemd units, the
version string (`taky-rs-<version>`), and the wording of log and `--help` texts.

| # | Area | What you may notice with taky-rs |
|---|---|---|
| D-1 | DPS video feeds | XML with a DTD or entities (`<!DOCTYPE …>`) is rejected with `400 Malformed XML`; the original could be made to read local files (XXE). |
| D-2 | CoT | A single event larger than 4 MiB disconnects the client; junk that is not an `<event>` is not kept in memory. |
| D-3 | CoT | A client that does not read its data fast enough is disconnected instead of growing server memory without limit; a management request over 1 MiB is dropped. |
| D-4 | Redis | Items are listed with `SCAN` instead of `KEYS` (does not block Redis; same keys). |
| D-5 | Redis | Items are written with one `SETEX` instead of `SET` + `EXPIRE` (same value and TTL). |
| D-6 | DPS | One process instead of a gunicorn pool of `2 × CPUs + 1` workers; less memory, same HTTP behaviour. |
| D-7 | CoT | `taky-rs -d` is accepted but does nothing (no Python debugger). |
| D-8 | CoT | An event without `version` or `how` is not stored and no longer crashes the server later; an ERROR is logged, and the CoT log always gets an error record. |
| D-9 | CoT | An open `takyctl-rs status`/`kickban` connection no longer stops CoT traffic. |
| D-10 | Management socket | A malformed request gets `{"error": "Invalid cmd: None"}` instead of crashing the server. |
| D-11 | Certificates | Both servers pick up changes to `cert-db.txt` (new clients, bans) without a restart; writes are locked, so `build_client` and a `kickban` never overwrite each other. |
| D-12 | CoT log | Log file names cannot escape the `log_cot` directory: `/` and NUL become `_`. |
| D-13 | Config | A bad `taky.conf` or `cert-db.txt` gives a one-line error instead of a Python traceback (exit code still 1). |
| D-14 | Config | `%%` and `%(key)s` work as in normal INI files; a lone `%` is an error. `setup` writes `%` in passwords as `%%`. |
| D-15 | DPS | Requests that crashed the original with `500` get `404 File not found` / `400 Invalid XML document`. |
| D-16 | CLI | `takyctl-rs systemd` works (the original read the wrong config path) and detects the system install. |
| D-17 | CLI | `takyctl-rs status` no longer crashes when all clients are anonymous; the IP column is empty. |
| D-18 | Certificates | Certificate dates are real UTC (the original wrote local time labelled as UTC); identical when the server's time zone is UTC. |
| D-19 | Certificates | Client `.p12` files and key files are created with mode 0600 (the original: 0644 for client `.p12`). |
| D-20 | DPS | An encrypted server key (`[ssl] key_pw`) also works in the DPS. |
| D-21 | DPS, plain HTTP | The `X-USER` header is trusted only from a proxy on the same host (127.0.0.1/::1); other clients get `401`. In TLS mode it is always ignored. |
| D-22 | DPS | An invalid `hash` parameter (path characters, `..`) gets `400 Invalid hash`; the original allowed reading files outside the storage. |
| D-23 | CoT | An unknown XML entity drops only that event; a broken `&` reference disconnects the client instead of leaving a dead connection open. |
| D-24 | Management socket | The error text for an invalid JSON request is worded differently (same reply format). |
| D-25 | CLI | `build_client` refuses a name that contains `/`. |
| D-26 | CoT | A failure writing `cert-db.txt` during `kickban` is logged and the server keeps running; in plain mode an unreadable `cert-db.txt` gives a warning instead of a crash. |
| D-27 | DPS | `[ssl] key =` (empty) stops the DPS at startup instead of failing every TLS connection later. |
| D-28 | CoT | A leftover dangling symlink at `taky-mgmt.sock` is replaced, so `status`/`kickban` keep working. |
| D-29 | CoT | Control characters, NUL or invalid UTF-8 inside XML markup disconnect the client instead of leaving a silently dead connection. |
| D-30 | Redis, DPS video | Events and video feeds whose XML namespace URI libxml2 considers invalid are kept and replayed instead of being dropped. On a Redis database shared with a Python taky, the Python server may still delete such entries. |

Things that look odd but are **kept** on purpose, because clients or data depend on them
(for example the double slash in some DPS URLs, or `Teams` colour quirks), are listed after
the table in `ARCHITECTURE.md` §17.

## References

Decisions: ADR-008 (D-1..D-22), ADR-009 (D-23..D-26), ADR-010 (D-27, D-28), ADR-012
(D-29, D-30). Full technical description of each item: `ARCHITECTURE.md` §17 (same numbering).
