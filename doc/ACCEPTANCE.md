# taky-rs 1.0 acceptance checklist

This is the form for the final acceptance of taky-rs 1.0 on your own devices and in your own
GitHub account. You do not need to be a developer: every item says what to do and what you
should see. Each item gets one result:

- **PASS** — it worked as described;
- **FAIL** — it did not; write in *Notes* what you saw (an error message, a screenshot name);
- **N-A** — not applicable (for example, you have no iPhone); write why in one word.

Go through the sections in order: **G** (GitHub) first, then **A**–**E** on your devices. The
minimum for acceptance is **G**, **A** (ATAK) and **D** (Raspberry Pi); B, C and E only if you
have those devices. At the end, send the results back as described in
[How to send the results back](#how-to-send-the-results-back).

Commands below come from [QUICKSTART.md](QUICKSTART.md), [MIGRATION.md](MIGRATION.md) and
`packaging/docker/README.md`; look there when a step needs more detail. `203.0.113.10` stands
for your server's address and `JENNY`, `alice`, `bob` for user names — replace them with yours.

## 0. About this test

| Field | Your answer |
|---|---|
| Date(s) of the test | |
| Tested by | |
| taky-rs version (`taky-rs --version`) | |
| GitHub repository and commit / tag tested | |
| Server 1: device, OS, `uname -m` | e.g. Raspberry Pi 4, Raspberry Pi OS 12, `aarch64` |
| Server 2 (if any): device, OS, `uname -m` | |
| Python taky version on the same server (if any) | |
| Client devices (one line each: app + version, phone/PC, OS) | e.g. ATAK-CIV 5.2.0, Pixel 6, Android 14 |

## G. GitHub CI (Actions tab of your repository)

Open your repository on GitHub, then the **Actions** tab. There are three workflows: **ci**,
**docker** and **fuzz**. A green tick means PASS, a red cross means FAIL. To start a workflow
by hand: click its name on the left, then **Run workflow** (top right) → **Run workflow**.

| # | What to do | What you should see | Result | Notes |
|---|---|---|---|---|
| G1 | Open the latest **ci** run of the commit you test (it starts by itself on every push). | All jobs green: `check (fmt, clippy, test, deny)`; `build …` for 6 targets (x86_64, aarch64, armv7; gnu and musl); `cross test aarch64-…` and `cross test armv7-…` (qemu); `smoke …` for 6 targets. The `GitHub release` job is skipped (it runs only for a `v*` tag). | | |
| G2 | In **ci** run of G1, scroll down to **Artifacts**. | 6 artifacts `taky-rs-<target>` (the release archives). Optional: download the one for your Pi and use it in D1. | | |
| G3 | Start **docker** by hand (*Run workflow*). | Jobs `build …` (3 musl targets) and `buildx (amd64, arm64, arm/v7)` green; inside `buildx`, the steps `Smoke test`, `Image layout …` and `Compose smoke test …` green. Nothing is pushed (it pushes only on a `v*` tag). | | |
| G4 | Open the **docker** run of G3 → its **Summary** page (or the step *Base image digests* of the `buildx` job). | Three lines like `busybox:1.36.1-musl@sha256:…`, `gcr.io/distroless/static-debian12:nonroot@sha256:…`, `redis:7.2.7-alpine@sha256:…`. **Copy these three lines exactly and send them** — the team must pin them in the Dockerfile and compose file before the release tag `v1.0.0`. | | |
| G5 | **fuzz** runs every night at 01:17 UTC by itself (or start it by hand). Let it run on **at least 4 nights** (4 runs). | Each run has 9 jobs `fuzz <target>` (`cot_decoder_stream`, `parse_element`, `serialize_roundtrip`, `ini_parse`, `isoparse`, `py_float`, `mgmt_frame`, `secure_filename`, `dps_multipart`), all green, about 1 hour each. | | number of green runs: |
| G6 | In each fuzz run of G5, look at **Artifacts**. | `fuzz-stats-<target>` for every target. If a job is red there is also a `fuzz-crash-<target>`: **download it and send it** (it is the input that broke the parser). | | |
| G7 | *(Only after the team tells you that `v1.0.0` is tagged.)* Open the **ci** and **docker** runs of the tag. | ci: job `GitHub release` green; the **Releases** page of the repository has `v1.0.0` with 6 `.tar.gz` archives and `SHA256SUMS`. docker: green, and the **Packages** page has `taky-rs` with tags `1.0.0` and `1.0`. | | |

## A. ATAK-CIV (Android)

Do this for each ATAK version you use. You need the server set up as in QUICKSTART steps 1–4
(binaries installed, `takyctl-rs setup`, `takyctl-rs systemd`) and **two** devices (A3–A5,
A8). Make two packages: `sudo -u taky takyctl-rs build_client alice` and `… build_client bob`
(run in `/var/taky/clients`, see QUICKSTART step 4).

| # | What to do | What you should see | Result | Notes |
|---|---|---|---|---|
| A1 | Copy `alice.zip` to device 1, import it: menu → *Import* → *Local SD* (or *Import Manager*). | No error on import. *Settings → Network Preferences → TAK Servers* lists `203.0.113.10:8089 (SSL)`; the server icon turns green within a minute. On the server `sudo -u taky takyctl-rs status` shows alice's callsign. | | |
| A2 | *(Only if the Python taky is installed somewhere.)* (a) Make a package with the **Python** `takyctl build_client carol` on the taky-rs server and import it; (b) make a package with `takyctl-rs build_client dave` against a **Python** taky server and import it. | Both connect (green). For (b): restart the Python server after `build_client` (see MIGRATION, *Mixing Python and Rust tools*). | | |
| A3 | Import `bob.zip` on device 2. Look at the map on both devices; then place a marker on device 1. | Each device shows the other with the right callsign and team colour. The marker appears on device 2 within a few seconds. | | |
| A4 | GeoChat: send a message in *All Chat Rooms*; then in your team's chat; then a direct message to the other user. | All Chat Rooms: received. Team chat: received only by users of the same team (if you can, change device 2 to another team and check it does **not** get the team message). Direct: received only by that user. | | |
| A5 | Put device 2 into airplane mode for about 1 minute, then switch it back. | It reconnects by itself; markers placed by device 1 while device 2 was offline (and earlier ones) show up again. | | |
| A6 | On device 1 send a data package to the server (select items → *Send* → *TAK Server*, or *Data Package* → *Upload*). On device 2 open the server's package list (*Import Manager* → *Server* / *TAK Server* search) and download it. | Upload succeeds; the package is listed on device 2 and opens after download. | | |
| A7 | Video: add a video feed on device 1 (Video Player → *+* / alias), share it to the server; sync on device 2. | Device 2 sees the feed in its video list. | | |
| A8 | On the server: `sudo -u taky takyctl-rs kickban alice`. | Device 1 is disconnected at once and cannot reconnect (icon stays red). Device 2 (bob) keeps working. `cat /etc/taky/ssl/cert-db.txt` shows alice's line as revoked (`R`). | | |
| A9 | Leave both devices connected and untouched for at least 30 minutes (screen may be off, app in the foreground or background as you normally use it). | The connection stays green the whole time; no reconnect messages in `journalctl -u taky-rs-cot -e` for these devices. | | |

## B. WinTAK (Windows)

| # | What to do | What you should see | Result | Notes |
|---|---|---|---|---|
| B1 | Make a package `sudo -u taky takyctl-rs build_client WINUSER` and import `WINUSER.zip` into WinTAK (*Import*, or drag the zip onto the map). Alternative: import the `.p12` from the zip as client certificate and the CA (truststore) by hand, password `atakatak`. | The server connection `203.0.113.10:8089` (SSL) appears and connects. | | |
| B2 | Repeat **A3** with WinTAK and one ATAK device. | Both see each other; markers pass both ways. | | |
| B3 | Repeat **A4** (chat). | As in A4. | | |
| B4 | Repeat **A5** (unplug the network or disable Wi-Fi for 1 minute). | As in A5. | | |
| B5 | Repeat **A6** (data package upload / download). | As in A6. | | |

## C. iTAK (iPhone / iPad)

| # | What to do | What you should see | Result | Notes |
|---|---|---|---|---|
| C1 | `sudo -u taky takyctl-rs build_client --is_itak IUSER`, copy `IUSER.zip` to the device, then *Settings → Network → Servers → +* → *Upload Server Package*. | The server is added and connects. | | |
| C2 | Repeat **A3** with iTAK and one ATAK device. | As in A3. | | |
| C3 | Repeat **A4** (chat). | As in A4. | | |
| C4 | Repeat **A6** (data packages), as far as your iTAK version supports it. | As in A6. | | |

## D. Raspberry Pi

Do D1–D3 on each Pi type you have (64-bit OS = `aarch64`, 32-bit OS = `armv7l`; see `uname -m`).

| # | What to do | What you should see | Result | Notes |
|---|---|---|---|---|
| D1 | Install as in QUICKSTART 1–3: unpack the archive for your `uname -m`, `sudo install … /usr/local/bin/`, `takyctl-rs --version`, `sudo takyctl-rs setup --host myserver --public-ip 203.0.113.10 --user taky`, `sudo takyctl-rs systemd --user taky`. Then `systemctl status taky-rs-cot taky-rs-dps`, `ps -o user= -C taky-rs`, `sudo reboot`, and after the reboot `systemctl status taky-rs-cot taky-rs-dps` again. | `--version` prints `takyctl-rs version 1.0.0…`; the units `taky-rs.service`, `taky-rs-cot.service`, `taky-rs-dps.service` are written; both services `active (running)` before **and after** the reboot; `ps` shows the user `taky`, not `root`. `curl -k https://127.0.0.1:8443/Marti/api/version` prints `taky-rs-1.0.0…`. | | |
| D2 | *(Only on a Pi that runs the Python taky.)* Follow MIGRATION.md: *Before you start* (backup, counts), *Switch-over*, *Check the result*. Then the *Rollback to Python* section, check that devices connect to Python again, and switch forward to taky-rs once more. | Devices connect to taky-rs **without new packages**; old markers (with Redis) and uploaded data packages are still there; a user banned before the switch stays banned. After the rollback the Python taky works with the same devices. | | |
| D3 | 24-hour memory check: see [D3 in detail](#d3-in-detail-24-hour-memory-check) below. | The script ends with `RESULT: PASS` and prints the name of an archive `taky-rs-soak-<host>-<date>.tar.gz`. **Send this archive**, also when the result is FAIL. | | RESULT line: |
| D4 | Docker on the Pi (needs Docker with the compose plugin; use the image built in G7, or skip until the tag exists): follow `packaging/docker/README.md` *First run* steps 1–4 (`.env` with the image, `docker compose run --rm --no-deps taky-rs takyctl-rs setup --host myserver --public-ip 203.0.113.10`, `docker compose up -d`, `docker compose ps`). Make a package with `docker compose exec taky-rs takyctl-rs build_client JENNY` + `docker compose cp taky-rs:/var/taky/JENNY.zip .` and connect one device. Then `docker compose down` (without `-v`) and `docker compose up -d` again. | `docker compose ps` shows `taky-rs` as `healthy`; `docker compose logs taky-dps-rs` shows `Listening at: https://0.0.0.0:8443`; `docker compose exec taky-rs takyctl-rs status` works; `docker top` of the containers shows user `65532`, not `root`. The device connects. After `down` / `up -d` the device connects again **with the same package** and an uploaded data package is still there. | | |

### D3 in detail: 24-hour memory check

The script `tools/soak/run-soak.sh` watches the memory and open files of the **running**
taky-rs and taky_dps-rs every 10 seconds, checks them at the end and packs everything into one
archive. It does not start, stop or change taky-rs. The tools are not in the release archive:
take the folders `tools/memwatch` and `tools/soak` from the repository (GitHub: *Code* →
*Download ZIP*, unpack, keep both folders side by side). They need only `python3` (preinstalled
on Raspberry Pi OS).

1. Make sure taky-rs runs (D1 or D2) and, if you can, connect your devices and leave them
   connected for the whole day (normal use is fine — that is the best test).
2. Trial run of 6 minutes, to see that everything works:

   ```sh
   cd <unpacked repository folder>     # the one that contains tools/
   sudo tools/soak/run-soak.sh --hours 0.1
   ```

   It ends with `RESULT: …` and `Send this file back: …tar.gz`. For such a short run the result
   is usually `NOT ENOUGH DATA` or `PASS`; that is fine.
3. The real run, in the background (you can log out and close the terminal):

   ```sh
   sudo tools/soak/run-soak.sh --hours 24 --detach
   ```

   It prints where the progress log is (`tail -f …/run-soak.log`) and how to stop it early
   (`sudo kill <pid>`; the archive is still written). Do not restart taky-rs during these
   24 hours — a restart counts as a FAIL (if it happens anyway, write why in Notes).
4. After 24 hours: `tail …/run-soak.log` shows `RESULT: PASS` or `RESULT: FAIL` and the
   archive name. The archive contains the memory samples (`rss.csv`), the verdict
   (`analysis.txt`), system information and the service log of that day — no keys or
   certificates. Send the archive.

What the verdict checks, for each of the two processes: memory never above **128 MB**; after
the first 30 minutes it grows by at most **1 MB per hour**; at the end it is at most **1.1 ×**
the value after the first hour; the process was not restarted.

*Optional, with synthetic load.* If the team gives you a `loadgen` binary for your machine
(or you have Rust: `cargo build --release` in the loadgen folder), you can add 100 simulated
clients at 300 events/s:

```sh
mkdir lg-pem && cd lg-pem && sudo -u taky takyctl-rs build_client --dump_pem loadgen && rm -f *.p12 *.zip && cd ..
sudo tools/soak/run-soak.sh --hours 24 --detach --load --loadgen ./loadgen --tls --certs ./lg-pem
```

(`build_client` needs a directory the `taky` user can write; if it complains, run the first
line in `/var/taky/clients` and pass that path to `--certs`.) Then revoke that test user:
`sudo -u taky takyctl-rs kickban loadgen`.

*Docker.* The same script works for taky-rs in Docker: run it on the Docker host with `sudo`
(the container processes are visible there as `taky-rs` and `taky_dps-rs`).

## E. x86_64 server (if you have one)

| # | What to do | What you should see | Result | Notes |
|---|---|---|---|---|
| E1 | D1 on the x86_64 server (archive `x86_64-unknown-linux-gnu`). | As in D1. | | |
| E2 | D2 on the x86_64 server (if it runs the Python taky). | As in D2. | | |
| E3 | D3 on the x86_64 server. | As in D3; send the archive. | | RESULT line: |
| E4 | D4 on the x86_64 server (optional). | As in D4. | | |

## How to send the results back

Choose one:

1. **Paste into the chat with pm01**: copy the block below, fill in one line per item and paste
   it. Notes may be in Russian.
2. **As a file**: save a copy of this page with the tables filled in (or the block below in a
   text file `acceptance-results.txt`) and send it in the chat.

In both cases also attach:

- the soak archive(s) `taky-rs-soak-<host>-<date>.tar.gz` from D3 / E3;
- the three digest lines from G4;
- links to the GitHub runs of G1, G3 and G5 (copy the address of each run page), and any
  `fuzz-crash-<target>` artifact from G6;
- for every FAIL: a screenshot or photo of the device, and on the server the output of
  `journalctl -u taky-rs-cot -u taky-rs-dps --since "1 hour ago" > taky-rs-log.txt` (attach the file).

```text
taky-rs acceptance results
date:            tester:
taky-rs version:              repository + commit/tag:
server 1 (device, OS, uname -m):
server 2 (device, OS, uname -m):
clients (app + version, device):

G1  ci workflow green                      :
G2  ci artifacts (6 archives)              :
G3  docker workflow green                  :
G4  base image digests (paste 3 lines)     :
G5  fuzz nightly, number of green runs     :
G6  fuzz artifacts / crashes               :
G7  release v1.0.0 (later)                 :
A1  ATAK import + connect                  :
A2  Python/Rust packages mixed             :
A3  SA + marker between devices            :
A4  GeoChat all / team / direct            :
A5  reconnect after airplane mode          :
A6  data package upload / download         :
A7  video feed                             :
A8  kickban                                :
A9  30 min idle connection                 :
B1  WinTAK import + connect                :
B2  WinTAK SA + markers                    :
B3  WinTAK chat                            :
B4  WinTAK reconnect                       :
B5  WinTAK data packages                   :
C1  iTAK import + connect                  :
C2  iTAK SA + markers                      :
C3  iTAK chat                              :
C4  iTAK data packages                     :
D1  Pi install, systemd, reboot, non-root  :
D2  Pi drop-in switch + rollback           :
D3  Pi 24 h soak (RESULT line)             :
D4  Pi Docker                              :
E1  x86_64 install                         :
E2  x86_64 drop-in                         :
E3  x86_64 24 h soak (RESULT line)         :
E4  x86_64 Docker                          :
```

Write each line as `PASS`, `FAIL: <what you saw>` or `N-A: <why>`.
