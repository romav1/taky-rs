# taky-rs in Docker

| File | What |
|---|---|
| `Dockerfile` | The `taky-rs` image (linux/amd64, linux/arm64, linux/arm/v7), built by `.github/workflows/docker.yml` from the static musl binaries |
| `compose.yaml` | CoT server + Data Package Server + Redis, with named volumes |

The image is published as `ghcr.io/<owner>/taky-rs:<version>` on release tags (`v1.0.0` →
`1.0.0` and `1.0`; a pre-release such as `v1.0.0-rc.1` → only `1.0.0-rc.1`). Use an exact
version. It contains `taky-rs`, `taky_dps-rs` and `takyctl-rs` in `/usr/local/bin`, has no
shell, and runs as the non-root user `65532:65532` (`nonroot`). The default command is
`taky-rs`; the other two are given as the command.

| Volume (compose name) | Mounted at | Contents |
|---|---|---|
| `taky-rs-etc` | `/etc/taky` | `taky.conf`, `ssl/` (CA key, server certificate, `cert-db.txt`) |
| `taky-rs-var` | `/var/taky` | `taky-mgmt.sock`, `dp-user/` (uploaded data packages); working directory |
| `taky-rs-redis` | `/data` (redis) | Redis snapshot |

Ports published on the host: **8089/tcp** (CoT over TLS) and **8443/tcp** (Data Package
Server). Open both in the firewall. Redis is not published.

## First run

Run these in the directory that holds `compose.yaml`.

1. Choose the image:

   ```sh
   echo 'TAKY_RS_IMAGE=ghcr.io/<owner>/taky-rs:1.0.0' > .env
   ```

2. Create the configuration and certificates in the volumes (a system install, see
   `doc/DEPLOYMENT.md`):

   ```sh
   docker compose run --rm --no-deps taky-rs \
     takyctl-rs setup --host myserver --public-ip 203.0.113.10
   ```

   - `--public-ip` is the address **clients** use to reach the Docker host, not the
     container's address. It is written into every client package.
   - Always give `--host`: without it the name of the one-off container (a random ID)
     becomes the server certificate name and the Redis key prefix.
   - `--user` is not needed: everything is created as `65532:65532` already.
   - `setup` refuses to run twice. To start again, `docker compose down -v` (deletes all
     data, including the CA).

3. Optional, use Redis (keeps persisted map items over restarts): replace the bare
   `redis` line in `[taky]`. The image has no shell or editor, so use a helper container
   **as the same user**:

   ```sh
   docker run --rm --user 65532:65532 -v taky-rs-etc:/etc/taky busybox:1.36.1-musl \
     sed -i 's|^redis$|redis = redis://redis:6379/0|' /etc/taky/taky.conf
   ```

   Other edits work the same way (`... busybox:1.36.1-musl vi /etc/taky/taky.conf` with
   `-it`). Restart the services after any change.

4. Start:

   ```sh
   docker compose up -d
   docker compose ps          # taky-rs should become "healthy"
   docker compose logs taky-dps-rs   # INFO:taky.dps:Listening at: https://0.0.0.0:8443
   ```

The `taky-rs` healthcheck runs `takyctl-rs status` against the management socket. The DPS has
no healthcheck (no HTTP client in the image, and it needs a client certificate).

## Client packages (`build_client`)

`build_client` writes `<NAME>.zip` into its working directory, `/var/taky`:

```sh
docker compose exec taky-rs takyctl-rs build_client JENNY      # --is_itak for iTAK
docker compose cp taky-rs:/var/taky/JENNY.zip .
docker run --rm --user 65532:65532 -v taky-rs-var:/var/taky busybox:1.36.1-musl \
  rm /var/taky/JENNY.zip
```

The zip contains the client's private key: hand it over privately, then delete it from the
volume (last command). Other admin commands:

```sh
docker compose exec taky-rs takyctl-rs status
docker compose exec taky-rs takyctl-rs kickban JENNY
```

`takyctl-rs systemd` is not used with Docker; `restart: unless-stopped` starts the services
with the Docker daemon.

## Upgrade

Config, certificates and data stay in the volumes.

```sh
sed -i 's|^TAKY_RS_IMAGE=.*|TAKY_RS_IMAGE=ghcr.io/<owner>/taky-rs:1.0.1|' .env
docker compose pull
docker compose up -d
```

To roll back, put the previous version back into `.env` and run `docker compose up -d`.
Read `CHANGELOG.md` before upgrading.

## Backup and restore

Back up all three volumes while the services are stopped. The archive contains the CA key:
keep it private.

```sh
docker compose stop
docker run --rm -v taky-rs-etc:/etc/taky:ro -v taky-rs-var:/var/taky:ro \
  -v taky-rs-redis:/data:ro -v "$PWD":/backup busybox:1.36.1-musl \
  sh -c 'umask 077; tar -czf /backup/taky-rs-backup.tar.gz -C / etc/taky var/taky data'
docker compose start
```

Restore into empty volumes (for example on a new host; this replaces steps 2 and 3 of the
first run):

```sh
docker compose create      # creates the volumes, starts nothing
docker run --rm -v taky-rs-etc:/etc/taky -v taky-rs-var:/var/taky -v taky-rs-redis:/data \
  -v "$PWD":/backup:ro busybox:1.36.1-musl tar -xzf /backup/taky-rs-backup.tar.gz -C /
docker compose up -d
```

The archive keeps the numeric owners (`65532` for taky-rs, the image's `redis` user for
`/data`).

## Notes

- **Bind mounts instead of volumes**: create the directories owned by the image user, e.g.
  `sudo install -d -o 65532 -g 65532 -m 0750 /srv/taky/etc /srv/taky/var`, and replace
  `etc:` / `var:` in `compose.yaml` with those paths. A named volume gets this ownership
  from the image automatically; a bind mount does not. With rootless Docker or
  `userns-remap` the host owner is the mapped UID.
- **Existing taky (Python) data**: copy the old `/etc/taky` and `/var/taky/dp-user` into
  the volumes with the busybox helper and `chown -R 65532:65532`. The paths inside
  `taky.conf` must point to `/etc/taky/...` and `/var/taky/...`.
- **`log_cot`**: the CoT container has a read-only root file system; put the log directory
  under `/var/taky`.
- **No TLS** (`setup --no-ssl`, testing only): the ports become 8087 (CoT) and 8080 (DPS);
  change `ports:` accordingly.
- Logs go to `docker compose logs`; to change the level edit `command:` (`-l debug`).
