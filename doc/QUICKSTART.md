# taky-rs quickstart

From an empty Linux box (or Raspberry Pi) to an ATAK device on the map, with TLS and
client certificates. This guide assumes:

1. you have `sudo`;
2. the server should not run as root (we create a user `taky`);
3. you want TLS (port 8089) and can copy a file to your devices;
4. nothing else uses ports 8089 and 8443;
5. the server's address that clients will use is `203.0.113.10` — replace it with yours
   (a LAN address such as `192.168.1.50` is fine for a local network).

For the details behind each step see [DEPLOYMENT.md](DEPLOYMENT.md).

## 1. Install the binaries

Pick the archive for your machine (`uname -m`: `x86_64`, `aarch64` or `armv7l`) from the
release page — see the platform table in the [README](../README.md#supported-platforms).
Example for a Raspberry Pi with a 64-bit OS:

```sh
tar xzf taky-rs-aarch64-unknown-linux-gnu.tar.gz
sudo install -m 0755 aarch64-unknown-linux-gnu/taky-rs \
                     aarch64-unknown-linux-gnu/taky_dps-rs \
                     aarch64-unknown-linux-gnu/takyctl-rs /usr/local/bin/
takyctl-rs --version
```

Optional, for map items that survive a restart: `sudo apt install redis-server`.

## 2. Create the config, CA and server certificate

```sh
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin taky
sudo takyctl-rs setup --host myserver --public-ip 203.0.113.10 --user taky
```

Expected output:

```
Installing site to system
 - Wrote /etc/taky/taky.conf
 - Generating certificate authority
 - Initializing certificate database
 - Generating server certificate
 - Changing ownership to taky
```

This writes `/etc/taky/taky.conf`, the CA and server certificate in `/etc/taky/ssl/`,
and the data directory `/var/taky/`, all owned by `taky`. `--public-ip` is required: it is the address that
goes into every client package, so it must be reachable from the devices.

If you installed Redis, enable it now: in `/etc/taky/taky.conf`, section `[taky]`, change
the bare line `redis` to `redis = true`.

## 3. Install and start the services

```sh
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

Check that both servers are up:

```sh
systemctl status taky-rs-cot taky-rs-dps
sudo -u taky takyctl-rs status
```

`status` prints the uptime and a table of connected clients (empty for now).

## 4. Build a client package

Every user needs their own client certificate. `build_client` writes `<NAME>.zip` into the
current directory, so run it as the `taky` user in a directory that user can write:

```sh
sudo -u taky mkdir -p /var/taky/clients
cd /var/taky/clients
sudo -u taky takyctl-rs build_client JENNY                    # ATAK, WinTAK
sudo -u taky takyctl-rs build_client --is_itak JENNY-ITAK     # iTAK
ls -l JENNY.zip JENNY-ITAK.zip
```

The package contains the user's certificate (`.p12`), the server's CA and the connection
settings (`203.0.113.10:8089`, TLS). The default certificate password is `atakatak`
(change it with `--p12_pw`). The running server accepts the new certificate at once; no
restart is needed.

Treat each `.zip` like a password: anyone holding it can connect as that user.

## 5. Import into the device

Copy the zip to the device (USB, a messenger, e-mail, or serve it once on your LAN with
`python3 -m http.server 8000` in `/var/taky/clients` and open
`http://<server-ip>:8000/JENNY.zip` on the phone — stop it with Ctrl+C afterwards).

- **ATAK:** menu → *Import* → *Local SD* (or *Import Manager*), select `JENNY.zip`.
  A server connection to `203.0.113.10:8089` appears under *Settings → Network
  Preferences → TAK Servers* and connects by itself.
- **WinTAK:** *Import* (or drag the zip onto the map) and select `JENNY.zip`.
- **iTAK:** *Settings → Network → Servers → +* → *Upload Server Package*, select
  `JENNY-ITAK.zip`.

## 6. Check the connection

The server icon in ATAK turns green. On the server:

```sh
sudo -u taky takyctl-rs status
```

shows one row per connected device with its callsign. Two devices with packages from the
same server now see each other on the map.

If a device does not connect: make sure ports 8089/tcp and 8443/tcp are open in your
firewall or router (`sudo ufw allow 8089/tcp && sudo ufw allow 8443/tcp`), and look at the
log with `journalctl -u taky-rs-cot -e`.

## Remove a user

```sh
sudo -u taky takyctl-rs kickban JENNY
```

This revokes JENNY's certificate(s) and disconnects the device. The CoT server must be
running. See [DEPLOYMENT.md](DEPLOYMENT.md#banning-a-user-kickban).

## Start over

```sh
sudo systemctl disable --now taky-rs
sudo rm /etc/systemd/system/taky-rs*.service
sudo systemctl daemon-reload
sudo rm -rf /etc/taky /var/taky     # deletes the CA, all certificates and uploaded data
```

Do not run the last line if the Python taky uses the same `/etc/taky` and `/var/taky`.
