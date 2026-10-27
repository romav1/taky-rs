# Reference systemd units

These are the units `sudo takyctl-rs systemd --user taky` writes for a **system install**
(`/etc/taky/taky.conf`) when the binaries are in `/usr/local/bin`:

| Unit | Role |
|---|---|
| `taky-rs.service` | umbrella unit; start/stop/enable this one |
| `taky-rs-cot.service` | CoT server (`taky-rs`) |
| `taky-rs-dps.service` | Data Package Server (`taky_dps-rs`) |

Prefer generating them with `takyctl-rs systemd` (it also handles site installs, `--no-dps`
and other binary locations). To install these copies by hand instead:

```sh
sudo install -m 0644 taky-rs.service taky-rs-cot.service taky-rs-dps.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now taky-rs
```

Edit `User=` and the `ExecStart=` paths if your user or install directory differ. Both service
units read the optional `/etc/default/taky-rs`. See `doc/DEPLOYMENT.md`, section
"systemd services".
