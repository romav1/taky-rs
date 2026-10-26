//! `takyctl-rs systemd` (`cli/systemd_cmd.py`; spec dps-cli-config §7.3, compat 1.4.14).
//!
//! Same flags, messages, checks and order as the original, with the approved differences:
//!
//! * unit names and binaries carry `-rs` (R3): `taky-rs.service`, `taky-rs-cot.service`,
//!   `taky-rs-dps.service` (site: `taky-rs-<hostname>[-cot|-dps].service`), ExecStart
//!   `taky-rs` / `taky_dps-rs`; descriptions say `taky-rs`;
//! * every unit declares `Conflicts=` + `After=` on the Python units of the same mode (G-1:
//!   either-or; `After=` orders the Python stop before the Rust start, so ports are free);
//! * `EnvironmentFile=-/etc/default/taky-rs[-<hostname>]` (G-2), also in the DPS unit;
//! * the mode is decided by the **real** config path (D-16 / OQ-L1): `/etc/taky/taky.conf`
//!   ⇒ system units, otherwise site units with `WorkingDirectory=<config dir>` (Python uses
//!   the `log_cot` value and so never detects system mode, and fails without `log_cot`);
//! * ExecStart: Python uses `<venv>/bin/taky[_dps]` in a virtualenv, else the bare name.
//!   Rust uses the absolute path of the binary when it sits next to `takyctl-rs`, else the
//!   bare name (systemd resolves it in its fixed search path). No extra stdout lines.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use taky_config::{TakyConfig, load_config};

use crate::build_client::printed_config_error;
use crate::cli::SystemdArgs;
use crate::pyerr::os_error;

/// The system-wide config path that selects system mode.
pub const SYSTEM_CONFIG: &str = "/etc/taky/taky.conf";

/// Process-dependent inputs (injected by tests).
#[derive(Debug, Clone)]
pub struct SystemdEnv {
    /// Directory holding `taky-rs` / `taky_dps-rs` candidates (the `takyctl-rs` directory).
    pub bin_dir: Option<PathBuf>,
    /// `systemctl` program (tests use a fake one).
    pub systemctl: PathBuf,
}

impl SystemdEnv {
    /// The running process: `bin_dir` = directory of `current_exe`, `systemctl` from `PATH`.
    pub fn from_process() -> SystemdEnv {
        SystemdEnv {
            bin_dir: std::env::current_exe()
                .ok()
                .and_then(|p| p.canonicalize().ok())
                .and_then(|p| p.parent().map(Path::to_path_buf)),
            systemctl: PathBuf::from("systemctl"),
        }
    }

    /// `<bin_dir>/<name>` when it exists, else the bare `name`.
    fn exec(&self, name: &str) -> String {
        match &self.bin_dir {
            Some(d) if d.join(name).is_file() => d.join(name).to_string_lossy().into_owned(),
            _ => name.to_owned(),
        }
    }
}

/// Unit names of one installation (`svcs` in the original).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitNames {
    /// Umbrella unit.
    pub taky: String,
    /// CoT server unit.
    pub cot: String,
    /// DPS unit.
    pub dps: String,
}

impl UnitNames {
    /// `prefix` = `taky` (Python) or `taky-rs`; `host` = `Some(hostname)` for a site.
    pub fn new(prefix: &str, host: Option<&str>) -> UnitNames {
        let base = match host {
            Some(h) => format!("{prefix}-{h}"),
            None => prefix.to_owned(),
        };
        UnitNames {
            taky: format!("{base}.service"),
            cot: format!("{base}-cot.service"),
            dps: format!("{base}-dps.service"),
        }
    }

    fn all(&self) -> String {
        format!("{} {} {}", self.taky, self.cot, self.dps)
    }
}

/// Everything the unit texts depend on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitPlan {
    /// The `taky-rs*` units written.
    pub names: UnitNames,
    /// The Python units of the same mode (`Conflicts=` / `After=`).
    pub python: UnitNames,
    /// `Some(hostname)` in site mode.
    pub host: Option<String>,
    /// `WorkingDirectory` (site mode only).
    pub site_path: Option<String>,
    /// `User=` (`--user`).
    pub user: Option<String>,
    /// Write and want the DPS unit.
    pub dps: bool,
    /// ExecStart of the CoT unit (binary only).
    pub taky_exec: String,
    /// ExecStart of the DPS unit.
    pub dps_exec: String,
}

fn env_file(host: Option<&str>) -> String {
    match host {
        Some(h) => format!("EnvironmentFile=-/etc/default/taky-rs-{h}"),
        None => "EnvironmentFile=-/etc/default/taky-rs".to_owned(),
    }
}

fn finish(mut lines: Vec<String>) -> String {
    lines.extend(["", "[Install]", "WantedBy=multi-user.target"].map(String::from));
    let mut s = lines.join("\n");
    s.push('\n');
    s
}

impl UnitPlan {
    fn conflicts(&self) -> [String; 2] {
        let py = self.python.all();
        [format!("Conflicts={py}"), format!("After={py}")]
    }

    /// CoT unit text (`write_cot_svc`).
    pub fn cot_unit(&self) -> String {
        let mut l = vec![
            "[Unit]".to_owned(),
            "Description=taky-rs CoT Server".to_owned(),
            format!("PartOf={}", self.names.taky),
        ];
        l.extend(self.conflicts());
        l.extend(
            [
                "",
                "[Service]",
                "Environment=\"LOG_LEVEL=info\"",
                "Restart=always",
                "RestartSec=3",
            ]
            .map(String::from),
        );
        l.push(env_file(self.host.as_deref()));
        if let Some(u) = &self.user {
            l.push(format!("User={u}"));
        }
        if let Some(p) = &self.site_path {
            l.push(format!("WorkingDirectory={p}"));
        }
        l.push(format!(
            "ExecStart={} -l \"${{LOG_LEVEL}}\"",
            self.taky_exec
        ));
        finish(l)
    }

    /// DPS unit text (`write_dps_svc`).
    pub fn dps_unit(&self) -> String {
        let mut l = vec![
            "[Unit]".to_owned(),
            "Description=taky-rs Data Package Server".to_owned(),
            format!("PartOf={}", self.names.taky),
        ];
        l.extend(self.conflicts());
        l.extend(
            [
                "",
                "[Service]",
                "Type=simple",
                "Restart=always",
                "RestartSec=3",
            ]
            .map(String::from),
        );
        l.push(env_file(self.host.as_deref()));
        if let Some(u) = &self.user {
            l.push(format!("User={u}"));
        }
        if let Some(p) = &self.site_path {
            l.push(format!("WorkingDirectory={p}"));
        }
        l.push(format!("ExecStart={}", self.dps_exec));
        finish(l)
    }

    /// Umbrella unit text (`write_uni_svc`).
    pub fn taky_unit(&self) -> String {
        let mut l = vec![
            "[Unit]".to_owned(),
            "Description=taky-rs Server".to_owned(),
            format!("Wants={}", self.names.cot),
        ];
        if self.dps {
            l.push(format!("Wants={}", self.names.dps));
        }
        let [conflicts, after] = self.conflicts();
        l.push(conflicts);
        l.push("After=network.target".to_owned());
        l.push(after);
        l.extend(
            [
                "",
                "[Service]",
                "Type=oneshot",
                "ExecStart=/bin/true",
                "RemainAfterExit=yes",
            ]
            .map(String::from),
        );
        finish(l)
    }
}

/// Runs `systemd`: loads the config (explicit) and calls [`systemd_with`].
pub fn systemd(
    args: &SystemdArgs,
    cfg_file: Option<&Path>,
    env: &SystemdEnv,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    let cfg = match load_config(cfg_file, true) {
        Ok(c) => c,
        Err(e) if printed_config_error(&e) => {
            writeln!(err, "{e}")?;
            return Ok(1);
        }
        Err(e) => return Err(e.into()),
    };
    systemd_with(args, &cfg, env, out, err)
}

/// `systemd()` after `load_config`: returns the exit code; `Err` ⇒ the "failed" path.
pub fn systemd_with(
    args: &SystemdArgs,
    cfg: &TakyConfig,
    env: &SystemdEnv,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    writeln!(out, "Building systemd services")?;

    let cfg_path = cfg
        .cfg_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (host, site_path) = if cfg_path == SYSTEM_CONFIG {
        writeln!(out, " - Detected system-wide site install")?;
        (None, None)
    } else {
        let site = Path::new(&cfg_path)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        // `config.get("taky", "hostname")`: a value-less key reads as None.
        let host = cfg
            .raw()
            .get("taky", "hostname")?
            .unwrap_or_else(|| "None".to_owned());
        writeln!(out, " - Detected site install: {site}")?;
        (Some(host), Some(site))
    };
    let plan = UnitPlan {
        names: UnitNames::new("taky-rs", host.as_deref()),
        python: UnitNames::new("taky", host.as_deref()),
        host,
        site_path,
        user: args.user.clone(),
        dps: args.dps,
        taky_exec: env.exec("taky-rs"),
        dps_exec: env.exec("taky_dps-rs"),
    };

    if args.user.is_none() {
        writeln!(
            err,
            " - WARNING: taky will run as root! It's strongly recommended"
        )?;
        writeln!(err, "            to create a system user for taky!")?;
    }

    let dir = args.path.to_string_lossy().into_owned();
    let unit_path = |name: &str| crate::fsutil::join(&dir, name);
    // Do not overwrite files if they exist (all three, even with --no-dps).
    for name in [&plan.names.taky, &plan.names.cot, &plan.names.dps] {
        let p = unit_path(name);
        if Path::new(&p).exists() {
            writeln!(err, "ERROR: Refusing to overwite service file: {p}")?;
            return Ok(1);
        }
    }

    writeln!(out, " - Writing services to {dir}")?;
    let mut units = vec![(&plan.names.cot, plan.cot_unit())];
    if plan.dps {
        units.push((&plan.names.dps, plan.dps_unit()));
    }
    units.push((&plan.names.taky, plan.taky_unit()));
    for (name, text) in units {
        writeln!(out, "   - Writing {name}")?;
        out.flush()?;
        let p = unit_path(name);
        if let Err(e) = std::fs::write(&p, text) {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                writeln!(
                    err,
                    "ERROR: Unable to write service files to {dir}, permission denied"
                )?;
            } else {
                writeln!(err, "ERROR: {}", os_error(&e, &p))?;
            }
            return Ok(1);
        }
    }

    if args.install {
        let calls: [(&str, Vec<&str>); 3] = [
            (" - Reloading systemctl services", vec!["daemon-reload"]),
            (" - Enabling service", vec!["enable", &plan.names.taky]),
            (" - Starting service", vec!["start", &plan.names.taky]),
        ];
        for (msg, argv) in calls {
            writeln!(out, "{msg}")?;
            out.flush()?;
            // `subprocess.check_output`: stdout captured, stderr inherited.
            let o = Command::new(&env.systemctl)
                .args(&argv)
                .stderr(std::process::Stdio::inherit())
                .output()
                .map_err(|e| os_error(&e, &env.systemctl.to_string_lossy()))?;
            if !o.status.success() {
                let mut cmd = vec![env.systemctl.to_string_lossy().into_owned()];
                cmd.extend(argv.iter().map(|s| (*s).to_owned()));
                let list = cmd
                    .iter()
                    .map(|s| taky_config::error::py_repr(s))
                    .collect::<Vec<_>>()
                    .join(", ");
                let status = match o.status.code() {
                    Some(c) => format!("returned non-zero exit status {c}."),
                    None => "died with a signal.".to_owned(),
                };
                writeln!(
                    out,
                    "ERROR: systemctl calls failed: Command '[{list}]' {status}"
                )?;
                return Ok(1);
            }
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(host: Option<&str>, user: Option<&str>, dps: bool) -> UnitPlan {
        UnitPlan {
            names: UnitNames::new("taky-rs", host),
            python: UnitNames::new("taky", host),
            host: host.map(str::to_owned),
            site_path: host.map(|_| "/srv/site".to_owned()),
            user: user.map(str::to_owned),
            dps,
            taky_exec: "taky-rs".into(),
            dps_exec: "taky_dps-rs".into(),
        }
    }

    #[test]
    fn system_units_golden() {
        let p = plan(None, Some("taky"), true);
        assert_eq!(
            p.cot_unit(),
            "[Unit]\nDescription=taky-rs CoT Server\nPartOf=taky-rs.service\n\
             Conflicts=taky.service taky-cot.service taky-dps.service\n\
             After=taky.service taky-cot.service taky-dps.service\n\n\
             [Service]\nEnvironment=\"LOG_LEVEL=info\"\nRestart=always\nRestartSec=3\n\
             EnvironmentFile=-/etc/default/taky-rs\nUser=taky\n\
             ExecStart=taky-rs -l \"${LOG_LEVEL}\"\n\n[Install]\nWantedBy=multi-user.target\n"
        );
        assert_eq!(
            p.taky_unit(),
            "[Unit]\nDescription=taky-rs Server\nWants=taky-rs-cot.service\n\
             Wants=taky-rs-dps.service\n\
             Conflicts=taky.service taky-cot.service taky-dps.service\n\
             After=network.target\nAfter=taky.service taky-cot.service taky-dps.service\n\n\
             [Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n\n\
             [Install]\nWantedBy=multi-user.target\n"
        );
    }

    #[test]
    fn site_units_golden() {
        let p = plan(Some("srv1"), None, false);
        assert_eq!(
            p.dps_unit(),
            "[Unit]\nDescription=taky-rs Data Package Server\nPartOf=taky-rs-srv1.service\n\
             Conflicts=taky-srv1.service taky-srv1-cot.service taky-srv1-dps.service\n\
             After=taky-srv1.service taky-srv1-cot.service taky-srv1-dps.service\n\n\
             [Service]\nType=simple\nRestart=always\nRestartSec=3\n\
             EnvironmentFile=-/etc/default/taky-rs-srv1\nWorkingDirectory=/srv/site\n\
             ExecStart=taky_dps-rs\n\n[Install]\nWantedBy=multi-user.target\n"
        );
        assert!(!p.taky_unit().contains("Wants=taky-rs-srv1-dps.service"));
        assert!(p.cot_unit().contains(
            "EnvironmentFile=-/etc/default/taky-rs-srv1\nWorkingDirectory=/srv/site\nExecStart="
        ));
    }

    #[test]
    fn exec_prefers_sibling_binary() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("taky-rs"), b"").unwrap();
        let env = SystemdEnv {
            bin_dir: Some(d.path().to_path_buf()),
            systemctl: "systemctl".into(),
        };
        assert_eq!(
            env.exec("taky-rs"),
            d.path().join("taky-rs").to_string_lossy()
        );
        assert_eq!(env.exec("taky_dps-rs"), "taky_dps-rs");
    }
}
