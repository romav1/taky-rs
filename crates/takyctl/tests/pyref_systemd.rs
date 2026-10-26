//! S-323: `takyctl-rs systemd` against the ORIGINAL `takyctl systemd` (`tests/pyref/takyctl.py`)
//! in fake unit directories (`--path <tmp>`; `systemctl` is a fake script first on `PATH`, so
//! nothing touches the real `/etc/systemd`).
//!
//! The Python unit texts are transformed by the documented differences only (spec DC §7.3,
//! compat 1.4.14, ADR-008 G-1/G-2, D-16) and must then equal the Rust ones byte for byte:
//! names `taky-rs[-<host>]…` (R3), `Description=taky-rs …`, `Conflicts=` + `After=` on the
//! Python units, `EnvironmentFile=-/etc/default/taky-rs[-<host>]` (also in the DPS unit),
//! ExecStart `taky-rs` / `taky_dps-rs`. Python runs in a virtualenv (absolute ExecStart and two
//! extra stdout lines); Rust uses the absolute path of the sibling binary — both normalised to
//! the bare name. Python needs `log_cot` directly in the site dir to work at all (DC §1.5 bug):
//! without it Python fails and Rust works (D-16). System mode (never reachable in Python) is
//! checked against golden text.
#![allow(clippy::expect_used, clippy::unwrap_used)] // test code

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn find_python() -> Option<PathBuf> {
    let mut cands = Vec::new();
    if let Some(p) = std::env::var_os("TAKY_PYREF_PYTHON") {
        cands.push(PathBuf::from(p));
    }
    cands.push(manifest().join("../../tools/pyref/.state/venv/bin/python"));
    cands.push(PathBuf::from("python3"));
    cands.into_iter().find(|py| {
        Command::new(py)
            .args(["-I", "-B", "-c", "import cryptography, lxml, pkg_resources"])
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

#[derive(Debug, Clone, PartialEq)]
struct Out {
    rc: i32,
    stdout: String,
    stderr: String,
}

struct Env {
    python: PathBuf,
    py_prefix: String,
    rs_bin_dir: String,
}

impl Env {
    fn new() -> Option<Env> {
        let python = find_python()?;
        let o = Command::new(&python)
            .args(["-I", "-c", "import sys; print(sys.prefix)"])
            .output()
            .unwrap();
        let py_prefix = String::from_utf8(o.stdout).unwrap().trim().to_owned();
        let rs_bin_dir = PathBuf::from(env!("CARGO_BIN_EXE_takyctl-rs"))
            .canonicalize()
            .unwrap()
            .parent()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        Some(Env {
            python,
            py_prefix,
            rs_bin_dir,
        })
    }

    fn run(&self, rust: bool, cwd: &Path, path_env: &str, args: &[&str]) -> Out {
        let mut c = if rust {
            Command::new(env!("CARGO_BIN_EXE_takyctl-rs"))
        } else {
            let mut c = Command::new(&self.python);
            c.args(["-I", "-B", "-W", "ignore"])
                .arg(manifest().join("tests/pyref/takyctl.py"))
                .arg(manifest().join("../../../taky"));
            c
        };
        let o = c
            .args(args)
            .current_dir(cwd)
            .env("PATH", path_env)
            .output()
            .unwrap();
        let d = cwd.to_string_lossy();
        let mut stdout = String::from_utf8_lossy(&o.stdout).replace(&*d, "<D>");
        if !rust {
            // Python virtualenv detection lines (no Rust equivalent on stdout).
            stdout = stdout
                .lines()
                .filter(|l| !l.starts_with(" - Detected virtualenv:") && !l.contains("virutalenv"))
                .map(|l| format!("{l}\n"))
                .collect();
        }
        Out {
            rc: o.status.code().unwrap_or(-1),
            stdout,
            stderr: String::from_utf8_lossy(&o.stderr).replace(&*d, "<D>"),
        }
    }

    /// Python unit text → the Rust one, by the documented differences.
    fn py_to_rs(&self, text: &str, host: &str) -> String {
        let py_units =
            format!("taky-{host}.service taky-{host}-cot.service taky-{host}-dps.service");
        let mut out = Vec::new();
        let is_dps = text.contains("Description=taky Data Package Server");
        for l in text.lines() {
            let l = l
                .replace(&format!("{}/bin/taky_dps", self.py_prefix), "taky_dps")
                .replace(&format!("{}/bin/taky", self.py_prefix), "taky");
            let l = match l.as_str() {
                "ExecStart=taky_dps" => "ExecStart=taky_dps-rs".to_owned(),
                l if l.starts_with("ExecStart=taky ") => l.replacen("taky", "taky-rs", 1),
                l if l.starts_with("Description=taky ") => l.replacen("taky", "taky-rs", 1),
                l => l.replace(&format!("taky-{host}"), &format!("taky-rs-{host}")),
            };
            let after_partof = l.starts_with("PartOf=");
            let is_net = l == "After=network.target";
            let restart = l == "RestartSec=3";
            if is_net {
                out.push(format!("Conflicts={py_units}"));
            }
            out.push(l);
            if after_partof {
                out.push(format!("Conflicts={py_units}"));
                out.push(format!("After={py_units}"));
            }
            if is_net {
                out.push(format!("After={py_units}"));
            }
            if restart && is_dps {
                out.push(format!("EnvironmentFile=-/etc/default/taky-rs-{host}"));
            }
        }
        out.join("\n") + "\n"
    }
}

fn unit_files(dir: &Path) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o7777;
            (
                format!("{} {m:o}", p.file_name().unwrap().to_string_lossy()),
                std::fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    v.sort();
    v
}

/// Site `<base>/site/taky.conf` (`hostname = srv1`), optionally with `log_cot = logs`.
fn site(base: &Path, log_cot: bool) {
    std::fs::create_dir_all(base.join("site")).unwrap();
    let log = if log_cot { "log_cot = logs\n" } else { "" };
    std::fs::write(
        base.join("site/taky.conf"),
        format!("[taky]\nhostname = srv1\n\n[cot_server]\n{log}\n[ssl]\nenabled = false\n"),
    )
    .unwrap();
}

/// A fake `systemctl` in `<base>/bin` that appends its argv to `<base>/systemctl.log` and
/// exits with `rc`; returns the `PATH` value.
fn fake_systemctl(base: &Path, rc: i32) -> String {
    let bin = base.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let p = bin.join("systemctl");
    std::fs::write(
        &p,
        format!(
            "#!/bin/sh\necho \"$@\" >> '{}'\nexit {rc}\n",
            base.join("systemctl.log").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    format!("{}:/usr/bin:/bin", bin.display())
}

/// Runs `args` (+ `--path <base>/units`) for Python in `<tmp>/py` and Rust in `<tmp>/rs`.
fn both(
    env: &Env,
    tmp: &Path,
    log_cot: bool,
    sysctl_rc: i32,
    args: &[&str],
) -> [(Out, PathBuf); 2] {
    [false, true].map(|rust| {
        let base = tmp.join(if rust { "rs" } else { "py" });
        site(&base, log_cot);
        std::fs::create_dir_all(base.join("units")).unwrap();
        let path_env = fake_systemctl(&base, sysctl_rc);
        let mut a: Vec<&str> = vec!["-c", "site/taky.conf", "systemd", "--path", "units"];
        a.extend(args);
        (env.run(rust, &base, &path_env, &a), base)
    })
}

#[test]
fn site_units_match_python() {
    let Some(env) = Env::new() else {
        eprintln!("SKIP: no Python with cryptography+lxml");
        return;
    };
    for (args, n_units) in [
        (&["--no-install", "-u", "taky"][..], 3),
        (&["--no-install", "--no-dps"][..], 2),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let [(py, pyb), (rs, rsb)] = both(&env, tmp.path(), true, 0, args);
        assert_eq!(rs.rc, 0, "{rs:?}");
        let rs_out = Out {
            stdout: rs.stdout.replace("taky-rs-srv1", "taky-srv1"),
            ..rs.clone()
        };
        assert_eq!(rs_out, py, "{args:?}");
        let (pu, ru) = (
            unit_files(&pyb.join("units")),
            unit_files(&rsb.join("units")),
        );
        assert_eq!(ru.len(), n_units);
        let expect: Vec<(String, String)> = pu
            .iter()
            .map(|(n, t)| {
                let t = env.py_to_rs(t, "srv1");
                let t = t.replace(&*pyb.to_string_lossy(), "<D>");
                (n.replace("taky-srv1", "taky-rs-srv1"), t)
            })
            .collect();
        let norm: Vec<(String, String)> = ru
            .into_iter()
            .map(|(n, t)| {
                let t = t.replace(&format!("={}/", env.rs_bin_dir), "=");
                (n, t.replace(&*rsb.to_string_lossy(), "<D>"))
            })
            .collect();
        assert_eq!(norm, expect, "{args:?}");
        assert!(norm[0].1.contains("WorkingDirectory=<D>/site\n"));
    }
}

#[test]
fn install_refusal_and_errors_match_python() {
    let Some(env) = Env::new() else {
        eprintln!("SKIP: no Python with cryptography+lxml");
        return;
    };
    let mask = |o: &Out| Out {
        stdout: o.stdout.replace("taky-rs-", "taky-"),
        stderr: o.stderr.replace("taky-rs-", "taky-"),
        ..o.clone()
    };

    // Install: daemon-reload, enable, start of the umbrella unit.
    let tmp = tempfile::tempdir().unwrap();
    let [(py, pyb), (rs, rsb)] = both(&env, tmp.path(), true, 0, &["-u", "taky"]);
    assert_eq!((rs.rc, mask(&rs)), (0, py));
    let log = |b: &Path| std::fs::read_to_string(b.join("systemctl.log")).unwrap();
    assert_eq!(
        log(&pyb),
        "daemon-reload\nenable taky-srv1.service\nstart taky-srv1.service\n"
    );
    assert_eq!(
        log(&rsb),
        "daemon-reload\nenable taky-rs-srv1.service\nstart taky-rs-srv1.service\n"
    );

    // Refusal: units already there (second run).
    let again = [false, true].map(|rust| {
        let b = if rust { &rsb } else { &pyb };
        env.run(
            rust,
            b,
            &fake_systemctl(b, 0),
            &["-c", "site/taky.conf", "systemd", "--path", "units"],
        )
    });
    assert_eq!(again[1].rc, 1);
    assert_eq!(mask(&again[1]), again[0]);
    assert!(
        again[1]
            .stderr
            .ends_with("ERROR: Refusing to overwite service file: units/taky-rs-srv1.service\n")
    );

    // systemctl failure.
    let tmp = tempfile::tempdir().unwrap();
    let [(py, _), (rs, _)] = both(&env, tmp.path(), true, 3, &["-u", "taky"]);
    assert_eq!((rs.rc, mask(&rs)), (1, py));
    assert!(rs.stdout.ends_with(
        "ERROR: systemctl calls failed: Command '['systemctl', 'daemon-reload']' returned non-zero exit status 3.\n"
    ));

    // `--path` is a file: OSError text.
    let tmp = tempfile::tempdir().unwrap();
    let [(py, _), (rs, _)] = [false, true].map(|rust| {
        let base = tmp.path().join(if rust { "rs" } else { "py" });
        site(&base, true);
        std::fs::write(base.join("file"), "").unwrap();
        let o = env.run(
            rust,
            &base,
            "/usr/bin:/bin",
            &[
                "-c",
                "site/taky.conf",
                "systemd",
                "--no-install",
                "--path",
                "file",
                "-u",
                "x",
            ],
        );
        (o, base)
    });
    assert_eq!((rs.rc, mask(&rs)), (1, py));
    assert!(
        rs.stderr
            .ends_with("ERROR: [Errno 20] Not a directory: 'file/taky-rs-srv1-cot.service'\n"),
        "{rs:?}"
    );

    // Missing config (explicit load).
    let tmp = tempfile::tempdir().unwrap();
    let o = [false, true].map(|rust| {
        env.run(
            rust,
            tmp.path(),
            "/usr/bin:/bin",
            &["-c", "nope.conf", "systemd"],
        )
    });
    assert_eq!(o[1], o[0]);
    assert_eq!(
        (o[1].rc, o[1].stderr.as_str()),
        (1, "Config file required, but not present\n")
    );

    // D-16: without log_cot Python fails (cfg_path = None), Rust writes site units.
    let tmp = tempfile::tempdir().unwrap();
    let [(py, _), (rs, rsb)] = both(&env, tmp.path(), false, 0, &["--no-install", "-u", "taky"]);
    assert_eq!(py.rc, 1);
    assert!(py.stderr.starts_with("systemd failed: "), "{py:?}");
    assert_eq!(rs.rc, 0, "{rs:?}");
    assert_eq!(unit_files(&rsb.join("units")).len(), 3);
}

#[test]
fn system_mode_golden() {
    use takyctl::cli::SystemdArgs;
    use takyctl::systemd::{SystemdEnv, systemd_with};
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("taky.conf"), "[taky]\nhostname = srv1\n").unwrap();
    let mut cfg =
        taky_config::load_config_in(Some(Path::new("taky.conf")), true, tmp.path()).unwrap();
    cfg.cfg_path = Some(PathBuf::from("/etc/taky/taky.conf"));
    let units = tmp.path().join("units");
    std::fs::create_dir(&units).unwrap();
    let args = SystemdArgs {
        path: units.clone(),
        install: false,
        dps: true,
        user: Some("taky".into()),
    };
    let env = SystemdEnv {
        bin_dir: None,
        systemctl: "/nonexistent/systemctl".into(),
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(
        systemd_with(&args, &cfg, &env, &mut out, &mut err).unwrap(),
        0
    );
    let u = units.display();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        format!(
            "Building systemd services\n - Detected system-wide site install\n - Writing services to {u}\n   - Writing taky-rs-cot.service\n   - Writing taky-rs-dps.service\n   - Writing taky-rs.service\n"
        )
    );
    assert!(err.is_empty());
    let files = unit_files(&units);
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "taky-rs-cot.service 644",
            "taky-rs-dps.service 644",
            "taky-rs.service 644"
        ]
    );
    assert_eq!(
        files[1].1,
        "[Unit]\nDescription=taky-rs Data Package Server\nPartOf=taky-rs.service\n\
         Conflicts=taky.service taky-cot.service taky-dps.service\n\
         After=taky.service taky-cot.service taky-dps.service\n\n\
         [Service]\nType=simple\nRestart=always\nRestartSec=3\n\
         EnvironmentFile=-/etc/default/taky-rs\nUser=taky\nExecStart=taky_dps-rs\n\n\
         [Install]\nWantedBy=multi-user.target\n"
    );
    assert!(!files[0].1.contains("WorkingDirectory"));
}
