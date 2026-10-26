//! `takyctl-rs setup` (`cli/setup_taky_cmd.py`; spec dps-cli-config §7.2).
//!
//! Same steps, files, messages and order as the original:
//!
//! * site mode (`path` given): `path`, `path/ssl` (path must not exist), `path/taky.conf` with
//!   relative paths (`root_dir = .`, `./ssl/…`, `./dp-user`); system mode: `/etc/taky`,
//!   `/etc/taky/ssl`, `/var/taky`, `/etc/taky/taky.conf` with the default paths;
//! * config = `DEFAULT_CFG` + `bind_ip`, `public_ip`, `hostname`, `port`, `ssl.enabled`,
//!   `server_p12_pw`, written like `ConfigParser.write`; an existing config is refused (stdout);
//! * `upload_path`, `upload_path/meta`;
//! * with SSL: refuse an existing CA (stderr, exit 1, config already written), `ca.crt`/`ca.key`,
//!   `server.key` (0600) / `server.crt` / `server.p12` (no key), one `V` line in `cert-db.txt`;
//! * `--user`: `chown user:user` of every directory created and every file written.
//!
//! Python `chdir`s into the site; we resolve the relative config paths against it instead
//! (same files, no process-wide side effect). The global `-c` is ignored (as in Python).
//! No environment file is written: neither does Python's `setup`; `/etc/default/taky-rs`
//! (ADR-008 G-2) is only referenced by the `systemd` units (S-323).

use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::NaiveDateTime;
use taky_config::{Ini, default_ini};
use taky_pki::CertDb;
use taky_pki::certgen::{self, CertAuthority, CertKind};
use taky_pki::pkcs12;

use crate::cli::SetupArgs;
use crate::fsutil::{abspath, chown, default_hostname, join, mkdir};
use crate::pyerr::{none_path, pki};

/// Process context of `setup` (injected for tests).
#[derive(Debug, Clone)]
pub struct SetupEnv {
    /// `os.getcwd()` (absolute).
    pub cwd: PathBuf,
    /// Where `/` is in system mode (`/` in production; a temp dir in tests).
    pub system_root: PathBuf,
    /// Certificate time base (naive UTC, D-18).
    pub now: NaiveDateTime,
}

impl SetupEnv {
    /// The real process context.
    pub fn from_process() -> anyhow::Result<SetupEnv> {
        Ok(SetupEnv {
            cwd: std::env::current_dir()?,
            system_root: PathBuf::from("/"),
            now: chrono::Utc::now().naive_utc(),
        })
    }
}

/// Maps the paths the original uses (relative to its cwd after `chdir`, or absolute) to disk.
struct Paths {
    base: PathBuf,
    root: PathBuf,
}

impl Paths {
    fn fs(&self, p: &str) -> PathBuf {
        match p.strip_prefix('/') {
            Some(rel) => self.root.join(rel),
            None => self.base.join(p),
        }
    }
}

fn get(ini: &Ini, s: &str, k: &str) -> anyhow::Result<String> {
    ini.get(s, k)?.ok_or_else(none_path)
}

/// Runs `setup`; returns the exit code. `Err` ⇒ the `"setup failed: …"` path (exit 1).
pub fn setup(
    args: &SetupArgs,
    env: &SetupEnv,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    let mut config = default_ini();
    let hostname = args.hostname.clone().unwrap_or_else(default_hostname);
    let user = args.user.as_deref();
    let own = |fs: &Path, shown: &str| -> anyhow::Result<()> {
        match user {
            Some(u) => chown(fs, shown, u),
            None => Ok(()),
        }
    };

    let (paths, ssl_path, config_path) = match &args.path {
        Some(path) => {
            if env.cwd.join(path).exists() {
                writeln!(err, "ERROR: Directory exists, refusing to run setup")?;
                return Ok(1);
            }
            let site = abspath(path, &env.cwd);
            let site_s = site.to_string_lossy().into_owned();
            writeln!(out, "Installing site to {site_s}")?;
            for dir in [site_s.clone(), join(&site_s, "ssl")] {
                let fs = PathBuf::from(&dir);
                if !fs.exists() {
                    mkdir(&fs, &dir)?;
                    own(&fs, &dir)?;
                }
            }
            config.set("taky", "root_dir", Some("."))?;
            for (k, f) in [
                ("ca", "ca.crt"),
                ("ca_key", "ca.key"),
                ("server_p12", "server.p12"),
                ("cert", "server.crt"),
                ("key", "server.key"),
                ("cert_db", "cert-db.txt"),
            ] {
                config.set("ssl", k, Some(&format!("./ssl/{f}")))?;
            }
            config.set("dp_server", "upload_path", Some("./dp-user"))?;
            let paths = Paths {
                base: site,
                root: PathBuf::from("/"),
            };
            (paths, "ssl".to_owned(), "taky.conf".to_owned())
        }
        None => {
            writeln!(out, "Installing site to system")?;
            let paths = Paths {
                base: env.cwd.clone(),
                root: env.system_root.clone(),
            };
            for dir in ["/etc/taky", "/etc/taky/ssl", "/var/taky"] {
                let fs = paths.fs(dir);
                if !fs.exists() {
                    mkdir(&fs, dir)?;
                    own(&fs, dir)?;
                }
            }
            (
                paths,
                "/etc/taky/ssl".to_owned(),
                "/etc/taky/taky.conf".to_owned(),
            )
        }
    };

    config.set("taky", "bind_ip", Some(&args.ip))?;
    config.set("taky", "public_ip", Some(&args.public_ip))?;
    config.set("taky", "hostname", Some(&hostname))?;
    let port = if args.use_ssl { "8089" } else { "8087" };
    config.set("cot_server", "port", Some(port))?;
    let enabled = if args.use_ssl { "true" } else { "false" };
    config.set("ssl", "enabled", Some(enabled))?;
    config.set("ssl", "server_p12_pw", Some(&args.p12_pw))?;

    let cfg_fs = paths.fs(&config_path);
    if cfg_fs.exists() {
        writeln!(
            out,
            "ERROR: Config already exists at {config_path}, refusing to setup"
        )?;
        return Ok(1);
    }
    std::fs::write(&cfg_fs, config.write())
        .map_err(|e| crate::pyerr::os_error(&e, &config_path))?;
    writeln!(out, " - Wrote {config_path}")?;
    own(&cfg_fs, &config_path)?;

    let upload = get(&config, "dp_server", "upload_path")?;
    for dir in [upload.clone(), join(&upload, "meta")] {
        let fs = paths.fs(&dir);
        if !fs.exists() {
            mkdir(&fs, &dir)?;
            own(&fs, &dir)?;
        }
    }

    if !config.getboolean("ssl", "enabled")? {
        return Ok(0);
    }
    let ca = get(&config, "ssl", "ca")?;
    let ca_key = get(&config, "ssl", "ca_key")?;
    if paths.fs(&ca).exists() {
        writeln!(err, "ERROR: CA exists at {ca}, stopping here")?;
        return Ok(1);
    }

    writeln!(out, " - Generating certificate authority")?;
    let ca_kc = certgen::make_ca(env.now, certgen::CA_YEARS).map_err(pki)?;
    certgen::write_certificate(&paths.fs(&ca), &paths.fs(&ca_key), &ca_kc).map_err(pki)?;
    own(&paths.fs(&ca), &ca)?;
    own(&paths.fs(&ca_key), &ca_key)?;

    writeln!(out, " - Initializing certificate database")?;
    let cert_db_s = get(&config, "ssl", "cert_db")?;
    let mut cert_db = CertDb::open(&paths.fs(&cert_db_s)).map_err(pki)?;

    writeln!(out, " - Generating server certificate")?;
    let authority = CertAuthority::load(&paths.fs(&ca), &paths.fs(&ca_key)).map_err(pki)?;
    let server = certgen::make_cert(
        &authority,
        &hostname,
        env.now,
        certgen::CERT_YEARS,
        CertKind::Server,
    )
    .map_err(pki)?;
    let file = |ext: &str| paths.fs(&join(&ssl_path, &format!("server.{ext}")));
    certgen::write_certificate(&file("crt"), &file("key"), &server).map_err(pki)?;
    let p12 =
        pkcs12::make_cert_p12(&server, &authority, &hostname, false, &args.p12_pw).map_err(pki)?;
    pkcs12::write_p12(&file("p12"), &p12, false).map_err(pki)?;
    cert_db.add(&server.cert_der).map_err(pki)?;

    if let Some(u) = user {
        writeln!(out, " - Changing ownership to {u}")?;
        for k in ["cert", "key", "server_p12", "cert_db"] {
            let p = get(&config, "ssl", k)?;
            own(&paths.fs(&p), &p)?;
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Command, try_parse_from};

    fn args(argv: &[&str]) -> SetupArgs {
        let mut v = vec!["takyctl-rs", "setup"];
        v.extend_from_slice(argv);
        match try_parse_from(v).unwrap().command {
            Some(Command::Setup(a)) => a,
            other => panic!("{other:?}"),
        }
    }

    fn run(a: &SetupArgs, env: &SetupEnv) -> (u8, String, String) {
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let rc = setup(a, env, &mut o, &mut e).unwrap();
        (
            rc,
            String::from_utf8(o).unwrap(),
            String::from_utf8(e).unwrap(),
        )
    }

    /// System mode under a fake `/`: default paths in the config, files where the defaults say,
    /// then "Config already exists" (stdout) and "CA exists" (stderr; config written first).
    #[test]
    fn system_mode_layout_and_refusals() {
        let root = tempfile::tempdir().unwrap();
        // `/etc` and `/var` exist on a real system (os.mkdir is not recursive).
        std::fs::create_dir(root.path().join("etc")).unwrap();
        std::fs::create_dir(root.path().join("var")).unwrap();
        let env = SetupEnv {
            cwd: root.path().to_owned(),
            system_root: root.path().to_owned(),
            now: chrono::Utc::now().naive_utc(),
        };
        let a = args(&["--public-ip", "203.0.113.9", "--host", "10.1.2.3"]);
        let (rc, out, err) = run(&a, &env);
        assert_eq!((rc, err.as_str()), (0, ""));
        assert_eq!(
            out,
            "Installing site to system\n - Wrote /etc/taky/taky.conf\n - Generating certificate \
             authority\n - Initializing certificate database\n - Generating server certificate\n"
        );
        let r = root.path();
        let conf = std::fs::read_to_string(r.join("etc/taky/taky.conf")).unwrap();
        let mut expected = default_ini();
        for (s, k, v) in [
            ("taky", "bind_ip", "0.0.0.0"),
            ("taky", "public_ip", "203.0.113.9"),
            ("taky", "hostname", "10.1.2.3"),
            ("cot_server", "port", "8089"),
            ("ssl", "enabled", "true"),
            ("ssl", "server_p12_pw", "atakatak"),
        ] {
            expected.set(s, k, Some(v)).unwrap();
        }
        assert_eq!(conf, expected.write());
        assert!(conf.contains("ca = /etc/taky/ssl/ca.crt\n"));
        assert!(conf.contains("upload_path = /var/taky/dp-user\n"));
        for f in [
            "etc/taky/ssl/ca.crt",
            "etc/taky/ssl/ca.key",
            "etc/taky/ssl/server.crt",
            "etc/taky/ssl/server.key",
            "etc/taky/ssl/server.p12",
            "etc/taky/ssl/cert-db.txt",
            "var/taky/dp-user/meta",
        ] {
            assert!(r.join(f).exists(), "{f}");
        }
        let db = std::fs::read_to_string(r.join("etc/taky/ssl/cert-db.txt")).unwrap();
        assert_eq!(db.lines().count(), 1);
        assert!(
            db.starts_with("V\t") && db.ends_with("\t10.1.2.3\n"),
            "{db}"
        );

        let (rc, out, err) = run(&a, &env);
        assert_eq!(rc, 1);
        assert_eq!(
            out,
            "Installing site to system\nERROR: Config already exists at /etc/taky/taky.conf, \
             refusing to setup\n"
        );
        assert_eq!(err, "");

        std::fs::remove_file(r.join("etc/taky/taky.conf")).unwrap();
        let (rc, out, err) = run(&args(&["--no-ssl", "--public-ip", "1"]), &env);
        assert_eq!((rc, err.as_str()), (0, ""), "{out}");
        assert!(
            std::fs::read_to_string(r.join("etc/taky/taky.conf"))
                .unwrap()
                .contains("port = 8087\n")
        );
        std::fs::remove_file(r.join("etc/taky/taky.conf")).unwrap();
        let (rc, out, err) = run(&a, &env);
        assert_eq!(rc, 1);
        assert_eq!(
            err,
            "ERROR: CA exists at /etc/taky/ssl/ca.crt, stopping here\n"
        );
        assert!(out.ends_with(" - Wrote /etc/taky/taky.conf\n"), "{out}");
        assert!(r.join("etc/taky/taky.conf").exists());
    }
}
