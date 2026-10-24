//! `load_config` branches beyond U003 (DC §1.1–§1.5): lookup order, explicit/non-explicit,
//! defaults without a file, symlinked config dir, `cfg_path` (D-16), typed view, `%` (D-14).

// Test code: helpers outside #[test] fns are not covered by clippy.toml allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use taky_config::load::SYSTEM_CONFIG;
use taky_config::{ConfigError, RedisSetting, TakyConfig, load_config_in};

/// A temporary working directory (canonical, like `os.getcwd()`).
fn cwd() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().canonicalize().unwrap();
    (t, p)
}

fn raw(cfg: &TakyConfig, s: &str, k: &str) -> Option<String> {
    cfg.raw().get(s, k).unwrap()
}

fn no_system_config() -> bool {
    !Path::new(SYSTEM_CONFIG).exists()
}

#[test]
fn defaults_without_a_file() {
    let (_t, cwd) = cwd();
    if !no_system_config() {
        return; // the lookup would find the system config on this host
    }
    let cfg = load_config_in(None, false, &cwd).unwrap();
    assert_eq!(cfg.taky.root_dir, cwd);
    assert_eq!(cfg.dp_server.upload_path, cwd.join("dp-user"));
    assert_eq!(
        raw(&cfg, "taky", "root_dir"),
        Some(cwd.display().to_string())
    );
    assert_eq!(cfg.taky.hostname, "taky.local");
    assert_eq!(cfg.taky.node_id, "TAKY");
    assert_eq!(cfg.taky.redis, RedisSetting::Disabled);
    assert_eq!(cfg.cot_server.port, 8087);
    assert_eq!(cfg.cot_server.mon_ip, None);
    assert_eq!(cfg.cot_server.mon_port, None);
    assert_eq!(cfg.cot_server.max_persist_ttl, -1);
    assert!(!cfg.ssl.enabled && cfg.ssl.client_cert_required);
    assert_eq!(cfg.ssl.cert_db, PathBuf::from("/etc/taky/ssl/cert-db.txt"));
    assert_eq!(cfg.cfg_path, None);
    assert!(cfg.raw().get("taky", "cfg_path").is_err());

    let e = load_config_in(None, true, &cwd).unwrap_err();
    assert!(matches!(e, ConfigError::DefaultNotFound), "{e:?}");
    assert_eq!(e.to_string(), "Unable to find default config file");
    assert_eq!(e.py_class(), "FileNotFoundError");
}

#[test]
fn local_taky_conf_is_found_first() {
    let (_t, cwd) = cwd();
    std::fs::write(
        cwd.join("taky.conf"),
        "[taky]\nhostname = local\nroot_dir = r\n",
    )
    .unwrap();
    let cfg = load_config_in(None, true, &cwd).unwrap();
    assert_eq!(cfg.taky.hostname, "local");
    assert_eq!(cfg.taky.root_dir, cwd.join("r"));
    assert_eq!(cfg.cfg_path, Some(cwd.join("taky.conf")));
    assert_eq!(
        raw(&cfg, "taky", "cfg_path"),
        Some(cwd.join("taky.conf").display().to_string())
    );
}

#[test]
fn missing_given_path() {
    let (_t, cwd) = cwd();
    // Not explicit: QUIRK kept — silently the defaults (relative to cwd).
    let cfg = load_config_in(Some(Path::new("nope.conf")), false, &cwd).unwrap();
    assert_eq!(cfg.taky.root_dir, cwd);
    // Empty path: no file either.
    let cfg = load_config_in(Some(Path::new("")), false, &cwd).unwrap();
    assert_eq!(cfg.dp_server.upload_path, cwd.join("dp-user"));
    let e = load_config_in(Some(Path::new("nope.conf")), true, &cwd).unwrap_err();
    assert!(matches!(e, ConfigError::Required), "{e:?}");
    assert_eq!(e.to_string(), "Config file required, but not present");
}

#[test]
fn explicit_relative_path_gives_real_cfg_path() {
    let (_t, cwd) = cwd();
    std::fs::create_dir(cwd.join("conf")).unwrap();
    // log_cot set: Python would put this value into cfg_path (DC §1.5); Rust keeps the file path.
    std::fs::write(cwd.join("conf/taky.conf"), "[cot_server]\nlog_cot = logs\n").unwrap();
    let cfg = load_config_in(Some(Path::new("./conf/../conf/taky.conf")), true, &cwd).unwrap();
    assert_eq!(cfg.cfg_path, Some(cwd.join("conf/taky.conf")));
    assert_eq!(cfg.cot_server.log_cot, Some(cwd.join("conf/logs")));
    // Not explicit: no cfg_path.
    let cfg = load_config_in(Some(Path::new("conf/taky.conf")), false, &cwd).unwrap();
    assert_eq!(cfg.cfg_path, None);
}

#[cfg(unix)]
#[test]
fn config_dir_symlinks_are_resolved() {
    let (_t, cwd) = cwd();
    std::fs::create_dir_all(cwd.join("real/data")).unwrap();
    std::os::unix::fs::symlink(cwd.join("real"), cwd.join("link")).unwrap();
    std::os::unix::fs::symlink("data", cwd.join("real/d")).unwrap();
    std::fs::write(
        cwd.join("real/taky.conf"),
        "[taky]\nroot_dir = .\n[dp_server]\nupload_path = d/../up\n[cot_server]\nlog_cot = /abs/../x\n",
    )
    .unwrap();
    let cfg = load_config_in(Some(&cwd.join("link/taky.conf")), false, &cwd).unwrap();
    assert_eq!(cfg.taky.root_dir, cwd.join("real"));
    // `..` after a resolved symlink applies to its target (realpath, not normpath).
    assert_eq!(cfg.dp_server.upload_path, cwd.join("real/up"));
    // Absolute paths are left alone (no normalization).
    assert_eq!(
        raw(&cfg, "cot_server", "log_cot").as_deref(),
        Some("/abs/../x")
    );
}

#[test]
fn ssl_enabled_typed_view() {
    let (_t, cwd) = cwd();
    std::fs::write(
        cwd.join("taky.conf"),
        "[taky]\nredis = yes\nbind_ip =\n[cot_server]\nmon_ip = 0.0.0.0\nmax_persist_ttl = 1_000\n\
         [ssl]\nenabled = true\nclient_cert_required = off\nca = ssl/ca.crt\nkey_pw = s3cret\ncert =\n",
    )
    .unwrap();
    let cfg = load_config_in(None, false, &cwd).unwrap();
    assert_eq!(cfg.taky.redis, RedisSetting::Localhost);
    assert_eq!(cfg.taky.bind_ip.as_deref(), Some(""));
    assert_eq!(cfg.cot_server.port, 8089);
    assert_eq!(cfg.cot_server.mon_ip.as_deref(), Some("0.0.0.0"));
    assert_eq!(cfg.cot_server.mon_port, Some(8087));
    assert_eq!(cfg.cot_server.max_persist_ttl, 1000);
    assert_eq!(
        raw(&cfg, "cot_server", "max_persist_ttl").as_deref(),
        Some("1000")
    );
    assert!(cfg.ssl.enabled && !cfg.ssl.client_cert_required);
    assert_eq!(cfg.ssl.ca, Some(cwd.join("ssl/ca.crt")));
    assert_eq!(cfg.ssl.cert, None);
    assert_eq!(cfg.ssl.key_pw.as_deref(), Some("s3cret"));
    assert_eq!(cfg.ssl.server_p12_pw.as_deref(), Some("atakatak"));
}

#[test]
fn redis_settings() {
    let (_t, cwd) = cwd();
    let f = cwd.join("taky.conf");
    for (v, want) in [
        ("redis", RedisSetting::Disabled),
        ("redis =", RedisSetting::Disabled),
        ("redis = Off", RedisSetting::Disabled),
        ("redis = 1", RedisSetting::Localhost),
        (
            "redis = unix:///run/r.sock",
            RedisSetting::Url("unix:///run/r.sock".into()),
        ),
    ] {
        std::fs::write(&f, format!("[taky]\n{v}\n")).unwrap();
        assert_eq!(
            load_config_in(Some(&f), false, &cwd).unwrap().taky.redis,
            want,
            "{v}"
        );
    }
}

#[test]
fn errors_and_percent() {
    let (_t, cwd) = cwd();
    let f = cwd.join("taky.conf");
    let load = |text: &str| {
        std::fs::write(&f, text).unwrap();
        load_config_in(Some(&f), false, &cwd)
    };
    let e = load("[cot_server]\nport = 65535\n").unwrap_err();
    assert_eq!(e.to_string(), "Invalid port: 65535");
    assert_eq!(e.py_class(), "ValueError");
    let e = load("[ssl]\nenabled = 1\n[cot_server]\nmon_port = x\n").unwrap_err();
    assert_eq!(e.to_string(), "Invalid port: x");
    let e = load("[cot_server]\nmax_persist_ttl = 1.5\n").unwrap_err();
    assert_eq!(e.to_string(), "Invalid max_persist_ttl: 1.5");
    let e = load("[taky]\nhostname = a\n[taky]\n").unwrap_err();
    assert_eq!(e.py_class(), "DuplicateSectionError");
    // No SSL: mon_port is neither validated nor changed.
    let cfg = load("[cot_server]\nmon_port = 9000\n").unwrap();
    assert_eq!(raw(&cfg, "cot_server", "mon_port").as_deref(), Some("9000"));
    // D-14: `%%` → `%`, kept through absolutization (raw stays interpolatable).
    let cfg = load("[cot_server]\nlog_cot = a%%b\n[taky]\nnode_id = 100%%\n").unwrap();
    assert_eq!(cfg.cot_server.log_cot, Some(cwd.join("a%b")));
    assert_eq!(cfg.taky.node_id, "100%");
    // Non-UTF-8 file.
    std::fs::write(&f, b"[taky]\nhostname = \xff\n").unwrap();
    let e = load_config_in(Some(&f), false, &cwd).unwrap_err();
    assert_eq!(e.py_class(), "UnicodeDecodeError");
}
