//! `load_config()` and the typed [`TakyConfig`] (ARCHITECTURE §9, §14).

use std::path::{Path, PathBuf};

use crate::{ConfigError, Ini, IniError, default_ini};

/// Value of `taky.redis` after "Python-style" interpretation (`build_persistence`):
/// `getboolean` → true/false, otherwise the string is a URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedisSetting {
    /// Key missing, without a value, or `false`/`no`/`off`/`0` — memory persistence.
    Disabled,
    /// `true`/`yes`/`on`/`1` — `redis://127.0.0.1:6379`.
    Localhost,
    /// Any other string — connection URL (`redis://`, `rediss://`, `unix://`).
    Url(String),
}

/// The `[taky]` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakySect {
    /// `hostname` (server FQDN; Redis key space).
    pub hostname: String,
    /// `node_id` (TAK Server nodeId).
    pub node_id: String,
    /// `bind_ip` (`None` — all addresses).
    pub bind_ip: Option<String>,
    /// `public_ip`.
    pub public_ip: Option<String>,
    /// `redis`.
    pub redis: RedisSetting,
    /// `root_dir` (absolute; `taky-mgmt.sock` lives here).
    pub root_dir: PathBuf,
}

/// The `[cot_server]` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CotSect {
    /// `port` (default 8087, 8089 with SSL; `0 < port < 65535`).
    pub port: u16,
    /// `mon_ip` (always `None` without SSL — monitor disabled).
    pub mon_ip: Option<String>,
    /// `mon_port` (default 8087 with SSL; without SSL — as in the file, unused).
    pub mon_port: Option<u16>,
    /// `log_cot` (absolute CoT log directory or `None`).
    pub log_cot: Option<PathBuf>,
    /// `max_persist_ttl` (`-1` — unlimited).
    pub max_persist_ttl: i64,
}

/// The `[dp_server]` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpSect {
    /// `upload_path` (absolute).
    pub upload_path: PathBuf,
}

/// The `[ssl]` section. Paths are made absolute only when `enabled` (as in the original).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SslSect {
    /// `enabled`.
    pub enabled: bool,
    /// `client_cert_required`.
    pub client_cert_required: bool,
    /// `ca` (PEM; empty — system roots).
    pub ca: Option<PathBuf>,
    /// `ca_key`.
    pub ca_key: Option<PathBuf>,
    /// `server_p12`.
    pub server_p12: Option<PathBuf>,
    /// `server_p12_pw`.
    pub server_p12_pw: Option<String>,
    /// `cert`.
    pub cert: Option<PathBuf>,
    /// `key`.
    pub key: Option<PathBuf>,
    /// `key_pw`.
    pub key_pw: Option<String>,
    /// `cert_db`.
    pub cert_db: PathBuf,
}

/// Loaded configuration (immutable; passed as `Arc<TakyConfig>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakyConfig {
    /// `[taky]`.
    pub taky: TakySect,
    /// `[cot_server]`.
    pub cot_server: CotSect,
    /// `[dp_server]`.
    pub dp_server: DpSect,
    /// `[ssl]`.
    pub ssl: SslSect,
    /// `taky.cfg_path` — the file path, if loading was `explicit`.
    pub cfg_path: Option<PathBuf>,
    /// Final INI (after defaults, path absolutization and normalization, as `app_config`).
    raw: Ini,
}

impl TakyConfig {
    /// Final INI, equivalent to the original's `app_config`.
    pub fn raw(&self) -> &Ini {
        &self.raw
    }
}

/// System-wide config path checked after `./taky.conf` (`config.py:50`).
pub const SYSTEM_CONFIG: &str = "/etc/taky/taky.conf";

/// Local config file name checked first, relative to the working directory (`config.py:47`).
pub const LOCAL_CONFIG: &str = "taky.conf";

/// `config.py:load_config` 1:1 (DC §1.1–§1.5), relative to the process working directory.
///
/// * `path = None`: `./taky.conf` → `/etc/taky/taky.conf` → `explicit` ?
///   [`ConfigError::DefaultNotFound`] : defaults;
/// * `path` given but missing: `explicit` ? [`ConfigError::Required`] : defaults (QUIRK kept;
///   Rust additionally logs a WARNING);
/// * defaults without a file: `cfg_dir = cwd`, `root_dir = "."`, `upload_path = "./dp-user"`;
/// * `root_dir`, `upload_path`, `log_cot` (always) and the `[ssl]` file paths (only with SSL) are
///   made absolute: `realpath(join(cfg_dir, value))` when truthy and relative;
/// * `port`, `max_persist_ttl`, `mon_port` (only with SSL) normalized/validated, monitor disabled
///   (`mon_ip = None`) without SSL;
/// * `cfg_path` (explicit only) is the **real config path** (absolute) — D-16, not Python's
///   `log_cot` value (DC §1.5 BUG).
///
/// Errors map to the Python exception classes via [`ConfigError::py_class`]. D-14: a `%`
/// that survives interpolation does not fail loading (Python raises `ValueError`).
pub fn load_config(path: Option<&Path>, explicit: bool) -> Result<TakyConfig, ConfigError> {
    let cwd = std::env::current_dir()?;
    load_config_in(path, explicit, &cwd)
}

/// [`load_config`] with an explicit working directory `cwd` (absolute, symlink-free like
/// `os.getcwd()`): relative paths and the `./taky.conf` lookup are resolved against it.
pub fn load_config_in(
    path: Option<&Path>,
    explicit: bool,
    cwd: &Path,
) -> Result<TakyConfig, ConfigError> {
    let cwd_s = cwd.to_string_lossy().into_owned();
    let on_disk = |p: &Path| -> PathBuf { cwd.join(p) };

    // File lookup (config.py:46-56).
    let path: Option<String> = match path {
        Some(p) => Some(p.to_string_lossy().into_owned()),
        None => {
            if on_disk(Path::new(LOCAL_CONFIG)).exists() {
                let p = abspath(LOCAL_CONFIG, &cwd_s);
                tracing::info!(target: "load_config", "Assuming {p}");
                Some(p)
            } else if Path::new(SYSTEM_CONFIG).exists() {
                tracing::info!(target: "load_config", "Assuming {SYSTEM_CONFIG}");
                Some(SYSTEM_CONFIG.to_string())
            } else if explicit {
                return Err(ConfigError::DefaultNotFound);
            } else {
                None
            }
        }
    };

    let mut ini = default_ini();
    let file = path.as_deref().filter(|p| !p.is_empty());
    let cfg_dir = match file {
        Some(p) if on_disk(Path::new(p)).exists() => {
            tracing::info!(target: "load_config", "Loading config file from {p}");
            let cfg_dir = realpath(&py_dirname(p), &cwd_s);
            let text = std::fs::read_to_string(on_disk(Path::new(p)))?;
            ini.read_str(&text, p)?;
            cfg_dir
        }
        _ if explicit => return Err(ConfigError::Required),
        missing => {
            if let Some(p) = missing {
                tracing::warn!(target: "load_config", "Config file {p} not found, using default config");
            }
            tracing::info!(target: "load_config", "Using default config");
            set_value(&mut ini, "taky", "root_dir", Some("."))?;
            set_value(&mut ini, "dp_server", "upload_path", Some("./dp-user"))?;
            cwd_s.clone()
        }
    };

    // Make directories absolute (config.py:79-88).
    for (sect, opt) in [
        ("taky", "root_dir"),
        ("dp_server", "upload_path"),
        ("cot_server", "log_cot"),
    ] {
        absolutize(&mut ini, sect, opt, &cfg_dir, &cwd_s)?;
    }

    // port (config.py:90-101).
    let port = match ini.get("cot_server", "port")?.as_deref() {
        None | Some("") => {
            if ini.getboolean("ssl", "enabled")? {
                8089
            } else {
                8087
            }
        }
        Some(v) => parse_port(v).ok_or_else(|| ConfigError::InvalidPort(v.to_string()))?,
    };
    set_value(&mut ini, "cot_server", "port", Some(&port.to_string()))?;

    // max_persist_ttl (config.py:103-111).
    let max_persist_ttl = match ini.get("cot_server", "max_persist_ttl")?.as_deref() {
        None | Some("") => PyInt::minus_one(),
        Some(v) => {
            PyInt::parse(v).ok_or_else(|| ConfigError::InvalidMaxPersistTtl(v.to_string()))?
        }
    };
    set_value(
        &mut ini,
        "cot_server",
        "max_persist_ttl",
        Some(&max_persist_ttl.to_string()),
    )?;

    // SSL / monitor (config.py:113-134).
    let ssl_enabled = ini.getboolean("ssl", "enabled")?;
    let mon_port = if !ssl_enabled {
        set_value(&mut ini, "cot_server", "mon_ip", None)?;
        // Not validated and not changed (DC §1.3); the typed value is informative only.
        ini.get("cot_server", "mon_port")?
            .as_deref()
            .and_then(parse_port)
    } else {
        let mon_port = match ini.get("cot_server", "mon_port")?.as_deref() {
            None | Some("") => 8087,
            Some(v) => parse_port(v).ok_or_else(|| ConfigError::InvalidPort(v.to_string()))?,
        };
        set_value(
            &mut ini,
            "cot_server",
            "mon_port",
            Some(&mon_port.to_string()),
        )?;
        for f_name in ["ca", "ca_key", "server_p12", "cert", "key", "cert_db"] {
            absolutize(&mut ini, "ssl", f_name, &cfg_dir, &cwd_s)?;
        }
        Some(mon_port)
    };

    // cfg_path (config.py:136-137): D-16 — the real config path.
    let cfg_path = match (explicit, file) {
        (true, Some(p)) => {
            let p = abspath(p, &cwd_s);
            set_value(&mut ini, "taky", "cfg_path", Some(&p))?;
            Some(PathBuf::from(p))
        }
        _ => None,
    };

    // `app_config.update(ret_config)` interpolates every value (config.py:139-140).
    check_all_values(&ini)?;

    build(
        ini,
        port,
        mon_port,
        max_persist_ttl.saturating_i64(),
        ssl_enabled,
        cfg_path,
    )
}

/// Typed view of the final INI.
fn build(
    ini: Ini,
    port: u16,
    mon_port: Option<u16>,
    max_persist_ttl: i64,
    ssl_enabled: bool,
    cfg_path: Option<PathBuf>,
) -> Result<TakyConfig, ConfigError> {
    let get = |s: &str, k: &str| ini.get(s, k);
    // Truthy path (not None and not "") — how the original tests optional paths.
    let path = |s: &str, k: &str| -> Result<Option<PathBuf>, ConfigError> {
        Ok(get(s, k)?.filter(|v| !v.is_empty()).map(PathBuf::from))
    };
    let redis = match get("taky", "redis")? {
        None => RedisSetting::Disabled,
        Some(v) => match ini.getboolean("taky", "redis") {
            Ok(true) => RedisSetting::Localhost,
            Ok(false) => RedisSetting::Disabled,
            Err(_) if v.is_empty() => RedisSetting::Disabled,
            Err(_) => RedisSetting::Url(v),
        },
    };
    // `client_cert_required` is not validated by `load_config` (Python: only the CoT server's
    // `getboolean` fails, with SSL). A bad value keeps the secure default `true` here.
    let client_cert_required = match ini.getboolean("ssl", "client_cert_required") {
        Ok(b) => b,
        Err(e) => {
            if ssl_enabled {
                tracing::warn!(target: "load_config", "ssl.client_cert_required: {e}; using True");
            }
            true
        }
    };
    let taky = TakySect {
        hostname: get("taky", "hostname")?.unwrap_or_default(),
        node_id: get("taky", "node_id")?.unwrap_or_default(),
        bind_ip: get("taky", "bind_ip")?,
        public_ip: get("taky", "public_ip")?,
        redis,
        root_dir: path("taky", "root_dir")?.unwrap_or_default(),
    };
    let cot_server = CotSect {
        port,
        mon_ip: get("cot_server", "mon_ip")?,
        mon_port,
        log_cot: path("cot_server", "log_cot")?,
        max_persist_ttl,
    };
    let dp_server = DpSect {
        upload_path: path("dp_server", "upload_path")?.unwrap_or_default(),
    };
    let ssl = SslSect {
        enabled: ssl_enabled,
        client_cert_required,
        ca: path("ssl", "ca")?,
        ca_key: path("ssl", "ca_key")?,
        server_p12: path("ssl", "server_p12")?,
        server_p12_pw: get("ssl", "server_p12_pw")?,
        cert: path("ssl", "cert")?,
        key: path("ssl", "key")?,
        key_pw: get("ssl", "key_pw")?,
        cert_db: path("ssl", "cert_db")?.unwrap_or_default(),
    };
    Ok(TakyConfig {
        taky,
        cot_server,
        dp_server,
        ssl,
        cfg_path,
        raw: ini,
    })
}

/// Store a final (already interpolated) value so that [`Ini::get`] returns it verbatim:
/// `%` is escaped as `%%` (D-14; Python's `set` would raise `ValueError` instead).
fn set_value(ini: &mut Ini, s: &str, k: &str, v: Option<&str>) -> Result<(), ConfigError> {
    let escaped = v.map(|v| v.replace('%', "%%"));
    ini.set_raw(s, k, escaped.as_deref())?;
    Ok(())
}

/// `if path and not isabs(path): path = realpath(join(cfg_dir, path))`.
fn absolutize(
    ini: &mut Ini,
    s: &str,
    k: &str,
    cfg_dir: &str,
    cwd: &str,
) -> Result<(), ConfigError> {
    if let Some(v) = ini.get(s, k)?
        && !v.is_empty()
        && !v.starts_with('/')
    {
        let p = realpath(&py_join(cfg_dir, &v), cwd);
        set_value(ini, s, k, Some(&p))?;
    }
    Ok(())
}

/// Interpolate every value of every section (incl. `DEFAULT`), as `app_config.update()` does.
fn check_all_values(ini: &Ini) -> Result<(), IniError> {
    let defaults = ini.section_items(DEFAULT).unwrap_or_default();
    for (k, _) in defaults {
        ini.get(DEFAULT, k)?;
    }
    for s in ini.sections() {
        for (k, _) in ini.section_items(s).unwrap_or_default() {
            ini.get(s, k)?;
        }
        for (k, _) in defaults {
            ini.get(s, k)?;
        }
    }
    Ok(())
}

const DEFAULT: &str = "DEFAULT";

/// `int(port)` with `0 < port < 65535` (65535 rejected — QUIRK kept).
fn parse_port(v: &str) -> Option<u16> {
    let n = PyInt::parse(v)?;
    if n.negative {
        return None;
    }
    let n: u32 = n.digits.parse().ok()?;
    (n > 0 && n < 65535).then_some(n as u16)
}

/// Result of Python `int(str)` (base 10): sign and canonical digits (no leading zeros).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PyInt {
    negative: bool,
    digits: String,
}

/// CPython `sys.get_int_max_str_digits()` default: longer strings raise `ValueError`.
const PY_INT_MAX_STR_DIGITS: usize = 4300;

impl PyInt {
    fn minus_one() -> PyInt {
        PyInt {
            negative: true,
            digits: "1".to_string(),
        }
    }

    /// `int(s)`: surrounding whitespace, optional `+`/`-`, decimal digits (any Unicode `Nd`
    /// digit, as Python accepts) with single `_` between digits.
    fn parse(s: &str) -> Option<PyInt> {
        let t = s.trim_matches(py_isspace);
        let (negative, body) = match t.as_bytes().first()? {
            b'-' => (true, &t[1..]),
            b'+' => (false, &t[1..]),
            _ => (false, t),
        };
        let mut digits = String::with_capacity(body.len());
        let mut prev_digit = false;
        for c in body.chars() {
            if let Some(d) = py_decimal(c) {
                digits.push(char::from(b'0' + d));
                prev_digit = true;
            } else if c == '_' && prev_digit {
                prev_digit = false;
            } else {
                return None;
            }
        }
        if !prev_digit || digits.len() > PY_INT_MAX_STR_DIGITS {
            return None;
        }
        let trimmed = digits.trim_start_matches('0');
        let digits = if trimmed.is_empty() { "0" } else { trimmed }.to_string();
        let negative = negative && digits != "0";
        Some(PyInt { negative, digits })
    }

    /// Value clamped to `i64` (Python ints are unbounded).
    fn saturating_i64(&self) -> i64 {
        match self.digits.parse::<i64>() {
            Ok(n) if self.negative => -n,
            Ok(n) => n,
            Err(_) if self.negative => i64::MIN,
            Err(_) => i64::MAX,
        }
    }
}

impl std::fmt::Display for PyInt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.negative {
            f.write_str("-")?;
        }
        f.write_str(&self.digits)
    }
}

/// First code points (digit zero) of the Unicode `Nd` blocks; every block has 10 contiguous
/// digits (Unicode 15.1, as in CPython 3.13 `unicodedata`).
const ND_ZEROS: [u32; 68] = [
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66,
    0xDE6, 0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90,
    0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
    0x104A0, 0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650,
    0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50, 0x11DA0, 0x11F50, 0x16A60, 0x16AC0,
    0x16B50, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E4F0, 0x1E950,
    0x1FBF0,
];

/// Decimal value of a Unicode `Nd` character (`unicodedata.decimal`).
fn py_decimal(c: char) -> Option<u8> {
    let n = c as u32;
    let i = ND_ZEROS.partition_point(|z| *z <= n).checked_sub(1)?;
    let d = n - ND_ZEROS[i];
    (d < 10).then_some(d as u8)
}

/// `str.isspace` (Unicode `White_Space` plus the ASCII separators U+001C..U+001F).
fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `posixpath.join(a, b)` for two components.
fn py_join(a: &str, b: &str) -> String {
    if b.starts_with('/') || a.is_empty() {
        b.to_string()
    } else if a.ends_with('/') {
        format!("{a}{b}")
    } else {
        format!("{a}/{b}")
    }
}

/// `posixpath.dirname`.
fn py_dirname(p: &str) -> String {
    let i = p.rfind('/').map_or(0, |i| i + 1);
    let head = &p[..i];
    if !head.is_empty() && head.bytes().any(|b| b != b'/') {
        head.trim_end_matches('/').to_string()
    } else {
        head.to_string()
    }
}

/// `posixpath.normpath`.
fn py_normpath(p: &str) -> String {
    if p.is_empty() {
        return ".".to_string();
    }
    let lead = p.bytes().take_while(|b| *b == b'/').count();
    let initial = match lead {
        0 => "",
        2 => "//",
        _ => "/",
    };
    let mut comps: Vec<&str> = Vec::new();
    for c in p.split('/') {
        if c.is_empty() || c == "." {
            continue;
        }
        if c != ".." || (initial.is_empty() && comps.is_empty()) || comps.last() == Some(&"..") {
            comps.push(c);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let out = format!("{initial}{}", comps.join("/"));
    if out.is_empty() { ".".to_string() } else { out }
}

/// `posixpath.abspath` relative to `cwd`.
fn abspath(p: &str, cwd: &str) -> String {
    if p.starts_with('/') {
        py_normpath(p)
    } else {
        py_normpath(&py_join(cwd, p))
    }
}

/// `posixpath.realpath(p)` (non-strict, CPython 3.13 algorithm): symlinks resolved, missing
/// components kept lexically, `..` applied to the resolved prefix.
fn realpath(p: &str, cwd: &str) -> String {
    enum Part {
        Name(String),
        /// Marker: the symlink at this path has been fully resolved to the current `path`.
        Resolved(String),
    }
    let mut rest: Vec<Part> = p
        .split('/')
        .rev()
        .map(|s| Part::Name(s.to_string()))
        .collect();
    let mut part_count = rest.len();
    let mut path = if p.starts_with('/') {
        "/".to_string()
    } else {
        cwd.to_string()
    };
    let mut seen: std::collections::HashMap<String, Option<String>> = Default::default();
    while part_count > 0 {
        let Some(part) = rest.pop() else { break };
        let name = match part {
            Part::Resolved(link) => {
                seen.insert(link, Some(path.clone()));
                continue;
            }
            Part::Name(n) => n,
        };
        part_count -= 1;
        if name.is_empty() || name == "." {
            continue;
        }
        if name == ".." {
            path = match path.rfind('/') {
                Some(0) | None => "/".to_string(),
                Some(i) => path[..i].to_string(),
            };
            continue;
        }
        let newpath = if path == "/" {
            format!("/{name}")
        } else {
            format!("{path}/{name}")
        };
        let is_link = std::fs::symlink_metadata(&newpath)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if !is_link {
            path = newpath;
            continue;
        }
        if let Some(cached) = seen.get(&newpath) {
            // Resolved earlier (use it) or a symlink loop (keep the link path).
            path = cached.clone().unwrap_or(newpath);
            continue;
        }
        let Ok(target) = std::fs::read_link(&newpath) else {
            path = newpath;
            continue;
        };
        let target = target.to_string_lossy().into_owned();
        if target.starts_with('/') {
            path = "/".to_string();
        }
        seen.insert(newpath.clone(), None);
        rest.push(Part::Resolved(newpath));
        let parts: Vec<&str> = target.split('/').collect();
        part_count += parts.len();
        rest.extend(parts.into_iter().rev().map(|s| Part::Name(s.to_string())));
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn py_int_like_python() {
        let ok = |s: &str| PyInt::parse(s).map(|n| n.to_string());
        assert_eq!(ok(" 8_087 ").as_deref(), Some("8087"));
        assert_eq!(ok("+80").as_deref(), Some("80"));
        assert_eq!(ok("-0").as_deref(), Some("0"));
        assert_eq!(ok("007").as_deref(), Some("7"));
        assert_eq!(ok("-5").as_deref(), Some("-5"));
        assert_eq!(ok("\u{663}\u{0660}").as_deref(), Some("30"));
        assert_eq!(ok("\u{ff11}_\u{1d7ce}").as_deref(), Some("10"));
        assert_eq!(ok("\u{2003}7\u{1f}").as_deref(), Some("7"));
        for bad in [
            "", "+", "0x10", "1.5", "8__0", "_8", "8_", "+ 8", "abc", "1e3",
        ] {
            assert_eq!(ok(bad), None, "{bad:?}");
        }
        assert_eq!(ok(&"9".repeat(4301)), None);
        assert_eq!(
            PyInt::parse(&"9".repeat(30)).unwrap().saturating_i64(),
            i64::MAX
        );
    }

    #[test]
    fn ports() {
        assert_eq!(parse_port("65534"), Some(65534));
        assert_eq!(parse_port("65535"), None);
        assert_eq!(parse_port("0"), None);
        assert_eq!(parse_port("-1"), None);
        assert_eq!(parse_port("99999999999999999999"), None);
    }

    #[test]
    fn posix_path_helpers() {
        assert_eq!(py_dirname("taky.conf"), "");
        assert_eq!(py_dirname("/etc/taky/taky.conf"), "/etc/taky");
        assert_eq!(py_dirname("/taky.conf"), "/");
        assert_eq!(py_dirname("a//b"), "a");
        assert_eq!(py_normpath("//a/./b/../c/"), "//a/c");
        assert_eq!(py_normpath("///a"), "/a");
        assert_eq!(py_normpath("../x"), "../x");
        assert_eq!(abspath("taky.conf", "/srv/x"), "/srv/x/taky.conf");
        assert_eq!(py_join("/", "a"), "/a");
        assert_eq!(py_join("/x", "/abs"), "/abs");
    }

    #[cfg(unix)]
    #[test]
    fn realpath_resolves_symlinks_and_missing_parts() {
        let d = tempfile::tempdir().unwrap();
        let root = realpath(&d.path().to_string_lossy(), "/");
        std::fs::create_dir(format!("{root}/real")).unwrap();
        std::os::unix::fs::symlink(format!("{root}/real"), format!("{root}/link")).unwrap();
        std::os::unix::fs::symlink("real/../real", format!("{root}/rel")).unwrap();
        std::os::unix::fs::symlink("loop", format!("{root}/loop")).unwrap();
        assert_eq!(
            realpath(&format!("{root}/link/x/../y"), "/"),
            format!("{root}/real/y")
        );
        assert_eq!(
            realpath(&format!("{root}/rel/z"), "/"),
            format!("{root}/real/z")
        );
        assert_eq!(
            realpath(&format!("{root}/loop/a"), "/"),
            format!("{root}/loop/a")
        );
        assert_eq!(realpath("a/./b", &root), format!("{root}/a/b"));
        assert_eq!(realpath("/..", "/"), "/");
    }
}
