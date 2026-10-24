//! `load_config()` and the typed [`TakyConfig`] (ARCHITECTURE §9, §14).

use std::path::{Path, PathBuf};

use crate::{ConfigError, Ini};

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

/// `config.py:load_config` algorithm 1:1 (search `./taky.conf` → `/etc/taky/taky.conf`, defaults,
/// making paths absolute relative to the config directory, validation of ports and `max_persist_ttl`).
///
/// **T-10 scaffold:** implementation — T-20.
pub fn load_config(path: Option<&Path>, explicit: bool) -> Result<TakyConfig, ConfigError> {
    let _ = (path, explicit);
    todo!("T-20")
}
