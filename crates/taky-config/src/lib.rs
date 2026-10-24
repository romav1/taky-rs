//! `taky.conf`: configparser-compatible INI ([`Ini`], ADR-005) and configuration loading
//! ([`load_config`], parity with `taky/config.py`). Owner: dev01.
//!
//! Instead of the original's global `app_config` — an immutable [`TakyConfig`], passed
//! as `Arc<TakyConfig>`.
//!
//! Status: T-10 scaffold (types and signatures). Implementation: T-20.

pub mod defaults;
pub mod error;
pub mod ini;
pub mod load;

pub use defaults::default_ini;
pub use error::{ConfigError, IniError};
pub use ini::Ini;
pub use load::{CotSect, DpSect, RedisSetting, SslSect, TakyConfig, TakySect, load_config};
