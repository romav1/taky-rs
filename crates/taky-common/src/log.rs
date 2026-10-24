//! Logging in Python `logging.basicConfig()` format (ARCHITECTURE §8).
//!
//! Line: `LEVEL:logger:message` to stderr. Logger name is the `lgr` field of the `tracing` event
//! (macro [`pylog!`](crate::pylog)), otherwise `target`. CRITICAL = `error` + field `critical=true`.
//! `RUST_LOG`, if set, takes precedence over `-l`.

use std::fmt;
use std::str::FromStr;

/// Logging level, like Python `logging` level names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PyLevel {
    /// `DEBUG`
    Debug,
    /// `INFO`
    Info,
    /// `WARNING`
    Warning,
    /// `ERROR`
    Error,
    /// `CRITICAL`
    Critical,
}

impl PyLevel {
    /// Level name as Python prints it (`"WARNING"`, …).
    pub fn as_py_str(self) -> &'static str {
        match self {
            PyLevel::Debug => "DEBUG",
            PyLevel::Info => "INFO",
            PyLevel::Warning => "WARNING",
            PyLevel::Error => "ERROR",
            PyLevel::Critical => "CRITICAL",
        }
    }
}

impl fmt::Display for PyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_py_str())
    }
}

/// Error parsing a level name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid log level: {0}")]
pub struct ParseLevelError(pub String);

impl FromStr for PyLevel {
    type Err = ParseLevelError;

    /// Case-insensitive (`-l info` for `taky`, `INFO` by default for `taky_dps`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "debug" => Ok(PyLevel::Debug),
            "info" => Ok(PyLevel::Info),
            "warning" => Ok(PyLevel::Warning),
            "error" => Ok(PyLevel::Error),
            "critical" => Ok(PyLevel::Critical),
            _ => Err(ParseLevelError(s.to_owned())),
        }
    }
}

/// Logging initialization error.
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    /// A global subscriber is already installed.
    #[error("logging already initialized")]
    AlreadyInitialized,
}

/// Install the global `tracing` subscriber with the `LEVEL:logger:message` format on stderr.
///
/// **T-10 scaffold:** implementation — T-20 (dev01).
pub fn init(level: PyLevel) -> Result<(), LogError> {
    let _ = level;
    todo!("T-20: python-like FormatEvent")
}

/// Log a message with an explicit logger name (the `lgr` field), like `logging.getLogger(name)`.
///
/// ```ignore
/// pylog!("COTServer", tracing::Level::INFO, "Client connected: {}", addr);
/// ```
#[macro_export]
macro_rules! pylog {
    ($lgr:expr, $lvl:expr, $($arg:tt)+) => {
        ::tracing::event!($lvl, lgr = %$lgr, $($arg)+)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_levels_case_insensitive() {
        assert_eq!("INFO".parse::<PyLevel>(), Ok(PyLevel::Info));
        assert_eq!("critical".parse::<PyLevel>(), Ok(PyLevel::Critical));
        assert!("verbose".parse::<PyLevel>().is_err());
        assert_eq!(PyLevel::Warning.to_string(), "WARNING");
    }
}
