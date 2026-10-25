//! Logging in Python `logging.basicConfig()` format (ARCHITECTURE §8).
//!
//! Line: `LEVEL:logger:message` to stderr. Logger name is the `lgr` field of the `tracing` event
//! (macro [`pylog!`](crate::pylog)), otherwise `target`. CRITICAL = `error` + field `critical=true`.
//! `RUST_LOG`, if set, takes precedence over `-l`. Like Python's root logger, `-l` applies to
//! every target (library `debug` events included).

use std::fmt;
use std::str::FromStr;

use tracing::Level;
use tracing::field::{Field, Visit};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, MakeWriter};
use tracing_subscriber::registry::LookupSpan;

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
/// `level` is the `-l` level (Python `logging.basicConfig(level=...)`): events below it are
/// dropped; `Critical` keeps only `error` events with `critical = true`. A non-empty `RUST_LOG`
/// that parses as an `EnvFilter` directive takes precedence (debugging aid; then `TRACE` events
/// are printed with the level name `TRACE`). Errors if a global subscriber is already set.
pub fn init(level: PyLevel) -> Result<(), LogError> {
    let rust_log = std::env::var("RUST_LOG").ok();
    let sub = subscriber(level, rust_log.as_deref(), std::io::stderr);
    tracing::subscriber::set_global_default(sub).map_err(|_| LogError::AlreadyInitialized)
}

/// The subscriber [`init`] installs, writing to `writer` (tests use an in-memory writer).
/// `rust_log` is the value of `RUST_LOG` (an invalid or empty one is ignored).
pub fn subscriber<W>(
    level: PyLevel,
    rust_log: Option<&str>,
    writer: W,
) -> impl tracing::Subscriber + Send + Sync + 'static
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let env = rust_log
        .filter(|v| !v.trim().is_empty())
        .and_then(|v| EnvFilter::try_new(v).ok());
    let critical_only = env.is_none() && level == PyLevel::Critical;
    let filter = env.unwrap_or_else(|| EnvFilter::new(level_directive(level)));
    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .event_format(PyFormat { critical_only })
        .with_env_filter(filter)
        .finish()
}

fn level_directive(level: PyLevel) -> &'static str {
    match level {
        PyLevel::Debug => "debug",
        PyLevel::Info => "info",
        PyLevel::Warning => "warn",
        PyLevel::Error | PyLevel::Critical => "error",
    }
}

/// `FormatEvent` producing Python's default `logging` line: `LEVEL:logger:message`.
///
/// The logger is the `lgr` field ([`pylog!`](crate::pylog)), otherwise the event `target`;
/// `WARN` is printed as `WARNING`, `error` + `critical = true` as `CRITICAL`. Other fields
/// (besides `message`, `lgr`, `critical`) are appended as ` name=value`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PyFormat {
    /// Drop every event that is not CRITICAL (`-l critical`).
    pub critical_only: bool,
}

#[derive(Default)]
struct PyVisitor {
    message: String,
    lgr: Option<String>,
    critical: bool,
    rest: String,
}

impl Visit for PyVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "message" => self.message = value.to_owned(),
            "lgr" => self.lgr = Some(value.to_owned()),
            name => {
                use std::fmt::Write as _;
                let _ = write!(self.rest, " {name}={value}");
            }
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        if field.name() == "critical" {
            self.critical = value;
        } else {
            self.record_debug(field, &value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        use std::fmt::Write as _;
        match field.name() {
            "message" => self.message = format!("{value:?}"),
            "lgr" => self.lgr = Some(format!("{value:?}")),
            name => {
                let _ = write!(self.rest, " {name}={value:?}");
            }
        }
    }
}

impl<S, N> FormatEvent<S, N> for PyFormat
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> fmt::Result {
        let mut v = PyVisitor::default();
        event.record(&mut v);
        let meta = event.metadata();
        let level = match *meta.level() {
            Level::TRACE => "TRACE",
            Level::DEBUG => "DEBUG",
            Level::INFO => "INFO",
            Level::WARN => "WARNING",
            Level::ERROR if v.critical => "CRITICAL",
            Level::ERROR => "ERROR",
        };
        if self.critical_only && level != "CRITICAL" {
            return Ok(());
        }
        let lgr = v.lgr.as_deref().unwrap_or(meta.target());
        writeln!(writer, "{level}:{lgr}:{}{}", v.message, v.rest)
    }
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

    /// In-memory writer for the subscriber.
    #[derive(Clone, Default)]
    struct Buf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::ErrorKind::Other)?
                .extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture(level: PyLevel, rust_log: Option<&str>) -> String {
        let buf = Buf::default();
        let w = buf.clone();
        let sub = subscriber(level, rust_log, move || w.clone());
        tracing::subscriber::with_default(sub, || {
            tracing::debug!(target: "taky_cot::router", "debug {}", 1);
            crate::pylog!(
                "COTServer",
                Level::INFO,
                "Client connected: {}",
                "1.2.3.4:5"
            );
            tracing::warn!(lgr = "load_config", "no ssl");
            tracing::error!(target: "root", "boom");
            tracing::error!(lgr = "COTServer", critical = true, "fatal");
            tracing::info!(lgr = "Persistence", key = 7, "with field");
            tracing::trace!("trace");
        });
        let out = buf.0.lock().unwrap().clone();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn python_logging_format_and_levels() {
        assert_eq!(
            capture(PyLevel::Debug, None),
            "DEBUG:taky_cot::router:debug 1\n\
             INFO:COTServer:Client connected: 1.2.3.4:5\n\
             WARNING:load_config:no ssl\n\
             ERROR:root:boom\n\
             CRITICAL:COTServer:fatal\n\
             INFO:Persistence:with field key=7\n"
        );
        assert_eq!(
            capture(PyLevel::Warning, None),
            "WARNING:load_config:no ssl\nERROR:root:boom\nCRITICAL:COTServer:fatal\n"
        );
        assert_eq!(
            capture(PyLevel::Critical, None),
            "CRITICAL:COTServer:fatal\n"
        );
    }

    #[test]
    fn rust_log_takes_precedence() {
        let out = capture(PyLevel::Critical, Some("trace"));
        assert!(out.starts_with("DEBUG:taky_cot::router:debug 1\n"), "{out}");
        assert!(
            out.ends_with("TRACE:taky_common::log::tests:trace\n"),
            "{out}"
        );
        // empty / invalid RUST_LOG is ignored
        assert_eq!(
            capture(PyLevel::Error, Some("")),
            "ERROR:root:boom\nCRITICAL:COTServer:fatal\n"
        );
        assert_eq!(
            capture(PyLevel::Error, Some("=[")),
            "ERROR:root:boom\nCRITICAL:COTServer:fatal\n"
        );
    }
}
