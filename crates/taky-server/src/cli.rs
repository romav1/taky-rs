//! `taky-rs` command line, 1:1 with `taky/cot/__main__.py:arg_parse` (ARCHITECTURE §2, §2.1).
//!
//! `--version` prints `"<prog> version <VERSION>"` (ADR-008 G-3), where `prog` is the basename
//! of `argv[0]`, as in argparse.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::{ArgAction, CommandFactory, FromArgMatches, Parser};
use taky_common::log::PyLevel;
use taky_config::ConfigError;

/// Program name used when `argv[0]` is unavailable.
pub const DEFAULT_PROG: &str = "taky-rs";

/// Parsed `taky-rs` arguments.
#[derive(Debug, Clone, PartialEq, Eq, Parser)]
#[command(
    name = DEFAULT_PROG,
    about = "Start the taky server",
    disable_version_flag = true,
    infer_long_args = true
)]
pub struct Args {
    /// Log verbosity
    #[arg(
        short = 'l',
        value_name = "{debug,info,warning,error,critical}",
        value_parser = ["debug", "info", "warning", "error", "critical"],
        default_value = "info"
    )]
    pub log_level: String,

    /// Path to configuration file
    #[arg(short = 'c', value_name = "CFG_FILE")]
    pub cfg_file: Option<PathBuf>,

    /// Accepted for compatibility and ignored (the original attaches PDB on SIGUSR1)
    #[arg(short = 'd')]
    pub debug: bool,

    /// show program's version number and exit
    #[arg(long = "version", action = ArgAction::Version)]
    version: Option<bool>,
}

impl Args {
    /// Log level as [`PyLevel`] (`-l` is restricted to valid names by clap).
    pub fn level(&self) -> PyLevel {
        self.log_level.parse().unwrap_or(PyLevel::Info)
    }
}

/// clap command with argparse-style `prog` and version text.
pub fn command(argv0: Option<&str>) -> clap::Command {
    let prog = taky_common::prog_name(argv0, DEFAULT_PROG).to_owned();
    Args::command()
        .name(prog.clone())
        .bin_name(prog)
        .version(format!("version {}", taky_common::VERSION))
}

/// Parse `argv` (including `argv[0]`). `--help`/`--version` and errors come back as
/// [`clap::Error`]; the caller exits with [`clap::Error::exit`] (code 0 or 2).
pub fn try_parse_from<I, T>(argv: I) -> Result<Args, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let argv: Vec<OsString> = argv.into_iter().map(Into::into).collect();
    let argv0 = argv.first().and_then(|a| a.to_str());
    let matches = command(argv0).try_get_matches_from(&argv)?;
    Args::from_arg_matches(&matches)
}

/// Parse the process arguments; on `--help`/`--version`/error print and exit like argparse.
pub fn parse() -> Args {
    try_parse_from(std::env::args_os()).unwrap_or_else(|e| e.exit())
}

/// How `taky-rs` reports a `load_config` failure (`__main__.py:73-85`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigFailure {
    /// `FileNotFoundError`/`OSError` → `argp.error(msg)`: usage + `<prog>: error: <msg>` on
    /// stderr, exit 2.
    Usage(String),
    /// `configparser.ParsingError` → `Configuration file error: <exc>` on stderr, exit 1. Every
    /// other error (Python `ValueError`, `Duplicate*Error`, interpolation errors: a traceback,
    /// exit 1) gets the same readable line and exit code (D-13, OQ-02).
    Config(String),
}

impl ConfigFailure {
    /// Classify `err` for the `-c` value `cfg_file` (as typed on the command line).
    pub fn classify(cfg_file: Option<&Path>, err: &ConfigError) -> ConfigFailure {
        match err.py_class() {
            "FileNotFoundError" | "OSError" => ConfigFailure::Usage(match cfg_file {
                Some(f) => format!("Unable to load config file: '{}'", f.display()),
                // QUIRK kept: the message names /etc/taky.conf (spec §1.2).
                None => "Unable to load './taky.conf' or '/etc/taky.conf'".to_owned(),
            }),
            _ => ConfigFailure::Config(format!("Configuration file error: {err}")),
        }
    }

    /// Process exit code (argparse error 2, otherwise 1).
    pub fn exit_code(&self) -> u8 {
        match self {
            ConfigFailure::Usage(_) => 2,
            ConfigFailure::Config(_) => 1,
        }
    }

    /// The stderr text (with a trailing newline), argparse style for [`ConfigFailure::Usage`].
    pub fn render(&self, argv0: Option<&str>) -> String {
        match self {
            ConfigFailure::Usage(msg) => {
                let mut cmd = command(argv0);
                let prog = cmd.get_name().to_owned();
                format!("{}\n{prog}: error: {msg}\n", cmd.render_usage())
            }
            ConfigFailure::Config(msg) => format!("{msg}\n"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_failures() {
        let io = ConfigError::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        let f = ConfigFailure::classify(Some(Path::new("x.conf")), &io);
        assert_eq!(
            f,
            ConfigFailure::Usage("Unable to load config file: 'x.conf'".into())
        );
        assert_eq!(f.exit_code(), 2);
        let r = f.render(Some("/usr/bin/taky-rs"));
        assert!(
            r.ends_with("\ntaky-rs: error: Unable to load config file: 'x.conf'\n"),
            "{r}"
        );
        let f = ConfigFailure::classify(None, &ConfigError::DefaultNotFound);
        assert_eq!(
            f,
            ConfigFailure::Usage("Unable to load './taky.conf' or '/etc/taky.conf'".into())
        );
        let f = ConfigFailure::classify(None, &ConfigError::InvalidPort("x".into()));
        assert_eq!(
            f,
            ConfigFailure::Config("Configuration file error: Invalid port: x".into())
        );
        assert_eq!(f.exit_code(), 1);
        assert_eq!(
            f.render(None),
            "Configuration file error: Invalid port: x\n"
        );
    }

    #[test]
    fn defaults() {
        let a = try_parse_from(["taky-rs"]).unwrap();
        assert_eq!(a.level(), PyLevel::Info);
        assert_eq!(a.cfg_file, None);
        assert!(!a.debug);
    }

    #[test]
    fn flags() {
        let a =
            try_parse_from(["taky-rs", "-l", "debug", "-c", "/etc/taky/taky.conf", "-d"]).unwrap();
        assert_eq!(a.level(), PyLevel::Debug);
        assert_eq!(a.cfg_file, Some(PathBuf::from("/etc/taky/taky.conf")));
        assert!(a.debug);
    }

    #[test]
    fn bad_level_is_usage_error() {
        let e = try_parse_from(["taky-rs", "-l", "INFO"]).unwrap_err();
        assert_eq!(e.exit_code(), 2);
    }

    #[test]
    fn version_text() {
        let e = try_parse_from(["/usr/bin/taky-rs", "--version"]).unwrap_err();
        assert_eq!(e.kind(), clap::error::ErrorKind::DisplayVersion);
        assert_eq!(
            e.to_string(),
            format!("taky-rs version {}\n", taky_common::VERSION)
        );
        assert_eq!(e.exit_code(), 0);
    }
}
