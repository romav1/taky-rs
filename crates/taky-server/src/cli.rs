//! `taky-rs` command line, 1:1 with `taky/cot/__main__.py:arg_parse` (ARCHITECTURE §2, §2.1).
//!
//! `--version` prints `"<prog> version <VERSION>"` (ADR-008 G-3), where `prog` is the basename
//! of `argv[0]`, as in argparse.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{ArgAction, CommandFactory, FromArgMatches, Parser};
use taky_common::log::PyLevel;

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

    /// Accepted and ignored (PDB on SIGUSR1 in the original; ARCHITECTURE §2.1)
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

#[cfg(test)]
mod tests {
    use super::*;

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
