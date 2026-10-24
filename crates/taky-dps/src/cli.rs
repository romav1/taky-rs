//! `taky_dps-rs` command line, 1:1 with `taky/dps/__main__.py` (ARCHITECTURE §2, §2.1).
//!
//! `--version` prints `"<prog> version <VERSION>"` (ADR-008 G-3). The `TAKY_CONFIG` environment
//! variable takes priority over `-c` (see [`Args::config_path`]).

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{ArgAction, CommandFactory, FromArgMatches, Parser};
use taky_common::log::PyLevel;

/// Program name used when `argv[0]` is unavailable.
pub const DEFAULT_PROG: &str = "taky_dps-rs";

/// Environment variable with the config path; overrides `-c`.
pub const ENV_TAKY_CONFIG: &str = "TAKY_CONFIG";

/// Parsed `taky_dps-rs` arguments.
#[derive(Debug, Clone, PartialEq, Eq, Parser)]
#[command(
    name = DEFAULT_PROG,
    about = "Taky command line utility",
    disable_version_flag = true,
    infer_long_args = true
)]
pub struct Args {
    /// Path to configuration file
    #[arg(short = 'c', value_name = "CFG_FILE")]
    pub cfg_file: Option<PathBuf>,

    /// Log verbosity [default: INFO]
    // The original's default "INFO" is outside `choices` (argparse does not validate defaults),
    // so the default is applied in `Args::level`, not by clap.
    #[arg(
        short = 'l',
        value_name = "{debug,info,warning,error,critical}",
        value_parser = ["debug", "info", "warning", "error", "critical"]
    )]
    pub log_level: Option<String>,

    /// show program's version number and exit
    #[arg(long = "version", action = ArgAction::Version)]
    version: Option<bool>,
}

impl Args {
    /// Log level as [`PyLevel`]; `INFO` when `-l` is not given.
    pub fn level(&self) -> PyLevel {
        self.log_level
            .as_deref()
            .and_then(|l| l.parse().ok())
            .unwrap_or(PyLevel::Info)
    }

    /// Config path: `TAKY_CONFIG` (value of `env`, if set) first, then `-c`.
    pub fn config_path(&self, env: Option<OsString>) -> Option<PathBuf> {
        env.map(PathBuf::from).or_else(|| self.cfg_file.clone())
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
    fn defaults_and_env_priority() {
        let a = try_parse_from(["taky_dps-rs", "-c", "a.conf"]).unwrap();
        assert_eq!(a.level(), PyLevel::Info);
        assert_eq!(a.config_path(None), Some(PathBuf::from("a.conf")));
        assert_eq!(
            a.config_path(Some("b.conf".into())),
            Some(PathBuf::from("b.conf"))
        );
    }

    #[test]
    fn version_text() {
        let e = try_parse_from(["./taky_dps-rs", "--version"]).unwrap_err();
        assert_eq!(
            e.to_string(),
            format!("taky_dps-rs version {}\n", taky_common::VERSION)
        );
    }
}
