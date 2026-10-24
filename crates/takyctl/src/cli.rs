//! `takyctl-rs` arguments, 1:1 with `taky/cli/*.py` (`*_reg` functions).

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{ArgAction, CommandFactory, FromArgMatches, Parser, Subcommand};

/// Program name used when `argv[0]` is unavailable.
pub const DEFAULT_PROG: &str = "takyctl-rs";

/// Global `takyctl-rs` arguments (`cli/__main__.py:arg_parse`).
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

    /// show program's version number and exit
    #[arg(long = "version", action = ArgAction::Version)]
    version: Option<bool>,

    /// Subcommand; `None` — usage on stdout, exit code 1.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Subcommands.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Setup the taky server
    #[command(name = "setup")]
    Setup(SetupArgs),
    /// Build client file
    #[command(name = "build_client")]
    BuildClient(BuildClientArgs),
    /// Generate systemd service scripts
    #[command(name = "systemd")]
    Systemd(SystemdArgs),
    /// Check the status of the taky server
    #[command(name = "status")]
    Status(StatusArgs),
    /// Kick and banish a user
    #[command(name = "kickban")]
    Kickban(KickbanArgs),
}

impl Command {
    /// Subcommand name as typed (used in `"<cmd> failed: <err>"`).
    pub fn name(&self) -> &'static str {
        match self {
            Command::Setup(_) => "setup",
            Command::BuildClient(_) => "build_client",
            Command::Systemd(_) => "systemd",
            Command::Status(_) => "status",
            Command::Kickban(_) => "kickban",
        }
    }
}

/// `setup` (`cli/setup_taky_cmd.py:setup_taky_reg`).
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct SetupArgs {
    /// Password for server .p12
    #[arg(long = "p12_pw", default_value = "atakatak")]
    pub p12_pw: String,
    /// User/group for file permissions
    #[arg(long = "user")]
    pub user: Option<String>,
    /// Disable SSL for the server
    #[arg(long = "no-ssl", action = ArgAction::SetFalse)]
    pub use_ssl: bool,
    /// Server hostname [default: system hostname, "taky" if unavailable]
    #[arg(long = "host")]
    pub hostname: Option<String>,
    /// Bind Address
    #[arg(long = "bind-ip", default_value = "0.0.0.0")]
    pub ip: String,
    /// Public IP address
    #[arg(long = "public-ip", required = true)]
    pub public_ip: String,
    /// Optional path for taky install
    pub path: Option<PathBuf>,
}

/// `build_client` (`cli/build_client_cmd.py:build_client_reg`).
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct BuildClientArgs {
    /// Name for client
    pub name: String,
    /// Generate for iTAK instead of ATAK
    #[arg(long = "is_itak")]
    pub is_itak: bool,
    /// Password for server .p12
    #[arg(long = "p12_pw", default_value = "atakatak")]
    pub p12_pw: String,
    /// Save the .crt/.key files
    #[arg(long = "dump_pem")]
    pub dump_pem: bool,
}

/// `systemd` (`cli/systemd_cmd.py:systemd_reg`).
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct SystemdArgs {
    /// Where to store the systemd scripts
    #[arg(long = "path", default_value = "/etc/systemd/system")]
    pub path: PathBuf,
    /// Only write service files, do not activate
    #[arg(long = "no-install", action = ArgAction::SetFalse)]
    pub install: bool,
    /// Do not enable the Data Package Server
    #[arg(long = "no-dps", action = ArgAction::SetFalse)]
    pub dps: bool,
    /// Specify a user to run as
    #[arg(short = 'u', long = "user")]
    pub user: Option<String>,
}

/// `status` (`cli/status_cmd.py:status_reg`).
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct StatusArgs {
    /// Explicitly specify a socket to connect to
    #[arg(short = 'U', value_name = "SOCKET")]
    pub socket: Option<PathBuf>,
    /// Output the status in JSON
    #[arg(short = 'j', long = "json")]
    pub json: bool,
}

/// `kickban` (`cli/kickban_cmd.py:kickban_reg`).
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct KickbanArgs {
    /// Explicitly specify a socket to connect to
    #[arg(short = 'U', value_name = "SOCKET")]
    pub socket: Option<PathBuf>,
    /// Output the status in JSON
    #[arg(short = 'j', long = "json")]
    pub json: bool,
    /// Name for client
    pub name: String,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_flags_and_defaults() {
        let a = try_parse_from([
            "takyctl-rs",
            "-c",
            "x.conf",
            "setup",
            "--public-ip",
            "1.2.3.4",
        ])
        .unwrap();
        assert_eq!(a.cfg_file, Some(PathBuf::from("x.conf")));
        let Some(Command::Setup(s)) = a.command else {
            panic!("expected setup")
        };
        assert_eq!(s.p12_pw, "atakatak");
        assert!(s.use_ssl);
        assert_eq!(s.ip, "0.0.0.0");
        assert_eq!(s.public_ip, "1.2.3.4");
        assert_eq!(s.path, None);
    }

    #[test]
    fn setup_requires_public_ip() {
        let e = try_parse_from(["takyctl-rs", "setup"]).unwrap_err();
        assert_eq!(e.exit_code(), 2);
    }

    #[test]
    fn long_prefixes_like_argparse() {
        let a =
            try_parse_from(["takyctl-rs", "build_client", "--p12", "pw", "--is", "bob"]).unwrap();
        let Some(Command::BuildClient(b)) = a.command else {
            panic!("expected build_client")
        };
        assert_eq!(
            (b.name.as_str(), b.p12_pw.as_str(), b.is_itak),
            ("bob", "pw", true)
        );

        let a =
            try_parse_from(["takyctl-rs", "systemd", "--no-i", "--no-d", "-u", "taky"]).unwrap();
        let Some(Command::Systemd(s)) = a.command else {
            panic!("expected systemd")
        };
        assert!(!s.install && !s.dps);
        assert_eq!(s.path, PathBuf::from("/etc/systemd/system"));
    }

    #[test]
    fn status_kickban_and_no_command() {
        let a = try_parse_from(["takyctl-rs", "status", "-j", "-U", "/tmp/s.sock"]).unwrap();
        assert!(matches!(
            a.command,
            Some(Command::Status(StatusArgs { json: true, .. }))
        ));
        let a = try_parse_from(["takyctl-rs", "kickban", "alice"]).unwrap();
        assert_eq!(a.command.as_ref().map(Command::name), Some("kickban"));
        assert_eq!(try_parse_from(["takyctl-rs"]).unwrap().command, None);
    }

    #[test]
    fn version_text() {
        let e = try_parse_from(["takyctl-rs", "--version"]).unwrap_err();
        assert_eq!(
            e.to_string(),
            format!("takyctl-rs version {}\n", taky_common::VERSION)
        );
    }
}
