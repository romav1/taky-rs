//! `takyctl-rs` — taky command line utility (Python: `takyctl = taky.cli.__main__:main`).
//!
//! Arguments are parsed 1:1 with the original (ARCHITECTURE §2, §2.1). Implemented: `setup`,
//! `build_client` (S-322); `systemd`, `status`, `kickban` fail with
//! `"<cmd> failed: not implemented"` and exit code 1 until S-323.

use std::process::ExitCode;

use takyctl::cli::{self, Command};

fn run(args: &cli::Args, cmd: &Command) -> anyhow::Result<u8> {
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    match cmd {
        Command::Setup(a) => takyctl::setup::setup(
            a,
            &takyctl::setup::SetupEnv::from_process()?,
            &mut out,
            &mut err,
        ),
        Command::BuildClient(a) => takyctl::build_client::build_client(
            a,
            args.cfg_file.as_deref(),
            &std::env::current_dir()?,
            chrono::Utc::now().naive_utc(),
            &mut err,
        ),
        Command::Systemd(_) | Command::Status(_) | Command::Kickban(_) => {
            anyhow::bail!("not implemented")
        }
    }
}

fn main() -> ExitCode {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let argv0 = argv.first().and_then(|a| a.to_str()).map(str::to_owned);
    let args = cli::try_parse_from(argv).unwrap_or_else(|e| e.exit());

    let Some(cmd) = args.command.as_ref() else {
        // argparse `print_usage()` goes to stdout; exit code 1 (cli/__main__.py).
        print!("{}", cli::command(argv0.as_deref()).render_usage());
        println!();
        return ExitCode::FAILURE;
    };

    match run(&args, cmd) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            // cli/__main__.py:55-59 (no Python traceback; the error chain instead).
            eprintln!("{} failed: {e}", cmd.name());
            eprintln!("Unhandled exception:");
            eprintln!("{e:?}\n");
            ExitCode::FAILURE
        }
    }
}
