//! `takyctl-rs` — taky command line utility (Python: `takyctl = taky.cli.__main__:main`).
//!
//! Status: S-201 stub — arguments are parsed 1:1 with the original (ARCHITECTURE §2, §2.1),
//! every subcommand fails with `"<cmd> failed: not implemented"` and exit code 1.
//! Implementation — block 3E (S-320..S-323).

mod cli;

use std::process::ExitCode;

fn main() -> ExitCode {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let argv0 = argv.first().and_then(|a| a.to_str()).map(str::to_owned);
    let args = cli::try_parse_from(argv).unwrap_or_else(|e| e.exit());

    let Some(cmd) = args.command else {
        // argparse `print_usage()` goes to stdout; exit code 1 (cli/__main__.py).
        print!("{}", cli::command(argv0.as_deref()).render_usage());
        println!();
        return ExitCode::FAILURE;
    };

    eprintln!("{} failed: not implemented", cmd.name());
    ExitCode::FAILURE
}
