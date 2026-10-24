//! `taky-rs` — CoT server binary (Python: `taky = taky.cot.__main__:main`).
//!
//! Status: S-201 stub — arguments are parsed, the server itself is not implemented yet (S-314).

use std::process::ExitCode;

fn main() -> ExitCode {
    let _args = taky_server::cli::parse();
    eprintln!("taky-rs: not implemented");
    ExitCode::FAILURE
}
