//! `taky_dps-rs` — Data Package Server binary (Python: `taky_dps = taky.dps.__main__:main`).
//!
//! Status: S-201 stub — arguments are parsed, the server itself is not implemented yet (S-316).

use std::process::ExitCode;

fn main() -> ExitCode {
    let _args = taky_dps::cli::parse();
    eprintln!("taky_dps-rs: not implemented");
    ExitCode::FAILURE
}
