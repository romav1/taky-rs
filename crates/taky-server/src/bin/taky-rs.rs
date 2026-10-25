//! `taky-rs` — CoT server binary (Python: `taky = taky.cot.__main__:main`; spec cot-server.md §1,
//! ARCHITECTURE §2, §10).
//!
//! Sequence: arguments (clap, argparse-compatible) → logging (`LEVEL:logger:message` on stderr)
//! → `load_config` (lookup `./taky.conf` → `/etc/taky/taky.conf`, or `-c`) → signal handlers →
//! `Listeners::bind` + `start` → wait for SIGTERM/SIGINT → graceful shutdown.
//!
//! Exit codes: 0 after SIGTERM/SIGINT; 2 on an argument error or an unreadable config file
//! (argparse); 1 on a config file error, a startup error (`Unable to start COTServer: <err>`,
//! review-3B N-5), an unhandled server error, or a failed/overlong shutdown.

use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use taky_common::{Shutdown, SystemClock, VERSION, pylog};
use taky_config::TakyConfig;
use taky_server::cli::{self, ConfigFailure};
use taky_server::{Listeners, ServerOptions, start};
use tokio::signal::unix::{SignalKind, signal};
use tracing::Level;

/// Upper bound for the whole shutdown sequence (clients, listeners, mgmt socket).
const SHUTDOWN_LIMIT: Duration = Duration::from_secs(10);
/// Time given to leftover blocking tasks (CoT log writes) when the runtime is dropped.
const RUNTIME_DRAIN: Duration = Duration::from_secs(1);

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let argv0 = argv.first().and_then(|a| a.to_str()).map(str::to_owned);
    let args = cli::try_parse_from(&argv).unwrap_or_else(|e| e.exit());

    if let Err(e) = taky_common::log::init(args.level()) {
        eprintln!("taky-rs: {e}");
    }
    pylog!("root", Level::INFO, "taky-rs v{VERSION}");

    let cfg = match taky_config::load_config(args.cfg_file.as_deref(), false) {
        Ok(c) => c,
        Err(e) => {
            let f = ConfigFailure::classify(args.cfg_file.as_deref(), &e);
            eprint!("{}", f.render(argv0.as_deref()));
            return ExitCode::from(f.exit_code());
        }
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            pylog!("root", Level::ERROR, "Unable to start COTServer: {e}");
            return ExitCode::FAILURE;
        }
    };
    let code = rt.block_on(run(cfg, args.debug));
    rt.shutdown_timeout(RUNTIME_DRAIN);
    code
}

/// Signals, startup, main wait and shutdown (`__main__.py:87-117`).
async fn run(cfg: TakyConfig, debug: bool) -> ExitCode {
    // Handlers are installed before the sockets, like SigHdlr before sock_setup. SIGUSR1 is
    // caught (its default action would kill the process) and ignored (no PDB, OQ-01).
    let signals = (|| {
        Ok::<_, std::io::Error>((
            signal(SignalKind::terminate())?,
            signal(SignalKind::interrupt())?,
            signal(SignalKind::user_defined1())?,
        ))
    })();
    let (mut term, mut int, mut usr1) = match signals {
        Ok(s) => s,
        Err(e) => return startup_failed(&e),
    };

    let listeners = match Listeners::bind(&cfg).await {
        Ok(l) => l,
        Err(e) => return startup_failed(&e),
    };
    let shutdown = Shutdown::new();
    let opts = ServerOptions {
        cfg: Arc::new(cfg),
        clock: Arc::new(SystemClock),
        shutdown: shutdown.clone(),
    };
    let server = match start(opts, listeners).await {
        Ok(s) => s,
        Err(e) => return startup_failed(&e),
    };

    let by_signal = loop {
        tokio::select! {
            _ = term.recv() => {
                pylog!("root", Level::INFO, "Got SIGTERM");
                break true;
            }
            _ = int.recv() => {
                pylog!("root", Level::INFO, "Got SIGINT");
                break true;
            }
            _ = usr1.recv() => {
                if debug {
                    pylog!("root", Level::DEBUG, "SIGUSR1 ignored: no PDB shell in taky-rs");
                }
            }
            // The server stops on its own only after an unhandled error (already logged).
            () = shutdown.wait() => break false,
        }
    };
    shutdown.trigger();

    match tokio::time::timeout(SHUTDOWN_LIMIT, server.join()).await {
        Ok(Ok(())) if by_signal => ExitCode::SUCCESS,
        Ok(Ok(())) => ExitCode::FAILURE,
        Ok(Err(e)) => {
            if by_signal {
                tracing::error!(
                    lgr = "root",
                    critical = true,
                    "Exception during shutdown: {e}"
                );
            }
            ExitCode::FAILURE
        }
        Err(_) => {
            tracing::error!(
                lgr = "root",
                critical = true,
                "Exception during shutdown: not finished within {} s",
                SHUTDOWN_LIMIT.as_secs()
            );
            ExitCode::FAILURE
        }
    }
}

/// `Unable to start COTServer: <err>` (ERROR, logger `root`), exit 1 (spec §1.2 item 4, N-5).
fn startup_failed(e: &dyn std::fmt::Display) -> ExitCode {
    pylog!("root", Level::ERROR, "Unable to start COTServer: {e}");
    ExitCode::FAILURE
}
