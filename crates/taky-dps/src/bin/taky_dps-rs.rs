//! `taky_dps-rs` — Data Package Server binary (Python: `taky_dps = taky.dps.__main__:main`,
//! spec dps-cli-config §2.1).
//!
//! Config, bind (8443/8080), serve until SIGINT/SIGTERM, `DONE`; Python `logging` format on
//! stderr (`-l`, `RUST_LOG`) with one `Listening at: http[s]://<addr>` INFO line at startup (like
//! gunicorn), gunicorn-style access log on stdout.

use std::process::ExitCode;
use std::sync::Arc;

use taky_common::{Shutdown, SystemClock};
use taky_dps::{DpsOptions, cli};

fn main() -> ExitCode {
    let args = cli::parse();
    let argv0 = std::env::args().next();
    let prog = taky_common::prog_name(argv0.as_deref(), cli::DEFAULT_PROG).to_owned();
    // __main__.py:128 `logging.basicConfig(level=args.log_level.upper(), stream=sys.stderr)`,
    // before the config is loaded.
    if let Err(e) = taky_common::log::init(args.level()) {
        eprintln!("{prog}: {e}");
    }
    // gunicorn `accesslog="-"` and the views' `print()`s.
    taky_dps::set_stdout_output(true);

    // __main__.py:131-139: TAKY_CONFIG or -c ⇒ explicit; otherwise the default lookup.
    let path = args.config_path(std::env::var_os(cli::ENV_TAKY_CONFIG));
    let cfg = match taky_config::load_config(path.as_deref(), path.is_some()) {
        Ok(c) => c,
        Err(e) => {
            // argparse `argp.error(str(exc))`.
            eprintln!(
                "usage: {prog} [-h] [-c CFG_FILE] [-l {{debug,info,warning,error,critical}}] [--version]\n{prog}: error: {e}"
            );
            return ExitCode::from(2);
        }
    };

    let dp_path = &cfg.dp_server.upload_path;
    if !dp_path.exists() {
        let line = "-".repeat(30);
        eprintln!(
            "{line}\n[ WARNING ] Datapackage directory does not exist!\n            Please create it, or check permissions.\nCurrent Settings:\n  [dp_server]\n  upload_path = {}\n{line}",
            dp_path.display()
        );
    }

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("{prog}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let res = rt.block_on(async move {
        let shutdown = Shutdown::new();
        let listener = taky_dps::bind(&cfg).await?;
        let tls = cfg.ssl.enabled;
        let opts = DpsOptions {
            cfg: Arc::new(cfg),
            clock: SystemClock::shared(),
            shutdown: shutdown.clone(),
        };
        let dps = taky_dps::start(opts, listener).await?;
        // Operators look for gunicorn's "Listening at: https://…" line (S-503).
        taky_common::pylog!(
            "taky.dps",
            tracing::Level::INFO,
            "{}",
            taky_dps::listening_line(tls, dps.local_addr)
        );
        wait_signal().await;
        shutdown.trigger();
        dps.join().await
    });
    match res {
        Ok(()) => {
            println!("DONE");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{prog}: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn wait_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
