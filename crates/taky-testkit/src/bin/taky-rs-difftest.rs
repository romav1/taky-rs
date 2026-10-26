//! `taky-rs-difftest` — Rust CoT target of the difftest harness (qa01, S-315; test-only).
//!
//! Runs the real taky-rs CoT server — `taky_config::load_config` → [`Listeners::bind`] →
//! [`start`], the same code path as the `taky-rs` binary — but with a frozen
//! [`FakeClock`] instead of `SystemClock`, plus the black-box hooks of
//! `tools/difftest/harness/pylaunch_cot.py` (same contract as the Python launcher):
//!
//! ```text
//! taky-rs-difftest --conf <taky.conf> --now <ISO-8601 UTC> --ctl <dir> [--log-level info]
//! ```
//!
//! * `<ctl>/ready` (pid) after the listeners are bound and the server is started;
//! * control channel: the harness writes `<ctl>/cmd.json` and sends SIGUSR1; the command is
//!   executed and acknowledged in `<ctl>/ack.json` (both written atomically):
//!   `{"seq": n, "advance": seconds}` → clock += seconds, then a Hub settle barrier;
//!   `{"seq": n, "persist": true}` → ack carries `{"backend": "memory", "uids": [...]}` (sorted,
//!   `HubHandle::persist_snapshot`) or `{"backend": "redis"}` (the harness dumps Redis itself);
//!   `{"seq": n, "settle": true}` → Hub settle barrier only;
//! * SIGTERM/SIGINT → graceful shutdown, exit 0; a server that stops on its own (Hub panic) →
//!   `<ctl>/crash.txt`, exit 1.
//!
//! **Keep in sync with the `taky-rs` binary** (`crates/taky-server/src/bin/taky-rs.rs`,
//! review-3E N-4): this `main`/`run` mirror its `main` and `run` — `taky_config::load_config`
//! → multi-thread runtime → signal handlers before the sockets → [`Listeners::bind`] (same
//! stale mgmt-socket check) → [`start`] with [`ServerOptions`] → wait → `Shutdown::trigger` →
//! `RunningServer::join` within `SHUTDOWN_LIMIT` (10 s) → `shutdown_timeout(1 s)`. When the
//! startup sequence there changes (new `ServerOptions` field, new listener, another step
//! between `load_config` and `start`), change it here too, or switch both to a shared helper
//! if dev01 ever factors one out of `taky-rs.rs`. Deliberate differences, and only these:
//! * clock: [`FakeClock`] frozen at `--now` (advanced via the control channel) instead of
//!   `SystemClock`;
//! * arguments: the minimal parser above (`--conf/--now/--ctl/--log-level`) instead of
//!   `taky_server::cli` (clap) — no `ConfigFailure` rendering/exit 2, no `taky-rs v…` banner;
//!   `load_config(Some(conf), true)` (an explicit `-c` file);
//! * SIGUSR1 runs the control channel ([`handle_ctl`]) instead of being ignored; the
//!   `<ctl>/ready` marker after `start`; `<ctl>/crash.txt` when the server stops without a
//!   signal;
//! * logging: startup/config errors go to stderr via `eprintln!` (the same
//!   `ERROR:root:Unable to start COTServer: <err>` text); no `Got SIGTERM`/`Got SIGINT` or
//!   `Exception during shutdown` lines.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use chrono::{NaiveDateTime, TimeDelta};
use serde_json::{Value, json};
use taky_common::Shutdown;
use taky_common::clock::FakeClock;
use taky_common::log::PyLevel;
use taky_config::{RedisSetting, TakyConfig};
use taky_server::{HubHandle, Listeners, ServerOptions, start};
use tokio::signal::unix::{SignalKind, signal};

const SHUTDOWN_LIMIT: Duration = Duration::from_secs(10);

struct Args {
    conf: PathBuf,
    now: NaiveDateTime,
    ctl: PathBuf,
    level: PyLevel,
}

fn parse_args() -> Result<Args, String> {
    let mut conf = None;
    let mut now = None;
    let mut ctl = None;
    let mut level = PyLevel::Info;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("{a}: missing value"));
        match a.as_str() {
            "--conf" => conf = Some(PathBuf::from(val()?)),
            "--now" => now = Some(parse_now(&val()?)?),
            "--ctl" => ctl = Some(PathBuf::from(val()?)),
            "--log-level" => {
                let v = val()?;
                level = v.parse().map_err(|_| format!("bad --log-level {v}"))?;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Args {
        conf: conf.ok_or("--conf is required")?,
        now: now.ok_or("--now is required")?,
        ctl: ctl.ok_or("--ctl is required")?,
        level,
    })
}

fn parse_now(s: &str) -> Result<NaiveDateTime, String> {
    let s = s.trim_end_matches('Z');
    NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
        .map_err(|e| format!("bad --now {s}: {e}"))
}

fn atomic_write(path: &Path, data: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("taky-rs-difftest: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = taky_common::log::init(args.level) {
        eprintln!("taky-rs-difftest: {e}");
    }
    let cfg = match taky_config::load_config(Some(&args.conf), true) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("taky-rs-difftest: config: {e}");
            return ExitCode::FAILURE;
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("taky-rs-difftest: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let code = rt.block_on(run(cfg, args));
    rt.shutdown_timeout(Duration::from_secs(1));
    code
}

async fn run(cfg: TakyConfig, args: Args) -> ExitCode {
    let (mut term, mut int, mut usr1) = match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
        signal(SignalKind::user_defined1()),
    ) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        _ => {
            eprintln!("taky-rs-difftest: cannot install signal handlers");
            return ExitCode::FAILURE;
        }
    };
    let redis = !matches!(cfg.taky.redis, RedisSetting::Disabled);
    let clock = FakeClock::new(args.now);
    let listeners = match Listeners::bind(&cfg).await {
        Ok(l) => l,
        Err(e) => return startup_failed(&e),
    };
    let shutdown = Shutdown::new();
    let opts = ServerOptions {
        cfg: Arc::new(cfg),
        clock: clock.shared(),
        shutdown: shutdown.clone(),
    };
    let server = match start(opts, listeners).await {
        Ok(s) => s,
        Err(e) => return startup_failed(&e),
    };
    let hub = server.hub.clone();
    if let Err(e) = atomic_write(&args.ctl.join("ready"), &std::process::id().to_string()) {
        eprintln!("taky-rs-difftest: ready marker: {e}");
        return ExitCode::FAILURE;
    }

    let by_signal = loop {
        tokio::select! {
            _ = term.recv() => break true,
            _ = int.recv() => break true,
            _ = usr1.recv() => {
                if let Err(e) = handle_ctl(&args.ctl, &clock, &hub, redis).await {
                    eprintln!("taky-rs-difftest: control command failed: {e}");
                }
            }
            () = shutdown.wait() => break false,
        }
    };
    shutdown.trigger();
    let joined = tokio::time::timeout(SHUTDOWN_LIMIT, server.join()).await;
    if !by_signal {
        let why = match &joined {
            Ok(Err(e)) => format!("ServerStopped: {e}"),
            _ => "ServerStopped: the server stopped without a signal".to_owned(),
        };
        let _ = atomic_write(&args.ctl.join("crash.txt"), &why);
        return ExitCode::FAILURE;
    }
    match joined {
        Ok(Ok(())) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

async fn handle_ctl(
    ctl: &Path,
    clock: &Arc<FakeClock>,
    hub: &HubHandle,
    redis: bool,
) -> Result<(), String> {
    let raw = std::fs::read_to_string(ctl.join("cmd.json")).map_err(|e| e.to_string())?;
    let cmd: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let mut ack = json!({"seq": cmd["seq"].clone()});
    if let Some(secs) = cmd.get("advance").and_then(Value::as_f64) {
        // Microsecond resolution, like Python's datetime arithmetic.
        clock.advance(TimeDelta::microseconds((secs * 1_000_000.0).round() as i64));
        hub.settle().await;
    }
    if cmd.get("settle").and_then(Value::as_bool) == Some(true) {
        hub.settle().await;
    }
    if cmd.get("persist").and_then(Value::as_bool) == Some(true) {
        ack["persist"] = if redis {
            json!({"backend": "redis"})
        } else {
            let uids: Vec<Value> = hub
                .persist_snapshot()
                .await
                .iter()
                .map(|e| e.uid.clone().map_or(Value::Null, Value::String))
                .collect();
            json!({"backend": "memory", "uids": uids})
        };
    }
    atomic_write(&ctl.join("ack.json"), &ack.to_string()).map_err(|e| e.to_string())
}

fn startup_failed(e: &dyn std::fmt::Display) -> ExitCode {
    eprintln!("ERROR:root:Unable to start COTServer: {e}");
    ExitCode::FAILURE
}
