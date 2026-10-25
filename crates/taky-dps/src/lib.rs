//! Data Package Server for taky-rs (owner: dev02): Marti API on axum + rustls, DPS storage,
//! identity middleware; binary `taky_dps-rs` (ARCHITECTURE §1, §2, §12, ADR-004).
//!
//! Seams (S-202): [`start`] on a ready-made `TcpListener` (qa01 request A.3), [`bind`] for the
//! binary; [`DpsApp::serve_connection`] serves one stream with an arbitrary peer address
//! (black-box runners: `remote-addr`). With feature `testkit` the injected clock drives
//! `SubmissionDateTime`.
//!
//! Status: S-316 — accept loop, TLS identity, G-6 plain-mode policy, routing/404/405,
//! `/`, `/Marti/api/version[/config]`, `/Marti/api/clientEndPoints`; S-317 — storage
//! ([`storage`]), search, content, missionupload, metadata tool, missionquery. KML and vcm answer
//! `501` after auth until S-318.

pub mod app;
pub mod cli;
mod conn;
mod datapackage;
pub mod identity;
pub mod mimetypes;
pub mod storage;
mod werkzeug;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use taky_common::{SharedClock, Shutdown};
use taky_config::TakyConfig;
use taky_pki::{CertDb, TlsMode};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub use app::{RequireAuth, version_string};

/// Everything DPS needs besides the socket.
#[derive(Debug, Clone)]
pub struct DpsOptions {
    /// Loaded configuration (`dp_server.upload_path`, `[ssl]`, `taky.bind_ip`).
    pub cfg: Arc<TakyConfig>,
    /// Clock for `SubmissionDateTime` and cert-db revoke.
    pub clock: SharedClock,
    /// Graceful shutdown signal.
    pub shutdown: Shutdown,
}

/// A started DPS.
#[derive(Debug)]
pub struct RunningDps {
    /// Bound address.
    pub local_addr: SocketAddr,
    /// The server task; resolves after shutdown completes.
    pub task: JoinHandle<anyhow::Result<()>>,
}

impl RunningDps {
    /// Wait for DPS to finish (trigger `DpsOptions::shutdown` first).
    pub async fn join(self) -> anyhow::Result<()> {
        self.task.await?
    }
}

/// DPS port: `8443` with SSL, `8080` without (hardcoded, as the original).
pub fn port(cfg: &TakyConfig) -> u16 {
    if cfg.ssl.enabled { 8443 } else { 8080 }
}

/// Bind per config: `bind_ip:8443` with SSL, `bind_ip:8080` without; empty/unset `bind_ip` ⇒ all
/// IPv4 addresses (gunicorn `":8443"`); a host name is resolved.
pub async fn bind(cfg: &TakyConfig) -> std::io::Result<TcpListener> {
    let port = port(cfg);
    let host = cfg.taky.bind_ip.as_deref().unwrap_or("").trim();
    if host.is_empty() {
        return TcpListener::bind((IpAddr::from([0, 0, 0, 0]), port)).await;
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<IpAddr>() {
        Ok(ip) => TcpListener::bind((ip, port)).await,
        Err(_) => TcpListener::bind((host, port)).await,
    }
}

/// The DPS application without a listener: one connection at a time via
/// [`DpsApp::serve_connection`]. [`start`] wraps it in the accept loop.
#[derive(Clone)]
pub struct DpsApp {
    ctx: Arc<conn::Ctx>,
    shutdown: Shutdown,
}

impl std::fmt::Debug for DpsApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpsApp")
            .field("tls", &self.is_tls())
            .finish_non_exhaustive()
    }
}

impl DpsApp {
    /// Build the app from the config: TLS (`ssl.enabled`, client cert optional, ADR-003) with
    /// cert-db `ssl.cert_db`, otherwise plain HTTP with the G-6 header policy.
    pub fn new(opts: &DpsOptions) -> anyhow::Result<DpsApp> {
        let cfg = &opts.cfg;
        let scheme = if cfg.ssl.enabled { "ssl" } else { "tcp" };
        let state = app::AppState {
            hostname: cfg.taky.hostname.clone(),
            node_id: cfg.taky.node_id.clone(),
            cot_conn_str: format!("{scheme}:{}:{}", cfg.taky.hostname, cfg.cot_server.port),
            tls: cfg.ssl.enabled,
            store: storage::Store {
                root: cfg.dp_server.upload_path.clone(),
            },
            clock: opts.clock.clone(),
        };
        let (tls, certdb) = if cfg.ssl.enabled {
            let sc =
                taky_pki::server_config(&cfg.ssl, TlsMode::Dps).context("DPS TLS configuration")?;
            let db = CertDb::open(&cfg.ssl.cert_db)
                .with_context(|| format!("cert-db {}", cfg.ssl.cert_db.display()))?;
            (
                Some(tokio_rustls::TlsAcceptor::from(sc)),
                Some(Mutex::new(db)),
            )
        } else {
            (None, None)
        };
        Ok(DpsApp {
            ctx: Arc::new(conn::Ctx {
                router: app::router(Arc::new(state)),
                tls,
                certdb,
            }),
            shutdown: opts.shutdown.clone(),
        })
    }

    /// `true` in TLS mode.
    pub fn is_tls(&self) -> bool {
        self.ctx.tls.is_some()
    }

    /// Serve one accepted stream whose peer is `peer` (TLS handshake first in TLS mode); returns
    /// when the connection closes or after graceful shutdown.
    pub async fn serve_connection<IO>(&self, io: IO, peer: SocketAddr)
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.ctx
            .clone()
            .serve_connection(io, peer, self.shutdown.clone())
            .await;
    }
}

/// Start serving on `listener` (TLS when `ssl.enabled`, client cert optional).
/// Returns once the accept loop runs.
pub async fn start(opts: DpsOptions, listener: TcpListener) -> anyhow::Result<RunningDps> {
    let app = DpsApp::new(&opts)?;
    let local_addr = listener.local_addr()?;
    let task = tokio::spawn(conn::accept_loop(listener, app.ctx, opts.shutdown.clone()));
    Ok(RunningDps { local_addr, task })
}
