//! Data Package Server for taky-rs (owner: dev02): Marti API on axum + rustls, DPS storage,
//! identity middleware; binary `taky_dps-rs` (ARCHITECTURE §1, §2, §12, ADR-004).
//!
//! Seams (S-202, signatures defined by dev01; bodies `todo!()` — dev02, block 3D S-316..S-318):
//! [`start`] on a ready-made `TcpListener` (qa01 request A.3), [`bind`] for the binary.
//! With feature `testkit` the injected clock drives `SubmissionDateTime`.

pub mod cli;

use std::net::SocketAddr;
use std::sync::Arc;

use taky_common::{SharedClock, Shutdown};
use taky_config::TakyConfig;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

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

/// Bind per config: `bind_ip:8443` with SSL, `bind_ip:8080` without (hardcoded, as the original).
pub async fn bind(cfg: &TakyConfig) -> std::io::Result<TcpListener> {
    let _ = cfg;
    todo!("dev02: S-318")
}

/// Start serving on `listener` (TLS when `ssl.enabled`, client cert optional).
/// Returns once the accept loop runs.
pub async fn start(opts: DpsOptions, listener: TcpListener) -> anyhow::Result<RunningDps> {
    let _ = (opts, listener);
    todo!("dev02: S-318")
}
