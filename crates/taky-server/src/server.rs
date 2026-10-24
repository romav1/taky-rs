//! Server assembly: listeners → accept tasks → conn tasks → Hub (ARCHITECTURE §4.1, §10).
//!
//! [`start`] takes **ready-made** listeners, so tests bind `127.0.0.1:0` and read the
//! addresses back (qa01 request A.3); the binary uses [`Listeners::bind`].

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use taky_common::{SharedClock, Shutdown};
use taky_config::TakyConfig;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::hub::HubHandle;

/// Sockets the server serves.
#[derive(Debug)]
pub struct Listeners {
    /// CoT listener (TCP, or TLS when `ssl.enabled`).
    pub cot: TcpListener,
    /// Monitor listener (only with SSL and `mon_ip` set).
    pub monitor: Option<TcpListener>,
    /// Mgmt unix socket path (`{root_dir}/taky-mgmt.sock`); `None` — no mgmt (tests).
    pub mgmt_socket: Option<PathBuf>,
}

impl Listeners {
    /// Bind per config: `bind_ip:port`, `mon_ip:mon_port`, `{root_dir}/taky-mgmt.sock`.
    pub async fn bind(cfg: &TakyConfig) -> std::io::Result<Listeners> {
        let _ = cfg;
        todo!("dev02: S-314")
    }
}

/// Everything the server needs besides sockets.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    /// Loaded configuration.
    pub cfg: Arc<TakyConfig>,
    /// Clock for Router/Persistence/mgmt (`SystemClock` in production, `FakeClock` in tests).
    pub clock: SharedClock,
    /// Graceful shutdown signal (SIGTERM/SIGINT in the binary).
    pub shutdown: Shutdown,
}

/// A started server.
#[derive(Debug)]
pub struct RunningServer {
    /// Bound CoT address.
    pub local_addr: SocketAddr,
    /// Bound monitor address.
    pub monitor_addr: Option<SocketAddr>,
    /// Hub sender (testkit: `settle()`).
    pub hub: HubHandle,
    /// The server task; resolves after shutdown completes.
    pub task: JoinHandle<anyhow::Result<()>>,
}

impl RunningServer {
    /// Wait for the server to finish (trigger `ServerOptions::shutdown` first).
    pub async fn join(self) -> anyhow::Result<()> {
        self.task.await?
    }
}

/// Start serving on `listeners`: TLS config + cert-db (if SSL), Persistence, Router, Hub,
/// accept loops. Returns once everything is listening.
pub async fn start(opts: ServerOptions, listeners: Listeners) -> anyhow::Result<RunningServer> {
    let _ = (opts, listeners);
    todo!("dev02: S-314")
}
