//! Server assembly: listeners → accept tasks → conn tasks → Hub (ARCHITECTURE §4.1, §10).
//!
//! [`start`] takes **ready-made** listeners, so tests bind `127.0.0.1:0` and read the
//! addresses back (qa01 request A.3); the binary uses [`Listeners::bind`].

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use taky_common::{SharedClock, Shutdown, pylog};
use taky_config::TakyConfig;
use taky_cot::{ClientId, ClientKind, Persistence, Router};
use taky_pki::{CertDb, TlsMode, server_config};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, UnixListener, UnixStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_util::task::TaskTracker;
use tracing::Level;

use crate::conn::{self, ConnCtx};
use crate::hub::{Hub, HubHandle};
use crate::limits::CLOSE_TIMEOUT;

const LGR: &str = "COTServer";
/// Pause after a failed `accept` (e.g. out of descriptors).
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Sockets the server serves.
#[derive(Debug)]
pub struct Listeners {
    /// CoT listener (TCP, or TLS when `ssl.enabled`).
    pub cot: TcpListener,
    /// Monitor listener (only with SSL and `mon_ip` set).
    pub monitor: Option<TcpListener>,
    /// Mgmt unix socket, bound at `{root_dir}/taky-mgmt.sock` (spec §13); `None` — no mgmt.
    /// The socket file is removed when the server stops.
    pub mgmt: Option<UnixListener>,
}

/// Mgmt socket file name under `root_dir` (`server.py:100`).
pub const MGMT_SOCK_NAME: &str = "taky-mgmt.sock";
/// Python `socket.listen()` default backlog (`min(SOMAXCONN, 128)`).
const LISTEN_BACKLOG: u32 = 128;
/// `ping_socket` receive timeout (`server.py:58`).
const PING_TIMEOUT: Duration = Duration::from_secs(1);

impl Listeners {
    /// Bind per config, in the order of `COTServer.sock_setup` (spec §2): the mgmt socket
    /// `{root_dir}/taky-mgmt.sock`, then CoT `bind_ip:port`, then the monitor `mon_ip:mon_port`
    /// (only with SSL and `mon_ip` set).
    ///
    /// Mgmt: an existing socket file that answers a ping ⇒ error `Taky already appears to be
    /// running via <path>`; a stale one (no answer, any socket error, or not a socket) is
    /// removed and taken over. A mgmt bind error is logged (ERROR) and not fatal (`mgmt: None`).
    /// CoT/monitor: `SO_REUSEADDR`, backlog 128; `bind_ip`/`mon_ip` unset ⇒ all IPv4 addresses,
    /// otherwise the first `getaddrinfo` result (several ⇒ WARNING); a resolve error ⇒
    /// `Unable to determine address info for bind_ip: <ip>`. If a later bind fails, the mgmt
    /// socket file created here is removed again.
    pub async fn bind(cfg: &TakyConfig) -> std::io::Result<Listeners> {
        let mgmt_path = cfg.taky.root_dir.join(MGMT_SOCK_NAME);
        if !check_socket(&mgmt_path).await {
            return Err(std::io::Error::other(format!(
                "Taky already appears to be running via {}",
                mgmt_path.display()
            )));
        }
        let mgmt = match UnixListener::bind(&mgmt_path) {
            Ok(l) => Some(l),
            Err(e) => {
                pylog!(
                    LGR,
                    Level::ERROR,
                    "Unable to open management socket at {}: {e}",
                    mgmt_path.display()
                );
                None
            }
        };
        let guard = MgmtFileGuard(mgmt.as_ref().map(|_| mgmt_path.clone()));

        let cot = build_srv(cfg.taky.bind_ip.as_deref(), cfg.cot_server.port).await?;
        let monitor = match (&cfg.cot_server.mon_ip, cfg.ssl.enabled) {
            (Some(ip), true) => {
                let port = cfg.cot_server.mon_port.unwrap_or(8087);
                Some(build_srv(Some(ip), port).await?)
            }
            _ => None,
        };
        guard.disarm();
        Ok(Listeners { cot, monitor, mgmt })
    }
}

/// Removes the mgmt socket file on drop unless disarmed (failed bind / failed start).
struct MgmtFileGuard(Option<PathBuf>);

impl MgmtFileGuard {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for MgmtFileGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// `check_socket` (`server.py:39-48`): `true` if the path is free (possibly after removing a
/// stale file), `false` if a running server answered the ping.
async fn check_socket(path: &Path) -> bool {
    if std::fs::symlink_metadata(path).is_err() {
        return true;
    }
    if ping_socket(path).await {
        return false;
    }
    if let Err(e) = std::fs::remove_file(path) {
        // Python's os.remove would raise here; the bind below then reports the problem.
        pylog!(
            LGR,
            Level::DEBUG,
            "Unable to remove stale management socket {}: {e}",
            path.display()
        );
    }
    true
}

/// `ping_socket` (`server.py:51-64`): connect, send `{"cmd": "ping"}\0`, wait ≤ 1 s for any
/// reply byte.
async fn ping_socket(path: &Path) -> bool {
    let attempt = async {
        let mut s = UnixStream::connect(path).await?;
        s.write_all(b"{\"cmd\": \"ping\"}\0").await?;
        let mut buf = [0u8; 4096];
        let n = s.read(&mut buf).await?;
        std::io::Result::Ok(n > 0)
    };
    matches!(
        tokio::time::timeout(PING_TIMEOUT, attempt).await,
        Ok(Ok(true))
    )
}

/// `build_srv` (`server.py:15-36`).
async fn build_srv(ip: Option<&str>, port: u16) -> std::io::Result<TcpListener> {
    let addr = match ip {
        None => SocketAddr::from(([0, 0, 0, 0], port)),
        Some(ip) => {
            let unresolved = || {
                std::io::Error::other(format!(
                    "Unable to determine address info for bind_ip: {ip}"
                ))
            };
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((ip, port))
                .await
                .map_err(|_| unresolved())?
                .collect();
            if addrs.len() > 1 {
                pylog!(
                    "root",
                    Level::WARN,
                    "Multiple address entities for {ip}:{port}"
                );
            }
            *addrs.first().ok_or_else(unresolved)?
        }
    };
    let sock = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    sock.set_reuseaddr(true)?;
    sock.bind(addr)?;
    sock.listen(LISTEN_BACKLOG)
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
///
/// Errors (N-5): the binary logs ERROR `Unable to start COTServer: <err>` and exits 1 (spec §1.2
/// item 4). The error's `Display` is the bare cause: an invalid `ssl.client_cert_required`
/// (`Not a boolean: <v>`), a TLS/key/certificate or cert-db error ([`taky_pki::PkiError`]), an
/// invalid `[taky] redis` URL ([`taky_cot::PersistError`]). An unreachable Redis is not an error.
///
/// `listeners.mgmt` serves the mgmt protocol ([`crate::mgmt`]); with `cot_server.log_cot` set,
/// every connection writes its CoT log ([`taky_cot::CotLogger`]).
///
/// On error the mgmt socket file of `listeners.mgmt` is removed (like `COTServer.shutdown()`
/// after a failed `sock_setup`). If the Hub task ends unexpectedly (a panic), CRITICAL
/// `Unhandled exception: <err>` is logged, shutdown is triggered and [`RunningServer::join`]
/// returns the error (Python: an exception in `loop()` ends the process with exit 1).
pub async fn start(opts: ServerOptions, listeners: Listeners) -> anyhow::Result<RunningServer> {
    let guard = MgmtFileGuard(
        listeners
            .mgmt
            .as_ref()
            .and_then(|m| m.local_addr().ok())
            .and_then(|a| a.as_pathname().map(Path::to_path_buf)),
    );
    let running = start_inner(opts, listeners).await?;
    guard.disarm();
    Ok(running)
}

async fn start_inner(opts: ServerOptions, listeners: Listeners) -> anyhow::Result<RunningServer> {
    let cfg = &opts.cfg;
    let (tls, cert_db) = if cfg.ssl.enabled {
        // server.py:149 re-validates the key with getboolean (S-305 D-b).
        let required = cfg
            .raw()
            .getboolean("ssl", "client_cert_required")
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if !required {
            pylog!(
                LGR,
                Level::INFO,
                "Clients will not need to present a certificate"
            );
        }
        match cfg.ssl.ca.as_deref().filter(|p| !p.as_os_str().is_empty()) {
            Some(ca) => pylog!(
                LGR,
                Level::INFO,
                "Loading CA certificate from {}",
                ca.display()
            ),
            None => pylog!(LGR, Level::INFO, "Using default CA certificates"),
        }
        let mut ssl = cfg.ssl.clone();
        ssl.client_cert_required = required;
        let sc = server_config(&ssl, TlsMode::Cot).map_err(|e| {
            pylog!(LGR, Level::ERROR, "Unable to load SSL certificate: {e}");
            anyhow::Error::new(e)
        })?;
        let db = CertDb::open(&cfg.ssl.cert_db)?;
        (Some(TlsAcceptor::from(sc)), Some(db))
    } else {
        (None, None)
    };

    let persist = Persistence::from_config(cfg, opts.clock.clone()).await?;
    let router = Router::new(cfg.cot_server.max_persist_ttl, persist, opts.clock.clone());
    let (hub, hub_handle) = Hub::new(router, cert_db, opts.clock.clone());

    let local_addr = listeners.cot.local_addr()?;
    let monitor_addr = match &listeners.monitor {
        Some(m) => Some(m.local_addr()?),
        None => None,
    };
    let mode = if tls.is_some() { "ssl" } else { "tcp" };
    pylog!(
        LGR,
        Level::INFO,
        "Listening for {mode} on {}:{}",
        local_addr.ip(),
        local_addr.port()
    );
    if let Some(m) = monitor_addr {
        pylog!(
            LGR,
            Level::INFO,
            "Monitor listening for tcp on {}:{}",
            m.ip(),
            m.port()
        );
    }

    let shutdown = opts.shutdown.clone();
    let ctx = ConnCtx {
        hub: hub_handle.clone(),
        clock: opts.clock.clone(),
        shutdown: shutdown.clone(),
        log_cot: cfg.cot_server.log_cot.clone(),
        max_persist_ttl: cfg.cot_server.max_persist_ttl,
    };
    let ids = Arc::new(AtomicU64::new(1));
    let conns = TaskTracker::new();
    let hub_task = tokio::spawn(hub.run(shutdown.clone()));
    let mut accepts = vec![tokio::spawn(accept_loop(
        listeners.cot,
        ClientKind::Cot,
        tls,
        ctx.clone(),
        ids.clone(),
        conns.clone(),
    ))];
    if let Some(m) = listeners.monitor {
        accepts.push(tokio::spawn(accept_loop(
            m,
            ClientKind::Monitor,
            None,
            ctx,
            ids,
            conns.clone(),
        )));
    }

    if let Some(m) = listeners.mgmt {
        if let Ok(a) = m.local_addr()
            && let Some(p) = a.as_pathname()
        {
            pylog!(LGR, Level::INFO, "Management socket at {}", p.display());
        }
        accepts.push(tokio::spawn(crate::mgmt::accept_loop(
            m,
            hub_handle.clone(),
            shutdown.clone(),
            conns.clone(),
        )));
    }

    let task = tokio::spawn(async move {
        let mut hub_task = hub_task;
        let mut result = Ok(());
        let hub_done = tokio::select! {
            biased;
            () = shutdown.wait() => None,
            r = &mut hub_task => Some(r),
        };
        let hub_alive = hub_done.is_none();
        // The Hub returns by itself only on shutdown (it may win the race against the
        // `shutdown.wait()` above); anything else is a panic or an unexpected end.
        let failure = match hub_done {
            Some(Err(e)) => Some(anyhow::anyhow!("Hub task failed: {e}")),
            Some(Ok(())) if !shutdown.is_triggered() => {
                Some(anyhow::anyhow!("Hub task ended unexpectedly"))
            }
            _ => None,
        };
        if let Some(err) = failure {
            tracing::error!(lgr = "root", critical = true, "Unhandled exception: {err}");
            shutdown.trigger();
            result = Err(err);
        }
        for a in accepts {
            let _ = a.await;
        }
        if hub_alive {
            let _ = hub_task.await;
        }
        conns.close();
        let _ = tokio::time::timeout(CLOSE_TIMEOUT * 2, conns.wait()).await;
        pylog!(LGR, Level::INFO, "Stopped");
        result
    });

    Ok(RunningServer {
        local_addr,
        monitor_addr,
        hub: hub_handle,
        task,
    })
}

/// Accept connections until shutdown; one task per connection (`srv_accept`, server.py:193-241).
async fn accept_loop(
    listener: TcpListener,
    kind: ClientKind,
    tls: Option<TlsAcceptor>,
    ctx: ConnCtx,
    ids: Arc<AtomicU64>,
    conns: TaskTracker,
) {
    let stype = if tls.is_some() { "ssl" } else { "tcp" };
    let what = match kind {
        ClientKind::Cot => "cot",
        ClientKind::Monitor => "mon",
    };
    loop {
        let accepted = tokio::select! {
            () = ctx.shutdown.wait() => return,
            r = listener.accept() => r,
        };
        match accepted {
            Ok((sock, addr)) => {
                pylog!(
                    LGR,
                    Level::INFO,
                    "New {stype} {what} client from {}:{}",
                    addr.ip(),
                    addr.port()
                );
                let id = ClientId(ids.fetch_add(1, Ordering::Relaxed));
                conns.spawn(conn::serve(ctx.clone(), id, kind, sock, tls.clone()));
            }
            Err(e) => {
                pylog!(LGR, Level::INFO, "Client connect failed None:None ({e})");
                // EMFILE and friends: do not spin.
                tokio::time::sleep(ACCEPT_BACKOFF).await;
            }
        }
    }
}
