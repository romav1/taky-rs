//! Own accept loop: TCP → (TLS handshake, client cert optional) → hyper HTTP/1.1 → axum, with the
//! peer identity injected per request (ADR-004 option 1).

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::http::Request;
use axum::response::Response;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use taky_common::Shutdown;
use taky_pki::{CertDb, PeerIdentity, peer_identity};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::task::TaskTracker;
use tower::ServiceExt;

use crate::app::pre_route;
use crate::identity::{plain_header_policy, tls_header_policy};

/// TLS handshake / request header timeout (gunicorn sync worker `timeout = 30`).
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Graceful shutdown budget for open connections (ADR-004).
const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

/// Shared per-process connection context.
pub(crate) struct Ctx {
    pub router: Router,
    pub tls: Option<TlsAcceptor>,
    /// `ssl.cert_db` (TLS mode only); re-read by mtime on every request (D-11).
    pub certdb: Option<Mutex<CertDb>>,
}

/// What the connection layer knows about the peer.
#[derive(Clone)]
enum Peer {
    Plain(IpAddr),
    Tls(Option<Arc<PeerIdentity>>),
}

impl Ctx {
    fn revoked(&self, serial: &[u8]) -> bool {
        let Some(db) = &self.certdb else { return false };
        let Ok(mut db) = db.lock() else { return false };
        if let Err(e) = db.reload_if_changed() {
            tracing::warn!("cert-db {}: {e}", db.path().display());
        }
        db.is_revoked(serial)
    }

    async fn handle(&self, mut req: Request<Incoming>, peer: &Peer) -> Response {
        let scheme = match peer {
            Peer::Plain(ip) => {
                plain_header_policy(req.headers_mut(), *ip);
                "http"
            }
            Peer::Tls(id) => {
                let revoked = id.as_ref().is_some_and(|i| self.revoked(&i.serial));
                tls_header_policy(req.headers_mut(), id.as_deref(), revoked);
                if let Some(id) = id {
                    req.extensions_mut().insert(PeerIdentity::clone(id));
                }
                "https"
            }
        };
        match pre_route(req, scheme) {
            Err(resp) => *resp,
            Ok(req) => match self.router.clone().oneshot(req).await {
                Ok(r) => r,
                Err(e) => match e {},
            },
        }
    }

    /// Serve one accepted stream (TLS handshake first in TLS mode).
    pub(crate) async fn serve_connection<IO>(
        self: Arc<Self>,
        io: IO,
        addr: SocketAddr,
        shutdown: Shutdown,
    ) where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Some(acceptor) = self.tls.clone() else {
            return self.serve_http(io, Peer::Plain(addr.ip()), shutdown).await;
        };
        let stream = match tokio::time::timeout(IO_TIMEOUT, acceptor.accept(io)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::debug!("{addr}: TLS handshake failed: {e}");
                return;
            }
            Err(_) => {
                tracing::debug!("{addr}: TLS handshake timed out");
                return;
            }
        };
        let conn = stream.get_ref().1;
        let id = match conn.peer_certificates() {
            None => None,
            Some(_) => match peer_identity(conn) {
                // Python: `subject["commonName"]` KeyError ⇒ the connection is dropped.
                Some(id) if id.cn.is_some() => Some(Arc::new(id)),
                _ => {
                    tracing::info!("{addr}: client certificate without a CN, closing");
                    return;
                }
            },
        };
        self.serve_http(stream, Peer::Tls(id), shutdown).await;
    }

    async fn serve_http<IO>(self: Arc<Self>, io: IO, peer: Peer, shutdown: Shutdown)
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let ctx = self.clone();
        let svc = service_fn(move |req: Request<Incoming>| {
            let ctx = ctx.clone();
            let peer = peer.clone();
            async move { Ok::<_, Infallible>(ctx.handle(req, &peer).await) }
        });
        let conn = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(IO_TIMEOUT)
            .serve_connection(TokioIo::new(io), svc);
        tokio::pin!(conn);
        let res = tokio::select! {
            r = conn.as_mut() => r,
            _ = shutdown.wait() => {
                conn.as_mut().graceful_shutdown();
                conn.await
            }
        };
        if let Err(e) = res {
            tracing::debug!("http connection: {e}");
        }
    }
}

/// Accept until `shutdown`, then wait (≤ 30 s) for open connections to finish.
pub(crate) async fn accept_loop(
    listener: TcpListener,
    ctx: Arc<Ctx>,
    shutdown: Shutdown,
) -> anyhow::Result<()> {
    let tracker = TaskTracker::new();
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            r = listener.accept() => match r {
                Ok((stream, addr)) => {
                    let _ = stream.set_nodelay(true);
                    tracker.spawn(ctx.clone().serve_connection(stream, addr, shutdown.clone()));
                }
                Err(e) => {
                    // EMFILE and friends: back off instead of spinning.
                    tracing::warn!("accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
        }
    }
    drop(listener);
    tracker.close();
    if tokio::time::timeout(SHUTDOWN_GRACE, tracker.wait())
        .await
        .is_err()
    {
        tracing::warn!("DPS: connections still open after {SHUTDOWN_GRACE:?}, exiting");
    }
    Ok(())
}
