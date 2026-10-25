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
        let access = crate::stdout_enabled().then(|| AccessInfo::of(&req));
        let resp = match pre_route(req, scheme) {
            Err(resp) => *resp,
            Ok(req) => match self.router.clone().oneshot(req).await {
                Ok(r) => r,
                Err(e) => match e {},
            },
        };
        if let Some(a) = access {
            crate::stdout_line(&a.line(&resp));
        }
        resp
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

/// Request data for the gunicorn access log line (`accesslog="-"`,
/// `access_log_format='%(t)s "%(r)s" %(s)s %(b)s "%(a)s"'`, spec §2.1).
struct AccessInfo {
    head: bool,
    /// `%(r)s` = `REQUEST_METHOD RAW_URI SERVER_PROTOCOL`.
    request_line: String,
    /// `%(a)s` = `User-Agent` or `-`.
    agent: String,
}

impl AccessInfo {
    fn of<B>(req: &Request<B>) -> AccessInfo {
        let target = req
            .uri()
            .path_and_query()
            .map_or_else(|| req.uri().to_string(), |pq| pq.as_str().to_owned());
        let agent = req
            .headers()
            .get(axum::http::header::USER_AGENT)
            .map_or_else(
                || "-".to_owned(),
                |v| String::from_utf8_lossy(v.as_bytes()).into_owned(),
            );
        AccessInfo {
            head: req.method() == axum::http::Method::HEAD,
            request_line: format!("{} {target} {:?}", req.method(), req.version()),
            agent,
        }
    }

    /// `%(t)s` = `[%d/%b/%Y:%H:%M:%S %z]` (local time), `%(b)s` = body bytes sent
    /// (`0` for HEAD; `-` when unknown, i.e. a stream without a length).
    fn line(&self, resp: &Response) -> String {
        use axum::body::HttpBody as _;
        let t = chrono::Local::now().format("[%d/%b/%Y:%H:%M:%S %z]");
        let sent = if self.head {
            Some(0)
        } else {
            resp.body().size_hint().exact().or_else(|| {
                resp.headers()
                    .get(axum::http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok())
            })
        };
        let b = sent.map_or_else(|| "-".to_owned(), |n: u64| n.to_string());
        format!(
            "{t} \"{}\" {} {b} \"{}\"",
            self.request_line,
            resp.status().as_u16(),
            self.agent
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[test]
    fn gunicorn_access_line() {
        let req = Request::builder()
            .method("GET")
            .uri("/Marti/sync/search?keywords=a%20b")
            .header("user-agent", "ATAK")
            .body(())
            .unwrap();
        let a = AccessInfo::of(&req);
        let line = a.line(&(StatusCode::OK, "hello").into_response());
        let (t, rest) = line.split_at(line.find("] ").unwrap() + 2);
        assert!(t.starts_with('[') && t.len() == 29, "{t}");
        assert_eq!(
            rest,
            "\"GET /Marti/sync/search?keywords=a%20b HTTP/1.1\" 200 5 \"ATAK\""
        );

        let req = Request::builder().method("HEAD").uri("/").body(()).unwrap();
        let line = AccessInfo::of(&req).line(&(StatusCode::OK, "x").into_response());
        assert!(line.ends_with("\"HEAD / HTTP/1.1\" 200 0 \"-\""), "{line}");

        let req = Request::builder().uri("/x").body(()).unwrap();
        let stream = Response::new(Body::from_stream(tokio_util::io::ReaderStream::new(
            tokio::io::empty(),
        )));
        let line = AccessInfo::of(&req).line(&stream);
        assert!(line.ends_with("\"GET /x HTTP/1.1\" 200 - \"-\""), "{line}");
    }
}
