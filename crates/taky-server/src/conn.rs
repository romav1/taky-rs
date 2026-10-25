//! One client connection (ARCHITECTURE §4.1, §6; spec §3.1, §4, §6): the [`ConnOutbox`]
//! (the `taky_cot::Outbox` implementation) and the connection task.
//!
//! **Outbox contract (ARCHITECTURE §6, review-3B N-6):** the queue is bounded by **both**
//! [`OUTBOX_MAX_BYTES`] and [`OUTBOX_MAX_FRAMES`] (frames counted until written and flushed);
//! [`Outbox::try_send`] and [`Outbox::close`] never block or await; `close` is idempotent (the
//! first reason wins). On `Full` the Router closes the client with `"Slow client"`, and the
//! write half logs that reason (`Socket disconnect: Slow client`).
//!
//! **Connection task:** TLS handshake (≤ [`HANDSHAKE_TIMEOUT`], `"SSL Handshake timeout"`) →
//! `HubCmd::Connected` (ban check + registration + `send_persist` in the Hub) → read and write
//! halves until the first of: EOF (`"Client disconnected"`), I/O error (its text), decoder error
//! (`"XML Syntax Error"`), `Outbox::close` (its reason), write timeout, server shutdown
//! (`"Server shutting down"`). Then `Socket disconnect: <reason>` (INFO) and
//! `HubCmd::Disconnected`.
//!
//! Reading mirrors Python's `socket_rx` + `TAKClient.feed` up to the Hub: chunks of at most 4096
//! bytes; each chunk is fed to the [`CotDecoder`] once and all completed `<event>` elements are
//! taken; per element `ClientStats::record_rx`, then `Event::from_element` — an
//! `UnmarshalError` is logged (DEBUG) and the event dropped, the connection stays (spec §6
//! item 2); otherwise the event goes to the Hub **unmodified**.
//!
//! **CoT log (`log_cot`, S-313, review-3B N-1):** with `log_cot` set, each connection owns a
//! [`CotLogger`]. After the event is handed to the Hub, the logger gets the original element
//! and a clone of the event (it applies max_ttl to its own copy, mirrors `handle_atom` for the
//! file name and skips pings/empty types/`*-ping`); an `UnmarshalError` is logged with
//! `<__taky_err>`. File I/O runs in `spawn_blocking`, awaited in order (one record at a time
//! per connection).
//! A decoder error closes the connection after the events completed before it in the stream
//! were handed to the Hub (as qa01's `core_vectors` connection emulation).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use bytes::BytesMut;
use taky_common::{SharedClock, Shutdown, pylog};
use taky_cot::{
    ClientHandle, ClientId, ClientKind, ClientStats, CotDecoder, CotLogger, Event, Frame, Outbox,
    OutboxError,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::Decoder;
use tokio_util::sync::CancellationToken;
use tracing::Level;

use crate::hub::{ConnectVerdict, HubCmd, HubHandle};
use crate::limits::{
    CLOSE_TIMEOUT, HANDSHAKE_TIMEOUT, OUTBOX_MAX_BYTES, OUTBOX_MAX_FRAMES, READ_CHUNK,
    WRITE_TIMEOUT,
};

/// Reason logged when the peer closes the connection (`client.py:118`).
pub const CLIENT_DISCONNECTED: &str = "Client disconnected";
/// Reason for a fatal stream error (`client.py:123-125`).
pub const XML_SYNTAX_ERROR: &str = "XML Syntax Error";
/// Reason for a revoked client certificate (`server.py:254`).
pub const USER_BANNED: &str = "User banned";
/// Reason for a connection kicked by mgmt `kickban` (`mgmt.py:76`).
pub const BANNED: &str = "Banned";
/// Reason for a handshake that did not finish in [`HANDSHAKE_TIMEOUT`] (`server.py:322`).
pub const HANDSHAKE_TIMED_OUT: &str = "SSL Handshake timeout";
/// Reason on shutdown (`server.py:331`).
pub const SHUTTING_DOWN: &str = "Server shutting down";
/// Reason when a frame could not be written within [`WRITE_TIMEOUT`].
pub const WRITE_TIMED_OUT: &str = "Write timeout";

/// The outgoing queue of one connection (see the module docs for the contract).
#[derive(Debug)]
pub struct ConnOutbox {
    tx: mpsc::UnboundedSender<Frame>,
    /// Frames accepted and not yet written + flushed.
    frames: AtomicUsize,
    /// Bytes of those frames.
    bytes: AtomicUsize,
    /// First close reason.
    reason: OnceLock<String>,
    closed: CancellationToken,
}

impl ConnOutbox {
    /// New outbox and the receiver drained by the write half.
    pub fn new() -> (Arc<ConnOutbox>, mpsc::UnboundedReceiver<Frame>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let ob = ConnOutbox {
            tx,
            frames: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            reason: OnceLock::new(),
            closed: CancellationToken::new(),
        };
        (Arc::new(ob), rx)
    }

    /// The reason given to the first [`Outbox::close`] call.
    pub fn close_reason(&self) -> Option<&str> {
        self.reason.get().map(String::as_str)
    }

    /// `true` once [`Outbox::close`] was called.
    pub fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    /// Bytes currently queued (accepted, not yet written + flushed).
    pub fn queued_bytes(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }

    /// The write half finished one frame of `len` bytes (written and, if it was the last
    /// queued frame, flushed).
    fn written(&self, len: usize) {
        self.bytes.fetch_sub(len, Ordering::AcqRel);
        self.frames.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Outbox for ConnOutbox {
    /// Limits: `Full` if [`OUTBOX_MAX_FRAMES`] frames are queued, or if the frame would push the
    /// queue past [`OUTBOX_MAX_BYTES`] (a single frame into an empty queue is always accepted, so
    /// an oversized frame cannot wedge a healthy client). Only the Hub calls this (single
    /// producer), so check-then-add is exact.
    fn try_send(&self, frame: Frame) -> Result<(), OutboxError> {
        if self.closed.is_cancelled() || self.tx.is_closed() {
            return Err(OutboxError::Closed);
        }
        let n = self.frames.load(Ordering::Acquire);
        let b = self.bytes.load(Ordering::Acquire);
        if n >= OUTBOX_MAX_FRAMES || (n > 0 && b.saturating_add(frame.len()) > OUTBOX_MAX_BYTES) {
            return Err(OutboxError::Full);
        }
        let len = frame.len();
        self.frames.fetch_add(1, Ordering::AcqRel);
        self.bytes.fetch_add(len, Ordering::AcqRel);
        if self.tx.send(frame).is_err() {
            self.written(len);
            return Err(OutboxError::Closed);
        }
        Ok(())
    }

    fn close(&self, reason: &str) {
        let _ = self.reason.set(reason.to_owned());
        self.closed.cancel();
    }

    fn pending(&self) -> usize {
        if self.closed.is_cancelled() {
            0
        } else {
            self.frames.load(Ordering::Acquire)
        }
    }
}

/// What a connection task needs from the server.
#[derive(Debug, Clone)]
pub(crate) struct ConnCtx {
    pub hub: HubHandle,
    pub clock: SharedClock,
    pub shutdown: Shutdown,
    /// `cot_server.log_cot` (absolute; `None` — no CoT log).
    pub log_cot: Option<PathBuf>,
    /// `cot_server.max_persist_ttl` (the CoT log records the event as routed).
    pub max_persist_ttl: i64,
}

/// Python logger name of a socket client (`SocketTAKClient@ip:port`, `client.py:43`).
fn lgr_name(addr: Option<SocketAddr>) -> String {
    match addr {
        Some(a) => format!("SocketTAKClient@{}:{}", a.ip(), a.port()),
        None => "SocketTAKClient@None:None".to_owned(),
    }
}

/// Serve one accepted socket until it is closed. `tls` — wrap in TLS first (CoT port with SSL).
pub(crate) async fn serve(
    ctx: ConnCtx,
    id: ClientId,
    kind: ClientKind,
    sock: TcpStream,
    tls: Option<TlsAcceptor>,
) {
    let addr = sock.peer_addr().ok();
    let lgr = lgr_name(addr);
    match tls {
        None => run(ctx, id, kind, addr, None, sock, &lgr).await,
        Some(acc) => {
            let hs = tokio::select! {
                r = tokio::time::timeout(HANDSHAKE_TIMEOUT, acc.accept(sock)) => r,
                () = ctx.shutdown.wait() => {
                    pylog!(lgr, Level::INFO, "Socket disconnect: {SHUTTING_DOWN}");
                    return;
                }
            };
            match hs {
                Err(_) => pylog!(lgr, Level::INFO, "Socket disconnect: {HANDSHAKE_TIMED_OUT}"),
                Ok(Err(e)) => pylog!(lgr, Level::INFO, "Socket disconnect: {e}"),
                Ok(Ok(stream)) => {
                    let serial = taky_pki::peer_identity(stream.get_ref().1).map(|p| p.serial);
                    run(ctx, id, kind, addr, serial, stream, &lgr).await;
                }
            }
        }
    }
}

/// After the handshake: register with the Hub, then pump both halves.
async fn run<S>(
    ctx: ConnCtx,
    id: ClientId,
    kind: ClientKind,
    addr: Option<SocketAddr>,
    peer_serial: Option<Vec<u8>>,
    stream: S,
    lgr: &str,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (outbox, rx) = ConnOutbox::new();
    let stats = Arc::new(ClientStats::new(ctx.clock.epoch()));
    let handle = ClientHandle {
        id,
        kind,
        outbox: outbox.clone(),
        stats: stats.clone(),
        addr,
        peer_serial,
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    let verdict = if ctx
        .hub
        .send(HubCmd::Connected {
            handle,
            reply: reply_tx,
        })
        .await
        .is_ok()
    {
        reply_rx.await.ok()
    } else {
        None
    };
    let (mut rd, mut wr) = tokio::io::split(stream);
    match verdict {
        Some(ConnectVerdict::Accepted) => {}
        Some(ConnectVerdict::Banned) => {
            pylog!(lgr, Level::INFO, "Socket disconnect: {USER_BANNED}");
            outbox.close(USER_BANNED);
            let _ = tokio::time::timeout(CLOSE_TIMEOUT, wr.shutdown()).await;
            return;
        }
        None => {
            pylog!(lgr, Level::INFO, "Socket disconnect: {SHUTTING_DOWN}");
            return;
        }
    }

    let mut logger = ctx.log_cot.as_deref().map(|dir| {
        CotLogger::new(
            Some(dir),
            kind,
            addr.map(|a| a.ip()),
            ctx.max_persist_ttl,
            ctx.clock.clone(),
        )
        .with_logger_name(lgr)
    });
    let reason = tokio::select! {
        r = read_half(&ctx, id, &stats, &mut rd, &mut logger) => r,
        r = write_half(&outbox, rx, &mut wr) => r,
        () = outbox.closed.cancelled() => outbox.close_reason().unwrap_or(SHUTTING_DOWN).to_owned(),
        () = ctx.shutdown.wait() => SHUTTING_DOWN.to_owned(),
    };
    pylog!(lgr, Level::INFO, "Socket disconnect: {reason}");
    outbox.close(&reason);
    let _ = ctx.hub.send(HubCmd::Disconnected { id }).await;
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, wr.shutdown()).await;
}

/// Read half: returns the disconnect reason.
async fn read_half<R>(
    ctx: &ConnCtx,
    id: ClientId,
    stats: &ClientStats,
    rd: &mut R,
    logger: &mut Option<CotLogger>,
) -> String
where
    R: AsyncRead + Unpin,
{
    let mut dec = CotDecoder::new();
    let mut chunk = vec![0u8; READ_CHUNK];
    let mut buf = BytesMut::with_capacity(READ_CHUNK);
    loop {
        let n = match rd.read(&mut chunk).await {
            Ok(0) => return CLIENT_DISCONNECTED.to_owned(),
            Ok(n) => n,
            Err(e) => return e.to_string(),
        };
        buf.extend_from_slice(&chunk[..n]);
        loop {
            match dec.decode(&mut buf) {
                Ok(Some(elm)) => {
                    stats.record_rx(ctx.clock.epoch());
                    match Event::from_element(&elm) {
                        Ok(evt) => {
                            let copy = logger.is_some().then(|| evt.clone());
                            let cmd = HubCmd::Event {
                                id,
                                event: Box::new(evt),
                            };
                            if ctx.hub.send(cmd).await.is_err() {
                                return SHUTTING_DOWN.to_owned();
                            }
                            if let Some(evt) = copy {
                                log_with(logger, move |lg| lg.on_event(&elm, &evt)).await;
                            }
                        }
                        Err(e) => {
                            pylog!("TAKClient", Level::DEBUG, "Unable to parse Event: {}", e.0);
                            if logger.is_some() {
                                let exc = format!("UnmarshalError: {}\n", e.0);
                                log_with(logger, move |lg| lg.on_error(&elm, &exc)).await;
                            }
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    pylog!("TAKClient", Level::DEBUG, "XML Syntax Error: {e}");
                    return XML_SYNTAX_ERROR.to_owned();
                }
            }
        }
    }
}

/// Run one CoT-log step off the async threads. A logger that disabled itself (I/O error) or
/// panicked is dropped, so later events are not cloned for it.
async fn log_with(slot: &mut Option<CotLogger>, f: impl FnOnce(&mut CotLogger) + Send + 'static) {
    let Some(mut lg) = slot.take() else {
        return;
    };
    if let Ok(lg) = tokio::task::spawn_blocking(move || {
        f(&mut lg);
        lg
    })
    .await
        && lg.enabled()
    {
        *slot = Some(lg);
    }
}

/// Write half: drains the outbox; returns the disconnect reason on a write error/timeout.
async fn write_half<W>(
    outbox: &ConnOutbox,
    mut rx: mpsc::UnboundedReceiver<Frame>,
    wr: &mut W,
) -> String
where
    W: AsyncWrite + Unpin,
{
    while let Some(frame) = rx.recv().await {
        let res = tokio::time::timeout(WRITE_TIMEOUT, async {
            wr.write_all(&frame).await?;
            if rx.is_empty() {
                wr.flush().await?;
            }
            Ok::<(), std::io::Error>(())
        })
        .await;
        match res {
            Ok(Ok(())) => outbox.written(frame.len()),
            Ok(Err(e)) => return e.to_string(),
            Err(_) => return WRITE_TIMED_OUT.to_owned(),
        }
    }
    // The sender lives in the outbox, which this task holds: not reached in practice.
    SHUTTING_DOWN.to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn frame(n: usize) -> Frame {
        Arc::from(vec![b'x'; n].into_boxed_slice())
    }

    #[test]
    fn frame_limit() {
        let (ob, _rx) = ConnOutbox::new();
        for _ in 0..OUTBOX_MAX_FRAMES {
            ob.try_send(frame(1)).unwrap();
        }
        assert_eq!(ob.try_send(frame(1)), Err(OutboxError::Full));
        assert_eq!(ob.pending(), OUTBOX_MAX_FRAMES);
    }

    #[test]
    fn byte_limit() {
        let (ob, _rx) = ConnOutbox::new();
        let big = OUTBOX_MAX_BYTES / 4;
        for _ in 0..4 {
            ob.try_send(frame(big)).unwrap();
        }
        assert_eq!(ob.queued_bytes(), OUTBOX_MAX_BYTES);
        assert_eq!(ob.try_send(frame(1)), Err(OutboxError::Full));
        // A single oversized frame into an empty queue is accepted.
        let (ob2, _rx2) = ConnOutbox::new();
        ob2.try_send(frame(OUTBOX_MAX_BYTES + 1)).unwrap();
        assert_eq!(ob2.try_send(frame(1)), Err(OutboxError::Full));
    }

    #[test]
    fn written_frees_space() {
        let (ob, mut rx) = ConnOutbox::new();
        for _ in 0..OUTBOX_MAX_FRAMES {
            ob.try_send(frame(2)).unwrap();
        }
        let f = rx.try_recv().unwrap();
        ob.written(f.len());
        ob.try_send(frame(2)).unwrap();
        assert_eq!(ob.queued_bytes(), OUTBOX_MAX_FRAMES * 2);
    }

    #[test]
    fn close_is_idempotent_and_first_reason_wins() {
        let (ob, _rx) = ConnOutbox::new();
        ob.try_send(frame(3)).unwrap();
        ob.close("Slow client");
        ob.close("other");
        assert!(ob.is_closed());
        assert_eq!(ob.close_reason(), Some("Slow client"));
        assert_eq!(ob.try_send(frame(1)), Err(OutboxError::Closed));
        assert_eq!(ob.pending(), 0);
    }

    #[test]
    fn dropped_receiver_is_closed() {
        let (ob, rx) = ConnOutbox::new();
        drop(rx);
        assert_eq!(ob.try_send(frame(1)), Err(OutboxError::Closed));
        assert_eq!(ob.queued_bytes(), 0);
    }
}
