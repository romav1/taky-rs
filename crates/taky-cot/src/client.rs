//! Client-side seam types (ARCHITECTURE §14): what the Hub (dev02) hands to the [`crate::Router`].
//!
//! The Router never touches sockets: it pushes [`Frame`]s into an [`Outbox`] implemented by
//! taky-server (bounded queue + close), and reads/updates [`ClientStats`] shared with the
//! connection task.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::models::Frame;

/// Unique id of a connection for the lifetime of the process (assigned by the Hub).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientId(pub u64);

/// Kind of connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientKind {
    /// A regular CoT client (TCP 8087 / TLS 8089).
    Cot,
    /// A monitor connection (`mon_ip:mon_port`): receives a copy of every packet, is not routed to.
    Monitor,
}

/// Why [`Outbox::try_send`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OutboxError {
    /// The queue limit (8 MiB or 4096 frames, ARCHITECTURE §6) is reached; the Router then calls
    /// [`Outbox::close`] with `"Slow client"`.
    #[error("outbox full")]
    Full,
    /// The connection is already gone.
    #[error("outbox closed")]
    Closed,
}

/// Outgoing queue of one connection. **Implemented by dev02** (taky-server: bounded `mpsc`
/// drained by the write half); dev01 tests use [`crate::testkit::TestOutbox`].
///
/// Both methods are called from the Hub actor and must not block or await.
pub trait Outbox: Send + Sync + 'static {
    /// Queue a frame without waiting.
    fn try_send(&self, frame: Frame) -> Result<(), OutboxError>;

    /// Ask the connection task to disconnect, logging `reason` (e.g. `"Slow client"`).
    /// Idempotent; frames queued before the call may still be written.
    fn close(&self, reason: &str);
}

/// An `f64` stored as bits in an `AtomicU64` (for `last_rx`, an epoch timestamp).
#[derive(Debug, Default)]
pub struct AtomicF64(AtomicU64);

impl AtomicF64 {
    /// New value.
    pub fn new(v: f64) -> AtomicF64 {
        AtomicF64(AtomicU64::new(v.to_bits()))
    }

    /// Read (relaxed: statistics only).
    pub fn load(&self) -> f64 {
        f64::from_bits(self.0.load(Ordering::Relaxed))
    }

    /// Write (relaxed: statistics only).
    pub fn store(&self, v: f64) {
        self.0.store(v.to_bits(), Ordering::Relaxed);
    }
}

/// Per-connection statistics for mgmt `status` (`connected`, `num_rx`, `last_rx`).
/// Updated by the connection task (read half), read by the Hub.
#[derive(Debug, Default)]
pub struct ClientStats {
    /// Connection time, epoch seconds from the injected clock.
    pub connected: f64,
    /// Number of received events.
    pub num_rx: AtomicU64,
    /// Time of the last received event, epoch seconds (0.0 — none yet).
    pub last_rx: AtomicF64,
}

impl ClientStats {
    /// Stats of a connection established at `connected` (epoch seconds).
    pub fn new(connected: f64) -> ClientStats {
        ClientStats {
            connected,
            ..ClientStats::default()
        }
    }

    /// Record one received event at `now` (epoch seconds).
    pub fn record_rx(&self, now: f64) {
        self.num_rx.fetch_add(1, Ordering::Relaxed);
        self.last_rx.store(now);
    }
}

/// Everything the Router needs to know about a connection (`HubCmd::Connected`).
#[derive(Clone)]
pub struct ClientHandle {
    /// Connection id.
    pub id: ClientId,
    /// Cot or Monitor.
    pub kind: ClientKind,
    /// Outgoing queue.
    pub outbox: Arc<dyn Outbox>,
    /// Shared statistics.
    pub stats: Arc<ClientStats>,
    /// Peer address (`None` for in-process test clients).
    pub addr: Option<SocketAddr>,
    /// Serial of the client certificate (big-endian bytes), TLS only; used by kickban.
    pub peer_serial: Option<Vec<u8>>,
}

impl std::fmt::Debug for ClientHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHandle")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_record_rx() {
        let s = ClientStats::new(100.5);
        s.record_rx(101.25);
        s.record_rx(102.0);
        assert_eq!(s.num_rx.load(Ordering::Relaxed), 2);
        assert_eq!(s.last_rx.load(), 102.0);
        assert_eq!(s.connected, 100.5);
    }
}
