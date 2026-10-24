//! The Hub actor (ARCHITECTURE §5, ADR-001): one task owns `Router`, the client table, `CertDb`
//! and `Persistence`; everything that changes routing arrives as a [`HubCmd`] over one bounded
//! `mpsc` ([`crate::limits::HUB_QUEUE`]). No `Mutex` on the hot path.

use taky_common::{SharedClock, Shutdown};
use taky_cot::{ClientHandle, ClientId, Event, Router};
use taky_pki::CertDb;
use tokio::sync::{mpsc, oneshot};

use crate::mgmt::MgmtRequest;

/// Answer to [`HubCmd::Connected`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectVerdict {
    /// Registered; `send_persist` already done. The conn task starts reading.
    Accepted,
    /// The peer serial is revoked in cert-db: close with `"Banned"`.
    Banned,
}

/// Commands to the Hub. Order of processing = order of arrival.
#[derive(Debug)]
pub enum HubCmd {
    /// A connection finished its handshake (sent by the accept/conn task).
    Connected {
        /// The client.
        handle: ClientHandle,
        /// Verdict (ban check + registration + `send_persist`).
        reply: oneshot::Sender<ConnectVerdict>,
    },
    /// A parsed event from a connection (after `ClientStats::record_rx` and `CotLogger`).
    Event {
        /// Source.
        id: ClientId,
        /// The event (boxed: keeps `HubCmd` small in the queue).
        event: Box<Event>,
    },
    /// A connection is gone (EOF, error, "Slow client", kick).
    Disconnected {
        /// The client.
        id: ClientId,
    },
    /// A mgmt request; the reply is the JSON value to send back.
    Mgmt {
        /// Request.
        req: MgmtRequest,
        /// Reply channel.
        reply: oneshot::Sender<serde_json::Value>,
    },
    /// Periodic tick ([`crate::limits::TICK_INTERVAL`]): `Router::maybe_prune`.
    Tick,
    /// Testkit barrier, see [`HubHandle::settle`].
    #[cfg(feature = "testkit")]
    Settle {
        /// Fired when everything before it is processed and flushed.
        reply: oneshot::Sender<()>,
    },
}

/// Cloneable sender side of the Hub.
#[derive(Debug, Clone)]
pub struct HubHandle {
    tx: mpsc::Sender<HubCmd>,
}

impl HubHandle {
    /// Send a command, waiting for queue space (backpressure). `Err` ⇒ the Hub has stopped.
    pub async fn send(&self, cmd: HubCmd) -> Result<(), mpsc::error::SendError<HubCmd>> {
        self.tx.send(cmd).await
    }

    /// Testkit barrier (qa01 request A.2): resolves once every command sent before it is
    /// processed **and** the resulting frames are written to the client sockets.
    #[cfg(feature = "testkit")]
    pub async fn settle(&self) {
        todo!("dev02: S-314")
    }
}

/// The actor state. Created by [`crate::start`]; tests may drive it directly.
#[derive(Debug)]
pub struct Hub {
    router: Router,
    cert_db: Option<CertDb>,
    clock: SharedClock,
    rx: mpsc::Receiver<HubCmd>,
}

impl Hub {
    /// New Hub with a queue of [`crate::limits::HUB_QUEUE`]. `cert_db` is `None` without SSL.
    pub fn new(router: Router, cert_db: Option<CertDb>, clock: SharedClock) -> (Hub, HubHandle) {
        let (tx, rx) = mpsc::channel(crate::limits::HUB_QUEUE);
        (
            Hub {
                router,
                cert_db,
                clock,
                rx,
            },
            HubHandle { tx },
        )
    }

    /// Process commands until `shutdown` fires or all senders are dropped.
    pub async fn run(self, shutdown: Shutdown) {
        let _ = (self.router, self.cert_db, self.clock, self.rx, shutdown);
        todo!("dev02: S-312")
    }
}
