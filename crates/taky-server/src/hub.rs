//! The Hub actor (ARCHITECTURE §5, ADR-001): one task owns `Router`, the client table, `CertDb`
//! and `Persistence`; everything that changes routing arrives as a [`HubCmd`] over one bounded
//! `mpsc` ([`crate::limits::HUB_QUEUE`]). No `Mutex` on the hot path.
//!
//! Semantics (spec §3, §4.3, §4.6; ARCHITECTURE §6):
//! * `Connected` — ban check first (TLS peer with a serial: cert-db re-read if the file changed,
//!   D-11; status `R` ⇒ [`ConnectVerdict::Banned`], not registered, no persist), otherwise
//!   `Router::client_connect` + `send_persist`, then [`ConnectVerdict::Accepted`]. Plain-TCP and
//!   certificate-less clients skip the check (cert-db is a blacklist).
//! * `Event` — `Router::on_event` with the **unmodified** event (max_ttl is the Router's step 5;
//!   the monitor copy keeps the original stale). Events from an id the Router no longer knows
//!   (e.g. removed as a slow client) are dropped by the Router.
//! * `Disconnected` — `Router::client_disconnect`; a no-op for an id already removed.
//! * After **every** command and on every `Tick`, `Router::maybe_prune` (Python prunes once per
//!   select-loop iteration, gated to 10 s; qa01 `core_vectors` prunes after each chunk).
//! * Shutdown: every registered client is closed with `"Server shutting down"`, then the actor
//!   returns.

use std::sync::Arc;

use taky_common::{SharedClock, Shutdown, pylog};
use taky_cot::{ClientHandle, ClientId, Event, Outbox, Router};
use taky_pki::CertDb;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior};
use tracing::Level;

use crate::conn::SHUTTING_DOWN;
use crate::mgmt::MgmtRequest;

const LGR: &str = "COTServer";

/// Answer to [`HubCmd::Connected`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectVerdict {
    /// Registered; `send_persist` already done. The conn task starts reading.
    Accepted,
    /// The peer serial is revoked in cert-db: close with `"User banned"`.
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
    /// A parsed event from a connection (after `ClientStats::record_rx`).
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
    /// Testkit: `Router::persist_snapshot()` (memory or Redis), see
    /// [`HubHandle::persist_snapshot`].
    #[cfg(feature = "testkit")]
    PersistSnapshot {
        /// Kept events, sorted by uid.
        reply: oneshot::Sender<Vec<Arc<Event>>>,
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

    /// Testkit barrier (qa01 request A.2): resolves once every command sent to the Hub before it
    /// is processed **and** the resulting frames are written and flushed to the client sockets
    /// (bounded by [`crate::limits::SETTLE_TIMEOUT`] for a peer that does not read).
    ///
    /// It does not wait for bytes still in flight from a client to the server: a caller that
    /// just wrote to a socket must first observe an effect (e.g. a delivery) or wait.
    #[cfg(feature = "testkit")]
    pub async fn settle(&self) {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(HubCmd::Settle { reply }).await.is_ok() {
            let _ = rx.await;
        }
    }

    /// Testkit: the persisted events (`Router::persist_snapshot`, sorted by uid); empty if the
    /// Hub has stopped.
    #[cfg(feature = "testkit")]
    pub async fn persist_snapshot(&self) -> Vec<Arc<Event>> {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(HubCmd::PersistSnapshot { reply })
            .await
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
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

    /// The clock (mgmt `status` uptime / kickban revoke time, S-313).
    pub fn clock(&self) -> &SharedClock {
        &self.clock
    }

    /// Process commands until `shutdown` fires or all senders are dropped.
    pub async fn run(mut self, shutdown: Shutdown) {
        let mut tick = tokio::time::interval(crate::limits::TICK_INTERVAL);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            let cmd = tokio::select! {
                biased;
                () = shutdown.wait() => break,
                c = self.rx.recv() => match c {
                    Some(c) => c,
                    None => break,
                },
                _ = tick.tick() => HubCmd::Tick,
            };
            self.handle(cmd).await;
            self.router.maybe_prune(Instant::now()).await;
        }
        pylog!(LGR, Level::INFO, "Sending disconnect to clients");
        for (h, _) in self.router.clients() {
            h.outbox.close(SHUTTING_DOWN);
        }
    }

    /// Process one command.
    pub async fn handle(&mut self, cmd: HubCmd) {
        match cmd {
            HubCmd::Connected { handle, reply } => {
                let verdict = self.connect(handle).await;
                let _ = reply.send(verdict);
            }
            HubCmd::Event { id, event } => self.router.on_event(id, *event).await,
            HubCmd::Disconnected { id } => self.router.client_disconnect(id),
            HubCmd::Mgmt { req, reply } => {
                // Full mgmt (status/kickban) is S-313; ping needs no Router.
                let v = match req {
                    MgmtRequest::Ping => serde_json::json!({"pong": "taky"}),
                    _ => serde_json::json!({"error": "mgmt is not implemented yet"}),
                };
                let _ = reply.send(v);
            }
            HubCmd::Tick => {}
            #[cfg(feature = "testkit")]
            HubCmd::Settle { reply } => {
                let outboxes: Vec<Arc<dyn Outbox>> = self
                    .router
                    .clients()
                    .map(|(h, _)| h.outbox.clone())
                    .collect();
                tokio::spawn(async move {
                    let deadline = Instant::now() + crate::limits::SETTLE_TIMEOUT;
                    while outboxes.iter().any(|o| o.pending() > 0) && Instant::now() < deadline {
                        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                    }
                    let _ = reply.send(());
                });
            }
            #[cfg(feature = "testkit")]
            HubCmd::PersistSnapshot { reply } => {
                let _ = reply.send(self.router.persist_snapshot().await);
            }
        }
    }

    /// `client_connect` (server.py:243-255) + `router.client_connect`.
    async fn connect(&mut self, handle: ClientHandle) -> ConnectVerdict {
        if let (Some(serial), Some(db)) = (handle.peer_serial.as_deref(), self.cert_db.as_mut()) {
            pylog!(
                LGR,
                Level::DEBUG,
                "Checking {} against cert db",
                hex_upper(serial)
            );
            if let Err(e) = db.reload_if_changed() {
                pylog!(LGR, Level::WARN, "Unable to re-read cert-db: {e}");
            }
            if db.is_revoked(serial) {
                return ConnectVerdict::Banned;
            }
        }
        let id = handle.id;
        self.router.client_connect(handle);
        self.router.send_persist(id).await;
        ConnectVerdict::Accepted
    }
}

fn hex_upper(b: &[u8]) -> String {
    if b.is_empty() {
        return "00".to_owned();
    }
    b.iter().map(|x| format!("{x:02X}")).collect()
}
