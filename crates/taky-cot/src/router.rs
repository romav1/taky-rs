//! `Router` — sans-IO routing core (`COTRouter` + `TAKClient.feed` + `COTServer.mon_packet`).
//!
//! **Concurrency contract (ARCHITECTURE §5):** the Router is owned by the single Hub actor
//! (taky-server, dev02) and used through `&mut self` only; no locks. The only awaits are
//! [`Persistence`] calls. Events are handled strictly in the order the Hub receives them;
//! `persist.track` happens before fan-out, `send_persist` is atomic w.r.t. fan-outs.
//!
//! Order inside [`Router::on_event`] (ARCHITECTURE §4.1): (1) copy to all monitors unless the
//! source is a monitor; (2) no `type` → stop; (3) `t-x-c-t` → pong to the source, stop;
//! (4) `a*` + TakUser detail from a non-monitor → update the source's user; (5) `max_persist_ttl`;
//! (6) GeoChat → broadcast/group/uid; marti → by callsign; otherwise broadcast + `persist.track`.
//! A full [`crate::Outbox`] ⇒ `close("Slow client")` and the client is dropped by the Hub.

use std::collections::BTreeMap;

use taky_common::SharedClock;
use tokio::time::Instant;

use crate::client::{ClientHandle, ClientId};
use crate::models::{Event, TakUser};
use crate::persist::Persistence;

/// One registered connection.
#[derive(Debug)]
struct Entry {
    handle: ClientHandle,
    user: Option<TakUser>,
}

/// Routing state: clients, monitors, persistence, TTL policy.
#[derive(Debug)]
pub struct Router {
    clients: BTreeMap<ClientId, Entry>,
    persist: Persistence,
    max_persist_ttl: i64,
    clock: SharedClock,
    last_prune: Option<Instant>,
}

impl Router {
    /// New router. `max_persist_ttl` is `cot_server.max_persist_ttl` (`-1` — unlimited).
    ///
    /// Note: takes `clock` in addition to ARCHITECTURE §14 (qa01 request A.1: max_ttl, pong and
    /// prune must use the injected clock).
    pub fn new(max_persist_ttl: i64, persist: Persistence, clock: SharedClock) -> Router {
        Router {
            clients: BTreeMap::new(),
            persist,
            max_persist_ttl,
            clock,
            last_prune: None,
        }
    }

    /// `max_persist_ttl` as configured.
    pub fn max_persist_ttl(&self) -> i64 {
        self.max_persist_ttl
    }

    /// The injected clock.
    pub fn clock(&self) -> &SharedClock {
        &self.clock
    }

    /// Register a connection (after the TLS handshake and the cert-db ban check).
    /// Re-registering an existing id replaces it.
    pub fn client_connect(&mut self, h: ClientHandle) {
        self.clients.insert(
            h.id,
            Entry {
                handle: h,
                user: None,
            },
        );
    }

    /// Send all kept events to a freshly connected client (`send_persist`).
    pub async fn send_persist(&mut self, id: ClientId) {
        let _ = (id, &mut self.persist);
        todo!("S-307")
    }

    /// Forget a connection. Unknown ids are ignored.
    pub fn client_disconnect(&mut self, id: ClientId) {
        self.clients.remove(&id);
    }

    /// Handle one event from `src` (packet_rx + ping + ident + route; see the module docs).
    pub async fn on_event(&mut self, src: ClientId, evt: Event) {
        let _ = (src, evt);
        todo!("S-306")
    }

    /// Prune persistence if [`crate::limits::PRUNE_INTERVAL`] has passed since the last prune.
    /// `now` is `tokio::time::Instant`, so `tokio::time::pause/advance` drive it in tests.
    pub async fn maybe_prune(&mut self, now: Instant) {
        let _ = (now, self.last_prune);
        todo!("S-307")
    }

    /// All registered connections with their identified user (mgmt `status`, kickban),
    /// in [`ClientId`] order.
    pub fn clients(&self) -> impl Iterator<Item = (&ClientHandle, Option<&TakUser>)> {
        self.clients.values().map(|e| (&e.handle, e.user.as_ref()))
    }

    /// The handle of one connection.
    pub fn client(&self, id: ClientId) -> Option<&ClientHandle> {
        self.clients.get(&id).map(|e| &e.handle)
    }

    /// Mutable access to the persistence backend (Hub ticks, testkit).
    pub fn persistence(&mut self) -> &mut Persistence {
        &mut self.persist
    }

    #[cfg(feature = "testkit")]
    pub(crate) fn set_user(&mut self, id: ClientId, user: Option<TakUser>) {
        if let Some(e) = self.clients.get_mut(&id) {
            e.user = user;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use taky_common::SystemClock;

    use super::*;
    use crate::client::{ClientKind, ClientStats, Outbox, OutboxError};
    use crate::models::Frame;

    struct Null;
    impl Outbox for Null {
        fn try_send(&self, _: Frame) -> Result<(), OutboxError> {
            Ok(())
        }
        fn close(&self, _: &str) {}
    }

    fn handle(id: u64, kind: ClientKind) -> ClientHandle {
        ClientHandle {
            id: ClientId(id),
            kind,
            outbox: Arc::new(Null),
            stats: Arc::new(ClientStats::new(0.0)),
            addr: None,
            peer_serial: None,
        }
    }

    #[test]
    fn connect_disconnect_clients() {
        let clock = SystemClock::shared();
        let mut r = Router::new(-1, Persistence::memory(clock.clone()), clock);
        r.client_connect(handle(2, ClientKind::Monitor));
        r.client_connect(handle(1, ClientKind::Cot));
        let ids: Vec<_> = r.clients().map(|(h, u)| (h.id.0, u.is_none())).collect();
        assert_eq!(ids, vec![(1, true), (2, true)]);
        r.client_disconnect(ClientId(1));
        r.client_disconnect(ClientId(42));
        assert!(r.client(ClientId(1)).is_none());
        assert_eq!(
            r.client(ClientId(2)).map(|h| h.kind),
            Some(ClientKind::Monitor)
        );
        assert_eq!(r.max_persist_ttl(), -1);
    }
}
