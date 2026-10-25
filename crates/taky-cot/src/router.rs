//! `Router` — sans-IO routing core (`COTRouter` + `TAKClient.feed` + `COTServer.mon_packet`).
//!
//! **Concurrency contract (ARCHITECTURE §5):** the Router is owned by the single Hub actor
//! (taky-server, dev02) and used through `&mut self` only; no locks. The only awaits are
//! [`Persistence`] calls. Events are handled strictly in the order the Hub receives them;
//! `persist.track` happens before fan-out, `send_persist` is atomic w.r.t. fan-outs.
//!
//! Order inside [`Router::on_event`] (ARCHITECTURE §4.1, spec §6/§8/§10–§12): (1) copy to all
//! monitors unless the source is a monitor (serialized **before** max_ttl, as Python's
//! `send_event` serializes immediately); (2) empty `type` → stop; (3) `t-x-c-t` → pong to the
//! source, stop; (4) `a*` + TakUser detail from a non-monitor → replace the source's user;
//! (5) `max_persist_ttl`; (6) GeoChat → broadcast / group / uid; marti → by callsign
//! (`<dest uid>` ignored, ADR-008 G-9); otherwise broadcast + `persist.track`.
//!
//! Recipient order among different clients is [`ClientId`] order (Python: `set` order, not
//! normative); per-recipient order is the receive order.
//!
//! **Errors (log + drop, where Python would raise inside `TAKClient.feed`):** an event that
//! cannot be serialized ([`Event::to_frame`], D-8: no `version`/`uid`/`type`/`how`) is
//! logged at ERROR (`Unhandled exception parsing Event`) and dropped: not delivered, **not
//! persisted** (Python persisted it and later crashed, B2). `marti_cs` entries that are
//! `None` (a `<dest>` without `callsign`) match no one. Events from a source that is not (or no
//! longer) registered are dropped (DEBUG) — e.g. after a slow-client drop.
//!
//! **Slow clients (review-T-10 N-3, ARCHITECTURE §6, D-3):** the Router never waits for a
//! client. Frames are queued with [`crate::Outbox::try_send`]; the per-client queue limit
//! (8 MiB or 4096 frames) lives in the Outbox. Policy on a failed `try_send`:
//! * [`OutboxError::Full`] — the queue is past its limit: the frame is dropped and counted
//!   ([`Router::dropped_frames`], [`Router::slow_disconnects`]), WARNING `Slow client`,
//!   [`crate::Outbox::close`]`("Slow client")`, and the client is **removed from the routing
//!   table immediately** — no further fan-out to it (also not later in the same fan-out, e.g.
//!   repeated marti callsigns). The Hub's later `Disconnected{id}` is a no-op.
//! * [`OutboxError::Closed`] — the connection is already gone: the frame is dropped and
//!   counted, the client is removed from the table (no close call needed).
//!
//! Below the limit nothing is dropped; memory per client is bounded by the Outbox limit.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::TimeDelta;
use taky_common::{Clock, SharedClock, pylog};
use tokio::time::Instant;
use tracing::Level;

use crate::client::{ClientHandle, ClientId, ClientKind, OutboxError};
use crate::limits::PRUNE_INTERVAL;
use crate::models::{Event, EventDetail, Frame, Point, TakUser, Teams};
use crate::persist::Persistence;

const LGR: &str = "COTRouter";

/// Reason passed to [`crate::Outbox::close`] when a client's queue is full.
pub const SLOW_CLIENT: &str = "Slow client";

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
    dropped_frames: u64,
    slow_disconnects: u64,
}

/// `COTRouter.route` step 0: if `max_persist_ttl >= 0` and `persist_ttl > max_persist_ttl`,
/// set `stale = utcnow() + max_persist_ttl` (spec §8 #0). Returns `true` if `stale` changed.
///
/// Public so that the connection task can log (`log_cot`) the event as Python does, i.e.
/// after this correction.
pub fn apply_max_ttl(max_persist_ttl: i64, evt: &mut Event, clock: &dyn Clock) -> bool {
    if max_persist_ttl >= 0 && evt.persist_ttl(clock) > max_persist_ttl {
        evt.stale = clock.utc_now() + TimeDelta::seconds(max_persist_ttl);
        true
    } else {
        false
    }
}

/// `TAKClient.pong` (spec §11): `takPong`, `t-x-c-t-r`, stale = now + 20 s, default point.
pub fn pong_event(clock: &dyn Clock) -> Event {
    let now = clock.utc_now();
    Event {
        version: Some("2.0".into()),
        uid: Some("takPong".into()),
        etype: Some("t-x-c-t-r".into()),
        how: Some("h-g-i-g-o".into()),
        time: now,
        start: now,
        stale: now + TimeDelta::seconds(20),
        point: Point::default(),
        detail: None,
    }
}

/// Where a routed event goes (spec §8).
enum Dest {
    Broadcast,
    Group(Teams),
    Uid(Option<String>),
    Callsigns(Vec<Option<String>>),
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
            dropped_frames: 0,
            slow_disconnects: 0,
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

    /// Frames dropped because a recipient's Outbox was full or closed (N-3 counter).
    pub fn dropped_frames(&self) -> u64 {
        self.dropped_frames
    }

    /// Clients disconnected with `"Slow client"` (Outbox full).
    pub fn slow_disconnects(&self) -> u64 {
        self.slow_disconnects
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

    /// `send_persist` (spec §9.5): send all kept events to `id`, except those whose uid is the
    /// client's identified uid (always sent on a fresh connect: `user` is still `None`, V039).
    /// Unknown ids are ignored.
    pub async fn send_persist(&mut self, id: ClientId) {
        let Some(own_uid) = self
            .clients
            .get(&id)
            .map(|e| e.user.as_ref().and_then(|u| u.uid.clone()))
        else {
            return;
        };
        pylog!(LGR, Level::DEBUG, "Sending persistence objects to {id:?}");
        for (evt, frame) in self.persist.get_all_frames().await {
            if own_uid.is_some() && evt.uid == own_uid {
                continue;
            }
            self.send_to(id, &frame);
        }
    }

    /// Forget a connection. Unknown ids are ignored.
    pub fn client_disconnect(&mut self, id: ClientId) {
        self.clients.remove(&id);
    }

    /// Handle one event from `src` (packet_rx + ping + ident + route; see the module docs).
    pub async fn on_event(&mut self, src: ClientId, mut evt: Event) {
        let Some(src_kind) = self.clients.get(&src).map(|e| e.handle.kind) else {
            pylog!(
                LGR,
                Level::DEBUG,
                "Dropping event from unregistered {src:?}"
            );
            return;
        };
        let src_monitor = src_kind == ClientKind::Monitor;

        // (1) packet_rx → mon_packet: a copy to every monitor (only for non-monitor sources).
        if !src_monitor {
            let monitors: Vec<ClientId> = self
                .clients
                .values()
                .filter(|e| e.handle.kind == ClientKind::Monitor)
                .map(|e| e.handle.id)
                .collect();
            if !monitors.is_empty() {
                let Some(frame) = self.frame(&evt) else {
                    return;
                };
                for id in monitors {
                    self.send_to(id, &frame);
                }
            }
        }

        // (2) empty type → skipped silently (`None` is an UnmarshalError upstream).
        let Some(etype) = evt.etype.clone().filter(|t| !t.is_empty()) else {
            return;
        };

        // (3) ping → pong to the source only; not routed, not persisted.
        if etype == "t-x-c-t" {
            if let Some(frame) = self.frame(&pong_event(self.clock.as_ref())) {
                self.send_to(src, &frame);
            }
            return;
        }

        // (4) handle_atom: identification / re-identification.
        if etype.starts_with('a')
            && !src_monitor
            && let Some(EventDetail::TakUser(u)) = &evt.detail
            && let Some(e) = self.clients.get_mut(&src)
        {
            e.user = Some(u.clone());
        }

        // (5) max_persist_ttl, then (6) route.
        apply_max_ttl(self.max_persist_ttl, &mut evt, self.clock.as_ref());
        let dest = match &evt.detail {
            Some(EventDetail::GeoChat(chat)) if chat.broadcast() => Dest::Broadcast,
            Some(EventDetail::GeoChat(chat)) => match chat.dst_team {
                Some(team) => Dest::Group(team),
                None => Dest::Uid(chat.dst_uid.clone()),
            },
            Some(d) if d.has_marti() => {
                pylog!(LGR, Level::DEBUG, "Handling marti");
                Dest::Callsigns(d.marti_cs())
            }
            _ => Dest::Broadcast,
        };
        let Some(frame) = self.frame(&evt) else {
            return;
        };
        match dest {
            Dest::Broadcast => {
                let evt = Arc::new(evt);
                self.broadcast(src, &evt, &frame).await;
            }
            Dest::Group(team) => self.group_broadcast(src, team, &frame),
            Dest::Uid(uid) => {
                let ids = self.find(|u| matches_key(u.uid.as_deref(), uid.as_deref()));
                self.send_all(&ids, &frame);
            }
            Dest::Callsigns(css) => {
                for cs in css {
                    let ids = self.find(|u| matches_key(u.callsign.as_deref(), cs.as_deref()));
                    self.send_all(&ids, &frame);
                }
            }
        }
    }

    /// Prune persistence if [`PRUNE_INTERVAL`] has passed since the last prune (the first call
    /// always prunes, as Python's `last_prune = 0`).
    /// `now` is `tokio::time::Instant`, so `tokio::time::pause/advance` drive it in tests.
    pub async fn maybe_prune(&mut self, now: Instant) {
        let due = self
            .last_prune
            .is_none_or(|last| now.saturating_duration_since(last) > PRUNE_INTERVAL);
        if due {
            self.last_prune = Some(now);
            self.persist.prune().await;
        }
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

    /// The identified user of one connection.
    pub fn user(&self, id: ClientId) -> Option<&TakUser> {
        self.clients.get(&id).and_then(|e| e.user.as_ref())
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

    /// Serialize once for the whole fan-out; D-8 failures are logged and the event dropped.
    fn frame(&self, evt: &Event) -> Option<Frame> {
        match evt.to_frame() {
            Ok(f) => Some(f),
            Err(e) => {
                pylog!(
                    LGR,
                    Level::ERROR,
                    "Unhandled exception parsing Event: {e} (uid={:?})",
                    evt.uid
                );
                None
            }
        }
    }

    /// `COTRouter.broadcast`: `persist.track` first, then every client except the source.
    async fn broadcast(&mut self, src: ClientId, evt: &Arc<Event>, frame: &Frame) {
        self.persist.track(evt, frame).await;
        let ids: Vec<ClientId> = self
            .clients
            .keys()
            .copied()
            .filter(|&id| id != src)
            .collect();
        self.send_all(&ids, frame);
    }

    /// `COTRouter.group_broadcast`: identified clients of `team`, except the source.
    fn group_broadcast(&mut self, src: ClientId, team: Teams, frame: &Frame) {
        let ids: Vec<ClientId> = self
            .clients
            .values()
            .filter(|e| e.handle.id != src)
            .filter(|e| e.user.as_ref().is_some_and(|u| u.group == Some(team)))
            .map(|e| e.handle.id)
            .collect();
        self.send_all(&ids, frame);
    }

    /// `find_clients`: identified clients whose user matches (the source is not excluded).
    fn find(&self, pred: impl Fn(&TakUser) -> bool) -> Vec<ClientId> {
        self.clients
            .values()
            .filter(|e| e.user.as_ref().is_some_and(&pred))
            .map(|e| e.handle.id)
            .collect()
    }

    fn send_all(&mut self, ids: &[ClientId], frame: &Frame) {
        for &id in ids {
            self.send_to(id, frame);
        }
    }

    /// Queue `frame` for `id`, applying the slow-client policy (module docs).
    fn send_to(&mut self, id: ClientId, frame: &Frame) {
        let Some(e) = self.clients.get(&id) else {
            return;
        };
        match e.handle.outbox.try_send(frame.clone()) {
            Ok(()) => {}
            Err(OutboxError::Full) => {
                pylog!(
                    LGR,
                    Level::WARN,
                    "Slow client {id:?}: outbox full, disconnecting"
                );
                e.handle.outbox.close(SLOW_CLIENT);
                self.clients.remove(&id);
                self.dropped_frames += 1;
                self.slow_disconnects += 1;
            }
            Err(OutboxError::Closed) => {
                pylog!(
                    LGR,
                    Level::DEBUG,
                    "Outbox of {id:?} closed, dropping client"
                );
                self.clients.remove(&id);
                self.dropped_frames += 1;
            }
        }
    }
}

/// `find_clients(uid=…)` / `(callsign=…)`: Python `if uid and client.user.uid == uid` — an
/// empty or missing key matches no one (V024).
fn matches_key(have: Option<&str>, want: Option<&str>) -> bool {
    match want {
        Some(w) if !w.is_empty() => have == Some(w),
        _ => false,
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
