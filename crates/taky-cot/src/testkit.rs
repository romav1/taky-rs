//! Test hooks (feature `testkit`, qa01 request A.2/A.4; never enabled in release binaries).
//!
//! * [`TestOutbox`] — an in-memory [`Outbox`] (no tokio network);
//! * [`Router::persist_snapshot`], [`Router::find_clients`];
//! * `FakeClock` is re-exported from `taky_common::clock`.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

pub use taky_common::clock::FakeClock;

use crate::client::{ClientId, Outbox, OutboxError};
use crate::models::{Event, Frame, TakUser};
use crate::router::Router;

/// In-memory outbox: records frames and the close reason.
#[derive(Debug, Default)]
pub struct TestOutbox {
    state: Mutex<State>,
    capacity: Option<usize>,
}

#[derive(Debug, Default)]
struct State {
    frames: VecDeque<Frame>,
    closed: Option<String>,
}

impl TestOutbox {
    /// Unbounded outbox.
    pub fn new() -> Arc<TestOutbox> {
        Arc::new(TestOutbox::default())
    }

    /// Outbox that reports [`OutboxError::Full`] once it holds `capacity` frames.
    pub fn bounded(capacity: usize) -> Arc<TestOutbox> {
        Arc::new(TestOutbox {
            capacity: Some(capacity),
            ..TestOutbox::default()
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Take all queued frames.
    pub fn drain(&self) -> Vec<Frame> {
        self.lock().frames.drain(..).collect()
    }

    /// Number of queued frames.
    pub fn len(&self) -> usize {
        self.lock().frames.len()
    }

    /// `true` if nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The reason passed to [`Outbox::close`], if it was called.
    pub fn closed(&self) -> Option<String> {
        self.lock().closed.clone()
    }
}

impl Outbox for TestOutbox {
    fn try_send(&self, frame: Frame) -> Result<(), OutboxError> {
        let mut s = self.lock();
        if s.closed.is_some() {
            return Err(OutboxError::Closed);
        }
        if self.capacity.is_some_and(|c| s.frames.len() >= c) {
            return Err(OutboxError::Full);
        }
        s.frames.push_back(frame);
        Ok(())
    }

    fn close(&self, reason: &str) {
        let mut s = self.lock();
        if s.closed.is_none() {
            s.closed = Some(reason.to_owned());
        }
    }
}

/// Lookup key for [`Router::find_clients`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientQuery<'a> {
    /// Identified user's uid.
    Uid(&'a str),
    /// Identified user's callsign.
    Callsign(&'a str),
}

impl Router {
    /// All kept (persisted) events, sorted by uid — for `test_max_ttl` and vector replay.
    pub async fn persist_snapshot(&mut self) -> Vec<Arc<Event>> {
        let mut v = self.persistence().get_all().await;
        v.sort_by(|a, b| a.uid.cmp(&b.uid));
        v
    }

    /// Connections whose identified user matches `q`, in [`ClientId`] order.
    pub fn find_clients(&self, q: ClientQuery<'_>) -> Vec<ClientId> {
        self.clients()
            .filter(|(_, u)| {
                u.is_some_and(|u| match q {
                    ClientQuery::Uid(x) => u.uid.as_deref() == Some(x),
                    ClientQuery::Callsign(x) => u.callsign.as_deref() == Some(x),
                })
            })
            .map(|(h, _)| h.id)
            .collect()
    }

    /// Set the identified user of a connection directly (tests that skip the `a-*` ident event).
    pub fn testkit_set_user(&mut self, id: ClientId, user: Option<TakUser>) {
        self.set_user(id, user);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ClientHandle, ClientKind, ClientStats};
    use crate::persist::Persistence;

    #[test]
    fn test_outbox_bounded_and_close() {
        let o = TestOutbox::bounded(1);
        let f: Frame = Arc::from(&b"<event/>"[..]);
        assert_eq!(o.try_send(f.clone()), Ok(()));
        assert_eq!(o.try_send(f.clone()), Err(OutboxError::Full));
        o.close("Slow client");
        o.close("other");
        assert_eq!(o.closed().as_deref(), Some("Slow client"));
        assert_eq!(o.try_send(f), Err(OutboxError::Closed));
        assert_eq!(o.drain().len(), 1);
        assert!(o.is_empty());
    }

    #[test]
    fn find_clients_by_uid_and_callsign() {
        let t0 = chrono::NaiveDate::from_ymd_opt(2021, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let clock = FakeClock::new(t0).shared();
        let mut r = Router::new(-1, Persistence::memory(clock.clone()), clock);
        for id in [1, 2] {
            r.client_connect(ClientHandle {
                id: ClientId(id),
                kind: ClientKind::Cot,
                outbox: TestOutbox::new(),
                stats: Arc::new(ClientStats::new(0.0)),
                addr: None,
                peer_serial: None,
            });
        }
        let user = TakUser {
            uid: Some("ANDROID-1".into()),
            callsign: Some("JENNY".into()),
            ..TakUser::default()
        };
        r.testkit_set_user(ClientId(2), Some(user));
        assert_eq!(
            r.find_clients(ClientQuery::Uid("ANDROID-1")),
            vec![ClientId(2)]
        );
        assert_eq!(
            r.find_clients(ClientQuery::Callsign("JENNY")),
            vec![ClientId(2)]
        );
        assert!(r.find_clients(ClientQuery::Callsign("X")).is_empty());
    }
}
