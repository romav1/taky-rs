//! Persistence of "kept" events (`taky/cot/persistence.py`, ARCHITECTURE §13).
//!
//! An enum, not `dyn`: a new backend is a new variant (ARCHITECTURE §15). Owned by the
//! [`crate::Router`] inside the Hub actor; never shared.

use std::collections::HashMap;
use std::sync::Arc;

use taky_common::{Clock, SharedClock, pylog};
use taky_config::TakyConfig;
use tracing::Level;

use crate::models::{Event, Frame};

/// Persistence backend chosen by `build_persistence()` from `taky.redis`.
#[derive(Debug)]
pub enum Persistence {
    /// In-process map (`taky.redis` disabled).
    Memory(MemoryPersistence),
    /// Redis (`SET key frame EX ttl`, `SCAN` + `GET`).
    Redis(RedisPersistence),
}

impl Persistence {
    /// `build_persistence()`: memory or Redis from `cfg.taky.redis`; Redis connection failures
    /// are not fatal (logged, `rds_ok=false`, retried at most every 5 s).
    pub async fn from_config(cfg: &TakyConfig, clock: SharedClock) -> Persistence {
        let _ = (cfg, clock);
        todo!("S-308")
    }

    /// Memory persistence (tests, `redis` disabled).
    pub fn memory(clock: SharedClock) -> Persistence {
        Persistence::Memory(MemoryPersistence::new(clock))
    }

    /// `BasePersistence.track`: keep `evt` (already serialized as `frame`) for
    /// `evt.persist_ttl()` seconds if its `type` starts with one of [`KEPT_EVENTS`] and the
    /// TTL is positive (spec §9.1). A repeated uid replaces the kept event.
    pub async fn track(&mut self, evt: &Arc<Event>, frame: &Frame) {
        match self {
            Persistence::Memory(m) => {
                if let Some(ttl) = kept_ttl(evt, m.clock.as_ref()) {
                    m.track_event(evt, frame, ttl);
                }
            }
            Persistence::Redis(_) => todo!("S-309"),
        }
    }

    /// All kept, not yet stale events — for `send_persist` on connect.
    pub async fn get_all(&mut self) -> Vec<Arc<Event>> {
        self.get_all_frames()
            .await
            .into_iter()
            .map(|(e, _)| e)
            .collect()
    }

    /// All kept events with their wire frames (memory: first-insertion order of the uid).
    pub(crate) async fn get_all_frames(&mut self) -> Vec<(Arc<Event>, Frame)> {
        match self {
            Persistence::Memory(m) => m.get_all(),
            Persistence::Redis(_) => todo!("S-309"),
        }
    }

    /// Drop stale events (memory only; Redis expires by TTL).
    pub async fn prune(&mut self) {
        match self {
            Persistence::Memory(m) => m.prune(),
            Persistence::Redis(_) => {}
        }
    }
}

/// `KEPT_EVENTS` (`persistence.py:42-49`): plain `startswith` prefixes of persisted types.
pub const KEPT_EVENTS: [&str; 6] = ["a-", "b-m-p", "b-r-f-h-c", "u-d-c", "u-d-r", "u-d-f"];

/// The TTL to keep `evt` for, or `None` (type not kept, or `ttl <= 0`: `if not ttl or ttl < 0`).
pub fn kept_ttl(evt: &Event, clock: &dyn Clock) -> Option<i64> {
    let etype = evt.etype.as_deref()?;
    if !KEPT_EVENTS.iter().any(|k| etype.starts_with(k)) {
        return None;
    }
    let ttl = evt.persist_ttl(clock);
    (ttl > 0).then_some(ttl)
}

/// `MemoryPersistence`: `uid → event`, pruned by `stale` against the injected clock.
#[derive(Debug)]
pub struct MemoryPersistence {
    /// uid → (first-insertion sequence, event, frame); the sequence keeps Python dict order.
    events: HashMap<String, (u64, Arc<Event>, Frame)>,
    next_seq: u64,
    clock: SharedClock,
}

impl MemoryPersistence {
    /// Empty store.
    pub fn new(clock: SharedClock) -> MemoryPersistence {
        MemoryPersistence {
            events: HashMap::new(),
            next_seq: 0,
            clock,
        }
    }

    /// `Persistence.track_event`: store (replacing an existing uid in place), then prune.
    fn track_event(&mut self, evt: &Arc<Event>, frame: &Frame, ttl: i64) {
        let uid = evt.uid.clone().unwrap_or_default();
        let verb = if self.events.contains_key(&uid) {
            "Updating tracking for"
        } else {
            "New item to track"
        };
        pylog!("Persistence", Level::DEBUG, "{verb}: {uid} (ttl: {ttl})");
        let seq = match self.events.get(&uid) {
            Some((seq, _, _)) => *seq,
            None => {
                self.next_seq += 1;
                self.next_seq
            }
        };
        self.events.insert(uid, (seq, evt.clone(), frame.clone()));
        self.prune();
    }

    /// `Persistence.get_all`: prune, then all events in first-insertion order.
    fn get_all(&mut self) -> Vec<(Arc<Event>, Frame)> {
        self.prune();
        let mut v: Vec<_> = self.events.values().collect();
        v.sort_by_key(|(seq, _, _)| *seq);
        v.into_iter()
            .map(|(_, e, f)| (e.clone(), f.clone()))
            .collect()
    }

    /// `Persistence.prune`: drop events with `utcnow() > stale`.
    fn prune(&mut self) {
        let now = self.clock.utc_now();
        self.events.retain(|uid, (_, e, _)| {
            let keep = now <= e.stale;
            if !keep {
                pylog!(
                    "Persistence",
                    Level::INFO,
                    "Pruning {uid}, stale is {}",
                    e.stale
                );
            }
            keep
        });
    }

    /// Number of kept events (no pruning).
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// `true` if nothing is kept.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// The clock used for staleness checks.
    pub fn clock(&self) -> &SharedClock {
        &self.clock
    }
}

/// `RedisPersistence`: keys `taky:{hostname}:persist:{uid}` (or `taky:persist:{uid}`).
/// Connection internals (redis `ConnectionManager`, writer task) are private — S-308.
#[derive(Debug)]
pub struct RedisPersistence {
    key_space: String,
    clock: SharedClock,
}

impl RedisPersistence {
    /// Redis key prefix, e.g. `taky:example.com:persist:`.
    pub fn key_prefix(&self) -> &str {
        &self.key_space
    }

    /// The clock used for TTL computation.
    pub fn clock(&self) -> &SharedClock {
        &self.clock
    }
}
