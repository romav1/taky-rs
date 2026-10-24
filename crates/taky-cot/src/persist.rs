//! Persistence of "kept" events (`taky/cot/persistence.py`, ARCHITECTURE §13).
//!
//! An enum, not `dyn`: a new backend is a new variant (ARCHITECTURE §15). Owned by the
//! [`crate::Router`] inside the Hub actor; never shared.

use std::collections::HashMap;
use std::sync::Arc;

use taky_common::SharedClock;
use taky_config::TakyConfig;

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

    /// Keep `evt` (already serialized as `frame`) for `evt.persist_ttl()` seconds.
    pub async fn track(&mut self, evt: &Arc<Event>, frame: &Frame) {
        let _ = (evt, frame);
        todo!("S-308")
    }

    /// All kept, not yet stale events — for `send_persist` on connect.
    pub async fn get_all(&mut self) -> Vec<Arc<Event>> {
        todo!("S-308")
    }

    /// Drop stale events (memory only; Redis expires by TTL).
    pub async fn prune(&mut self) {
        todo!("S-308")
    }
}

/// `MemoryPersistence`: `uid → event`, pruned by `stale` against the injected clock.
#[derive(Debug)]
pub struct MemoryPersistence {
    events: HashMap<String, Arc<Event>>,
    clock: SharedClock,
}

impl MemoryPersistence {
    /// Empty store.
    pub fn new(clock: SharedClock) -> MemoryPersistence {
        MemoryPersistence {
            events: HashMap::new(),
            clock,
        }
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
