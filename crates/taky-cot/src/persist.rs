//! Persistence of "kept" events (`taky/cot/persistence.py`, ARCHITECTURE §13).
//!
//! An enum, not `dyn`: a new backend is a new variant (ARCHITECTURE §15). Owned by the
//! [`crate::Router`] inside the Hub actor; never shared.

use std::collections::HashMap;
use std::sync::Arc;

use std::time::Duration;
use taky_common::{Clock, SharedClock, pylog};

use chrono::{NaiveDateTime, TimeDelta};
use redis::AsyncCommands;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use taky_config::{RedisSetting, TakyConfig};
use tracing::Level;

use crate::limits::STREAM_LIMITS;
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
    ///
    /// Errors only for a `redis` URL that cannot be parsed (Python's `StrictRedis.from_url`
    /// raises `ValueError` at startup); an unreachable server is **not** an error.
    pub async fn from_config(
        cfg: &TakyConfig,
        clock: SharedClock,
    ) -> Result<Persistence, PersistError> {
        let url = match &cfg.taky.redis {
            RedisSetting::Disabled => return Ok(Persistence::memory(clock)),
            RedisSetting::Localhost => None,
            RedisSetting::Url(u) => Some(u.as_str()),
        };
        let r = RedisPersistence::connect(&cfg.taky.hostname, url, clock).await?;
        Ok(Persistence::Redis(r))
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
            Persistence::Redis(r) => {
                if let Some(ttl) = kept_ttl(evt, r.clock.as_ref()) {
                    r.track_event(evt, frame, ttl).await;
                }
            }
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
            Persistence::Redis(r) => r.get_all().await,
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

/// `Persistence::from_config` failure: the `[taky] redis` URL is invalid.
#[derive(Debug, thiserror::Error)]
#[error("invalid redis URL {url:?}: {source}")]
pub struct PersistError {
    /// The configured value.
    pub url: String,
    /// redis-rs parse error.
    #[source]
    pub source: redis::RedisError,
}

/// `redis = true`: Python's `StrictRedis()` default (`localhost:6379`, db 0).
pub const DEFAULT_REDIS_URL: &str = "redis://127.0.0.1:6379/0";
/// Connect timeout (ARCHITECTURE §13).
pub const REDIS_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
/// Per-command response timeout (ARCHITECTURE §13).
pub const REDIS_RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);
/// While the connection is down, at most one attempt per this interval (injected clock).
pub const REDIS_RETRY_INTERVAL: TimeDelta = TimeDelta::seconds(5);
/// `SCAN … COUNT` hint.
const SCAN_COUNT: usize = 1000;
const LGR: &str = "RedisPersistence";

/// `taky:{hostname}:persist`, or `taky:persist` for an empty hostname (`persistence.py:193-196`).
pub fn redis_key_space(hostname: &str) -> String {
    if hostname.is_empty() {
        "taky:persist".to_string()
    } else {
        format!("taky:{hostname}:persist")
    }
}

/// `RedisPersistence` (spec §9.4, byte-compatible with Python taky on the same DB):
/// * key `taky:{hostname}:persist:{uid}` (uid verbatim, no escaping);
/// * value = the wire frame, i.e. `etree.tostring(event.as_element)` bytes, no declaration;
/// * `SET key value EX ttl` (D-4; same resulting state as Python's `SET` + `EXPIRE`),
///   ttl = `persist_ttl` against the injected clock;
/// * read: `SCAN MATCH taky:{hostname}:persist:*` (D-5) + `GET`, parsed as one document;
///   a value that fails to parse/unmarshal, or a non-connection error (e.g. `WRONGTYPE`) ⇒
///   WARNING `Purging key …` + `DEL`. Other keyspaces are never touched.
///
/// Connection errors never propagate: the operation is skipped and the `rds_ok` latch logs
/// `Lost connection to redis` / `Connection to redis restored`. While down, a reconnect is
/// attempted at most every [`REDIS_RETRY_INTERVAL`] (injected clock); other calls are skipped
/// immediately, so the Hub never waits on a dead server more than once per interval.
pub struct RedisPersistence {
    key_space: String,
    client: redis::Client,
    conn: Option<ConnectionManager>,
    rds_ok: bool,
    last_attempt: Option<NaiveDateTime>,
    clock: SharedClock,
}

impl std::fmt::Debug for RedisPersistence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisPersistence")
            .field("key_space", &self.key_space)
            .field("connected", &self.conn.is_some())
            .field("rds_ok", &self.rds_ok)
            .finish()
    }
}

/// Python's `redis.ConnectionError` (and timeouts): skip + latch, never purge.
fn is_connection_error(e: &redis::RedisError) -> bool {
    e.is_io_error() || e.is_timeout() || e.is_connection_dropped() || e.is_connection_refusal()
}

impl RedisPersistence {
    /// `RedisPersistence.__init__`: parse the URL (`None` ⇒ [`DEFAULT_REDIS_URL`]), connect,
    /// count the keyspace (INFO `Tracking N items`). An unreachable server only clears the
    /// latch (WARNING `Lost connection to redis`).
    pub async fn connect(
        hostname: &str,
        url: Option<&str>,
        clock: SharedClock,
    ) -> Result<RedisPersistence, PersistError> {
        let key_space = redis_key_space(hostname);
        let target = match url {
            Some(u) => {
                pylog!(LGR, Level::INFO, "Connecting to {u}");
                u
            }
            None => {
                pylog!(LGR, Level::INFO, "Connecting to default redis");
                DEFAULT_REDIS_URL
            }
        };
        let client = redis::Client::open(target).map_err(|source| PersistError {
            url: target.to_string(),
            source,
        })?;
        let mut r = RedisPersistence {
            key_space,
            client,
            conn: None,
            rds_ok: true,
            last_attempt: None,
            clock,
        };
        if let Some(keys) = r.scan_keys().await {
            pylog!(LGR, Level::INFO, "Tracking {} items", keys.len());
        }
        Ok(r)
    }

    /// Redis key prefix, e.g. `taky:example.com:persist:`.
    pub fn key_prefix(&self) -> String {
        format!("{}:", self.key_space)
    }

    /// The key of `uid`: `taky:{hostname}:persist:{uid}`.
    pub fn key(&self, uid: &str) -> String {
        format!("{}:{uid}", self.key_space)
    }

    /// The clock used for TTL computation and the reconnect interval.
    pub fn clock(&self) -> &SharedClock {
        &self.clock
    }

    /// The `rds_ok` latch: `false` after a connection error until the next success.
    pub fn is_ok(&self) -> bool {
        self.rds_ok
    }

    /// `_redis_result`: set/reset latch with WARNING on each transition.
    fn result(&mut self, ok: bool) {
        if self.rds_ok && !ok {
            pylog!(LGR, Level::WARN, "Lost connection to redis");
        } else if !self.rds_ok && ok {
            pylog!(LGR, Level::WARN, "Connection to redis restored");
        }
        self.rds_ok = ok;
    }

    /// A live connection, or `None` (latch cleared) if the server cannot be reached now or the
    /// retry interval since the last failed attempt has not passed.
    async fn conn(&mut self) -> Option<ConnectionManager> {
        if let Some(c) = &self.conn {
            return Some(c.clone());
        }
        let now = self.clock.utc_now();
        if !self.rds_ok
            && let Some(t) = self.last_attempt
            && now >= t
            && now - t < REDIS_RETRY_INTERVAL
        {
            return None;
        }
        self.last_attempt = Some(now);
        let cfg = ConnectionManagerConfig::new()
            .set_connection_timeout(REDIS_CONNECT_TIMEOUT)
            .set_response_timeout(REDIS_RESPONSE_TIMEOUT)
            .set_number_of_retries(0);
        match ConnectionManager::new_with_config(self.client.clone(), cfg).await {
            Ok(c) => {
                self.conn = Some(c.clone());
                Some(c)
            }
            Err(e) => {
                pylog!(LGR, Level::DEBUG, "Redis connect failed: {e}");
                self.result(false);
                None
            }
        }
    }

    /// Record a command error: connection-class ⇒ drop the connection + latch; returns `true`
    /// if it was a connection error.
    fn on_error(&mut self, e: &redis::RedisError) -> bool {
        if is_connection_error(e) {
            pylog!(LGR, Level::DEBUG, "Redis connection error: {e}");
            self.conn = None;
            self.last_attempt = Some(self.clock.utc_now());
            self.result(false);
            true
        } else {
            false
        }
    }

    /// `track_event`: `SET key frame EX ttl` (`ttl > 0`, checked by the caller).
    async fn track_event(&mut self, evt: &Arc<Event>, frame: &Frame, ttl: i64) {
        let uid = evt.uid.as_deref().unwrap_or_default();
        pylog!(LGR, Level::DEBUG, "Tracking {uid} (ttl: {ttl})");
        let key = self.key(uid);
        let Some(mut c) = self.conn().await else {
            return;
        };
        let ttl = u64::try_from(ttl).unwrap_or(1);
        let res: redis::RedisResult<()> = c.set_ex(&key, &frame[..], ttl).await;
        match res {
            Ok(()) => self.result(true),
            Err(e) => {
                if !self.on_error(&e) {
                    pylog!(LGR, Level::WARN, "Unable to store {key}: {e}");
                }
            }
        }
    }

    /// All keys of the own keyspace (`SCAN MATCH {ks}:* COUNT 1000`); `None` on a connection
    /// error. A key is reported once even if `SCAN` returns it twice.
    async fn scan_keys(&mut self) -> Option<Vec<Vec<u8>>> {
        let mut c = self.conn().await?;
        let pattern = format!("{}:*", self.key_space);
        let mut cursor: u64 = 0;
        let mut keys: Vec<Vec<u8>> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        loop {
            let res: redis::RedisResult<(u64, Vec<Vec<u8>>)> = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(SCAN_COUNT)
                .query_async(&mut c)
                .await;
            match res {
                Ok((next, batch)) => {
                    for k in batch {
                        if seen.insert(k.clone()) {
                            keys.push(k);
                        }
                    }
                    if next == 0 {
                        break;
                    }
                    cursor = next;
                }
                Err(e) => {
                    if !self.on_error(&e) {
                        pylog!(LGR, Level::WARN, "Unable to list persistence store: {e}");
                    }
                    return None;
                }
            }
        }
        self.result(true);
        Some(keys)
    }

    /// `get_all`: every key of the keyspace through `_get_event(key)`; unparsable ones purged.
    async fn get_all(&mut self) -> Vec<(Arc<Event>, Frame)> {
        let Some(keys) = self.scan_keys().await else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(ef) = self.get_key(&key).await {
                out.push(ef);
            }
        }
        out
    }

    /// The event stored under `uid`, if any (`get_event`; purges an unparsable value).
    pub async fn get_event(&mut self, uid: &str) -> Option<Arc<Event>> {
        let key = self.key(uid);
        self.get_key(key.as_bytes()).await.map(|(e, _)| e)
    }

    /// `_get_event(key, uid_is_redis_key=True)`: `GET`, parse as one document, `Event.from_elm`,
    /// then re-serialize for the wire (attributes as in the store, spec §9.5).
    async fn get_key(&mut self, key: &[u8]) -> Option<(Arc<Event>, Frame)> {
        let shown = String::from_utf8_lossy(key).into_owned();
        let mut c = self.conn().await?;
        let res: redis::RedisResult<Option<Vec<u8>>> = c.get(key).await;
        let why = match res {
            Ok(None) => {
                self.result(true);
                return None;
            }
            Ok(Some(xml)) => {
                self.result(true);
                match decode_stored(&xml) {
                    Ok(evt) => match evt.to_frame() {
                        Ok(frame) => return Some((Arc::new(evt), frame)),
                        Err(e) => {
                            // Python would raise later in send_event (D-8); not purged there.
                            pylog!(
                                LGR,
                                Level::ERROR,
                                "Unhandled exception parsing Event from persistence store: {e}"
                            );
                            return None;
                        }
                    },
                    Err(why) => why,
                }
            }
            Err(e) => {
                if self.on_error(&e) {
                    return None;
                }
                format!("Unable to get Event from persistence store: {e}")
            }
        };
        pylog!(LGR, Level::WARN, "{why}");
        pylog!(LGR, Level::WARN, "Purging key {shown}");
        if let Some(mut c) = self.conn().await {
            let res: redis::RedisResult<i64> = c.del(key).await;
            if let Err(e) = res {
                self.on_error(&e);
            }
        }
        None
    }
}

/// Parse a stored value (`XMLParser(resolve_entities=False)` + `Event.from_elm`); `Err` carries
/// the WARNING text of `_get_event`.
fn decode_stored(xml: &[u8]) -> Result<Event, String> {
    let elm = taky_xml::parse_element(xml, &STREAM_LIMITS)
        .map_err(|e| format!("Unable to parse Event from persistence store: {e}"))?;
    Event::from_element(&elm)
        .map_err(|e| format!("Unable to parse Event from persistence store: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_space_matches_python() {
        assert_eq!(redis_key_space("taky.example"), "taky:taky.example:persist");
        assert_eq!(redis_key_space(""), "taky:persist");
    }

    #[test]
    fn decode_stored_rejects_corrupt_values() {
        assert!(decode_stored(b"<event><not closed").is_err());
        assert!(decode_stored(b"<other/>").is_err());
        let ok = b"<event version=\"2.0\" uid=\"X\" type=\"a-u-G\" how=\"h-e\" \
time=\"2030-01-01T00:00:00.000Z\" start=\"2030-01-01T00:00:00.000Z\" \
stale=\"2030-01-01T00:10:00.000Z\"/>";
        let evt = decode_stored(ok).expect("valid");
        assert_eq!(evt.uid.as_deref(), Some("X"));
        // Declaration allowed (external writers).
        let mut with_decl = b"<?xml version=\"1.0\"?>".to_vec();
        with_decl.extend_from_slice(ok);
        assert!(decode_stored(&with_decl).is_ok());
    }

    #[tokio::test]
    async fn invalid_url_is_an_error_unreachable_is_not() {
        let clock = taky_common::SystemClock::shared();
        assert!(
            RedisPersistence::connect("h", Some("nope://x"), clock.clone())
                .await
                .is_err()
        );
        // Nothing listens on port 1: connect succeeds, latch is cleared.
        let r = RedisPersistence::connect("h", Some("redis://127.0.0.1:1/0"), clock)
            .await
            .expect("valid URL");
        assert!(!r.is_ok());
        assert_eq!(r.key("U-1"), "taky:h:persist:U-1");
    }
}
