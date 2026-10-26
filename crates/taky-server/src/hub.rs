//! The Hub actor (ARCHITECTURE §5, ADR-001): one task owns `Router`, the client table, `CertDb`
//! and `Persistence`; everything that changes routing arrives as a [`HubCmd`] over one bounded
//! `mpsc` ([`crate::limits::HUB_QUEUE`]). No `Mutex` on the hot path.
//!
//! Semantics (spec §3, §4.3, §4.6; ARCHITECTURE §6):
//! * `Connected` — ban check first (TLS peer with a serial: cert-db re-read if the file changed,
//!   D-11; status `R` ⇒ [`ConnectVerdict::Banned`], not registered, no persist), otherwise
//!   `Router::client_connect` + `send_persist`, then [`ConnectVerdict::Accepted`]. Plain-TCP and
//!   certificate-less clients skip the check (cert-db is a blacklist). The cert-db is also
//!   opened in plain mode (Python always builds `CertificateDatabase()`, server.py:84) so that
//!   mgmt `kickban` revokes there (review-3C N-1); ban-on-connect stays TLS-only.
//! * `Event` — `Router::on_event` with the **unmodified** event (max_ttl is the Router's step 5;
//!   the monitor copy keeps the original stale). Events from an id the Router no longer knows
//!   (e.g. removed as a slow client) are dropped by the Router.
//! * `Disconnected` — `Router::client_disconnect`; a no-op for an id already removed.
//! * After **every** command and on every `Tick`, `Router::maybe_prune` (Python prunes once per
//!   select-loop iteration, gated to 10 s; qa01 `core_vectors` prunes after each chunk).
//! * Shutdown: every registered client is closed with `"Server shutting down"`, then the actor
//!   returns.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use chrono::{Local, NaiveDateTime, TimeZone};
use serde_json::{Map, Value, json};
use taky_common::{SharedClock, Shutdown, pylog};
use taky_cot::{ClientHandle, ClientId, Event, Outbox, Router};
use taky_pki::{CertDb, CertStatus, PkiError};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior};
use tracing::Level;

use crate::conn::{BANNED, SHUTTING_DOWN};
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
    /// Set when a kickban job was lost (JoinError) and the cert-db could not be re-opened:
    /// the next TLS connect retries the open and is refused while it fails (fail-closed,
    /// review-3C N-4).
    cert_db_lost: Option<PathBuf>,
    clock: SharedClock,
    /// Start time, epoch seconds (`COTServer.started`; mgmt `uptime`).
    started: f64,
    rx: mpsc::Receiver<HubCmd>,
}

impl Hub {
    /// New Hub with a queue of [`crate::limits::HUB_QUEUE`]. `cert_db` is `None` if the
    /// cert-db could not be opened (plain mode) or in tests.
    pub fn new(router: Router, cert_db: Option<CertDb>, clock: SharedClock) -> (Hub, HubHandle) {
        let (tx, rx) = mpsc::channel(crate::limits::HUB_QUEUE);
        (
            Hub {
                router,
                cert_db,
                cert_db_lost: None,
                started: clock.epoch(),
                clock,
                rx,
            },
            HubHandle { tx },
        )
    }

    /// The clock (mgmt `status` uptime / kickban revoke time).
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
                let v = self.mgmt(req).await;
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
        if let (Some(_), None, Some(path)) = (
            handle.peer_serial.as_ref(),
            self.cert_db.as_ref(),
            self.cert_db_lost.clone(),
        ) {
            match CertDb::open(&path) {
                Ok(db) => {
                    self.cert_db = Some(db);
                    self.cert_db_lost = None;
                }
                Err(e) => {
                    pylog!(
                        LGR,
                        Level::ERROR,
                        "Unable to re-open cert-db, refusing client: {e}"
                    );
                    return ConnectVerdict::Banned;
                }
            }
        }
        if let (Some(serial), Some(db)) = (handle.peer_serial.as_deref(), self.cert_db.as_mut()) {
            pylog!(
                LGR,
                Level::DEBUG,
                "Checking {} against cert db",
                hex_upper(serial)
            );
            // One WARNING per cert-db change, not per connect (review-3D N-2).
            if let Some(e) = db.refresh() {
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

/// Mgmt requests (spec §13, `mgmt.py:57-113`).
impl Hub {
    async fn mgmt(&mut self, req: MgmtRequest) -> Value {
        match req {
            MgmtRequest::Ping => json!({"pong": "taky"}),
            MgmtRequest::Status => self.status(),
            MgmtRequest::Kickban { user } => self.kickban(user.as_deref()).await,
            MgmtRequest::Invalid { cmd } => MgmtRequest::invalid_reply(&cmd),
        }
    }

    /// `status`: every registered client (regular + monitor) in connection order. Key order as
    /// Python's dict; `last_rx` is the int `0` until the first event; `group` is `str(Teams)`.
    fn status(&self) -> Value {
        let mut clients = Vec::new();
        for (h, user) in self.router.clients() {
            let mut m = Map::new();
            let num_rx = h.stats.num_rx.load(Ordering::Relaxed);
            let last_rx = if num_rx == 0 {
                Value::from(0)
            } else {
                py_float(h.stats.last_rx.load())
            };
            m.insert("last_rx".into(), last_rx);
            m.insert("num_rx".into(), Value::from(num_rx));
            m.insert("connected".into(), py_float(h.stats.connected));
            match user {
                Some(u) => {
                    if let Some(a) = h.addr {
                        m.insert("ip".into(), Value::from(a.ip().to_string()));
                    }
                    let group = u.group.map_or_else(|| "None".to_owned(), |g| g.py_str());
                    let d = &u.device;
                    for (k, v) in [
                        ("uid", u.uid.clone()),
                        ("callsign", u.callsign.clone()),
                        ("group", Some(group)),
                        ("battery", u.battery.clone()),
                        ("device", d.device.clone()),
                        ("os", d.os.clone()),
                        ("version", d.version.clone()),
                        ("platform", d.platform.clone()),
                    ] {
                        m.insert(k.into(), v.map_or(Value::Null, Value::from));
                    }
                }
                None => {
                    m.insert("anonymous".into(), Value::Bool(true));
                }
            }
            clients.push(Value::Object(m));
        }
        let mut ret = Map::new();
        ret.insert("uptime".into(), py_float(self.clock.epoch() - self.started));
        ret.insert("num_clients".into(), Value::from(clients.len()));
        ret.insert("clients".into(), Value::Array(clients));
        Value::Object(ret)
    }

    /// `kickban`: revoke every not-yet-revoked cert-db record named `user` (time = local
    /// `now()` from the injected clock, as `revoke_certificate`), then close each connection
    /// presenting that serial with `"Banned"` and drop it from the Router at once.
    /// The cert-db is re-read first if the file changed (D-11, V052). File I/O runs in
    /// `spawn_blocking`. A revoke that fails to write is logged (ERROR) and not reported.
    async fn kickban(&mut self, user: Option<&str>) -> Value {
        let mut revoked: Vec<Value> = Vec::new();
        // Check `user` before taking the db: a user-less request must not lose it (BUG-1, bans
        // would fail open). Python: `get_certificates_by_name(None / non-str)` matches nothing.
        let Some(user) = user else {
            return json!({ "revoked_sns": revoked });
        };
        let Some(db) = self.cert_db.take() else {
            return json!({ "revoked_sns": revoked });
        };
        let path = db.path().to_owned();
        let when = Local.from_utc_datetime(&self.clock.utc_now()).naive_local();
        let name = user.to_owned();
        let job = tokio::task::spawn_blocking(move || {
            let mut db = db;
            // A panic must not lose the db (bans would fail open, review-3C N-4).
            let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                kickban_blocking(&mut db, &name, when)
            }));
            (db, out)
        })
        .await;
        let (db, out) = match job {
            Ok(x) => x,
            Err(e) => {
                // Only a cancelled task (runtime shutting down) gets here: the db is gone.
                pylog!(LGR, Level::ERROR, "kickban failed: {e}");
                match CertDb::open(&path) {
                    Ok(db) => self.cert_db = Some(db),
                    Err(e) => {
                        pylog!(LGR, Level::ERROR, "Unable to re-open cert-db: {e}");
                        self.cert_db_lost = Some(path);
                    }
                }
                return json!({ "revoked_sns": revoked });
            }
        };
        self.cert_db = Some(db);
        let Ok(out) = out else {
            pylog!(LGR, Level::ERROR, "kickban failed: task panicked");
            return json!({ "revoked_sns": revoked });
        };
        let KickbanResult {
            refresh_err,
            results,
            skipped,
        } = out;
        if let Some(e) = refresh_err {
            pylog!(LGR, Level::WARN, "Unable to re-read cert-db: {e}");
        }
        for (sn, res) in results {
            if let Err(e) = res {
                pylog!(
                    "MgmtClient",
                    Level::ERROR,
                    "Unable to revoke certificate for {user} (SN: {}): {e}",
                    hex40(&sn)
                );
                continue;
            }
            pylog!(
                "MgmtClient",
                Level::INFO,
                "Revoked certificate for {user} (SN: {})",
                hex40(&sn)
            );
            revoked.push(big_int(&sn));
            let victims: Vec<(ClientId, Arc<dyn Outbox>)> = self
                .router
                .clients()
                .filter(|(h, _)| {
                    h.peer_serial
                        .as_deref()
                        .is_some_and(|p| strip_zeros(p) == strip_zeros(&sn))
                })
                .map(|(h, _)| (h.id, h.outbox.clone()))
                .collect();
            for (id, outbox) in victims {
                pylog!("MgmtClient", Level::INFO, "Kicking user {user} from server");
                outbox.close(BANNED);
                self.router.client_disconnect(id);
            }
        }
        if !skipped.is_empty() {
            for sn in &skipped {
                pylog!(
                    "MgmtClient",
                    Level::ERROR,
                    "Unable to revoke certificate for {user} (SN: {}): cert-db lock busy, not attempted",
                    hex40(sn)
                );
            }
            pylog!(
                "MgmtClient",
                Level::ERROR,
                "kickban {user}: {} certificate(s) not revoked after a cert-db lock timeout",
                skipped.len()
            );
        }
        json!({ "revoked_sns": revoked })
    }
}

/// Result of [`kickban_blocking`].
struct KickbanResult {
    /// The cert-db re-read error, if any.
    refresh_err: Option<PkiError>,
    /// Each revoke attempted, in cert-db order.
    results: Vec<(Vec<u8>, Result<(), PkiError>)>,
    /// Live serials not attempted after a lock timeout (review-3E N-1).
    skipped: Vec<Vec<u8>>,
}

#[cfg(test)]
static KICKBAN_PANIC: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Test hook: run once after the first successful revoke in the cert-db at this path.
#[cfg(test)]
type AfterRevokeHook = (PathBuf, Box<dyn FnOnce() + Send>);
#[cfg(test)]
static KICKBAN_AFTER_REVOKE: std::sync::Mutex<Option<AfterRevokeHook>> =
    std::sync::Mutex::new(None);

/// The blocking part of `kickban`: re-read the cert-db if changed, revoke `name`'s live records.
/// After the first lock timeout (`WouldBlock`, [`taky_pki::certdb::LOCK_WAIT`]) the remaining
/// serials are not attempted, so the Hub stalls for at most one lock wait (review-3E N-1).
fn kickban_blocking(db: &mut CertDb, name: &str, when: NaiveDateTime) -> KickbanResult {
    let refresh_err = db.refresh();
    #[cfg(test)]
    if KICKBAN_PANIC.swap(false, Ordering::SeqCst) {
        panic!("injected kickban panic");
    }
    let serials: Vec<Vec<u8>> = db
        .by_name(name)
        .filter(|r| r.status != CertStatus::Revoked)
        .map(|r| r.serial.clone())
        .collect();
    let mut results = Vec::with_capacity(serials.len());
    let mut serials = serials.into_iter();
    for sn in serials.by_ref() {
        let r = db.revoke(&sn, when);
        let lock_busy = matches!(
            &r,
            Err(PkiError::Io { source, .. }) if source.kind() == std::io::ErrorKind::WouldBlock
        );
        #[cfg(test)]
        if r.is_ok() {
            let mut hook = KICKBAN_AFTER_REVOKE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some((_, f)) = hook.take_if(|(p, _)| p.as_path() == db.path()) {
                f();
            }
        }
        results.push((sn, r));
        if lock_busy {
            break;
        }
    }
    KickbanResult {
        refresh_err,
        results,
        skipped: serials.collect(),
    }
}

/// A float as Python prints it (`5.0`, not `5`).
fn py_float(f: f64) -> Value {
    serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)
}

fn strip_zeros(b: &[u8]) -> &[u8] {
    let i = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[i..]
}

/// `f"{sn:040x}"`.
fn hex40(sn: &[u8]) -> String {
    let h: String = strip_zeros(sn).iter().map(|x| format!("{x:02x}")).collect();
    let h = h.trim_start_matches('0');
    format!("{h:0>40}")
}

/// A big-endian unsigned integer as a JSON integer of any size (`arbitrary_precision`).
fn big_int(sn: &[u8]) -> Value {
    // Repeated division by 10 of the big-endian byte string.
    let mut digits = Vec::new();
    let mut n: Vec<u8> = strip_zeros(sn).to_vec();
    while !n.is_empty() {
        let mut rem = 0u32;
        let mut q = Vec::with_capacity(n.len());
        for &b in &n {
            let cur = (rem << 8) | u32::from(b);
            let d = cur / 10;
            rem = cur % 10;
            if !(q.is_empty() && d == 0) {
                q.push(u8::try_from(d).unwrap_or(0));
            }
        }
        digits.push(b'0' + u8::try_from(rem).unwrap_or(0));
        n = q;
    }
    if digits.is_empty() {
        digits.push(b'0');
    }
    digits.reverse();
    let text = String::from_utf8(digits).unwrap_or_else(|_| "0".into());
    serde_json::from_str::<serde_json::Number>(&text).map_or(Value::Null, Value::Number)
}

fn hex_upper(b: &[u8]) -> String {
    if b.is_empty() {
        return "00".to_owned();
    }
    b.iter().map(|x| format!("{x:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::ConnOutbox;
    use taky_common::clock::FakeClock;
    use taky_cot::{ClientKind, ClientStats, Persistence};

    async fn connect_serial(hub: &mut Hub, id: u64, serial: Vec<u8>) -> ConnectVerdict {
        let (ob, _rx) = ConnOutbox::new();
        hub.connect(ClientHandle {
            id: ClientId(id),
            kind: ClientKind::Cot,
            outbox: ob,
            stats: Arc::new(ClientStats::new(0.0)),
            addr: None,
            peer_serial: Some(serial),
        })
        .await
    }

    /// review-3C N-4: a kickban job that panics keeps the cert-db (bans stay enforced), even
    /// when the file can no longer be opened; a lost db makes TLS connects fail closed.
    #[tokio::test]
    async fn kickban_panic_keeps_cert_db() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert-db.txt");
        std::fs::write(
            &path,
            "R\t2026-01-01T00:00:00\t2027-01-01T00:00:00\t0a\talice\n\
             V\t2026-01-01T00:00:00\t2027-01-01T00:00:00\t0b\tbob\n",
        )
        .unwrap();
        let clock =
            FakeClock::new(taky_cot::isoparse::isoparse("2030-01-01T00:00:00Z").unwrap()).shared();
        let router = Router::new(-1, Persistence::memory(clock.clone()), clock.clone());
        let mut hub = Hub::new(router, Some(CertDb::open(&path).unwrap()), clock).0;
        // The file becomes unreadable (a directory): a re-open would fail.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        KICKBAN_PANIC.store(true, Ordering::SeqCst);
        assert_eq!(hub.kickban(Some("bob")).await, json!({"revoked_sns": []}));
        assert!(hub.cert_db.is_some());
        assert_eq!(
            connect_serial(&mut hub, 1, vec![0x0a]).await,
            ConnectVerdict::Banned
        );
        assert_eq!(
            connect_serial(&mut hub, 2, vec![0x0b]).await,
            ConnectVerdict::Accepted
        );

        // Lost db (cancelled job, re-open failed): refused until the open succeeds.
        hub.cert_db = None;
        hub.cert_db_lost = Some(path.clone());
        assert_eq!(
            connect_serial(&mut hub, 3, vec![0x0b]).await,
            ConnectVerdict::Banned
        );
        std::fs::remove_dir(&path).unwrap();
        assert_eq!(
            connect_serial(&mut hub, 4, vec![0x0b]).await,
            ConnectVerdict::Accepted
        );
        assert!(hub.cert_db.is_some() && hub.cert_db_lost.is_none());
    }

    /// BUG-1 (S-403a): a kickban without a (string) user keeps the cert-db: a revoked peer is
    /// still refused and a later kickban with a user still revokes.
    #[tokio::test]
    async fn kickban_without_user_keeps_cert_db() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert-db.txt");
        std::fs::write(
            &path,
            "R\t2026-01-01T00:00:00\t2027-01-01T00:00:00\t0a\tcarol\n\
             V\t2026-01-01T00:00:00\t2027-01-01T00:00:00\t0b\tbob\n",
        )
        .unwrap();
        let clock =
            FakeClock::new(taky_cot::isoparse::isoparse("2030-01-01T00:00:00Z").unwrap()).shared();
        let router = Router::new(-1, Persistence::memory(clock.clone()), clock.clone());
        let mut hub = Hub::new(router, Some(CertDb::open(&path).unwrap()), clock).0;

        assert_eq!(hub.kickban(None).await, json!({"revoked_sns": []}));
        assert!(hub.cert_db.is_some() && hub.cert_db_lost.is_none());
        assert_eq!(
            connect_serial(&mut hub, 1, vec![0x0a]).await,
            ConnectVerdict::Banned
        );
        assert_eq!(hub.kickban(Some("bob")).await, json!({"revoked_sns": [11]}));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.lines()
                .any(|l| l.starts_with("R\t") && l.ends_with("\tbob"))
        );
        assert_eq!(
            connect_serial(&mut hub, 2, vec![0x0b]).await,
            ConnectVerdict::Banned
        );
    }

    /// review-3E N-1: under a held `<cert_db>.lock` kickban gives up after the first lock
    /// timeout: the Hub stalls ~one `LOCK_WAIT` (not one per live cert), the cert revoked before
    /// the lock was taken is still reported and its session kicked, the rest stay valid.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kickban_stops_after_first_lock_timeout() {
        use nix::fcntl::{Flock, FlockArg};
        use taky_pki::certdb::LOCK_WAIT;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert-db.txt");
        std::fs::write(
            &path,
            "V\t2026-01-01T00:00:00\t2027-01-01T00:00:00\t0b\tbob\n\
             V\t2026-01-01T00:00:00\t2027-01-01T00:00:00\t0c\tbob\n\
             V\t2026-01-01T00:00:00\t2027-01-01T00:00:00\t0d\tbob\n\
             V\t2026-01-01T00:00:00\t2027-01-01T00:00:00\t0e\tbob\n",
        )
        .unwrap();
        let clock =
            FakeClock::new(taky_cot::isoparse::isoparse("2030-01-01T00:00:00Z").unwrap()).shared();
        let router = Router::new(-1, Persistence::memory(clock.clone()), clock.clone());
        let mut hub = Hub::new(router, Some(CertDb::open(&path).unwrap()), clock).0;
        let mut outboxes = Vec::new();
        for (id, sn) in [(1u64, 0x0bu8), (2, 0x0c)] {
            let (ob, _rx) = ConnOutbox::new();
            outboxes.push(ob.clone());
            let verdict = hub
                .connect(ClientHandle {
                    id: ClientId(id),
                    kind: ClientKind::Cot,
                    outbox: ob,
                    stats: Arc::new(ClientStats::new(0.0)),
                    addr: None,
                    peer_serial: Some(vec![sn]),
                })
                .await;
            assert_eq!(verdict, ConnectVerdict::Accepted);
        }

        // Another process takes the lock right after the first revoke (0b).
        let held: Arc<std::sync::Mutex<Option<Flock<std::fs::File>>>> = Arc::default();
        let (lock_path, slot) = (dir.path().join("cert-db.txt.lock"), held.clone());
        *KICKBAN_AFTER_REVOKE.lock().unwrap() = Some((
            path.clone(),
            Box::new(move || {
                let f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(lock_path)
                    .unwrap();
                *slot.lock().unwrap() =
                    Some(Flock::lock(f, FlockArg::LockExclusiveNonblock).unwrap());
            }),
        ));

        let start = std::time::Instant::now();
        let out = hub.kickban(Some("bob")).await;
        let took = start.elapsed();
        assert_eq!(out, json!({"revoked_sns": [11]}));
        assert!(took >= LOCK_WAIT, "no lock wait: {took:?}");
        assert!(took < LOCK_WAIT * 2, "stalled once per cert: {took:?}");
        assert_eq!(outboxes[0].close_reason(), Some(BANNED));
        assert!(!outboxes[1].is_closed());
        let ids: Vec<u64> = hub.router.clients().map(|(h, _)| h.id.0).collect();
        assert_eq!(ids, vec![2]);
        let text = std::fs::read_to_string(&path).unwrap();
        let status: Vec<&str> = text.lines().map(|l| &l[..1]).collect();
        assert_eq!(status, ["R", "V", "V", "V"]);

        // Lock released: the next kickban revokes the rest and kicks 0c.
        drop(held.lock().unwrap().take());
        assert_eq!(
            hub.kickban(Some("bob")).await,
            json!({"revoked_sns": [12, 13, 14]})
        );
        assert_eq!(outboxes[1].close_reason(), Some(BANNED));
        assert_eq!(hub.router.clients().count(), 0);
    }

    #[test]
    fn big_int_and_hex() {
        assert_eq!(big_int(&[]).to_string(), "0");
        assert_eq!(big_int(&[0, 1, 0]).to_string(), "256");
        assert_eq!(big_int(&[0x8f, 0x03, 0x42]).to_string(), "9372482");
        let max = [0x7fu8; 20];
        assert_eq!(
            big_int(&max).to_string(),
            "727885129180488904360266563744972327436484050815"
        );
        assert_eq!(hex40(&[0x8f, 0x03, 0x42]), format!("{:0>40}", "8f0342"));
        assert_eq!(hex40(&[0x00, 0x0a]), format!("{:0>40}", "a"));
    }
}
