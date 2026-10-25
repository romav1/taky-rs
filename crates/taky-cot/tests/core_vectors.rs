//! qa01 S-310: replay of the an01 CoT vectors (`tests/vectors/cot`, format 2) against the
//! taky-cot core — `CotDecoder` + `Event::from_element` + `Router` + `Persistence` — with no
//! network (no sockets, TLS, mgmt socket, monitor port or log_cot).
//!
//! * Rust expectations: `exp = step.rust_expect ?? step.expect`,
//!   `final = vec.final_rust_expect ?? vec.final_expect` (vectors README, Format 2).
//! * The connection task is emulated minimally, as spec §5/§6 and ARCHITECTURE §14 describe it:
//!   each chunk goes through one `CotDecoder::decode` loop (like `FramedRead`), a decoder error closes
//!   the connection ("XML Syntax Error") and unregisters it, an `UnmarshalError` drops the event,
//!   everything else goes to `Router::on_event`. `connect` = `client_connect` + `send_persist`.
//! * The Hub's prune tick is emulated by `Router::maybe_prune` after every chunk / step, with a
//!   tokio `Instant` that follows the `FakeClock` (frozen `now` + `advance`).
//! * Settle = synchronous: after a step every `TestOutbox` is drained.
//! * Memory persist via `Router::persist_snapshot()` (testkit); Redis via a private
//!   `redis-server` (skipped with a note when the binary is missing, unless `TAKY_REQUIRE_REDIS`).
//! * Vectors that need the network layer are N/A (table `NA`). Some of them have a meaningful
//!   core subset (`core_subset`), which is replayed for information only (not counted).
//!
//! The test fails on an unexpected FAIL or when a vector listed in `KNOWN_FAIL` passes again.
//! Set `CORE_VECTORS_REPORT=<path>` to write the per-vector table (Markdown) to a file.
#![cfg(feature = "testkit")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use chrono::{NaiveDateTime, TimeDelta};
use serde_json::Value;
use taky_common::vectors::vectors_dir;
use taky_cot::testkit::{FakeClock, TestOutbox};
use taky_cot::{
    ClientHandle, ClientId, ClientKind, ClientStats, CotDecoder, Event, Persistence, Router,
};
use tokio_util::codec::Decoder;

/// Vectors that need a layer that is not part of the core (S-312..S-314).
/// `(id, reason, core_subset)`: `core_subset` = replay the routing part for information.
const NA: &[(&str, &str, bool)] = &[
    (
        "V044",
        "log_cot files (CotLogger, S-313); final_expect is log_files only",
        false,
    ),
    (
        "V045",
        "mgmt socket requests/responses (ping/status/invalid JSON, S-314)",
        false,
    ),
    (
        "V046",
        "mgmt_hold/mgmt_release need the mgmt socket (S-314); D-9 routing part replayed as core subset",
        true,
    ),
    (
        "V047",
        "TLS + monitor port + cert_db_status (S-312); monitor routing replayed as core subset",
        true,
    ),
    (
        "V048",
        "TLS handshake + revoked-cert ban on connect + cert-db (S-312)",
        false,
    ),
    ("V049", "TLS + mgmt kickban + cert-db (S-312/S-314)", false),
    ("V051", "mgmt socket only (D-10, S-314)", false),
    (
        "V052",
        "TLS + issue_cert + mgmt kickban, cert-db re-read (D-11, S-312/S-314)",
        false,
    ),
    (
        "V053",
        "log_cot path traversal (D-12, S-313); final_expect is log_files only",
        false,
    ),
];

/// Real Rust bugs reported to dev01, `(id, message id)`. The test fails if one of them passes,
/// so the list must be trimmed when dev01 fixes them.
const KNOWN_FAIL: &[(&str, &str)] = &[];

// ---------------------------------------------------------------------------------------------
// redis-server helper (same approach as tests/redis_live.rs)

struct RedisServer {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl RedisServer {
    fn start() -> Result<RedisServer, String> {
        let have = Command::new("redis-server")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !have {
            if std::env::var_os("TAKY_REQUIRE_REDIS").is_some() {
                panic!("redis-server not found and TAKY_REQUIRE_REDIS is set");
            }
            return Err("redis-server not on PATH".into());
        }
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dir = std::env::temp_dir().join(format!("taky-corevec-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let child = Command::new("redis-server")
            .args(["--port", &port.to_string(), "--bind", "127.0.0.1"])
            .args(["--save", "", "--appendonly", "no"])
            .arg("--dir")
            .arg(&dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let s = RedisServer { child, port, dir };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(mut c) = redis::Client::open(s.url()).unwrap().get_connection()
                && redis::cmd("PING").query::<String>(&mut c).is_ok()
            {
                return Ok(s);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "redis-server did not start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn url(&self) -> String {
        format!("redis://127.0.0.1:{}/0", self.port)
    }

    fn raw(&self) -> redis::Connection {
        redis::Client::open(self.url())
            .unwrap()
            .get_connection()
            .unwrap()
    }
}

impl Drop for RedisServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------------------------
// helpers

fn t(s: &str) -> NaiveDateTime {
    taky_cot::isoparse::isoparse(s).unwrap()
}

fn b64decode(s: &str) -> Vec<u8> {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = ALPHA.iter().position(|&a| a == c).expect("base64") as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn chunks_of(step: &Value) -> Vec<Vec<u8>> {
    if let Some(a) = step["chunks"].as_array() {
        a.iter()
            .map(|c| match c {
                Value::String(s) => s.as_bytes().to_vec(),
                Value::Object(o) => {
                    let mut s = o
                        .get("prefix")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let rep = o["repeat"].as_str().unwrap();
                    s.push_str(&rep.repeat(o["count"].as_u64().unwrap() as usize));
                    s.push_str(o.get("suffix").and_then(Value::as_str).unwrap_or(""));
                    s.into_bytes()
                }
                other => panic!("bad chunk {other}"),
            })
            .collect()
    } else {
        step["chunks_b64"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| b64decode(c.as_str().unwrap()))
            .collect()
    }
}

/// `taky.conf` text from the vector `config` (null = key without a value).
fn ini(config: &Value, redis_url: Option<&str>) -> String {
    let mut sects: BTreeMap<String, BTreeMap<String, Option<String>>> = BTreeMap::new();
    if let Some(o) = config.as_object() {
        for (sect, kv) in o {
            let e = sects.entry(sect.clone()).or_default();
            for (k, v) in kv.as_object().unwrap() {
                e.insert(k.clone(), v.as_str().map(str::to_string));
            }
        }
    }
    if let Some(u) = redis_url {
        sects
            .entry("taky".into())
            .or_default()
            .insert("redis".into(), Some(u.to_string()));
    }
    let mut s = String::new();
    for (sect, kv) in sects {
        s.push_str(&format!("[{sect}]\n"));
        for (k, v) in kv {
            match v {
                Some(v) => s.push_str(&format!("{k} = {v}\n")),
                None => s.push_str(&format!("{k}\n")),
            }
        }
    }
    s
}

fn load_config(text: &str) -> taky_config::TakyConfig {
    let dir = std::env::temp_dir().join(format!(
        "taky-corevec-cfg-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("taky.conf");
    std::fs::write(&p, text).unwrap();
    let cfg = taky_config::load_config_in(Some(&p), true, &dir).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    cfg
}

fn str_list(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().map(|s| s.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------
// runner

struct Client {
    id: ClientId,
    kind: ClientKind,
    out: Option<Arc<TestOutbox>>,
    stats: Option<Arc<ClientStats>>,
    dec: CotDecoder,
    /// Registered in the Router and not closed (by either side).
    live: bool,
}

struct Runner {
    clock: Arc<FakeClock>,
    t0: NaiveDateTime,
    base: tokio::time::Instant,
    router: Router,
    clients: BTreeMap<String, Client>,
    reported_closed: BTreeSet<String>,
    closed_now: BTreeSet<String>,
    redis: Option<RedisServer>,
    errors: Vec<String>,
    /// Ops that are no-ops for the core (core-subset replay only).
    noop_ops: &'static [&'static str],
    /// Final keys not checked by the core runner.
    unchecked: Vec<String>,
}

enum Outcome {
    Pass,
    Fail(Vec<String>),
    Skip(String),
}

impl Runner {
    async fn new(v: &Value, noop_ops: &'static [&'static str]) -> Result<Runner, String> {
        let vid = v["id"].as_str().unwrap().to_string();
        let wants_redis = v["config"]["taky"]["redis"].as_str().is_some_and(|r| {
            !matches!(
                r.to_ascii_lowercase().as_str(),
                "false" | "no" | "off" | "0" | ""
            )
        });
        let redis = if wants_redis {
            Some(RedisServer::start()?)
        } else {
            None
        };
        if let (Some(srv), Some(seed)) = (&redis, v["initial_redis"].as_object()) {
            let mut c = srv.raw();
            for (k, e) in seed {
                let _: () = redis::cmd("SET")
                    .arg(k)
                    .arg(e["value"].as_str().unwrap())
                    .arg("EX")
                    .arg(e["ttl"].as_i64().unwrap())
                    .query(&mut c)
                    .unwrap();
            }
        }
        let cfg = load_config(&ini(
            &v["config"],
            redis.as_ref().map(|r| r.url()).as_deref(),
        ));
        let t0 = t(v["now"].as_str().unwrap());
        let clock = FakeClock::new(t0);
        let persist = Persistence::from_config(&cfg, clock.shared())
            .await
            .map_err(|e| format!("Persistence::from_config: {e}"))?;
        assert_eq!(
            matches!(persist, Persistence::Redis(_)),
            redis.is_some(),
            "{vid}: backend"
        );
        let router = Router::new(cfg.cot_server.max_persist_ttl, persist, clock.shared());
        let mut clients = BTreeMap::new();
        for (n, (name, c)) in v["clients"].as_object().unwrap().iter().enumerate() {
            let kind = match c["kind"].as_str().unwrap() {
                "monitor" => ClientKind::Monitor,
                _ => ClientKind::Cot,
            };
            clients.insert(
                name.clone(),
                Client {
                    id: ClientId(n as u64 + 1),
                    kind,
                    out: None,
                    stats: None,
                    dec: CotDecoder::new(),
                    live: false,
                },
            );
        }
        Ok(Runner {
            clock,
            t0,
            base: tokio::time::Instant::now(),
            router,
            clients,
            reported_closed: BTreeSet::new(),
            closed_now: BTreeSet::new(),
            redis,
            errors: Vec::new(),
            noop_ops,
            unchecked: Vec::new(),
        })
    }

    /// The Hub's periodic prune tick, on a tokio `Instant` that follows the fake clock.
    async fn tick(&mut self) {
        let elapsed = (self.clock_now() - self.t0).to_std().unwrap_or_default();
        self.router.maybe_prune(self.base + elapsed).await;
    }

    fn clock_now(&self) -> NaiveDateTime {
        use taky_common::Clock;
        self.clock.utc_now()
    }

    async fn connect(&mut self, name: &str) {
        let c = self.clients.get_mut(name).unwrap();
        let out = TestOutbox::new();
        let stats = Arc::new(ClientStats::new(0.0));
        c.out = Some(out.clone());
        c.stats = Some(stats.clone());
        c.dec = CotDecoder::new();
        c.live = true;
        let (id, kind) = (c.id, c.kind);
        self.reported_closed.remove(name);
        self.router.client_connect(ClientHandle {
            id,
            kind,
            outbox: out,
            stats,
            addr: None,
            peer_serial: None,
        });
        self.router.send_persist(id).await;
    }

    /// One `recv` worth of bytes through the connection-task emulation.
    async fn feed(&mut self, name: &str, data: &[u8]) {
        let c = self.clients.get_mut(name).unwrap();
        if !c.live {
            return; // a send to a client the server has already closed is a no-op
        }
        let id = c.id;
        let mut buf = BytesMut::from(data);
        let mut events = Vec::new();
        let mut fatal = false;
        loop {
            match c.dec.decode(&mut buf) {
                Ok(Some(elm)) => {
                    if let Some(s) = &c.stats {
                        s.record_rx(0.0);
                    }
                    events.push(Event::from_element(&elm));
                }
                Ok(None) => break,
                Err(_) => {
                    fatal = true;
                    break;
                }
            }
        }
        for evt in events.into_iter().flatten() {
            self.router.on_event(id, evt).await;
        }
        if fatal {
            self.server_close(name);
        }
        self.tick().await;
    }

    fn server_close(&mut self, name: &str) {
        let c = self.clients.get_mut(name).unwrap();
        if c.live {
            c.live = false;
            self.router.client_disconnect(c.id);
            self.closed_now.insert(name.to_string());
        }
    }

    async fn snapshot(&mut self) -> Value {
        if let Some(srv) = &self.redis {
            let mut c = srv.raw();
            let mut keys: Vec<String> = redis::cmd("KEYS").arg("*").query(&mut c).unwrap();
            keys.sort();
            let mut m = serde_json::Map::new();
            for k in keys {
                let v: Vec<u8> = redis::cmd("GET").arg(&k).query(&mut c).unwrap();
                let ttl: i64 = redis::cmd("TTL").arg(&k).query(&mut c).unwrap();
                m.insert(
                    k,
                    serde_json::json!({"value": String::from_utf8_lossy(&v), "ttl": ttl}),
                );
            }
            serde_json::json!({"backend": "redis", "keys": m})
        } else {
            let uids: Vec<Value> = self
                .router
                .persist_snapshot()
                .await
                .iter()
                .map(|e| e.uid.clone().map_or(Value::Null, Value::String))
                .collect();
            serde_json::json!({"backend": "memory", "uids": uids})
        }
    }

    fn persist_equal(exp: &Value, obs: &Value) -> bool {
        if exp["backend"] != "redis" {
            return exp == obs;
        }
        let (Some(ek), Some(ok)) = (exp["keys"].as_object(), obs["keys"].as_object()) else {
            return false;
        };
        if ek.keys().collect::<Vec<_>>() != ok.keys().collect::<Vec<_>>() {
            return false;
        }
        ek.iter().all(|(k, e)| {
            let o = &ok[k];
            let (et, ot) = (
                e["ttl"].as_i64().unwrap(),
                o["ttl"].as_i64().unwrap_or(i64::MIN),
            );
            e["value"] == o["value"] && (et - 1..=et).contains(&ot)
        })
    }

    async fn step(&mut self, idx: usize, step: &Value) {
        let op = step["op"].as_str().unwrap();
        let who = step["client"].as_str();
        let where_ = format!(
            "step {idx} ({op}{})",
            who.map(|w| format!(" {w}")).unwrap_or_default()
        );
        self.closed_now.clear();
        match op {
            "connect" => self.connect(who.unwrap()).await,
            "send" => {
                for ch in chunks_of(step) {
                    self.feed(who.unwrap(), &ch).await;
                }
            }
            "close" => {
                let c = self.clients.get_mut(who.unwrap()).unwrap();
                if c.live {
                    c.live = false;
                    self.router.client_disconnect(c.id);
                }
                self.reported_closed.insert(who.unwrap().to_string());
            }
            "advance" => {
                let secs = step["seconds"].as_f64().unwrap();
                self.clock
                    .advance(TimeDelta::microseconds((secs * 1e6).round() as i64));
            }
            o if self.noop_ops.contains(&o) => {}
            o => {
                self.errors
                    .push(format!("{where_}: op {o} not supported by the core runner"));
                return;
            }
        }
        self.tick().await;

        // Observe (settle is synchronous here).
        let mut deliveries: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, c) in &self.clients {
            if let Some(out) = &c.out {
                let got: Vec<String> = out
                    .drain()
                    .iter()
                    .map(|f| String::from_utf8_lossy(f).into_owned())
                    .collect();
                if !got.is_empty() {
                    deliveries.insert(name.clone(), got);
                }
                if out.closed().is_some() && c.live {
                    // Router-initiated close (slow client).
                    self.closed_now.insert(name.clone());
                }
            }
        }
        let mut closed: Vec<String> = self
            .closed_now
            .iter()
            .filter(|n| !self.reported_closed.contains(*n))
            .cloned()
            .collect();
        closed.sort();
        self.reported_closed.extend(closed.iter().cloned());

        let exp = if step.get("rust_expect").is_some() {
            &step["rust_expect"]
        } else {
            &step["expect"]
        };
        if exp["server_crash"].as_bool() == Some(true) {
            self.errors.push(format!(
                "{where_}: expectation is a server crash (no rust_expect)"
            ));
            return;
        }
        let exp_d = exp["deliveries"].as_object().cloned().unwrap_or_default();
        let names: BTreeSet<String> = exp_d
            .keys()
            .cloned()
            .chain(deliveries.keys().cloned())
            .collect();
        for n in names {
            let mut e = str_list(exp_d.get(&n));
            let mut o = deliveries.get(&n).cloned().unwrap_or_default();
            if op == "connect" {
                e.sort();
                o.sort();
            }
            if e != o {
                self.errors.push(format!(
                    "{where_}: deliveries to {n} differ\n    expected: {e:?}\n    observed: {o:?}"
                ));
            }
        }
        let mut exp_closed = str_list(exp.get("server_closed"));
        exp_closed.sort();
        if exp_closed != closed {
            self.errors.push(format!(
                "{where_}: server_closed expected {exp_closed:?} observed {closed:?}"
            ));
        }
        if exp.get("mgmt_response").is_some() {
            self.unchecked.push(format!("{where_}: mgmt_response"));
        }
        if let Some(p) = exp.get("persist") {
            let obs = self.snapshot().await;
            if !Self::persist_equal(p, &obs) {
                self.errors.push(format!(
                    "{where_}: persist\n    expected: {p}\n    observed: {obs}"
                ));
            }
        }
    }

    async fn finish(&mut self, v: &Value) {
        let fin = if v.get("final_rust_expect").is_some() {
            &v["final_rust_expect"]
        } else {
            &v["final_expect"]
        };
        for (k, val) in fin.as_object().cloned().unwrap_or_default() {
            if k == "persist" {
                let obs = self.snapshot().await;
                if !Self::persist_equal(&val, &obs) {
                    self.errors.push(format!(
                        "final persist\n    expected: {val}\n    observed: {obs}"
                    ));
                }
            } else {
                self.unchecked.push(format!("final {k}"));
            }
        }
    }
}

async fn run_vector(v: &Value, noop_ops: &'static [&'static str]) -> (Outcome, Vec<String>) {
    let mut r = match Runner::new(v, noop_ops).await {
        Ok(r) => r,
        Err(e) => return (Outcome::Skip(e), Vec::new()),
    };
    for (i, s) in v["steps"].as_array().unwrap().iter().enumerate() {
        r.step(i, s).await;
    }
    r.finish(v).await;
    let unchecked = std::mem::take(&mut r.unchecked);
    if r.errors.is_empty() {
        (Outcome::Pass, unchecked)
    } else {
        (Outcome::Fail(std::mem::take(&mut r.errors)), unchecked)
    }
}

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', "<br>")
}

#[tokio::test]
async fn core_vectors() {
    let dir = vectors_dir().join("cot");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no CoT vectors in {}", dir.display());

    let (mut pass, mut fail, mut na, mut skip) = (0, 0, 0, 0);
    let mut rows = Vec::new();
    let mut unexpected = Vec::new();
    for f in &files {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
        let id = v["id"].as_str().unwrap().to_string();
        assert_eq!(v["format"], 2, "{id}: unknown vector format");
        assert_eq!(v["runner"], "cot", "{id}: runner");
        let title = v["title"].as_str().unwrap_or("").to_string();
        let div = v["expected-divergence"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        if let Some((_, reason, subset)) = NA.iter().find(|(n, _, _)| *n == id) {
            na += 1;
            let mut note = (*reason).to_string();
            if *subset {
                let (o, unchecked) = run_vector(&v, &["mgmt_hold", "mgmt_release"]).await;
                let res = match o {
                    Outcome::Pass => "PASS".to_string(),
                    Outcome::Fail(e) => format!("FAIL: {}", e.join("; ")),
                    Outcome::Skip(s) => format!("SKIP: {s}"),
                };
                note.push_str(&format!(
                    ". Core subset (info, not counted): {res}; not checked: {}",
                    unchecked.join(", ")
                ));
            }
            rows.push((id, title, div, "N/A-network".to_string(), note));
            continue;
        }
        let (o, unchecked) = run_vector(&v, &[]).await;
        let known = KNOWN_FAIL.iter().find(|(n, _)| *n == id);
        let extra = if unchecked.is_empty() {
            String::new()
        } else {
            format!(" (not checked: {})", unchecked.join(", "))
        };
        match o {
            Outcome::Pass => {
                pass += 1;
                if let Some((_, msg)) = known {
                    unexpected.push(format!("{id}: listed in KNOWN_FAIL ({msg}) but passes"));
                }
                rows.push((id, title, div, "PASS".into(), extra));
            }
            Outcome::Fail(errs) => {
                fail += 1;
                let text = errs.join("\n");
                match known {
                    Some((_, msg)) => rows.push((
                        id,
                        title,
                        div,
                        "FAIL".into(),
                        format!("known, {msg}: {text}"),
                    )),
                    None => {
                        unexpected.push(format!("{id}:\n  {}", errs.join("\n  ")));
                        rows.push((id, title, div, "FAIL".into(), text));
                    }
                }
            }
            Outcome::Skip(s) => {
                skip += 1;
                rows.push((id, title, div, "SKIP".into(), s));
            }
        }
    }

    let mut md = format!(
        "pass {pass} / fail {fail} / N/A-network {na} / skip {skip} (total {})\n\n\
         | Vector | Title | D-n | Result | Notes |\n|---|---|---|---|---|\n",
        files.len()
    );
    for (id, title, div, res, note) in &rows {
        md.push_str(&format!(
            "| {id} | {} | {div} | {res} | {} |\n",
            md_cell(title),
            md_cell(note)
        ));
    }
    println!("{md}");
    if let Some(p) = std::env::var_os("CORE_VECTORS_REPORT") {
        std::fs::write(p, &md).unwrap();
    }
    assert!(
        unexpected.is_empty(),
        "core vector failures not in KNOWN_FAIL:\n{}",
        unexpected.join("\n")
    );
}

/// Negative controls: the runner must notice a wrong delivery, a missed close, a wrong
/// memory snapshot, a wrong Redis TTL and an extra delivery.
#[tokio::test]
async fn core_vectors_negative_controls() {
    let load = |id: &str| -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(vectors_dir().join(format!("cot/{id}.json"))).unwrap(),
        )
        .unwrap()
    };
    let mut cases: Vec<(&str, Value)> = Vec::new();

    let mut v = load("V001");
    v["steps"][2]["expect"]["deliveries"]["B"][0] = Value::String("<event/>".into());
    cases.push(("wrong delivery", v));

    let mut v = load("V001");
    v["steps"][2]["expect"]["deliveries"] = serde_json::json!({});
    cases.push(("extra delivery", v));

    let mut v = load("V007");
    v["steps"][2]["expect"]["server_closed"] = serde_json::json!([]);
    cases.push(("missed close", v));

    let mut v = load("V035");
    v["final_expect"]["persist"]["uids"] = serde_json::json!(["P-2"]);
    cases.push(("memory snapshot", v));

    let mut v = load("V042");
    let keys = v["final_expect"]["persist"]["keys"]
        .as_object_mut()
        .unwrap();
    let k = keys.keys().next().unwrap().clone();
    let ttl = keys[&k]["ttl"].as_i64().unwrap();
    keys[&k]["ttl"] = Value::from(ttl + 5);
    cases.push(("redis ttl", v));

    for (what, v) in cases {
        match run_vector(&v, &[]).await.0 {
            Outcome::Fail(_) => {}
            Outcome::Skip(s) => eprintln!("SKIP negative control {what}: {s}"),
            Outcome::Pass => panic!("negative control '{what}' was not detected"),
        }
    }
}
