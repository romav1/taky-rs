//! Redis persistence against a real `redis-server` (spec §9.4, V040/V042/V043).
//!
//! Gating: every test spawns its own throw-away `redis-server` (random port, no persistence)
//! and **skips with a note** when the binary is not on `PATH`, so `scripts/check.sh` stays green
//! without Redis. Set `TAKY_REQUIRE_REDIS=1` to turn a missing binary into a failure (CI with
//! Redis). Install: `apt-get install redis-server` (any 6.2+).
//!
//! Python cross-compat (T-33 pre-check, see `dev01/handoff/S-309.md`): `xcompat_*` run only when
//! `TAKY_XCOMPAT_REDIS_URL` is set, and are driven by a script that writes/reads the same DB
//! with Python taky's `RedisPersistence`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use chrono::{NaiveDateTime, TimeDelta};
use serde_json::Value;
use taky_common::vectors::read_vector;
use taky_cot::limits::STREAM_LIMITS;
use taky_cot::persist::{DEFAULT_REDIS_URL, REDIS_RETRY_INTERVAL, redis_key_space};
use taky_cot::testkit::{FakeClock, TestOutbox};
use taky_cot::{
    ClientHandle, ClientId, ClientKind, ClientStats, CotDecoder, Event, Persistence,
    RedisPersistence, Router,
};
use taky_xml::parse_element;
use tokio_util::codec::Decoder;

/// A private `redis-server` killed on drop.
struct Server {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Server {
    fn url(&self) -> String {
        format!("redis://127.0.0.1:{}/0", self.port)
    }

    /// `None` (test skipped) when `redis-server` is unavailable.
    fn start() -> Option<Server> {
        Server::start_on(None)
    }

    fn start_on(port: Option<u16>) -> Option<Server> {
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
            eprintln!("SKIP: redis-server not on PATH (set TAKY_REQUIRE_REDIS=1 to fail)");
            return None;
        }
        let port = port.unwrap_or_else(|| {
            TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        });
        let dir = std::env::temp_dir().join(format!("taky-redis-{}-{port}", std::process::id()));
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
        let s = Server { child, port, dir };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(mut c) = redis::Client::open(s.url()).unwrap().get_connection()
                && redis::cmd("PING").query::<String>(&mut c).is_ok()
            {
                return Some(s);
            }
            assert!(Instant::now() < deadline, "redis-server did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn raw(&self) -> redis::Connection {
        redis::Client::open(self.url())
            .unwrap()
            .get_connection()
            .unwrap()
    }

    /// All keys → (value, ttl).
    fn dump(&self) -> Vec<(String, Vec<u8>, i64)> {
        let mut c = self.raw();
        let mut keys: Vec<String> = redis::cmd("KEYS").arg("*").query(&mut c).unwrap();
        keys.sort();
        keys.into_iter()
            .map(|k| {
                let v: Vec<u8> = redis::cmd("GET").arg(&k).query(&mut c).unwrap();
                let ttl: i64 = redis::cmd("TTL").arg(&k).query(&mut c).unwrap();
                (k, v, ttl)
            })
            .collect()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn t(s: &str) -> NaiveDateTime {
    taky_cot::isoparse::isoparse(s).unwrap()
}

/// Write `ini` into a fresh dir and load it like `taky -c`.
fn config(ini: &str) -> taky_config::TakyConfig {
    let dir = std::env::temp_dir().join(format!(
        "taky-cfg-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("taky.conf");
    std::fs::write(&p, ini).unwrap();
    let cfg = taky_config::load_config_in(Some(&p), true, &dir).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    cfg
}

async fn redis_router(url: &str, hostname: &str, max_ttl: i64, clock: &Arc<FakeClock>) -> Router {
    let cfg = config(&format!(
        "[taky]\nhostname = {hostname}\nredis = {url}\n[cot_server]\nmax_persist_ttl = {max_ttl}\n"
    ));
    let p = Persistence::from_config(&cfg, clock.shared())
        .await
        .unwrap();
    assert!(matches!(p, Persistence::Redis(_)));
    Router::new(cfg.cot_server.max_persist_ttl, p, clock.shared())
}

async fn feed(router: &mut Router, src: ClientId, data: &str) {
    let mut dec = CotDecoder::new();
    let mut buf = BytesMut::from(data.as_bytes());
    while let Some(elm) = dec.decode(&mut buf).unwrap() {
        if let Ok(evt) = Event::from_element(&elm) {
            router.on_event(src, evt).await;
        }
    }
}

fn connect(router: &mut Router, id: u64) -> (ClientId, Arc<TestOutbox>) {
    let out = TestOutbox::new();
    let id = ClientId(id);
    router.client_connect(ClientHandle {
        id,
        kind: ClientKind::Cot,
        outbox: out.clone(),
        stats: Arc::new(ClientStats::new(0.0)),
        addr: None,
        peer_serial: None,
    });
    (id, out)
}

fn frames(out: &TestOutbox) -> Vec<String> {
    let mut v: Vec<String> = out
        .drain()
        .iter()
        .map(|f| String::from_utf8(f.to_vec()).unwrap())
        .collect();
    v.sort();
    v
}

/// Run a `requires: [clock, redis]` CoT vector (connect/send steps, `initial_redis`,
/// `final_expect.persist`). Replay order from Redis is not normative ⇒ deliveries compared
/// as sorted lists.
async fn run_vector(name: &str) {
    let Some(srv) = Server::start() else { return };
    let v: Value = serde_json::from_str(&read_vector(&format!("cot/{name}.json"))).unwrap();
    let cfg = &v["config"];
    let hostname = cfg["taky"]["hostname"].as_str().unwrap();
    let max_ttl: i64 = cfg["cot_server"]["max_persist_ttl"]
        .as_str()
        .map_or(-1, |s| s.parse().unwrap());
    if let Some(seed) = v["initial_redis"].as_object() {
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
    let clock = FakeClock::new(t(v["now"].as_str().unwrap()));
    let mut router = redis_router(&srv.url(), hostname, max_ttl, &clock).await;
    let mut clients = std::collections::BTreeMap::new();
    for (n, name) in v["clients"].as_object().unwrap().keys().enumerate() {
        clients.insert(
            name.clone(),
            (ClientId(n as u64 + 1), None::<Arc<TestOutbox>>),
        );
    }
    for step in v["steps"].as_array().unwrap() {
        let who = step["client"].as_str().unwrap();
        match step["op"].as_str().unwrap() {
            "connect" => {
                let id = clients[who].0;
                let (_, out) = connect(&mut router, id.0);
                clients.get_mut(who).unwrap().1 = Some(out);
                router.send_persist(id).await;
            }
            "send" => {
                let id = clients[who].0;
                for chunk in step["chunks"].as_array().unwrap() {
                    feed(&mut router, id, chunk.as_str().unwrap()).await;
                }
            }
            op => panic!("{name}: unsupported op {op}"),
        }
        let want = step["expect"]["deliveries"].as_object().unwrap();
        for (c, (_, out)) in &clients {
            let Some(out) = out else { continue };
            let mut exp: Vec<String> = want
                .get(c)
                .map(|a| {
                    a.as_array()
                        .unwrap()
                        .iter()
                        .map(|s| s.as_str().unwrap().to_string())
                        .collect()
                })
                .unwrap_or_default();
            exp.sort();
            assert_eq!(frames(out), exp, "{name}: deliveries to {c}");
        }
    }
    let keys = v["final_expect"]["persist"]["keys"].as_object().unwrap();
    let got = srv.dump();
    assert_eq!(
        got.iter().map(|(k, _, _)| k.as_str()).collect::<Vec<_>>(),
        keys.keys().map(String::as_str).collect::<Vec<_>>(),
        "{name}: key set"
    );
    for (k, val, ttl) in &got {
        let e = &keys[k];
        assert_eq!(
            String::from_utf8(val.clone()).unwrap(),
            e["value"].as_str().unwrap(),
            "{name}: value of {k}"
        );
        let exp_ttl = e["ttl"].as_i64().unwrap();
        // Redis counts down in real time; allow one elapsed second.
        assert!(
            *ttl == exp_ttl || *ttl == exp_ttl - 1,
            "{name}: ttl of {k}: {ttl} vs {exp_ttl}"
        );
    }
}

#[tokio::test]
async fn v040_max_ttl_clamps_redis_ttl() {
    run_vector("V040").await;
}

#[tokio::test]
async fn v042_keyspace_value_ttl() {
    run_vector("V042").await;
}

#[tokio::test]
async fn v043_seed_replay_purge_foreign() {
    run_vector("V043").await;
}

#[tokio::test]
async fn kept_rules_and_replace_on_redis() {
    let Some(srv) = Server::start() else { return };
    let clock = FakeClock::new(t("2030-01-01T00:00:00Z"));
    let mut router = redis_router(&srv.url(), "", -1, &clock).await;
    let (a, _) = connect(&mut router, 1);
    let ev = |uid: &str, ty: &str, stale: &str| {
        format!(
            r#"<event version="2.0" uid="{uid}" type="{ty}" how="h-e" time="2030-01-01T00:00:00.000Z" start="2030-01-01T00:00:00.000Z" stale="{stale}"><point lat="1.0" lon="2.0" hae="3.0" ce="4.0" le="5.0"/></event>"#
        )
    };
    // Kept prefixes, not kept, ttl 0, negative ttl, replacement with a longer stale.
    feed(
        &mut router,
        a,
        &ev("K1", "u-d-f", "2030-01-01T00:01:00.000Z"),
    )
    .await;
    feed(
        &mut router,
        a,
        &ev("N1", "b-t-f", "2030-01-01T00:01:00.000Z"),
    )
    .await;
    feed(
        &mut router,
        a,
        &ev("Z0", "a-u-G", "2030-01-01T00:00:00.400Z"),
    )
    .await;
    feed(
        &mut router,
        a,
        &ev("NEG", "a-u-G", "2029-12-31T23:00:00.000Z"),
    )
    .await;
    feed(
        &mut router,
        a,
        &ev("K1", "u-d-f", "2030-01-01T00:02:00.000Z"),
    )
    .await;
    let got = srv.dump();
    assert_eq!(got.len(), 1, "{got:?}");
    let (k, v, ttl) = &got[0];
    assert_eq!(k, "taky:persist:K1"); // empty hostname ⇒ taky:persist
    assert!(String::from_utf8_lossy(v).contains(r#"stale="2030-01-01T00:02:00.000Z""#));
    assert!((119..=120).contains(ttl));
    // get_event / replay to a new client; own uid excluded only after identification.
    if let Persistence::Redis(r) = router.persistence() {
        assert_eq!(r.get_event("K1").await.unwrap().uid.as_deref(), Some("K1"));
        assert!(r.get_event("NOPE").await.is_none());
    } else {
        unreachable!()
    }
    let (b, out_b) = connect(&mut router, 2);
    router.send_persist(b).await;
    assert_eq!(frames(&out_b).len(), 1);
}

#[tokio::test]
async fn wrong_type_and_bad_event_purged_foreign_untouched() {
    let Some(srv) = Server::start() else { return };
    let mut c = srv.raw();
    let _: () = redis::cmd("RPUSH")
        .arg("taky:h:persist:LIST")
        .arg("x")
        .query(&mut c)
        .unwrap();
    // Parses as XML but Event.from_elm fails (no uid) ⇒ purged.
    let _: () = redis::cmd("SET")
        .arg("taky:h:persist:NOUID")
        .arg(r#"<event type="a" time="2030-01-01T00:00:00Z" start="2030-01-01T00:00:00Z" stale="2030-01-01T00:00:00Z"/>"#)
        .query(&mut c)
        .unwrap();
    let _: () = redis::cmd("SET")
        .arg("taky:hx:persist:KEEP")
        .arg("garbage")
        .query(&mut c)
        .unwrap();
    let clock = FakeClock::new(t("2030-01-01T00:00:00Z"));
    let p = RedisPersistence::connect("h", Some(&srv.url()), clock.shared())
        .await
        .unwrap();
    assert!(p.is_ok());
    let mut p = Persistence::Redis(p);
    assert!(p.get_all().await.is_empty());
    let keys: Vec<String> = srv.dump().into_iter().map(|(k, _, _)| k).collect();
    assert_eq!(keys, vec!["taky:hx:persist:KEEP".to_string()]);
}

#[tokio::test]
async fn connection_loss_latch_and_retry_interval() {
    let Some(srv) = Server::start() else { return };
    let port = srv.port;
    let url = srv.url();
    let clock = FakeClock::new(t("2030-01-01T00:00:00Z"));
    let mut router = redis_router(&url, "h", -1, &clock).await;
    let (a, _) = connect(&mut router, 1);
    let ev = |uid: &str| {
        format!(
            r#"<event version="2.0" uid="{uid}" type="a-u-G" how="h-e" time="2030-01-01T00:00:00.000Z" start="2030-01-01T00:00:00.000Z" stale="2030-01-01T01:00:00.000Z"><point lat="1.0" lon="2.0" hae="3.0" ce="4.0" le="5.0"/></event>"#
        )
    };
    feed(&mut router, a, &ev("U1")).await;
    drop(srv); // server gone
    let started = Instant::now();
    feed(&mut router, a, &ev("U2")).await; // fails: latch cleared, no panic
    let (b, out_b) = connect(&mut router, 2);
    router.send_persist(b).await; // skipped within the retry interval
    assert!(frames(&out_b).is_empty());
    let ok = |r: &mut Router| match r.persistence() {
        Persistence::Redis(p) => p.is_ok(),
        _ => unreachable!(),
    };
    assert!(!ok(&mut router));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "bounded by timeouts"
    );
    // Server back on the same port (empty DB); before the interval nothing is attempted.
    let srv2 = Server::start_on(Some(port)).unwrap();
    clock.advance(REDIS_RETRY_INTERVAL - TimeDelta::seconds(1));
    feed(&mut router, a, &ev("U3")).await;
    assert!(srv2.dump().is_empty());
    assert!(!ok(&mut router));
    clock.advance(TimeDelta::seconds(1));
    feed(&mut router, a, &ev("U4")).await;
    assert!(ok(&mut router), "Connection to redis restored");
    let keys: Vec<String> = srv2.dump().into_iter().map(|(k, _, _)| k).collect();
    assert_eq!(keys, vec!["taky:h:persist:U4".to_string()]);
}

#[tokio::test]
async fn from_config_backend_selection() {
    let clock = FakeClock::new(t("2030-01-01T00:00:00Z"));
    for (v, memory) in [
        ("", true),
        ("false", true),
        ("off", true),
        ("redis://127.0.0.1:1/0", false),
    ] {
        let cfg = config(&format!("[taky]\nhostname = h\nredis = {v}\n"));
        let p = Persistence::from_config(&cfg, clock.shared())
            .await
            .unwrap();
        assert_eq!(matches!(p, Persistence::Memory(_)), memory, "redis = {v:?}");
    }
    let cfg = config("[taky]\nhostname = h\n");
    let p = Persistence::from_config(&cfg, clock.shared())
        .await
        .unwrap();
    assert!(matches!(p, Persistence::Memory(_)));
    let cfg = config("[taky]\nhostname = h\nredis = not a url\n");
    assert!(
        Persistence::from_config(&cfg, clock.shared())
            .await
            .is_err()
    );
    assert_eq!(DEFAULT_REDIS_URL, "redis://127.0.0.1:6379/0");
    assert_eq!(redis_key_space("h"), "taky:h:persist");
}

// ---- Python cross-compat (driven externally; no-ops unless TAKY_XCOMPAT_REDIS_URL is set) ----

fn xcompat_url() -> Option<String> {
    std::env::var("TAKY_XCOMPAT_REDIS_URL").ok()
}

/// Rust tracks every event of `$TAKY_XCOMPAT_IN` (one XML event per line) into keyspace
/// `taky:$TAKY_XCOMPAT_HOST:persist`, with the clock at `$TAKY_XCOMPAT_NOW`.
#[tokio::test]
async fn xcompat_rust_writes() {
    let Some(url) = xcompat_url() else { return };
    let Ok(input) = std::env::var("TAKY_XCOMPAT_IN") else {
        return;
    };
    let host = std::env::var("TAKY_XCOMPAT_HOST").unwrap();
    let clock = FakeClock::new(t(&std::env::var("TAKY_XCOMPAT_NOW").unwrap()));
    let mut router = redis_router(&url, &host, -1, &clock).await;
    // Straight into `Persistence::track` (Python side calls `track` directly too): routing
    // decisions (marti ⇒ not broadcast ⇒ not kept) are covered by the router tests.
    for line in std::fs::read_to_string(input).unwrap().lines() {
        let evt =
            Event::from_element(&parse_element(line.as_bytes(), &STREAM_LIMITS).unwrap()).unwrap();
        let frame = evt.to_frame().unwrap();
        router.persistence().track(&Arc::new(evt), &frame).await;
    }
}

/// Rust reads keyspace `taky:$TAKY_XCOMPAT_HOST:persist` and writes the replayed frames
/// (sorted, one per line) to `$TAKY_XCOMPAT_OUT`.
#[tokio::test]
async fn xcompat_rust_reads() {
    let Some(url) = xcompat_url() else { return };
    let Ok(out_path) = std::env::var("TAKY_XCOMPAT_OUT") else {
        return;
    };
    let host = std::env::var("TAKY_XCOMPAT_HOST").unwrap();
    let clock = FakeClock::new(t(&std::env::var("TAKY_XCOMPAT_NOW").unwrap()));
    let mut router = redis_router(&url, &host, -1, &clock).await;
    let (b, out) = connect(&mut router, 1);
    router.send_persist(b).await;
    let mut s = String::new();
    for f in frames(&out) {
        // Re-parse check: what Rust sends is a valid single event.
        parse_element(f.as_bytes(), &STREAM_LIMITS).unwrap();
        s.push_str(&f);
        s.push('\n');
    }
    std::fs::write(out_path, s).unwrap();
}
