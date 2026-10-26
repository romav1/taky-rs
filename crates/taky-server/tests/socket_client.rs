//! Port of `taky/tests/test_takclient.py::SocketTAKClientTest` (test-strategy §2 row 16).
//!
//! The original mocks `socket.socket` (`recv` → `b"</invalid>"`), calls `socket_rx()` once and
//! asserts `sock.close` was called. Here a real plain-TCP pair against `taky_server::start` on
//! 127.0.0.3: the server must close the connection, with the reason `"XML Syntax Error"`
//! (`Socket disconnect: XML Syntax Error`, captured from the server's tracing events), and an
//! unrelated client stays connected.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use taky_common::Shutdown;
use taky_common::clock::FakeClock;
use taky_server::conn::XML_SYNTAX_ERROR;
use taky_server::{Listeners, ServerOptions, start};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

const HOST: &str = "127.0.0.3";
const WAIT: Duration = Duration::from_secs(5);

/// A minimal subscriber that records the `message` of every event (no tracing-subscriber
/// dev-dependency needed). This binary holds one test, so a global default is safe.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);

struct MsgVisitor<'a>(&'a mut String);

impl Visit for MsgVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            *self.0 = format!("{value:?}");
        }
    }
}

impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut msg = String::new();
        event.record(&mut MsgVisitor(&mut msg));
        self.0.lock().unwrap().push(msg);
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

impl Capture {
    fn contains(&self, needle: &str) -> bool {
        self.0.lock().unwrap().iter().any(|m| m == needle)
    }
}

/// Read until EOF (`true`) or `WAIT` passes (`false`).
async fn closed_by_server(s: &mut TcpStream) -> bool {
    let fut = async {
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    };
    tokio::time::timeout(WAIT, fut).await.is_ok()
}

/// `test_takclient.SocketTAKClientTest.test_invalid_xml`.
#[tokio::test]
async fn invalid_xml_disconnects() {
    let logs = Capture::default();
    tracing::subscriber::set_global_default(logs.clone()).unwrap();

    // load_config(os.devnull) + redis = false: an empty-ish taky.conf, plain TCP.
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("taky.conf");
    std::fs::write(
        &conf,
        format!(
            "[taky]\nbind_ip = {HOST}\nroot_dir = {}\nredis = false\n[ssl]\nenabled = false\n",
            dir.path().display()
        ),
    )
    .unwrap();
    let cfg = taky_config::load_config_in(Some(&conf), true, dir.path()).unwrap();
    let shutdown = Shutdown::new();
    let opts = ServerOptions {
        cfg: Arc::new(cfg),
        clock: FakeClock::new(
            chrono::NaiveDate::from_ymd_opt(2030, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
        )
        .shared(),
        shutdown: shutdown.clone(),
    };
    let listeners = Listeners {
        cot: TcpListener::bind((HOST, 0)).await.unwrap(),
        monitor: None,
        mgmt: None,
    };
    let srv = start(opts, listeners).await.unwrap();

    let mut bystander = TcpStream::connect(srv.local_addr).await.unwrap();
    let mut sock = TcpStream::connect(srv.local_addr).await.unwrap();
    sock.write_all(b"</invalid>").await.unwrap();

    // self.sock.close.assert_called()
    assert!(closed_by_server(&mut sock).await, "connection not closed");
    let want = format!("Socket disconnect: {XML_SYNTAX_ERROR}");
    let deadline = tokio::time::Instant::now() + WAIT;
    while !logs.contains(&want) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        logs.contains(&want),
        "no '{want}' in {:?}",
        logs.0.lock().unwrap()
    );

    // Extra: only the offending connection is closed.
    let mut one = [0u8; 1];
    let still_open =
        tokio::time::timeout(Duration::from_millis(150), bystander.read(&mut one)).await;
    assert!(still_open.is_err(), "bystander was closed: {still_open:?}");

    shutdown.trigger();
    assert!(closed_by_server(&mut bystander).await);
    srv.join().await.unwrap();
}
