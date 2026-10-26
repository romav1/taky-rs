//! S-312/S-313: network-level tests of the CoT server — real sockets on 127.0.0.3, plain TCP and
//! TLS (client certificates generated at test time), the mgmt unix socket, `log_cot` files, Hub
//! settle barrier, and the an01 vectors that need TLS / ban / the monitor port / mgmt / log_cot
//! (V044, V045, V046, V047, V048, V049, V051, V052, V053).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use chrono::{NaiveDateTime, TimeDelta};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SerialNumber, date_time_ymd,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde_json::Value;
use taky_common::clock::FakeClock;
use taky_common::{SharedClock, Shutdown};
use taky_pki::CertDb;
use taky_server::{Listeners, RunningServer, ServerOptions, start};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, WriteHalf};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

const HOST: &str = "127.0.0.3";
const WAIT: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(150);

// ---------------------------------------------------------------------------------------------
// PKI (ECDSA P-256 keys: fast; the server key is PKCS#8 PEM)

struct Pki {
    _dir: tempfile::TempDir,
    root: PathBuf,
    ca_path: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_db: PathBuf,
    ca_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    clients: BTreeMap<String, (CertificateDer<'static>, KeyPair)>,
}

fn leaf(
    issuer: &Issuer<'static, KeyPair>,
    cn: &str,
    server: bool,
    serial: u8,
) -> (CertificateDer<'static>, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let sans = if server { vec![cn.to_owned()] } else { vec![] };
    let mut p = CertificateParams::new(sans).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.is_ca = IsCa::ExplicitNoCa;
    p.serial_number = Some(SerialNumber::from_slice(&[0x8f, serial, 0x42]));
    p.not_before = date_time_ymd(2024, 1, 1);
    p.not_after = date_time_ymd(2080, 1, 1);
    p.extended_key_usages = if server {
        vec![ExtendedKeyUsagePurpose::ServerAuth]
    } else {
        vec![ExtendedKeyUsagePurpose::ClientAuth]
    };
    let cert = p.signed_by(&key, issuer).unwrap();
    (cert.der().clone(), key)
}

impl Pki {
    /// vector op `issue_cert`: a new client certificate added to cert-db.txt while the server
    /// runs (as takyctl build_client would).
    fn issue(&mut self, cn: &str) {
        let serial = 2 + u8::try_from(self.clients.len()).unwrap();
        let (der, key) = leaf(&self.issuer, cn, false, serial);
        CertDb::open(&self.cert_db).unwrap().add(&der).unwrap();
        self.clients.insert(cn.to_owned(), (der, key));
    }

    /// The certificate serial of `cn` as a decimal integer.
    fn serial_int(&self, cn: &str) -> String {
        let sn = taky_pki::identity::identity_from_der(&self.clients[cn].0)
            .unwrap()
            .serial;
        let mut n: u128 = 0;
        for b in sn {
            n = (n << 8) | u128::from(b);
        }
        n.to_string()
    }
}

fn pki(cns: &[&str], revoked: &[&str]) -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, "CA");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.not_before = date_time_ymd(2020, 1, 1);
    p.not_after = date_time_ymd(2090, 1, 1);
    let ca = p.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(p, ca_key);

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_owned();
    let (server_der, server_key) = leaf(&issuer, "localhost", true, 1);
    let ca_path = root.join("ca.crt");
    let cert_path = root.join("server.crt");
    let key_path = root.join("server.key");
    let cert_db = root.join("cert-db.txt");
    std::fs::write(&ca_path, ca.pem()).unwrap();
    std::fs::write(&cert_path, pem("CERTIFICATE", &server_der)).unwrap();
    std::fs::write(&key_path, server_key.serialize_pem()).unwrap();

    let mut db = CertDb::open(&cert_db).unwrap();
    db.add(&server_der).unwrap();
    let mut clients = BTreeMap::new();
    for (i, cn) in cns.iter().enumerate() {
        let (der, key) = leaf(&issuer, cn, false, 2 + u8::try_from(i).unwrap());
        db.add(&der).unwrap();
        if revoked.contains(cn) {
            let sn = taky_pki::identity::identity_from_der(&der).unwrap().serial;
            db.revoke(&sn, NaiveDateTime::default()).unwrap();
        }
        clients.insert((*cn).to_owned(), (der, key));
    }
    Pki {
        _dir: dir,
        root,
        ca_path,
        cert_path,
        key_path,
        cert_db,
        ca_der: ca.der().clone(),
        issuer,
        clients,
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for c in der.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            b64.push(if i <= c.len() {
                T[((n >> (18 - 6 * i)) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out + &format!("-----END {label}-----\n")
}

fn client_tls(p: &Pki, cn: Option<&str>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(p.ca_der.clone()).unwrap();
    let b = rustls::ClientConfig::builder_with_provider(taky_pki::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    Arc::new(match cn {
        Some(cn) => {
            let (der, key) = &p.clients[cn];
            let k = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
            b.with_client_auth_cert(vec![der.clone()], k).unwrap()
        }
        None => b.with_no_client_auth(),
    })
}

// ---------------------------------------------------------------------------------------------
// server

type Sections = BTreeMap<String, BTreeMap<String, Option<String>>>;

fn set(s: &mut Sections, sect: &str, k: &str, v: &str) {
    s.entry(sect.into())
        .or_default()
        .insert(k.into(), Some(v.into()));
}

/// taky.conf for the test: bind 127.0.0.3, root_dir/ssl paths in the PKI dir, then `overrides`
/// (vector `config`: section → key → string | null; `log_cot = AUTO` → `<root>/cotlog`, created).
fn config(p: &Pki, ssl: bool, overrides: &Value) -> taky_config::TakyConfig {
    let mut s = Sections::new();
    set(&mut s, "taky", "bind_ip", HOST);
    set(&mut s, "taky", "root_dir", p.root.to_str().unwrap());
    set(&mut s, "ssl", "enabled", if ssl { "true" } else { "false" });
    set(&mut s, "ssl", "ca", p.ca_path.to_str().unwrap());
    set(&mut s, "ssl", "cert", p.cert_path.to_str().unwrap());
    set(&mut s, "ssl", "key", p.key_path.to_str().unwrap());
    set(&mut s, "ssl", "cert_db", p.cert_db.to_str().unwrap());
    if let Some(o) = overrides.as_object() {
        for (sect, kv) in o {
            for (k, v) in kv.as_object().unwrap() {
                let mut v = v.as_str().map(str::to_owned);
                if sect == "cot_server" && k == "log_cot" && v.as_deref() == Some("AUTO") {
                    let d = p.root.join("cotlog");
                    std::fs::create_dir_all(&d).unwrap();
                    v = Some(d.to_str().unwrap().to_owned());
                }
                s.entry(sect.clone()).or_default().insert(k.clone(), v);
            }
        }
    }
    let mut text = String::new();
    for (sect, kv) in &s {
        text.push_str(&format!("[{sect}]\n"));
        for (k, v) in kv {
            match v {
                Some(v) => text.push_str(&format!("{k} = {v}\n")),
                None => text.push_str(&format!("{k}\n")),
            }
        }
    }
    let path = p.root.join("taky.conf");
    std::fs::write(&path, text).unwrap();
    taky_config::load_config_in(Some(&path), true, &p.root).unwrap()
}

struct Server {
    run: RunningServer,
    shutdown: Shutdown,
    mgmt: PathBuf,
}

async fn listeners(cfg: &taky_config::TakyConfig) -> Listeners {
    let monitor = match cfg.cot_server.mon_ip {
        Some(_) => Some(TcpListener::bind((HOST, 0)).await.unwrap()),
        None => None,
    };
    Listeners {
        cot: TcpListener::bind((HOST, 0)).await.unwrap(),
        monitor,
        mgmt: Some({
            // Ready-made listener (no `Listeners::bind` stale-socket check here): clear any
            // leftover file first. A failed `start` removes it itself (S-314).
            let _ = std::fs::remove_file(mgmt_path(cfg));
            UnixListener::bind(mgmt_path(cfg)).unwrap()
        }),
    }
}

fn mgmt_path(cfg: &taky_config::TakyConfig) -> PathBuf {
    cfg.taky.root_dir.join("taky-mgmt.sock")
}

async fn try_serve(
    cfg: taky_config::TakyConfig,
    clock: SharedClock,
) -> anyhow::Result<(RunningServer, Shutdown)> {
    let l = listeners(&cfg).await;
    let shutdown = Shutdown::new();
    let opts = ServerOptions {
        cfg: Arc::new(cfg),
        clock,
        shutdown: shutdown.clone(),
    };
    Ok((start(opts, l).await?, shutdown))
}

async fn serve(cfg: taky_config::TakyConfig, clock: SharedClock) -> Server {
    let mgmt = mgmt_path(&cfg);
    let (run, shutdown) = try_serve(cfg, clock).await.unwrap();
    assert_eq!(run.local_addr.ip().to_string(), HOST);
    Server {
        run,
        shutdown,
        mgmt,
    }
}

/// A mgmt client (takyctl status/kickban speak this protocol).
struct Mgmt {
    s: UnixStream,
    buf: Vec<u8>,
}

impl Mgmt {
    async fn connect(path: &std::path::Path) -> Mgmt {
        Mgmt {
            s: UnixStream::connect(path).await.unwrap(),
            buf: Vec::new(),
        }
    }

    async fn send_raw(&mut self, b: &[u8]) {
        self.s.write_all(b).await.unwrap();
    }

    /// The next reply frame (without the `\0`).
    async fn recv(&mut self) -> String {
        let fut = async {
            loop {
                if let Some(i) = self.buf.iter().position(|&b| b == 0) {
                    let f: Vec<u8> = self.buf.drain(..=i).collect();
                    return String::from_utf8(f[..i].to_vec()).unwrap();
                }
                let mut chunk = [0u8; 4096];
                let n = self.s.read(&mut chunk).await.unwrap();
                assert!(n > 0, "mgmt: EOF before a reply");
                self.buf.extend_from_slice(&chunk[..n]);
            }
        };
        tokio::time::timeout(WAIT, fut).await.expect("mgmt reply")
    }

    async fn request(&mut self, req: &[u8]) -> String {
        let mut b = req.to_vec();
        b.push(0);
        self.send_raw(&b).await;
        self.recv().await
    }
}

fn dumps(v: &Value) -> String {
    taky_common::pyjson::dumps(v, &taky_common::pyjson::DumpOpts::default())
}

fn now() -> SharedClock {
    FakeClock::new(t("2030-01-01T00:00:00Z")).shared()
}

fn t(s: &str) -> NaiveDateTime {
    taky_cot::isoparse::isoparse(s).unwrap()
}

// ---------------------------------------------------------------------------------------------
// clients

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

#[derive(Default)]
struct RxState {
    data: Vec<u8>,
    eof: bool,
}

struct Client {
    /// The client's source IP (what the server sees as the peer address).
    ip: String,
    wr: WriteHalf<Box<dyn Io>>,
    rx: Arc<Mutex<RxState>>,
    mark: usize,
    eof_mark: bool,
}

impl Client {
    async fn connect(addr: SocketAddr, tls: Option<Arc<rustls::ClientConfig>>) -> Client {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let ip = tcp.local_addr().unwrap().ip().to_string();
        let io: Box<dyn Io> = match tls {
            None => Box::new(tcp),
            Some(cfg) => {
                let name = ServerName::try_from("localhost").unwrap();
                match tokio_rustls::TlsConnector::from(cfg)
                    .connect(name, tcp)
                    .await
                {
                    Ok(s) => Box::new(s),
                    // The server may reject during the handshake: an already-closed client.
                    Err(_) => Box::new(Closed),
                }
            }
        };
        let (mut rd, wr) = tokio::io::split(io);
        let rx = Arc::new(Mutex::new(RxState::default()));
        let rx2 = rx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        rx2.lock().unwrap().eof = true;
                        return;
                    }
                    Ok(n) => rx2.lock().unwrap().data.extend_from_slice(&buf[..n]),
                }
            }
        });
        Client {
            ip,
            wr,
            rx,
            mark: 0,
            eof_mark: false,
        }
    }

    async fn send(&mut self, data: &[u8]) {
        // A write to a socket the server already closed may fail: that is fine.
        let _ = self.wr.write_all(data).await;
        let _ = self.wr.flush().await;
    }

    fn received(&self) -> Vec<u8> {
        self.rx.lock().unwrap().data[self.mark..].to_vec()
    }

    fn eof(&self) -> bool {
        self.rx.lock().unwrap().eof
    }

    fn begin_step(&mut self) {
        let s = self.rx.lock().unwrap();
        self.mark = s.data.len();
        self.eof_mark = s.eof;
    }
}

/// A stream that is at EOF and swallows writes (a TLS client the server rejected).
struct Closed;

impl AsyncRead for Closed {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Closed {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Wait until every `(client, n)` has received at least `n` bytes since its step mark, then
/// settle the Hub and give stray frames a short quiet window.
async fn settle(srv: &Server, clients: &BTreeMap<String, Client>, want: &BTreeMap<String, usize>) {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let done = want.iter().all(|(c, n)| clients[c].received().len() >= *n);
        if done || tokio::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    srv.run.hub.settle().await;
    tokio::time::sleep(QUIET).await;
    srv.run.hub.settle().await;
}

async fn wait_eof(c: &Client) -> bool {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !c.eof() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    c.eof()
}

// ---------------------------------------------------------------------------------------------
// direct tests

const EVT_IN: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><event version="2.0" uid="ANDROID-A" type="a-f-G-U-C" time="2030-01-01T00:00:00.000Z" start="2030-01-01T00:00:00.000Z" stale="2030-01-01T00:10:00.000Z" how="m-g"><point lat="1.234567" lon="-3.141592" hae="-25.7" ce="9.9" le="9999999.0"/><detail><contact endpoint="*:-1:stcp" callsign="ALPHA"/></detail></event>"#;
const EVT_OUT: &str = r#"<event version="2.0" uid="ANDROID-A" type="a-f-G-U-C" how="m-g" time="2030-01-01T00:00:00.000Z" start="2030-01-01T00:00:00.000Z" stale="2030-01-01T00:10:00.000Z"><point lat="1.234567" lon="-3.141592" hae="-25.7" ce="9.9" le="9999999.0"/><detail><contact endpoint="*:-1:stcp" callsign="ALPHA"/></detail></event>"#;

async fn read_exact(c: &Client, n: usize) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + WAIT;
    while c.received().len() < n && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    c.received()
}

/// The S-312 done criterion: two plain-TCP clients on 127.0.0.3, a broadcast is delivered to
/// the other client only (byte-exact), a late client gets the persisted event on connect.
#[tokio::test]
async fn plain_two_clients_broadcast_and_persist_replay() {
    let p = pki(&[], &[]);
    let srv = serve(config(&p, false, &Value::Null), now()).await;
    let mut a = Client::connect(srv.run.local_addr, None).await;
    let b = Client::connect(srv.run.local_addr, None).await;
    srv.run.hub.settle().await;
    a.send(EVT_IN.as_bytes()).await;
    assert_eq!(read_exact(&b, EVT_OUT.len()).await, EVT_OUT.as_bytes());
    srv.run.hub.settle().await;
    tokio::time::sleep(QUIET).await;
    assert!(a.received().is_empty(), "no echo to the sender");
    assert_eq!(b.received(), EVT_OUT.as_bytes());

    let c = Client::connect(srv.run.local_addr, None).await;
    assert_eq!(read_exact(&c, EVT_OUT.len()).await, EVT_OUT.as_bytes());
    let uids: Vec<_> = srv
        .run
        .hub
        .persist_snapshot()
        .await
        .iter()
        .map(|e| e.uid.clone().unwrap())
        .collect();
    assert_eq!(uids, ["ANDROID-A"]);

    srv.shutdown.trigger();
    assert!(wait_eof(&a).await && wait_eof(&b).await && wait_eof(&c).await);
    srv.run.join().await.unwrap();
}

/// The same over TLS with client certificates (client_cert_required = true).
#[tokio::test]
async fn tls_two_clients_broadcast() {
    let p = pki(&["alice", "bob"], &[]);
    let srv = serve(config(&p, true, &Value::Null), now()).await;
    let mut a = Client::connect(srv.run.local_addr, Some(client_tls(&p, Some("alice")))).await;
    let b = Client::connect(srv.run.local_addr, Some(client_tls(&p, Some("bob")))).await;
    srv.run.hub.settle().await;
    // Split the event over two writes (multi-chunk input).
    let (x, y) = EVT_IN.as_bytes().split_at(100);
    a.send(x).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    a.send(y).await;
    assert_eq!(read_exact(&b, EVT_OUT.len()).await, EVT_OUT.as_bytes());
    srv.run.hub.settle().await;
    tokio::time::sleep(QUIET).await;
    assert!(a.received().is_empty());
    srv.shutdown.trigger();
    srv.run.join().await.unwrap();
}

/// client_cert_required: a client without a certificate never gets a delivery.
#[tokio::test]
async fn tls_required_rejects_client_without_cert() {
    let p = pki(&["alice"], &[]);
    let srv = serve(config(&p, true, &Value::Null), now()).await;
    let n = Client::connect(srv.run.local_addr, Some(client_tls(&p, None))).await;
    assert!(wait_eof(&n).await, "server closes a cert-less client");
    let mut a = Client::connect(srv.run.local_addr, Some(client_tls(&p, Some("alice")))).await;
    a.send(EVT_IN.as_bytes()).await;
    srv.run.hub.settle().await;
    tokio::time::sleep(QUIET).await;
    assert!(n.received().is_empty());
    srv.shutdown.trigger();
    srv.run.join().await.unwrap();
}

/// Spec §6 item 2 / §3.1: an unparseable event is dropped and the connection stays; an XML
/// syntax error closes the connection.
#[tokio::test]
async fn unmarshal_error_drops_event_syntax_error_closes() {
    let p = pki(&[], &[]);
    let srv = serve(config(&p, false, &Value::Null), now()).await;
    let mut a = Client::connect(srv.run.local_addr, None).await;
    let b = Client::connect(srv.run.local_addr, None).await;
    srv.run.hub.settle().await;
    a.send(b"<event uid=\"x\"/>").await;
    a.send(EVT_IN.as_bytes()).await;
    assert_eq!(read_exact(&b, EVT_OUT.len()).await, EVT_OUT.as_bytes());
    assert!(!a.eof());
    // An event completed in the same chunk as the syntax error is not routed (the decoder
    // rejects the whole chunk, like lxml's feed() raising before read_events; = core_vectors).
    let second = EVT_IN.replace("ANDROID-A", "ANDROID-B");
    a.send(format!("{second}<event><</event>").as_bytes()).await;
    assert!(wait_eof(&a).await, "XML Syntax Error closes the connection");
    srv.run.hub.settle().await;
    tokio::time::sleep(QUIET).await;
    assert_eq!(b.received(), EVT_OUT.as_bytes());
    assert!(!b.eof());
    srv.shutdown.trigger();
    srv.run.join().await.unwrap();
}

/// N-5: startup errors are returned by `start` with the bare cause as `Display`.
#[tokio::test]
async fn start_errors() {
    let p = pki(&[], &[]);
    let mut o = serde_json::json!({"taky": {"redis": "not a url"}});
    let err = try_serve(config(&p, false, &o), now()).await.err().unwrap();
    assert!(err.to_string().starts_with("invalid redis URL"), "{err}");
    o = serde_json::json!({"ssl": {"client_cert_required": "maybe"}});
    let err = try_serve(config(&p, true, &o), now()).await.err().unwrap();
    assert_eq!(err.to_string(), "Not a boolean: maybe");
    o = serde_json::json!({"ssl": {"cert": "/nonexistent/server.crt"}});
    let cfg = config(&p, true, &o);
    let sock = mgmt_path(&cfg);
    assert!(try_serve(cfg, now()).await.is_err());
    assert!(
        !sock.exists(),
        "a failed start must remove the mgmt socket file"
    );
}

// ---------------------------------------------------------------------------------------------
// vector runner (network level): connect / send; deliveries, server_closed; final persist and
// cert_db_status

fn split_events(b: &[u8]) -> Vec<String> {
    let s = String::from_utf8_lossy(b).into_owned();
    let mut out = Vec::new();
    let mut rest = s.as_str();
    while let Some(i) = rest[1.min(rest.len())..].find("<event ") {
        out.push(rest[..=i].to_owned());
        rest = &rest[i + 1..];
    }
    if !rest.is_empty() {
        out.push(rest.to_owned());
    }
    out
}

/// Vector placeholders in an expected mgmt reply: `"$SERIAL_INT:<cn>"` → that certificate's
/// serial as a JSON integer; status `ip` → the clients' source address `ip`.
fn subst(v: &Value, p: &Pki, ip: &str) -> Value {
    match v {
        Value::String(s) => match s.strip_prefix("$SERIAL_INT:") {
            Some(cn) => serde_json::from_str(&p.serial_int(cn)).unwrap(),
            None => v.clone(),
        },
        Value::Array(a) => Value::Array(a.iter().map(|x| subst(x, p, ip)).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| {
                    let x = if k == "ip" {
                        Value::from(ip)
                    } else {
                        subst(x, p, ip)
                    };
                    (k.clone(), x)
                })
                .collect(),
        ),
        _ => v.clone(),
    }
}

/// `pattern` with `$ERROR_TEXT` wildcards (the traceback text is not normative) matches `got`.
fn wildcard_match(pattern: &str, got: &str) -> bool {
    let parts: Vec<&str> = pattern.split("$ERROR_TEXT").collect();
    if parts.len() == 1 {
        return pattern == got;
    }
    let Some(mut rest) = got.strip_prefix(parts[0]) else {
        return false;
    };
    let last = parts[parts.len() - 1];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

/// The files in `<root>/cotlog` (name → content).
fn log_files(p: &Pki) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir(p.root.join("cotlog")).unwrap() {
        let e = e.unwrap();
        out.insert(
            e.file_name().into_string().unwrap(),
            std::fs::read_to_string(e.path()).unwrap(),
        );
    }
    out
}

fn check_log_files(id: &str, p: &Pki, ip: &str, want: &Value) {
    let got = log_files(p);
    let want: BTreeMap<String, String> = want
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.replace("$IP", ip), v.as_str().unwrap().to_owned()))
        .collect();
    assert_eq!(
        got.keys().collect::<Vec<_>>(),
        want.keys().collect::<Vec<_>>(),
        "{id}: log_cot file names"
    );
    for (name, pat) in &want {
        assert!(
            wildcard_match(pat, &got[name]),
            "{id}: log file {name}:\n--- got\n{}\n--- want\n{pat}",
            got[name]
        );
    }
    // D-12: nothing escaped the log directory.
    for e in std::fs::read_dir(&p.root).unwrap() {
        let n = e.unwrap().file_name().into_string().unwrap();
        assert!(!n.ends_with(".cot"), "{id}: {n} written outside log_cot");
    }
}

async fn run_vector(id: &str) {
    let path = taky_common::vectors::vectors_dir().join(format!("cot/{id}.json"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cns: Vec<&str> = v["clients"]
        .as_object()
        .unwrap()
        .values()
        .filter_map(|c| c["cert"].as_str())
        .collect();
    let revoked: Vec<&str> = v["revoked_before_start"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut p = pki(&cns, &revoked);
    let ssl = v["config"]["ssl"]["enabled"].as_str() == Some("true");
    let clock = FakeClock::new(t(v["now"].as_str().unwrap()));
    let srv = serve(config(&p, ssl, &v["config"]), clock.shared()).await;

    let mut clients: BTreeMap<String, Client> = BTreeMap::new();
    let mut held: Option<Mgmt> = None;
    for (idx, step) in v["steps"].as_array().unwrap().iter().enumerate() {
        let exp = step.get("rust_expect").unwrap_or(&step["expect"]);
        let name = step["client"].as_str().map(str::to_owned);
        for c in clients.values_mut() {
            c.begin_step();
        }
        let mut reply: Option<String> = None;
        match step["op"].as_str().unwrap() {
            "connect" => {
                let name = name.unwrap();
                let spec = &v["clients"][&name];
                let monitor = spec["kind"].as_str() == Some("monitor");
                let addr = if monitor {
                    srv.run.monitor_addr.unwrap()
                } else {
                    srv.run.local_addr
                };
                let cert = spec["cert"].as_str().or_else(|| {
                    let other = spec["same_cert_as"].as_str()?;
                    v["clients"][other]["cert"].as_str()
                });
                let tls = (ssl && !monitor).then(|| client_tls(&p, cert));
                clients.insert(name, Client::connect(addr, tls).await);
            }
            "send" => {
                let c = clients.get_mut(&name.unwrap()).unwrap();
                for chunk in step["chunks"].as_array().unwrap() {
                    c.send(chunk.as_str().unwrap().as_bytes()).await;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
            "advance" => {
                let secs = step["seconds"].as_i64().unwrap();
                clock.advance(TimeDelta::seconds(secs));
            }
            "mgmt" => {
                let req = match &step["request"] {
                    Value::String(raw) => raw.clone(),
                    obj => dumps(obj),
                };
                let mut m = Mgmt::connect(&srv.mgmt).await;
                reply = Some(m.request(req.as_bytes()).await);
            }
            "mgmt_hold" => {
                // D-9: an open (and active) mgmt connection must not affect CoT traffic.
                let mut m = Mgmt::connect(&srv.mgmt).await;
                assert_eq!(
                    m.request(br#"{"cmd": "ping"}"#).await,
                    r#"{"pong": "taky"}"#
                );
                held = Some(m);
            }
            "mgmt_release" => {
                assert!(held.take().is_some(), "{id} step {idx}: nothing held");
            }
            "issue_cert" => p.issue(step["cn"].as_str().unwrap()),
            op => panic!("{id}: op {op} not supported by this runner"),
        }
        if let Some(want) = exp.get("mgmt_response") {
            let got = reply.as_deref().expect("mgmt_response without a mgmt op");
            let ip = clients.values().next().map_or(HOST, |c| c.ip.as_str());
            assert_eq!(
                got,
                dumps(&subst(want, &p, ip)),
                "{id} step {idx}: mgmt reply"
            );
        }
        let deliveries = exp["deliveries"].as_object().cloned().unwrap_or_default();
        let want: BTreeMap<String, Vec<String>> = deliveries
            .iter()
            .map(|(c, l)| {
                let l = l.as_array().unwrap().iter();
                (
                    c.clone(),
                    l.map(|x| x.as_str().unwrap().to_owned()).collect(),
                )
            })
            .collect();
        let lens = want
            .iter()
            .map(|(c, l)| (c.clone(), l.iter().map(String::len).sum()))
            .collect();
        settle(&srv, &clients, &lens).await;
        let closed: Vec<&str> = exp["server_closed"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        for (cname, c) in &clients {
            let mut got = split_events(&c.received());
            let mut exp_l = want.get(cname).cloned().unwrap_or_default();
            if step["op"] == "connect" {
                got.sort();
                exp_l.sort();
            }
            assert_eq!(got, exp_l, "{id} step {idx}: deliveries to {cname}");
            if closed.contains(&cname.as_str()) {
                assert!(wait_eof(c).await, "{id} step {idx}: {cname} not closed");
            } else if !c.eof_mark {
                assert!(!c.eof(), "{id} step {idx}: {cname} closed unexpectedly");
            }
        }
    }
    drop(held);
    let ip = clients
        .values()
        .next()
        .map_or_else(|| HOST.to_owned(), |c| c.ip.clone());

    let fin = v.get("final_rust_expect").unwrap_or(&v["final_expect"]);
    let mut logs = None;
    for (k, e) in fin.as_object().into_iter().flatten() {
        match k.as_str() {
            "persist" => {
                assert_eq!(e["backend"], "memory");
                let got: Vec<Value> = srv
                    .run
                    .hub
                    .persist_snapshot()
                    .await
                    .iter()
                    .map(|e| Value::from(e.uid.clone().unwrap()))
                    .collect();
                assert_eq!(Value::from(got), e["uids"], "{id}: final persist");
            }
            "cert_db_status" => {
                let db = CertDb::open(&p.cert_db).unwrap();
                let got: serde_json::Map<String, Value> = db
                    .records()
                    .iter()
                    .map(|r| (r.name.clone(), Value::from(r.status.as_str())))
                    .collect();
                assert_eq!(Value::Object(got), *e, "{id}: cert_db_status");
            }
            "log_files" => logs = Some(e),
            other => panic!("{id}: final key {other} not supported"),
        }
    }
    srv.shutdown.trigger();
    srv.run.join().await.unwrap();
    assert!(!srv.mgmt.exists(), "{id}: mgmt socket removed on stop");
    if let Some(e) = logs {
        check_log_files(id, &p, &ip, e);
    }
}

/// V047: TLS + monitor port: the monitor gets a raw copy of every packet (incl. pings) plus
/// broadcasts; an event injected on the monitor port is routed.
#[tokio::test]
async fn vector_v047_tls_monitor() {
    run_vector("V047").await;
}

/// V048: a certificate with status R in cert-db is disconnected right after the handshake.
#[tokio::test]
async fn vector_v048_ban_on_connect() {
    run_vector("V048").await;
}

/// V044: log_cot — anonymous file, then `<uid>-<callsign>.cot`; pings skipped; unparsable
/// events logged with `<__taky_err>` (byte-exact apart from the error text).
#[tokio::test]
async fn vector_v044_log_cot() {
    run_vector("V044").await;
}

/// V053 (D-12): a uid with `/` cannot escape the log directory.
#[tokio::test]
async fn vector_v053_log_cot_traversal() {
    run_vector("V053").await;
}

/// V045: mgmt ping / unknown cmd / invalid JSON (D-24) / status / kickban of an unknown user.
#[tokio::test]
async fn vector_v045_mgmt() {
    run_vector("V045").await;
}

/// V046 (D-9): CoT traffic flows while a mgmt connection is open.
#[tokio::test]
async fn vector_v046_mgmt_held_open() {
    run_vector("V046").await;
}

/// V049: kickban revokes in cert-db, kicks the live session, blocks the reconnect.
#[tokio::test]
async fn vector_v049_kickban() {
    run_vector("V049").await;
}

/// V051 (D-10): a non-object JSON request is answered, the server keeps running.
#[tokio::test]
async fn vector_v051_mgmt_non_object() {
    run_vector("V051").await;
}

/// V052 (D-11): kickban sees a certificate added to cert-db.txt after startup.
#[tokio::test]
async fn vector_v052_kickban_reread() {
    run_vector("V052").await;
}

// ---------------------------------------------------------------------------------------------
// S-313 direct tests: log_cot wiring (review-3B N-1), mgmt framing

/// N-1: with max_persist_ttl the CoT log records the event as routed (stale corrected) while
/// the monitor copy keeps the original stale (V047); a D-8 event (no `how`) is logged as the
/// original element with `<__taky_err>`; an `a*` event with a `*-ping` uid is routed, not logged.
#[tokio::test]
async fn log_cot_max_ttl_clone_d8_and_ping_uid() {
    let p = pki(&["alice", "bob"], &[]);
    let o = serde_json::json!({"cot_server": {"log_cot": "AUTO", "max_persist_ttl": "60", "mon_ip": HOST}});
    let srv = serve(config(&p, true, &o), now()).await;
    let mut a = Client::connect(srv.run.local_addr, Some(client_tls(&p, Some("alice")))).await;
    let b = Client::connect(srv.run.local_addr, Some(client_tls(&p, Some("bob")))).await;
    let m = Client::connect(srv.run.monitor_addr.unwrap(), None).await;
    srv.run.hub.settle().await;

    let routed = EVT_OUT.replace("00:10:00.000Z", "00:01:00.000Z");
    a.send(EVT_IN.as_bytes()).await;
    assert_eq!(read_exact(&b, routed.len()).await, routed.as_bytes());
    // The monitor: the raw copy (original stale) first, then the broadcast (spec §12 quirk).
    let mon = format!("{EVT_OUT}{routed}");
    assert_eq!(read_exact(&m, mon.len()).await, mon.as_bytes());

    let d8 = r#"<event version="2.0" uid="N-1" type="a-u-G" time="2030-01-01T00:00:00.000Z" start="2030-01-01T00:00:00.000Z" stale="2030-01-01T00:00:30.000Z"><point lat="1.0" lon="2.0" hae="0.0" ce="1.0" le="1.0"/></event>"#;
    a.send(d8.as_bytes()).await;
    let ping_uid = EVT_IN.replace("ANDROID-A", "X-ping");
    a.send(ping_uid.as_bytes()).await;
    let ping_out = routed.replace("ANDROID-A", "X-ping");
    assert_eq!(
        read_exact(&b, routed.len() + ping_out.len()).await,
        format!("{routed}{ping_out}").as_bytes()
    );
    srv.run.hub.settle().await;
    tokio::time::sleep(QUIET).await;
    srv.shutdown.trigger();
    srv.run.join().await.unwrap();

    let files = log_files(&p);
    let name = format!("anonymous-{}.cot", a.ip);
    assert_eq!(files.keys().collect::<Vec<_>>(), [&name], "{files:?}");
    let want = concat!(
        r#"<event version="2.0" uid="ANDROID-A" type="a-f-G-U-C" how="m-g" time="2030-01-01T00:00:00.000Z" start="2030-01-01T00:00:00.000Z" stale="2030-01-01T00:01:00.000Z">"#,
        "\n",
        r#"  <point lat="1.234567" lon="-3.141592" hae="-25.7" ce="9.9" le="9999999.0"/>"#,
        "\n  <detail>\n",
        r#"    <contact endpoint="*:-1:stcp" callsign="ALPHA"/>"#,
        "\n  </detail>\n</event>\n",
        r#"<event version="2.0" uid="N-1" type="a-u-G" time="2030-01-01T00:00:00.000Z" start="2030-01-01T00:00:00.000Z" stale="2030-01-01T00:00:30.000Z">"#,
        "\n",
        r#"  <point lat="1.0" lon="2.0" hae="0.0" ce="1.0" le="1.0"/>"#,
        "\n  <__taky_err>\n    <!--$ERROR_TEXT-->\n  </__taky_err>\n</event>\n",
    );
    assert!(
        wildcard_match(want, &files[&name]),
        "got:\n{}\nwant:\n{want}",
        files[&name]
    );
}

/// A missing log_cot directory is not created: WARNING, logging disabled, traffic unaffected.
#[tokio::test]
async fn log_cot_missing_dir_disables_logging() {
    let p = pki(&[], &[]);
    let missing = p.root.join("no-such-dir");
    let o = serde_json::json!({"cot_server": {"log_cot": missing.to_str().unwrap()}});
    let srv = serve(config(&p, false, &o), now()).await;
    let mut a = Client::connect(srv.run.local_addr, None).await;
    let b = Client::connect(srv.run.local_addr, None).await;
    srv.run.hub.settle().await;
    a.send(EVT_IN.as_bytes()).await;
    a.send(EVT_IN.as_bytes()).await;
    let two = EVT_OUT.repeat(2);
    assert_eq!(read_exact(&b, two.len()).await, two.as_bytes());
    srv.shutdown.trigger();
    srv.run.join().await.unwrap();
    assert!(!missing.exists());
}

/// Mgmt framing (spec §13): several requests in one write, a request split over writes,
/// replies in order on the same connection; invalid UTF-8 keeps the `{"error": ...}` shape
/// (D-24) and the connection; an unknown cmd value is rendered as Python `str()`.
#[tokio::test]
async fn mgmt_framing_and_errors() {
    let p = pki(&[], &[]);
    let srv = serve(config(&p, false, &Value::Null), now()).await;
    let mut m = Mgmt::connect(&srv.mgmt).await;
    m.send_raw(b"{\"cmd\": \"ping\"}\0{\"cmd\": [1, \"a\"]}\0{\"cmd\": \"st")
        .await;
    assert_eq!(m.recv().await, r#"{"pong": "taky"}"#);
    assert_eq!(m.recv().await, r#"{"error": "Invalid cmd: [1, 'a']"}"#);
    tokio::time::sleep(Duration::from_millis(20)).await;
    m.send_raw(b"atus\"}\0").await;
    assert_eq!(
        m.recv().await,
        r#"{"uptime": 0.0, "num_clients": 0, "clients": []}"#
    );
    let r = m.request(b"\xff").await;
    assert!(r.starts_with(r#"{"error": ""#), "{r}");
    assert_eq!(m.request(b"[]").await, r#"{"error": "Invalid cmd: None"}"#);
    assert_eq!(
        m.request(br#"{"cmd": "kickban"}"#).await,
        r#"{"revoked_sns": []}"#
    );
    assert_eq!(
        m.request(br#"{"cmd": "ping"}"#).await,
        r#"{"pong": "taky"}"#
    );
    srv.shutdown.trigger();
    srv.run.join().await.unwrap();
    assert!(!srv.mgmt.exists());
}

/// BUG-1 (S-403a): kickban with a missing / null / non-string `user` answers `[]` (Python:
/// `get_certificates_by_name` matches nothing) and keeps the cert-db: a revoked (`R`) client is
/// still refused over TLS and a later kickban with a user still revokes and kicks.
#[tokio::test]
async fn kickban_without_user_keeps_bans() {
    let p = pki(&["bob", "carol"], &["carol"]);
    let srv = serve(config(&p, true, &Value::Null), now()).await;
    let bob = Client::connect(srv.run.local_addr, Some(client_tls(&p, Some("bob")))).await;
    let mut m = Mgmt::connect(&srv.mgmt).await;
    for req in [
        &br#"{"cmd": "kickban"}"#[..],
        br#"{"cmd": "kickban", "user": null}"#,
        br#"{"cmd": "kickban", "user": 5}"#,
        br#"{"cmd": "kickban", "user": ["bob"]}"#,
        br#"{"cmd": "kickban", "user": {"name": "bob"}}"#,
    ] {
        assert_eq!(m.request(req).await, r#"{"revoked_sns": []}"#);
    }
    let carol = Client::connect(srv.run.local_addr, Some(client_tls(&p, Some("carol")))).await;
    assert!(
        wait_eof(&carol).await,
        "revoked carol must still be refused"
    );
    srv.run.hub.settle().await;
    assert!(!bob.eof());
    assert_eq!(
        m.request(br#"{"cmd": "kickban", "user": "bob"}"#).await,
        format!(r#"{{"revoked_sns": [{}]}}"#, p.serial_int("bob"))
    );
    assert!(wait_eof(&bob).await, "bob is kicked");
    let again = Client::connect(srv.run.local_addr, Some(client_tls(&p, Some("bob")))).await;
    assert!(
        wait_eof(&again).await,
        "revoked bob is refused on reconnect"
    );
    srv.shutdown.trigger();
    srv.run.join().await.unwrap();
}

/// review-3C N-1: without SSL the cert-db is still opened (server.py:84), so kickban revokes
/// there and returns the serials; a plain client is still accepted (ban-on-connect is TLS-only).
/// An unopenable cert-db in plain mode is a WARNING, not a startup error.
#[tokio::test]
async fn plain_kickban_revokes_in_cert_db() {
    let p = pki(&["bob"], &[]);
    let srv = serve(config(&p, false, &Value::Null), now()).await;
    let mut m = Mgmt::connect(&srv.mgmt).await;
    assert_eq!(
        m.request(br#"{"cmd": "kickban", "user": "bob"}"#).await,
        format!(r#"{{"revoked_sns": [{}]}}"#, p.serial_int("bob"))
    );
    let rec = CertDb::open(&p.cert_db).unwrap();
    let bob: Vec<_> = rec.by_name("bob").collect();
    assert_eq!(bob.len(), 1);
    assert_eq!(bob[0].status, taky_pki::CertStatus::Revoked);
    let line = std::fs::read_to_string(&p.cert_db).unwrap();
    assert!(
        line.lines()
            .any(|l| l.starts_with("R\t") && l.ends_with("\tbob")),
        "{line}"
    );
    assert_eq!(
        m.request(br#"{"cmd": "kickban", "user": "bob"}"#).await,
        r#"{"revoked_sns": []}"#
    );
    let c = Client::connect(srv.run.local_addr, None).await;
    srv.run.hub.settle().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!c.eof());
    srv.shutdown.trigger();
    srv.run.join().await.unwrap();

    // cert-db that cannot be read: the plain server still starts, kickban revokes nothing.
    let p = pki(&[], &[]);
    std::fs::remove_file(&p.cert_db).unwrap();
    std::fs::create_dir(&p.cert_db).unwrap();
    let srv = serve(config(&p, false, &Value::Null), now()).await;
    let mut m = Mgmt::connect(&srv.mgmt).await;
    assert_eq!(
        m.request(br#"{"cmd": "kickban", "user": "bob"}"#).await,
        r#"{"revoked_sns": []}"#
    );
    srv.shutdown.trigger();
    srv.run.join().await.unwrap();
}
