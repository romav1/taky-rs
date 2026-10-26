//! S-314: the real `taky-rs` binary, spawned as a process (tools/pyref `smoke.py` pattern on
//! 127.0.0.3): CoT broadcast between two TLS clients, mgmt ping, clean SIGTERM/SIGINT (exit 0,
//! clients closed, mgmt socket removed); "already running" and stale-socket takeover; startup
//! and config errors with their exit codes (spec cot-server.md §1.2, review-3B N-5).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SerialNumber, date_time_ymd,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use taky_pki::CertDb;

const HOST: &str = "127.0.0.3";
const BIN: &str = env!("CARGO_BIN_EXE_taky-rs");
const WAIT: Duration = Duration::from_secs(10);

struct Site {
    _dir: tempfile::TempDir,
    root: PathBuf,
    ca_der: CertificateDer<'static>,
    clients: Vec<(CertificateDer<'static>, KeyPair)>,
    port: u16,
}

impl Site {
    fn conf(&self) -> PathBuf {
        self.root.join("taky.conf")
    }
    fn sock(&self) -> PathBuf {
        self.root.join("taky-mgmt.sock")
    }
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
    p.serial_number = Some(SerialNumber::from_slice(&[0x5e, serial, 0x14]));
    p.not_before = date_time_ymd(2024, 1, 1);
    p.not_after = date_time_ymd(2080, 1, 1);
    p.extended_key_usages = vec![if server {
        ExtendedKeyUsagePurpose::ServerAuth
    } else {
        ExtendedKeyUsagePurpose::ClientAuth
    }];
    (p.signed_by(&key, issuer).unwrap().der().clone(), key)
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

fn free_port() -> u16 {
    TcpListener::bind((HOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A takyctl-setup-like site: relative paths in taky.conf (resolved against the config dir),
/// `root_dir = .`, TLS with required client certs, two clients in cert-db, `log_cot`.
fn site(extra: &str) -> Site {
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
    std::fs::create_dir_all(root.join("ssl")).unwrap();
    std::fs::create_dir_all(root.join("cot-log")).unwrap();
    let (sder, skey) = leaf(&issuer, "localhost", true, 1);
    std::fs::write(root.join("ssl/ca.crt"), ca.pem()).unwrap();
    std::fs::write(root.join("ssl/server.crt"), pem("CERTIFICATE", &sder)).unwrap();
    std::fs::write(root.join("ssl/server.key"), skey.serialize_pem()).unwrap();
    let mut db = CertDb::open(&root.join("ssl/cert-db.txt")).unwrap();
    db.add(&sder).unwrap();
    let mut clients = Vec::new();
    for (i, cn) in ["alpha", "bravo"].iter().enumerate() {
        let c = leaf(&issuer, cn, false, 2 + u8::try_from(i).unwrap());
        db.add(&c.0).unwrap();
        clients.push(c);
    }
    let port = free_port();
    let conf = format!(
        "[taky]\nbind_ip = {HOST}\nroot_dir = .\nredis\n{extra}\n[cot_server]\nport = {port}\n\
         log_cot = ./cot-log\n\n[ssl]\nenabled = true\nclient_cert_required = true\n\
         ca = ./ssl/ca.crt\ncert = ./ssl/server.crt\nkey = ./ssl/server.key\n\
         cert_db = ./ssl/cert-db.txt\n"
    );
    std::fs::write(root.join("taky.conf"), conf).unwrap();
    Site {
        _dir: dir,
        root,
        ca_der: ca.der().clone(),
        clients,
        port,
    }
}

fn spawn(args: &[&str], cwd: &Path) -> Child {
    Command::new(BIN)
        .args(args)
        .current_dir(cwd)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn run(args: &[&str], cwd: &Path) -> Output {
    let child = spawn(args, cwd);
    wait_exit(child)
}

fn wait_exit(mut child: Child) -> Output {
    let t0 = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if t0.elapsed() > WAIT {
            let _ = child.kill();
            panic!("taky-rs did not exit within {WAIT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

fn signal(child: &Child, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &child.id().to_string()])
        .status()
        .unwrap();
    assert!(ok.success());
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Wait until the server answers a mgmt ping (it is then also listening on CoT: the mgmt
/// accept loop starts after the CoT listener in `start`).
fn wait_ready(s: &Site, child: &mut Child) {
    let t0 = Instant::now();
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            let mut e = String::new();
            child.stderr.take().unwrap().read_to_string(&mut e).unwrap();
            panic!("taky-rs exited early ({st}): {e}");
        }
        if s.sock().exists() && ping(&s.sock()).is_some() {
            return;
        }
        assert!(t0.elapsed() < WAIT, "taky-rs did not come up");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn ping(path: &Path) -> Option<String> {
    let mut m = UnixStream::connect(path).ok()?;
    m.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    m.write_all(b"{\"cmd\": \"ping\"}\0").ok()?;
    let mut resp = Vec::new();
    let mut b = [0u8; 4096];
    while !resp.ends_with(b"\0") {
        let n = m.read(&mut b).ok()?;
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&b[..n]);
    }
    Some(String::from_utf8(resp).unwrap())
}

type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

fn connect(s: &Site, i: usize) -> Tls {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(s.ca_der.clone()).unwrap();
    let (der, key) = &s.clients[i];
    let k = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let cfg = rustls::ClientConfig::builder_with_provider(taky_pki::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![der.clone()], k)
        .unwrap();
    let conn =
        rustls::ClientConnection::new(Arc::new(cfg), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let tcp = TcpStream::connect((HOST, s.port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    rustls::StreamOwned::new(conn, tcp)
}

/// Read until `needle` appears, EOF, or `timeout`; returns (data, eof).
fn read_until(c: &mut Tls, needle: &[u8], timeout: Duration) -> (Vec<u8>, bool) {
    let t0 = Instant::now();
    let mut data = Vec::new();
    let mut b = [0u8; 65536];
    while t0.elapsed() < timeout {
        match c.read(&mut b) {
            Ok(0) => return (data, true),
            Ok(n) => {
                data.extend_from_slice(&b[..n]);
                if !needle.is_empty() && data.windows(needle.len()).any(|w| w == needle) {
                    return (data, false);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return (data, true),
        }
    }
    (data, false)
}

fn sa(uid: &str, callsign: &str) -> Vec<u8> {
    format!(
        "<event version=\"2.0\" uid=\"{uid}\" type=\"a-f-G-U-C\" how=\"m-g\" \
         time=\"2026-01-01T00:00:00Z\" start=\"2026-01-01T00:00:00Z\" stale=\"2099-01-01T00:00:00Z\">\
         <point lat=\"10.0\" lon=\"20.0\" hae=\"0\" ce=\"9999999\" le=\"9999999\"/>\
         <detail><contact callsign=\"{callsign}\" endpoint=\"*:-1:stcp\"/>\
         <__group name=\"Cyan\" role=\"Team Member\"/>\
         <takv device=\"smoke\" platform=\"taky-rs-smoke\" os=\"linux\" version=\"0\"/></detail></event>"
    )
    .into_bytes()
}

#[test]
fn smoke_tls_broadcast_mgmt_ping_sigterm() {
    let s = site("");
    // Started from another directory: relative paths resolve against the config dir.
    let mut child = spawn(&["-c", s.conf().to_str().unwrap()], Path::new("/"));
    wait_ready(&s, &mut child);
    assert_eq!(ping(&s.sock()).unwrap(), "{\"pong\": \"taky\"}\0");

    let mut bravo = connect(&s, 1);
    bravo.write_all(&sa("bravo-uid", "BRAVO")).unwrap();
    bravo.flush().unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let mut alpha = connect(&s, 0);
    alpha.write_all(&sa("alpha-uid", "ALPHA")).unwrap();
    alpha.flush().unwrap();
    let (got, _) = read_until(&mut bravo, b"</event>", Duration::from_secs(5));
    let got = String::from_utf8(got).unwrap();
    assert!(
        got.contains("uid=\"alpha-uid\"") && got.contains("callsign=\"ALPHA\""),
        "{got}"
    );
    assert!(!got.contains("bravo-uid"), "echo: {got}");
    // alpha gets bravo's persisted SA on connect.
    let (a, _) = read_until(&mut alpha, b"</event>", Duration::from_secs(5));
    assert!(String::from_utf8(a).unwrap().contains("uid=\"bravo-uid\""));

    signal(&child, "-TERM");
    let (_, eof_a) = read_until(&mut alpha, b"", Duration::from_secs(5));
    let (_, eof_b) = read_until(&mut bravo, b"", Duration::from_secs(5));
    assert!(eof_a && eof_b, "clients not closed on shutdown");
    let out = wait_exit(child);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(!s.sock().exists(), "mgmt socket left behind");
    for line in [
        format!("INFO:root:taky-rs v{}", taky_common::VERSION),
        format!("INFO:COTServer:Listening for ssl on {HOST}:{}", s.port),
        "INFO:root:Got SIGTERM".into(),
        "INFO:COTServer:Sending disconnect to clients".into(),
        "Socket disconnect: Server shutting down".into(),
        "INFO:COTServer:Stopped".into(),
    ] {
        assert!(err.contains(&line), "missing {line:?} in:\n{err}");
    }
    let logs: Vec<String> = std::fs::read_dir(s.root.join("cot-log"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        logs.contains(&"alpha-uid-ALPHA.cot".to_owned()),
        "{logs:?}\n{err}"
    );
}

#[test]
fn sigint_is_a_clean_exit_and_sigusr1_is_ignored() {
    let s = site("");
    let mut child = spawn(
        &["-c", s.conf().to_str().unwrap(), "-d", "-l", "debug"],
        &s.root,
    );
    wait_ready(&s, &mut child);
    signal(&child, "-USR1");
    std::thread::sleep(Duration::from_millis(200));
    assert!(ping(&s.sock()).is_some(), "SIGUSR1 killed the server");
    signal(&child, "-INT");
    let out = wait_exit(child);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stderr(&out).contains("SIGUSR1 ignored"));
    assert!(!s.sock().exists());
}

#[test]
fn already_running_and_stale_socket_takeover() {
    let s = site("");
    // A stale socket file (nobody listening) is removed and taken over.
    drop(UnixListener::bind(s.sock()).unwrap());
    assert!(s.sock().exists());
    let mut first = spawn(&["-c", "taky.conf"], &s.root);
    wait_ready(&s, &mut first);

    // A second instance on the same root_dir: the ping is answered ⇒ exit 1, socket untouched.
    let out = run(&["-c", "taky.conf"], &s.root);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    let want = format!(
        "ERROR:root:Unable to start COTServer: Taky already appears to be running via {}",
        s.sock().display()
    );
    assert!(err.contains(&want), "{err}");
    assert!(
        ping(&s.sock()).is_some(),
        "the running server lost its socket"
    );

    signal(&first, "-TERM");
    let out = wait_exit(first);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(!s.sock().exists());
}

/// review-3C N-2: a stale mgmt path that cannot be removed (here a non-empty directory: no ping
/// answer, `os.remove` fails) is a startup error, exit 1, as Python; nothing is bound.
#[test]
fn unremovable_stale_socket_fails_startup() {
    let s = site("");
    std::fs::create_dir(s.sock()).unwrap();
    std::fs::write(s.sock().join("keep"), b"x").unwrap();
    let out = run(&["-c", "taky.conf"], &s.root);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    let want = format!(
        "ERROR:root:Unable to start COTServer: Is a directory (os error 21) ({})",
        s.sock().display()
    );
    assert!(err.contains(&want), "{err}");
    assert!(s.sock().join("keep").exists(), "the stale path was touched");
    assert!(
        TcpListener::bind((HOST, s.port)).is_ok(),
        "CoT port was bound"
    );
}

#[test]
fn startup_errors_exit_1_and_remove_the_socket() {
    // N-5: PersistError (invalid redis URL) after the sockets are bound.
    let s = site("");
    let conf = std::fs::read_to_string(s.conf())
        .unwrap()
        .replace("redis\n", "redis = not a url\n");
    std::fs::write(s.conf(), conf).unwrap();
    let out = run(&["-c", "taky.conf"], &s.root);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(
        err.contains("ERROR:root:Unable to start COTServer: invalid redis URL"),
        "{err}"
    );
    assert!(!s.sock().exists(), "mgmt socket left after a failed start");

    // Bad ssl.client_cert_required (validated at start, server.py:149).
    let s = site("");
    let conf = std::fs::read_to_string(s.conf()).unwrap().replace(
        "client_cert_required = true",
        "client_cert_required = maybe",
    );
    std::fs::write(s.conf(), conf).unwrap();
    let out = run(&["-c", "taky.conf"], &s.root);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("ERROR:root:Unable to start COTServer: Not a boolean: maybe"));
    assert!(!s.sock().exists());

    // CoT port in use: bind fails after the mgmt socket was created.
    let s = site("");
    let _busy = TcpListener::bind((HOST, s.port)).unwrap();
    let out = run(&["-c", "taky.conf"], &s.root);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("ERROR:root:Unable to start COTServer: "),
        "{}",
        stderr(&out)
    );
    assert!(!s.sock().exists());

    // Unresolvable bind_ip.
    let s = site("");
    let conf = std::fs::read_to_string(s.conf()).unwrap().replace(
        &format!("bind_ip = {HOST}"),
        "bind_ip = no-such-host.invalid",
    );
    std::fs::write(s.conf(), conf).unwrap();
    let out = run(&["-c", "taky.conf"], &s.root);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains(
        "ERROR:root:Unable to start COTServer: Unable to determine address info for bind_ip: no-such-host.invalid"
    ));
}

/// S-A06 Q1: SSL on, `key =` (empty), key inside the `cert` file ⇒ Python `load_cert_chain(keyfile="")`
/// fails (`FileNotFoundError`): two ERROR lines, exit 1, mgmt socket removed. A valueless `key`
/// line still reads the key from the cert file.
#[test]
fn empty_ssl_key_fails_startup() {
    let s = site("");
    let both = std::fs::read_to_string(s.root.join("ssl/server.crt")).unwrap()
        + &std::fs::read_to_string(s.root.join("ssl/server.key")).unwrap();
    std::fs::write(s.root.join("ssl/both.pem"), both).unwrap();
    let conf = std::fs::read_to_string(s.conf())
        .unwrap()
        .replace("cert = ./ssl/server.crt", "cert = ./ssl/both.pem");
    std::fs::write(s.conf(), conf.replace("key = ./ssl/server.key", "key =")).unwrap();
    let out = run(&["-c", "taky.conf"], &s.root);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    let load = err
        .find("ERROR:COTServer:Unable to load SSL certificate: ")
        .expect(&err);
    let start = err
        .find("ERROR:root:Unable to start COTServer: ")
        .expect(&err);
    assert!(load < start, "{err}");
    assert!(err.contains("No such file or directory"), "{err}");
    assert!(!s.sock().exists(), "mgmt socket left after a failed start");

    // Valueless `key`: the key comes from the cert file, the server starts.
    std::fs::write(s.conf(), conf.replace("key = ./ssl/server.key", "key")).unwrap();
    let mut child = spawn(&["-c", "taky.conf"], &s.root);
    wait_ready(&s, &mut child);
    signal(&child, "-TERM");
    let out = wait_exit(child);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}

#[test]
fn config_errors_and_cli() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    std::fs::write(d.join("nosect.conf"), "port = 1\n").unwrap();
    let out = run(&["-c", "nosect.conf"], d);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("Configuration file error: File contains no section headers."),
        "{}",
        stderr(&out)
    );

    std::fs::write(d.join("port.conf"), "[cot_server]\nport = x\n").unwrap();
    let out = run(&["-c", "port.conf"], d);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("Configuration file error: Invalid port: x"));

    // An existing but unreadable path (a directory): OSError → argparse error, exit 2.
    std::fs::create_dir(d.join("dir.conf")).unwrap();
    let out = run(&["-c", "dir.conf"], d);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("taky-rs: error: Unable to load config file: 'dir.conf'"),
        "{}",
        stderr(&out)
    );

    let out = run(&["-l", "verbose"], d);
    assert_eq!(out.status.code(), Some(2));

    let out = run(&["--version"], d);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("taky-rs version {}\n", taky_common::VERSION)
    );
}
