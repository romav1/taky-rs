//! DPS vector runner (`runner: "dps"`, shared/spec/vectors/README.md "DPS vector format").
//!
//! * The config is written as a real `taky.conf` (vector sections + `upload_path` + test PKI) and
//!   loaded with `taky_config::load_config_in`.
//! * TLS identity ⇒ a real client certificate with that CN (generated at test time, no keys in
//!   the repo); `revoked` ⇒ an `R` line in cert-db. Plain identity ⇒ `X-USER` (+`X-REVOKED: 1`)
//!   headers (README rule 5).
//! * `remote_addr` (non-loopback) ⇒ the stream is served via `DpsApp::serve_connection` over an
//!   in-memory duplex with that peer address; otherwise a real TCP connection from 127.0.0.1.
//! * `exp = rust_expect ?? expect`, `final = final_rust_expect ?? final_expect`.
//! * `multipart` is encoded like the Werkzeug test client (raw UTF-8 `filename="…"`, part
//!   Content-Type = given ?? `mimetypes.guess_type(filename)` ?? `application/octet-stream`).
//! * `upload_path/meta` is pre-created (as `takyctl setup` and the Python runner do); final files
//!   are compared as the full snapshot of `upload_path` (Python `snapshot_files`), with
//!   `SubmissionDateTime` values normalized to `$TIMESTAMP`; `$UPLOAD_PATH` in bodies.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SerialNumber, date_time_ymd,
};
use serde_json::Value;
use taky_common::{Shutdown, SystemClock};
use taky_dps::{DpsApp, DpsOptions, RunningDps};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};

/// Test CA + server certificate, client certificates by CN.
pub struct Pki {
    issuer: Issuer<'static, KeyPair>,
    ca_der: CertificateDer<'static>,
    pub ca_pem: String,
    pub server_pem: String,
    pub server_key_pem: String,
    next_serial: u8,
}

pub struct Client {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

impl Pki {
    pub fn new() -> Pki {
        let key = KeyPair::generate().expect("key");
        let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
        p.distinguished_name.push(DnType::CommonName, "CA");
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.not_before = date_time_ymd(2020, 1, 1);
        p.not_after = date_time_ymd(2090, 1, 1);
        let ca = p.self_signed(&key).expect("ca");
        let mut pki = Pki {
            ca_der: ca.der().clone(),
            ca_pem: ca.pem(),
            issuer: Issuer::new(p, key),
            server_pem: String::new(),
            server_key_pem: String::new(),
            next_serial: 1,
        };
        let skey = KeyPair::generate().expect("key");
        let cert = pki.sign(&skey, "localhost", true);
        pki.server_pem = pem_wrap("CERTIFICATE", &cert);
        pki.server_key_pem = skey.serialize_pem();
        pki
    }

    fn sign(&mut self, key: &KeyPair, cn: &str, server: bool) -> CertificateDer<'static> {
        let sans = if server { vec![cn.to_owned()] } else { vec![] };
        let mut p = CertificateParams::new(sans).expect("params");
        p.distinguished_name.push(DnType::CommonName, cn);
        p.is_ca = IsCa::ExplicitNoCa;
        p.serial_number = Some(SerialNumber::from_slice(&[0x5a, self.next_serial]));
        self.next_serial += 1;
        p.not_before = date_time_ymd(2024, 3, 4);
        p.not_after = date_time_ymd(2080, 5, 6);
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![if server {
            ExtendedKeyUsagePurpose::ServerAuth
        } else {
            ExtendedKeyUsagePurpose::ClientAuth
        }];
        p.signed_by(key, &self.issuer).expect("sign").der().clone()
    }

    pub fn client(&mut self, cn: &str) -> Client {
        let key = KeyPair::generate().expect("key");
        let cert = self.sign(&key, cn, false);
        Client {
            cert,
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        }
    }

    pub fn connector(&self, client: Option<&Client>) -> TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.ca_der.clone()).expect("root");
        let b = rustls::ClientConfig::builder_with_provider(taky_pki::provider())
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(roots);
        let cfg = match client {
            Some(c) => b
                .with_client_auth_cert(vec![c.cert.clone()], c.key.clone_key())
                .expect("client cert"),
            None => b.with_no_client_auth(),
        };
        TlsConnector::from(Arc::new(cfg))
    }
}

pub fn pem_wrap(label: &str, der: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for c in der.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                b64.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                b64.push('=');
            }
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// A raw HTTP/1.1 response.
#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A request as the vectors describe it.
#[derive(Debug, Clone, Default)]
pub struct HttpRequest {
    pub method: String,
    /// Path plus optional `?query`.
    pub target: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Send `req` with `Connection: close` and read one response.
pub async fn roundtrip<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    req: &HttpRequest,
) -> HttpResponse {
    let mut out = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        req.method, req.target, req.host
    );
    for (n, v) in &req.headers {
        out.push_str(&format!("{n}: {v}\r\n"));
    }
    if !req.body.is_empty() || matches!(req.method.as_str(), "POST" | "PUT") {
        out.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&req.body);
    s.write_all(&bytes).await.expect("write request");
    s.flush().await.expect("flush");

    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(r) = parse_response(&buf, &req.method) {
            return r;
        }
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    parse_response_eof(&buf).expect("complete HTTP response")
}

type Headers = Vec<(String, String)>;

fn split_head(buf: &[u8]) -> Option<(u16, Headers, usize)> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..end]).expect("utf8 head");
    let mut lines = head.split("\r\n");
    let status = lines.next()?.split(' ').nth(1)?.parse().ok()?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_owned(), v.trim().to_owned()))
        .collect();
    Some((status, headers, end + 4))
}

fn parse_response(buf: &[u8], method: &str) -> Option<HttpResponse> {
    let (status, headers, off) = split_head(buf)?;
    let r = HttpResponse {
        status,
        headers,
        body: Vec::new(),
    };
    if method == "HEAD" {
        return Some(r);
    }
    let len: usize = r.header("content-length")?.parse().ok()?;
    if buf.len() < off + len {
        return None;
    }
    Some(HttpResponse {
        body: buf[off..off + len].to_vec(),
        ..r
    })
}

fn parse_response_eof(buf: &[u8]) -> Option<HttpResponse> {
    let (status, headers, off) = split_head(buf)?;
    Some(HttpResponse {
        status,
        headers,
        body: buf[off..].to_vec(),
    })
}

fn percent(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// A running DPS built from a vector's `config`.
pub struct Harness {
    pub dir: tempfile::TempDir,
    pub upload_path: PathBuf,
    pub cert_db: PathBuf,
    pub tls: bool,
    pub pki: Option<Pki>,
    clients: HashMap<String, Client>,
    pub opts: DpsOptions,
    pub app: DpsApp,
    pub dps: Option<RunningDps>,
    pub addr: SocketAddr,
}

impl Harness {
    /// `config`: `{section: {key: value}}` as in the vectors.
    pub async fn new(config: &Value) -> Harness {
        let dir = tempfile::tempdir().expect("tmp");
        let root = dir.path().canonicalize().expect("canon");
        let upload_path = root.join("dp-user");
        std::fs::create_dir_all(upload_path.join("meta")).expect("mkdir");
        let cert_db = root.join("cert-db.txt");
        let mut sections: Vec<(String, Vec<(String, String)>)> = Vec::new();
        let mut set = |s: &str, k: &str, v: &str| {
            let idx = match sections.iter().position(|(n, _)| n == s) {
                Some(i) => i,
                None => {
                    sections.push((s.to_owned(), Vec::new()));
                    sections.len() - 1
                }
            };
            let kv = &mut sections[idx].1;
            kv.retain(|(kk, _)| kk != k);
            kv.push((k.to_owned(), v.to_owned()));
        };
        if let Some(m) = config.as_object() {
            for (s, kv) in m {
                for (k, v) in kv.as_object().expect("section object") {
                    set(s, k, v.as_str().expect("string value"));
                }
            }
        }
        set(
            "dp_server",
            "upload_path",
            upload_path.to_str().expect("utf8"),
        );
        let tls = config
            .pointer("/ssl/enabled")
            .and_then(Value::as_str)
            .is_some_and(|v| {
                matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on")
            });
        let pki = if tls {
            let pki = Pki::new();
            let w = |n: &str, body: &str| {
                let p = root.join(n);
                std::fs::write(&p, body).expect("write");
                p.to_str().expect("utf8").to_owned()
            };
            set("ssl", "ca", &w("ca.crt", &pki.ca_pem));
            set("ssl", "cert", &w("server.crt", &pki.server_pem));
            set("ssl", "key", &w("server.key", &pki.server_key_pem));
            set("ssl", "cert_db", cert_db.to_str().expect("utf8"));
            Some(pki)
        } else {
            None
        };
        let mut ini = String::new();
        for (s, kv) in &sections {
            ini.push_str(&format!("[{s}]\n"));
            for (k, v) in kv {
                ini.push_str(&format!("{k} = {v}\n"));
            }
        }
        let conf = root.join("taky.conf");
        std::fs::write(&conf, ini).expect("write conf");
        let cfg = taky_config::load_config_in(Some(&conf), true, &root).expect("config");
        let opts = DpsOptions {
            cfg: Arc::new(cfg),
            clock: SystemClock::shared(),
            shutdown: Shutdown::new(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let app = DpsApp::new(&opts).expect("app");
        let dps = taky_dps::start(opts.clone(), listener)
            .await
            .expect("start");
        Harness {
            addr: dps.local_addr,
            dir,
            upload_path,
            cert_db,
            tls,
            pki,
            clients: HashMap::new(),
            opts,
            app,
            dps: Some(dps),
        }
    }

    fn ensure_client(&mut self, cn: &str, revoked: bool) {
        if !self.clients.contains_key(cn) {
            let pki = self.pki.as_mut().expect("pki");
            let c = pki.client(cn);
            let mut db = taky_pki::CertDb::open(&self.cert_db).expect("cert-db");
            db.add(&c.cert).expect("add");
            if revoked {
                let serial = taky_pki::identity::identity_from_der(&c.cert)
                    .expect("id")
                    .serial;
                let now = chrono::Utc::now().naive_utc();
                db.revoke(&serial, now).expect("revoke");
            }
            self.clients.insert(cn.to_owned(), c);
        }
    }

    /// Send one request; `identity` = `(cn, revoked)` or none, `remote` = peer address override.
    pub async fn send(
        &mut self,
        mut req: HttpRequest,
        identity: Option<(&str, bool)>,
        remote: Option<IpAddr>,
    ) -> HttpResponse {
        if !self.tls {
            if let Some((cn, revoked)) = identity {
                req.headers.push(("X-USER".into(), cn.into()));
                if revoked {
                    req.headers.push(("X-REVOKED".into(), "1".into()));
                }
            }
        } else if let Some((cn, revoked)) = identity {
            self.ensure_client(cn, revoked);
        }
        let remote = remote.filter(|ip| !taky_dps::identity::is_loopback(*ip));
        let (client_io, server_io): (Box<dyn Io>, Option<tokio::io::DuplexStream>) = match remote {
            Some(_) => {
                let (a, b) = tokio::io::duplex(1 << 16);
                (Box::new(a), Some(b))
            }
            None => (
                Box::new(
                    tokio::net::TcpStream::connect(self.addr)
                        .await
                        .expect("connect"),
                ),
                None,
            ),
        };
        let serve = server_io.map(|io| {
            let app = self.app.clone();
            let peer = SocketAddr::new(remote.expect("remote"), 50000);
            tokio::spawn(async move { app.serve_connection(io, peer).await })
        });
        let resp = if self.tls {
            let client = identity.and_then(|(cn, _)| self.clients.get(cn));
            let conn = self.pki.as_ref().expect("pki").connector(client);
            let name = ServerName::try_from("localhost").expect("name");
            let s = conn.connect(name, client_io).await.expect("tls connect");
            roundtrip(s, &req).await
        } else {
            roundtrip(client_io, &req).await
        };
        if let Some(t) = serve {
            let _ = t.await;
        }
        resp
    }

    pub async fn stop(mut self) {
        self.opts.shutdown.trigger();
        if let Some(d) = self.dps.take() {
            d.join().await.expect("join");
        }
    }
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

fn str_field<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

/// Run a DPS vector (`rel` relative to the vector directory) against the Rust DPS.
pub async fn run_vector(rel: &str) {
    let vec: Value = serde_json::from_str(&taky_common::vectors::read_vector(rel)).expect("json");
    assert_eq!(vec["runner"], "dps", "{rel}: not a dps vector");
    assert_eq!(vec["format"], 2, "{rel}: unknown format");
    let id = vec["id"].as_str().unwrap_or(rel).to_owned();
    let base = str_field(&vec, "base_url").unwrap_or("https://taky.example:8443/");
    let host = base
        .split("://")
        .nth(1)
        .unwrap_or("")
        .trim_end_matches('/')
        .to_owned();
    let mut h = Harness::new(&vec["config"]).await;
    if let Some(files) = vec["initial_files"].as_object() {
        for (rel_path, spec) in files {
            write_file(&h.upload_path, rel_path, spec);
        }
    }
    for (i, step) in vec["steps"].as_array().expect("steps").iter().enumerate() {
        let r = &step["request"];
        let mut target = r["path"].as_str().expect("path").to_owned();
        if let Some(q) = r["query"].as_object() {
            let qs: Vec<String> = q
                .iter()
                .map(|(k, v)| format!("{}={}", percent(k), percent(v.as_str().expect("q"))))
                .collect();
            if !qs.is_empty() {
                target = format!("{target}?{}", qs.join("&"));
            }
        }
        let mut headers: Vec<(String, String)> = r["headers"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().expect("header").to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        let mut body = str_field(r, "body").unwrap_or("").as_bytes().to_vec();
        if let Some(parts) = r["multipart"].as_array() {
            let (ct, b) = encode_multipart(parts);
            headers.push(("Content-Type".into(), ct));
            body = b;
        }
        let req = HttpRequest {
            method: r["method"].as_str().expect("method").to_owned(),
            target,
            host: host.clone(),
            headers,
            body,
        };
        let identity = r["identity"].as_object().map(|o| {
            (
                o["cn"].as_str().expect("cn").to_owned(),
                o.get("revoked").and_then(Value::as_bool).unwrap_or(false),
            )
        });
        let remote = str_field(r, "remote_addr").map(|a| a.parse().expect("remote_addr"));
        let resp = h
            .send(
                req,
                identity.as_ref().map(|(c, rv)| (c.as_str(), *rv)),
                remote,
            )
            .await;
        let exp = step.get("rust_expect").unwrap_or(&step["expect"]);
        let up = h.upload_path.to_str().expect("utf8").to_owned();
        check(&format!("{id} step {}", i + 1), exp, &resp, &up);
    }
    let fin = vec.get("final_rust_expect").unwrap_or(&vec["final_expect"]);
    if let Some(files) = fin.get("files") {
        let got = snapshot_files(&h.upload_path);
        assert_eq!(
            &got, files,
            "{id}: final files (full snapshot of upload_path)"
        );
    }
    h.stop().await;
}

/// Werkzeug test client multipart encoding (`stream_encode_multipart`).
pub fn encode_multipart(parts: &[Value]) -> (String, Vec<u8>) {
    let boundary = "---------------WerkzeugFormPart_1761400000.1234567";
    let mut b = Vec::new();
    for p in parts {
        let name = p["name"].as_str().expect("name");
        let filename = p["filename"].as_str().expect("filename");
        let data = match str_field(p, "data_b64") {
            Some(x) => b64_decode(x),
            None => p["data"].as_str().expect("data").as_bytes().to_vec(),
        };
        let ct = match str_field(p, "content_type") {
            Some(c) => c.to_owned(),
            None => taky_dps::mimetypes::guess_type(filename)
                .ok()
                .and_then(|t| t.0)
                .unwrap_or_else(|| "application/octet-stream".into()),
        };
        b.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        b.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {ct}\r\n\r\n"
            )
            .as_bytes(),
        );
        b.extend_from_slice(&data);
        b.extend_from_slice(b"\r\n");
    }
    b.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), b)
}

pub fn b64_decode(s: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut n = 0;
    for c in s.bytes().filter(|c| *c != b'=' && !c.is_ascii_whitespace()) {
        let v = T.iter().position(|t| *t == c).expect("base64") as u32;
        acc = (acc << 6) | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
            acc &= (1 << n) - 1;
        }
    }
    out
}

pub fn b64_encode(der: &[u8]) -> String {
    pem_wrap("X", der)
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect()
}

/// `("SubmissionDateTime": ?")[^"]*(")` ⇒ `$TIMESTAMP` (Python runner `norm_text`).
pub fn norm_text(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("\"SubmissionDateTime\":") {
        let after = i + "\"SubmissionDateTime\":".len();
        let (sp, val_start) = if rest[after..].starts_with(" \"") {
            (true, after + 2)
        } else if rest[after..].starts_with('"') {
            (false, after + 1)
        } else {
            out.push_str(&rest[..after]);
            rest = &rest[after..];
            continue;
        };
        let Some(end) = rest[val_start..].find('"') else {
            break;
        };
        out.push_str(&rest[..i]);
        out.push_str(if sp {
            "\"SubmissionDateTime\": \"$TIMESTAMP\""
        } else {
            "\"SubmissionDateTime\":\"$TIMESTAMP\""
        });
        rest = &rest[val_start + end + 1..];
    }
    out.push_str(rest);
    out
}

/// Python runner `norm_json`.
pub fn norm_json(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| {
                    let x = if k == "SubmissionDateTime" {
                        Value::from("$TIMESTAMP")
                    } else {
                        norm_json(x)
                    };
                    (k.clone(), x)
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(norm_json).collect()),
        x => x.clone(),
    }
}

/// Python runner `snapshot_files`: every file and symlink under `root` (symlinked directories as
/// links, not descended), `{rel: {"content"|"content_b64"|"symlink_to": …}}`.
pub fn snapshot_files(root: &Path) -> Value {
    fn walk(root: &Path, dir: &Path, out: &mut serde_json::Map<String, Value>) {
        for e in std::fs::read_dir(dir).expect("read_dir") {
            let e = e.expect("entry");
            let p = e.path();
            let rel = p
                .strip_prefix(root)
                .expect("rel")
                .to_str()
                .expect("utf8")
                .to_owned();
            let ft = std::fs::symlink_metadata(&p).expect("lstat").file_type();
            if ft.is_symlink() {
                let t = std::fs::read_link(&p).expect("readlink");
                out.insert(
                    rel,
                    serde_json::json!({"symlink_to": t.to_str().expect("utf8")}),
                );
            } else if ft.is_dir() {
                walk(root, &p, out);
            } else {
                let data = std::fs::read(&p).expect("read");
                let v = match String::from_utf8(data) {
                    Ok(t) => serde_json::json!({"content": norm_text(&t)}),
                    Err(e) => serde_json::json!({"content_b64": b64_encode(e.as_bytes())}),
                };
                out.insert(rel, v);
            }
        }
    }
    let mut m = serde_json::Map::new();
    walk(root, root, &mut m);
    let mut entries: Vec<(String, Value)> = m.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Value::Object(entries.into_iter().collect())
}

fn check(ctx: &str, exp: &Value, r: &HttpResponse, upload_path: &str) {
    assert_eq!(
        Some(u64::from(r.status)),
        exp["status"].as_u64(),
        "{ctx}: status; body {:?}",
        String::from_utf8_lossy(&r.body)
    );
    if let Some(ct) = str_field(exp, "content_type") {
        assert_eq!(r.header("content-type"), Some(ct), "{ctx}: content type");
    }
    if let Some(b) = str_field(exp, "body") {
        let got = String::from_utf8_lossy(&r.body)
            .replace(&taky_dps::version_string(), "taky-$VERSION")
            .replace(upload_path, "$UPLOAD_PATH");
        assert_eq!(got, b, "{ctx}: body");
    }
    if let Some(b) = str_field(exp, "body_b64") {
        assert_eq!(r.body, b64_decode(b), "{ctx}: body_b64");
    }
    if let Some(j) = exp.get("body_json") {
        // `$VERSION` placeholder as in `body` (the version string has no JSON-special chars).
        let raw =
            String::from_utf8_lossy(&r.body).replace(&taky_dps::version_string(), "taky-$VERSION");
        let mut got = norm_json(&serde_json::from_str(&raw).expect("json body"));
        let mut want = j.clone();
        // `expect.unordered`: top-level body keys whose arrays come in `listdir` order (search),
        // which depends on the filesystem in Python and Rust alike ⇒ compared as multisets.
        for k in exp["unordered"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            for v in [&mut got, &mut want] {
                if let Some(Value::Array(a)) = v.get_mut(k) {
                    a.sort_by_key(Value::to_string);
                }
            }
        }
        assert_eq!(got, want, "{ctx}: body_json");
        assert!(r.body.ends_with(b"\n"), "{ctx}: jsonify trailing newline");
    }
    if exp.get("body_is_framework_page").and_then(Value::as_bool) == Some(true) {
        assert!(
            r.body.starts_with(b"<!doctype html>\n"),
            "{ctx}: framework page"
        );
    }
    if let Some(hs) = exp["headers"].as_object() {
        for (n, v) in hs {
            assert_eq!(r.header(n), v.as_str(), "{ctx}: header {n}");
        }
    }
}

fn write_file(root: &Path, rel: &str, spec: &Value) {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    if let Some(t) = str_field(spec, "symlink_to") {
        std::os::unix::fs::symlink(t, &p).expect("symlink");
    } else if let Some(c) = str_field(spec, "content") {
        std::fs::write(&p, c).expect("write");
    } else if let Some(c) = str_field(spec, "content_b64") {
        std::fs::write(&p, b64_decode(c)).expect("write");
    } else {
        panic!("unsupported initial file spec {spec}");
    }
}
