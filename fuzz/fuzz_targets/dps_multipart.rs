//! `dps_multipart` (S-407): the DPS request path end to end — HTTP/1.1 parsing (hyper), Werkzeug
//! query/option-header ports, axum `Multipart` + `datapackage::upload`, `/Marti/vcm` (parse_element,
//! D-1), metadata `tool` PUT and `TracksKML` — through the public `DpsApp::serve_connection` over an
//! in-memory duplex from a loopback peer (plain mode, `X-USER` trusted, G-6).
//! The multipart parser and Werkzeug helpers are private to taky-dps, so this is the only public way in.
//!
//! Input: `data[0] % 4` selects the endpoint; the bytes up to the first `\n` are the query string
//! (or, for `/Marti/api/sync/metadata/{hash}/tool`, the hash), the rest is the body. Multipart bodies
//! use the boundary `taky` (seeds are encoded the way the Werkzeug test client does).
//! Invariants: no panic (a panic in the handler aborts the process); the connection always ends
//! with a well-formed HTTP status line.
#![no_main]
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use taky_common::{Shutdown, SystemClock};
use taky_dps::{DpsApp, DpsOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Env {
    rt: tokio::runtime::Runtime,
    app: DpsApp,
    upload: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

fn env() -> &'static Env {
    static E: OnceLock<Env> = OnceLock::new();
    E.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let root = dir.path().to_path_buf();
        let upload = root.join("upload");
        std::fs::create_dir_all(upload.join("meta")).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let conf = root.join("taky.conf");
        let ini = format!(
            "[taky]\nroot_dir = {r}\n[ssl]\nenabled = false\n[dp_server]\nupload_path = {u}\n",
            r = root.display(),
            u = upload.display()
        );
        std::fs::write(&conf, ini).unwrap_or_else(|e| panic!("conf: {e}"));
        let cfg = taky_config::load_config_in(Some(&conf), true, &root)
            .unwrap_or_else(|e| panic!("config: {e}"));
        let opts = DpsOptions {
            cfg: Arc::new(cfg),
            clock: SystemClock::shared(),
            shutdown: Shutdown::new(),
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|e| panic!("runtime: {e}"));
        let app = rt
            .block_on(async { DpsApp::new(&opts) })
            .unwrap_or_else(|e| panic!("app: {e}"));
        Env {
            rt,
            app,
            upload,
            _dir: dir,
        }
    })
}

fn request(data: &[u8]) -> Vec<u8> {
    let (sel, rest) = data.split_first().map_or((0, &[][..]), |(a, b)| (*a, b));
    let (q, body) = match rest.iter().position(|b| *b == b'\n') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, &[][..]),
    };
    // The request target must stay a single line: drop CR/LF/space from the fuzzed part.
    let q: String = String::from_utf8_lossy(q)
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .collect();
    let (method, target, ctype) = match sel % 4 {
        0 => (
            "POST",
            format!("/Marti/sync/missionupload?{q}"),
            "multipart/form-data; boundary=taky",
        ),
        1 => ("POST", format!("/Marti/vcm?{q}"), "application/xml"),
        2 => (
            "PUT",
            format!(
                "/Marti/api/sync/metadata/{}/tool",
                if q.is_empty() { "h" } else { &q }
            ),
            "text/plain",
        ),
        _ => (
            "POST",
            format!("/Marti/TracksKML?{q}"),
            "application/x-www-form-urlencoded",
        ),
    };
    let mut out = format!(
        "{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-USER: fuzz\r\n\
         Content-Type: {ctype}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fuzz_target!(|data: &[u8]| {
    static N: AtomicU64 = AtomicU64::new(0);
    let e = env();
    if N.fetch_add(1, Ordering::Relaxed) % 1000 == 999 {
        let _ = std::fs::remove_dir_all(&e.upload);
        let _ = std::fs::create_dir_all(e.upload.join("meta"));
    }
    let req = request(data);
    let peer: SocketAddr = ([127, 0, 0, 1], 40000).into();
    let resp = e.rt.block_on(async {
        let (mut cli, srv) = tokio::io::duplex(1 << 16);
        let client = async move {
            let _ = cli.write_all(&req).await;
            let _ = cli.flush().await;
            let mut buf = Vec::new();
            let _ = cli.read_to_end(&mut buf).await;
            buf
        };
        let (_, buf) = tokio::join!(e.app.serve_connection(srv, peer), client);
        buf
    });
    assert!(
        resp.starts_with(b"HTTP/1.1 ")
            && resp.len() >= 12
            && resp[9..12].iter().all(u8::is_ascii_digit),
        "malformed/no response: {:?}",
        String::from_utf8_lossy(&resp[..resp.len().min(200)])
    );
});
