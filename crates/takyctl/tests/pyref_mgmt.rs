//! S-323: `takyctl-rs status` / `kickban` against the ORIGINAL ones (`taky/taky/cli` run from
//! the read-only source tree by `tests/pyref/takyctl.py`), each against a running Rust server
//! (`taky-rs`) **and** a running Python server (`tests/pyref/taky_cot.py`) on the same site:
//!
//! * kickban (SSL site with `alice` ×2, `bob`): all four CLI × server combinations print the
//!   same bytes (text and `-j`, big-int serials), the serials are the cert-db ones, cert-db ends
//!   with `R` for the banned names; a second kickban / unknown name → "Unable to find …";
//! * status (plain site, one identified + one anonymous TCP client): the same table / JSON
//!   after masking times; with only the anonymous client Python crashes (OQ-L3) and Rust
//!   prints an empty IP (D-17);
//! * errors without a server: missing socket, stale socket (ECONNREFUSED), `-U`, a config
//!   parse error, a server that closes without replying / replies garbage.
//!
//! Needs a Python with `cryptography` and `lxml` (`TAKY_PYREF_PYTHON`, else
//! `tools/pyref/.state/venv/bin/python`, else `python3`); otherwise skipped.
#![allow(clippy::expect_used, clippy::unwrap_used)] // test code

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn taky_root() -> PathBuf {
    manifest().join("../../../taky")
}

fn find_python() -> Option<PathBuf> {
    let mut cands = Vec::new();
    if let Some(p) = std::env::var_os("TAKY_PYREF_PYTHON") {
        cands.push(PathBuf::from(p));
    }
    cands.push(manifest().join("../../tools/pyref/.state/venv/bin/python"));
    cands.push(PathBuf::from("python3"));
    cands.into_iter().find(|py| {
        Command::new(py)
            .args(["-I", "-B", "-c", "import cryptography, lxml, pkg_resources"])
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

/// `taky-rs` next to `takyctl-rs` (built by the workspace test run); built on demand otherwise.
fn taky_rs_bin() -> PathBuf {
    let ctl = PathBuf::from(env!("CARGO_BIN_EXE_takyctl-rs"));
    let bin = ctl.with_file_name("taky-rs");
    if !bin.exists() {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let st = Command::new(cargo)
            .args(["build", "-p", "taky-server", "--bin", "taky-rs"])
            .current_dir(manifest())
            .status()
            .expect("cargo build taky-rs");
        assert!(st.success());
    }
    bin
}

#[derive(Debug, Clone, PartialEq)]
struct Out {
    rc: i32,
    stdout: String,
    stderr: String,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Lang {
    Rs,
    Py,
}

struct Env {
    python: PathBuf,
}

impl Env {
    fn ctl(&self, lang: Lang, cwd: &Path, args: &[&str]) -> Out {
        let mut c = match lang {
            Lang::Py => {
                let mut c = Command::new(&self.python);
                c.args(["-I", "-B", "-W", "ignore"])
                    .arg(manifest().join("tests/pyref/takyctl.py"))
                    .arg(taky_root());
                c
            }
            Lang::Rs => Command::new(env!("CARGO_BIN_EXE_takyctl-rs")),
        };
        c.args(args);
        let o = c.current_dir(cwd).env("TZ", "UTC").output().expect("spawn");
        let d = cwd.to_string_lossy();
        Out {
            rc: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).replace(&*d, "<D>"),
            stderr: String::from_utf8_lossy(&o.stderr).replace(&*d, "<D>"),
        }
    }

    /// Both CLIs; asserts equal output and returns it.
    fn both(&self, cwd: &Path, args: &[&str], mask: fn(&str) -> String) -> Out {
        let m = |o: Out| Out {
            stdout: mask(&o.stdout),
            ..o
        };
        let py = m(self.ctl(Lang::Py, cwd, args));
        let rs = m(self.ctl(Lang::Rs, cwd, args));
        assert_eq!(rs, py, "takyctl {args:?}");
        rs
    }

    fn server(&self, lang: Lang, site: &Path) -> Server {
        let mut c = match lang {
            Lang::Py => {
                let mut c = Command::new(&self.python);
                c.args(["-I", "-B", "-W", "ignore"])
                    .arg(manifest().join("tests/pyref/taky_cot.py"))
                    .arg(taky_root());
                c
            }
            Lang::Rs => Command::new(taky_rs_bin()),
        };
        let log = std::fs::File::create(site.join(format!("server-{lang:?}.log"))).unwrap();
        let child = c
            .args(["-c", "taky.conf", "-l", "info"])
            .current_dir(site)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("spawn server");
        let srv = Server {
            child,
            sock: site.join("taky-mgmt.sock"),
            port: port_of(site),
        };
        let t0 = Instant::now();
        loop {
            if mgmt(&srv.sock, &json!({"cmd": "ping"})).is_some()
                && TcpStream::connect(("127.0.0.1", srv.port)).is_ok()
            {
                // Python drops all CoT while a mgmt connection is registered (B3/V046, fixed
                // in Rust as D-9): let it reap the probe connection first.
                std::thread::sleep(Duration::from_millis(500));
                return srv;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(30),
                "{lang:?} server did not start: {}",
                std::fs::read_to_string(site.join(format!("server-{lang:?}.log"))).unwrap()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

struct Server {
    child: Child,
    sock: PathBuf,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(10) {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One mgmt request from the test itself (readiness / polling).
fn mgmt(sock: &Path, req: &Value) -> Option<Value> {
    let mut s = UnixStream::connect(sock).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let mut f = serde_json::to_vec(req).unwrap();
    f.push(0);
    s.write_all(&f).ok()?;
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    while !data.contains(&0) {
        let n = s.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(&buf[..n]);
    }
    data.pop();
    serde_json::from_slice(&data).ok()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn port_of(site: &Path) -> u16 {
    let conf = std::fs::read_to_string(site.join("taky.conf")).unwrap();
    let in_cot = conf.split("[cot_server]").nth(1).unwrap();
    in_cot
        .lines()
        .find_map(|l| l.strip_prefix("port = "))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// SSL site made by `takyctl-rs setup` + `build_client alice` ×2 + `bob`; listens on
/// 127.0.0.1:<free port>, monitor on another free port.
fn make_site(base: &Path, ssl: bool) -> PathBuf {
    let rs = env!("CARGO_BIN_EXE_takyctl-rs");
    let run = |args: &[&str], cwd: &Path| {
        let o = Command::new(rs)
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(o.status.success(), "{args:?}: {o:?}");
    };
    std::fs::create_dir_all(base).unwrap();
    run(
        &[
            "setup",
            "--public-ip",
            "127.0.0.1",
            "--host",
            "srv1",
            "site",
        ],
        base,
    );
    let site = base.join("site");
    for n in ["alice", "alice", "bob"] {
        run(&["-c", "site/taky.conf", "build_client", n], base);
    }
    let conf = std::fs::read_to_string(site.join("taky.conf")).unwrap();
    let conf = conf
        .replace("bind_ip = 0.0.0.0", "bind_ip = 127.0.0.1")
        .replace("port = 8089", &format!("port = {}", free_port()))
        .replace(
            "mon_ip\nmon_port\n",
            &format!("mon_ip = 127.0.0.1\nmon_port = {}\n", free_port()),
        );
    let conf = if ssl {
        conf
    } else {
        conf.replace("enabled = true", "enabled = false")
    };
    std::fs::write(site.join("taky.conf"), conf).unwrap();
    site
}

fn copy_site(from: &Path, to: &Path) -> PathBuf {
    std::fs::create_dir_all(to).unwrap();
    let st = Command::new("cp")
        .arg("-a")
        .arg(from)
        .arg(to)
        .status()
        .unwrap();
    assert!(st.success());
    to.join(from.file_name().unwrap())
}

fn cert_db(site: &Path) -> Vec<Vec<String>> {
    std::fs::read_to_string(site.join("ssl/cert-db.txt"))
        .unwrap()
        .lines()
        .map(|l| l.split('\t').map(str::to_owned).collect())
        .collect()
}

/// Masks `NNh NNm NN.NNNs` durations (with an optional `Nd ` prefix) as `<T>`.
fn mask_times(s: &str) -> String {
    let mut out = String::new();
    let b = s.as_bytes();
    let mut i = 0;
    let is_dur = |w: &[u8]| {
        w.len() >= 15
            && w[0..2].iter().all(u8::is_ascii_digit)
            && &w[2..4] == b"h "
            && w[4..6].iter().all(u8::is_ascii_digit)
            && &w[6..8] == b"m "
            && w[8..10].iter().all(u8::is_ascii_digit)
            && w[10] == b'.'
            && w[11..14].iter().all(u8::is_ascii_digit)
            && w[14] == b's'
    };
    while i < b.len() {
        if is_dur(&b[i..]) {
            out.push_str("<T>");
            i += 15;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

/// Masks every JSON float (`digits.digits[e±NN]`) as `<F>`.
fn mask_floats(s: &str) -> String {
    let b = s.as_bytes();
    let (mut out, mut i) = (String::new(), 0);
    while i < b.len() {
        if b[i].is_ascii_digit() && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) {
            let mut j = i;
            while j < b.len() && (b[j].is_ascii_digit() || b"._e+-".contains(&b[j])) {
                j += 1;
            }
            let tok = &s[i..j];
            if tok.contains('.') {
                out.push_str("<F>");
            } else {
                out.push_str(tok);
            }
            i = j;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

fn ident(s: &str) -> String {
    s.to_owned()
}

#[test]
fn kickban_rs_py_cross() {
    if !taky_root().join("taky/cli/__main__.py").exists() {
        eprintln!("SKIP pyref_mgmt: taky/ (original) not available");
        return;
    }
    let Some(python) = find_python() else {
        eprintln!("SKIP: no Python with cryptography+lxml");
        return;
    };
    let env = Env { python };
    let tmp = tempfile::tempdir().unwrap();
    let tpl = make_site(&tmp.path().join("tpl"), true);
    let db0 = cert_db(&tpl);
    let sns: Vec<&str> = db0
        .iter()
        .filter(|r| r[4] == "alice")
        .map(|r| r[3].as_str())
        .collect();
    assert_eq!(sns.len(), 2);
    let alice_text = format!(
        "Revoked certificate SNs for alice:\n - {}\n - {}\n",
        sns[0], sns[1]
    );

    let mut outputs: Vec<(String, Vec<Out>)> = Vec::new();
    for srv_lang in [Lang::Rs, Lang::Py] {
        for cli in [Lang::Rs, Lang::Py] {
            let label = format!("server {srv_lang:?} / cli {cli:?}");
            let site = copy_site(&tpl, &tmp.path().join(format!("{srv_lang:?}-{cli:?}")));
            let srv = env.server(srv_lang, &site);
            let cwd = site.parent().unwrap();
            let k = |args: &[&str]| env.ctl(cli, cwd, args);
            let outs = vec![
                k(&["-c", "site/taky.conf", "kickban", "alice"]),
                k(&["-c", "site/taky.conf", "kickban", "alice"]),
                k(&["-c", "site/taky.conf", "kickban", "-j", "bob"]),
                k(&["-c", "site/taky.conf", "kickban", "-j", "nobody"]),
                k(&["-c", "site/taky.conf", "kickban", "nobody"]),
                {
                    let mut o = k(&["-c", "site/taky.conf", "status"]);
                    o.stdout = mask_times(&o.stdout);
                    o
                },
                {
                    let mut o = k(&["-c", "site/taky.conf", "status", "-j"]);
                    o.stdout = mask_floats(&o.stdout);
                    o
                },
            ];
            drop(srv);
            assert_eq!(outs[0].stdout, alice_text, "{label}");
            assert_eq!(
                outs[1].stdout, "Unable to find certificates for user alice\n",
                "{label}"
            );
            assert_eq!(outs[3].stdout, "{\"revoked_sns\": []}\n", "{label}");
            assert_eq!(outs[5].stdout, "Uptime: <T>\nNum Clients: 0\n\n", "{label}");
            assert_eq!(
                outs[6].stdout, "{\"uptime\": <F>, \"num_clients\": 0, \"clients\": []}\n",
                "{label}"
            );
            for o in &outs {
                assert_eq!((o.rc, o.stderr.as_str()), (0, ""), "{label}: {o:?}");
            }
            let db = cert_db(&site);
            assert_eq!(db.len(), db0.len());
            for (a, b) in db.iter().zip(&db0) {
                let banned = ["alice", "bob"].contains(&a[4].as_str());
                assert_eq!(a[0], if banned { "R" } else { "V" }, "{label}: {a:?}");
                assert_eq!((&a[1], &a[3], &a[4]), (&b[1], &b[3], &b[4]), "{label}");
            }
            outputs.push((label, outs));
        }
    }
    // Same site copies ⇒ byte-identical outputs across all combinations (incl. the bob big int).
    let (l0, o0) = &outputs[0];
    let bob: Value = serde_json::from_str(&o0[2].stdout).unwrap();
    let bob_hex = db0.iter().find(|r| r[4] == "bob").unwrap()[3].clone();
    assert_eq!(
        takyctl::mgmt::hex040(&bob["revoked_sns"][0]).unwrap(),
        bob_hex
    );
    for (l, o) in &outputs[1..] {
        assert_eq!(o, o0, "{l} vs {l0}");
    }
}

const SA: &str = concat!(
    r#"<?xml version="1.0" standalone="yes"?><event version="2.0" uid="ANDROID-A" "#,
    r#"type="a-f-G-U-C" time="2026-10-26T00:00:00.000Z" start="2026-10-26T00:00:00.000Z" "#,
    r#"stale="2036-10-26T00:00:00.000Z" how="m-g"><point lat="1.0" lon="2.0" hae="0.0" "#,
    r#"ce="9.9" le="9.9"/><detail><contact callsign="ALPHA" endpoint="*:-1:stcp"/>"#,
    r#"<__group name="Cyan" role="Team Member"/><takv device="dev" platform="ATAK-CIV" "#,
    r#"os="29" version="4.5"/><track speed="0.0" course="0.0"/></detail></event>"#
);

fn wait_status(site: &Path, pred: impl Fn(&Value) -> bool) -> Value {
    let sock = &site.join("taky-mgmt.sock");
    let t0 = Instant::now();
    loop {
        let last = mgmt(sock, &json!({"cmd": "status"}));
        if let Some(v) = &last
            && pred(v)
        {
            return v.clone();
        }
        assert!(
            t0.elapsed() < Duration::from_secs(20),
            "status never matched: {last:?}; logs: {:?}",
            std::fs::read_dir(site)
                .unwrap()
                .filter_map(|e| {
                    let p = e.unwrap().path();
                    p.to_string_lossy()
                        .ends_with(".log")
                        .then(|| std::fs::read_to_string(p).unwrap())
                })
                .collect::<Vec<_>>()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn status_rs_py_cross() {
    if !taky_root().join("taky/cli/__main__.py").exists() {
        eprintln!("SKIP pyref_mgmt: taky/ (original) not available");
        return;
    }
    let Some(python) = find_python() else {
        eprintln!("SKIP: no Python with cryptography+lxml");
        return;
    };
    let env = Env { python };
    let tmp = tempfile::tempdir().unwrap();
    let tpl = make_site(&tmp.path().join("tpl"), false);
    let mut tables = Vec::new();
    for srv_lang in [Lang::Rs, Lang::Py] {
        let site = copy_site(&tpl, &tmp.path().join(format!("{srv_lang:?}")));
        let srv = env.server(srv_lang, &site);
        let cwd = site.parent().unwrap();

        let mut a = TcpStream::connect(("127.0.0.1", srv.port)).unwrap();
        let b = TcpStream::connect(("127.0.0.1", srv.port)).unwrap();
        // (Re)send the SA until the client is identified: Python drops an event that arrives
        // while a polling mgmt connection is still registered (B3, D-9 in Rust).
        let t0 = Instant::now();
        loop {
            a.write_all(SA.as_bytes()).unwrap();
            std::thread::sleep(Duration::from_millis(300));
            let v = wait_status(&site, |_| true);
            if v["num_clients"] == 2
                && v["clients"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|c| c["callsign"] == "ALPHA")
            {
                break;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(20),
                "not identified: {v:?}"
            );
            std::thread::sleep(Duration::from_millis(300));
        }

        let table = env.both(cwd, &["-c", "site/taky.conf", "status"], mask_times);
        assert_eq!(table.rc, 0);
        let mut lines: Vec<&str> = table.stdout.lines().collect();
        lines[5..].sort_unstable(); // client order follows the server's dict order
        assert_eq!(
            lines,
            [
                "Uptime: <T>",
                "Num Clients: 2",
                "",
                "Callsign    | UID         | Connected       | IP        | LastRx         ",
                "------------+-------------+-----------------+-----------+----------------",
                "(anonymous) | (anonymous) | <T> | None      | never          ",
                "ALPHA       | ANDROID-A   | <T> | 127.0.0.1 | <T>",
            ],
            "{srv_lang:?}"
        );
        let j = env.both(cwd, &["-c", "site/taky.conf", "status", "-j"], mask_floats);
        assert!(j.stdout.contains("\"callsign\": \"ALPHA\""), "{j:?}");
        tables.push(table);

        // Only the anonymous client left: Python crashes (OQ-L3), Rust prints an empty IP (D-17).
        drop(a);
        wait_status(&site, |v| v["num_clients"] == 1);
        let py = env.ctl(Lang::Py, cwd, &["-c", "site/taky.conf", "status"]);
        assert_eq!(py.rc, 1, "{py:?}");
        assert_eq!(
            py.stderr.lines().next(),
            Some("status failed: object of type 'NoneType' has no len()")
        );
        let rs = env.ctl(Lang::Rs, cwd, &["-c", "site/taky.conf", "status"]);
        assert_eq!(rs.rc, 0, "{rs:?}");
        assert_eq!(
            mask_times(&rs.stdout),
            "Uptime: <T>\nNum Clients: 1\n\n\
             Callsign    | UID         | Connected       | IP | LastRx\n\
             ------------+-------------+-----------------+----+-------\n\
             (anonymous) | (anonymous) | <T> |    | never \n"
        );
        drop(b);
        drop(srv);
    }
    assert_eq!(tables[0], tables[1], "Rust server vs Python server");
}

#[test]
fn errors_without_server() {
    if !taky_root().join("taky/cli/__main__.py").exists() {
        eprintln!("SKIP pyref_mgmt: taky/ (original) not available");
        return;
    }
    let Some(python) = find_python() else {
        eprintln!("SKIP: no Python with cryptography+lxml");
        return;
    };
    let env = Env { python };
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    std::fs::write(d.join("taky.conf"), "[taky]\nroot_dir = .\n").unwrap();
    std::fs::write(d.join("bad.conf"), "no section\n").unwrap();

    for cmd in [&["status"][..], &["kickban", "alice"]] {
        let a = |pre: &[&str]| -> Vec<String> {
            pre.iter()
                .map(|s| (*s).to_owned())
                .chain(cmd.iter().map(|s| (*s).to_owned()))
                .collect()
        };
        let run = |args: Vec<String>| {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            env.both(d, &args, ident)
        };
        // Missing socket (default path from root_dir).
        let o = run(a(&[]));
        assert_eq!(o.rc, 1);
        assert_eq!(
            o.stderr,
            "ERROR: Unable to connect to mgmt socket: <D>/taky-mgmt.sock\n       Is taky running?\n"
        );
        // Config parse error.
        let o = run(a(&["-c", "bad.conf"]));
        assert_eq!(o.rc, 1);
        assert!(
            o.stderr.starts_with("File contains no section headers."),
            "{o:?}"
        );
        // Stale socket file: ECONNREFUSED on stdout, hint on stderr; `-U` relative.
        drop(UnixListener::bind(d.join("stale.sock")).unwrap());
        let mut args = vec![
            "-c".to_owned(),
            "taky.conf".to_owned(),
            cmd[0].to_owned(),
            "-U".into(),
            "stale.sock".into(),
        ];
        args.extend(cmd[1..].iter().map(|s| (*s).to_owned()));
        let o = run(args);
        assert_eq!(
            (o.rc, o.stdout.as_str(), o.stderr.as_str()),
            (
                1,
                "ERROR: Socket error: [Errno 111] Connection refused\n",
                "       Is taky running?\n"
            )
        );
        std::fs::remove_file(d.join("stale.sock")).unwrap();
    }

    // A server that closes without a NUL, then one that replies garbage.
    for (reply, expect) in [
        (&b"{\"x\": 1}"[..], "ERROR: No response from server\n"),
        (
            b"\xff\x00",
            "ERROR: Invalid data in response: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte\n",
        ),
    ] {
        let sock = d.join("fake.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let reply = reply.to_vec();
        let t = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut s, _) = l.accept().unwrap();
                let mut buf = [0u8; 256];
                let _ = s.read(&mut buf).unwrap();
                s.write_all(&reply).unwrap();
            }
        });
        let o = env.both(d, &["status", "-U", "fake.sock"], ident);
        assert_eq!(
            (o.rc, o.stdout.as_str(), o.stderr.as_str()),
            (1, "", expect)
        );
        t.join().unwrap();
        std::fs::remove_file(&sock).unwrap();
    }
}
