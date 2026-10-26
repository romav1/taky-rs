//! S-322 done criterion: `takyctl-rs setup` and `build_client` produce the same layout as the
//! ORIGINAL `takyctl` (`taky/taky/cli/__main__.py` run from the read-only source tree by
//! `tests/pyref/takyctl.py`), each run in its own temp dir with the same arguments:
//!
//! * exit code, stdout and stderr (temp dir prefix masked; for the "failed" path only the
//!   first stderr line — Python adds a traceback);
//! * the file tree: names (UUIDs masked), type, mode bits, owner — except the ADR-003 cert-db
//!   lock file `cert-db.txt.lock` that only Rust creates (OQ-C3, accepted);
//! * `taky.conf` byte for byte; `cert-db.txt` line shape (dates/serial masked);
//! * certificates: subject, issuer, BC/KU/EKU/SAN (`openssl x509`), `openssl verify`, PKCS#1 key;
//!   `server.p12` / client p12 structure (`taky_pki::pkcs12::parse`);
//! * the client ZIP (via Python `zipfile`): names, every header field, modes (client p12: 0600
//!   in Rust, D-19), `preference.pref` / `manifest.xml` after masking UUIDs, the server p12 entry
//!   equal to the site's `server.p12`;
//! * cross use (R1): Rust `build_client` on a Python site and Python on a Rust site.
//!
//! Needs a Python with `cryptography` and `lxml` (`TAKY_PYREF_PYTHON`, else
//! `tools/pyref/.state/venv/bin/python`, else `python3`) and `openssl`; otherwise skipped.
#![allow(clippy::expect_used, clippy::unwrap_used)] // test code

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use taky_pki::pkcs12;

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

#[derive(Debug, Clone, PartialEq)]
struct Out {
    rc: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    /// First stderr line (the `"<cmd> failed: <exc>"` line; the rest is a traceback in Python).
    fn err1(&self) -> &str {
        self.stderr.lines().next().unwrap_or("")
    }
}

struct Env {
    python: PathBuf,
}

impl Env {
    fn py(&self, cwd: &Path, args: &[&str]) -> Out {
        let mut c = Command::new(&self.python);
        c.args(["-I", "-B", "-W", "ignore"])
            .arg(manifest().join("tests/pyref/takyctl.py"))
            .arg(taky_root())
            .args(args);
        run(c, cwd)
    }

    fn rs(&self, cwd: &Path, args: &[&str]) -> Out {
        let mut c = Command::new(env!("CARGO_BIN_EXE_takyctl-rs"));
        c.args(args);
        run(c, cwd)
    }

    /// Runs `args` in `<base>/py` and `<base>/rs` (fresh dirs); outputs with the dir masked.
    fn both(&self, base: &Path, args: &[&str]) -> (Out, Out) {
        let (pd, rd) = (base.join("py"), base.join("rs"));
        std::fs::create_dir_all(&pd).unwrap();
        std::fs::create_dir_all(&rd).unwrap();
        (
            mask_dir(self.py(&pd, args), &pd),
            mask_dir(self.rs(&rd, args), &rd),
        )
    }
}

fn run(mut c: Command, cwd: &Path) -> Out {
    let o = c.current_dir(cwd).env("TZ", "UTC").output().expect("spawn");
    Out {
        rc: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn mask_dir(mut o: Out, d: &Path) -> Out {
    let d = d.to_string_lossy();
    o.stdout = o.stdout.replace(&*d, "<D>");
    o.stderr = o.stderr.replace(&*d, "<D>");
    o
}

/// Replaces every 8-4-4-4-12 hex UUID with `<uuid>`.
fn mask_uuid(s: &str) -> String {
    let b = s.as_bytes();
    let is_uuid = |w: &[u8]| {
        w.len() == 36
            && w.iter().enumerate().all(|(i, c)| match i {
                8 | 13 | 18 | 23 => *c == b'-',
                _ => c.is_ascii_hexdigit(),
            })
    };
    let (mut out, mut i) = (String::new(), 0);
    while i < b.len() {
        if i + 36 <= b.len() && is_uuid(&b[i..i + 36]) {
            out.push_str("<uuid>");
            i += 36;
        } else {
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// `relpath kind mode uid:gid` for everything under `root`, sorted; `*.lock` skipped.
fn tree(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let m = std::fs::symlink_metadata(&p).unwrap();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            if rel.ends_with(".lock") {
                continue;
            }
            let kind = if m.is_dir() { "d" } else { "f" };
            out.push(format!(
                "{} {kind} {:o} {}:{}",
                mask_uuid(&rel),
                m.mode() & 0o7777,
                m.uid(),
                m.gid()
            ));
            if m.is_dir() {
                walk(root, &p, out);
            }
        }
    }
    let mut v = Vec::new();
    if root.exists() {
        walk(root, root, &mut v);
    }
    v.sort();
    v
}

/// Rust tree with the D-19 difference undone: a dumped client p12 (`<name>-<uuid>.p12` outside
/// `ssl/`) is 0600 in Rust, 0644 in Python. Asserts that Rust really wrote 0600.
fn d19(t: Vec<String>) -> Vec<String> {
    t.into_iter()
        .map(|e| {
            if e.contains("-<uuid>.p12 f ") && !e.starts_with("ssl/") {
                assert!(e.contains(".p12 f 600 "), "D-19: {e}");
                e.replace(".p12 f 600 ", ".p12 f 644 ")
            } else {
                e
            }
        })
        .collect()
}

fn openssl(args: &[&str]) -> String {
    let o = Command::new("openssl")
        .args(args)
        .output()
        .expect("openssl");
    assert!(
        o.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn cert_fields(crt: &Path) -> String {
    openssl(&[
        "x509",
        "-noout",
        "-subject",
        "-issuer",
        "-ext",
        "basicConstraints,keyUsage,extendedKeyUsage,subjectAltName",
        "-in",
        crt.to_str().unwrap(),
    ])
}

fn verify(ca: &Path, crt: &Path) {
    let out = openssl(&[
        "verify",
        "-CAfile",
        ca.to_str().unwrap(),
        crt.to_str().unwrap(),
    ]);
    assert!(out.trim_end().ends_with(": OK"), "{out}");
}

fn key_ok(key: &Path) {
    let pem = std::fs::read_to_string(key).unwrap();
    assert!(
        pem.starts_with("-----BEGIN RSA PRIVATE KEY-----\n"),
        "{key:?}"
    );
    openssl(&["rsa", "-check", "-noout", "-in", key.to_str().unwrap()]);
}

/// cert-db lines with dates and serial masked.
fn cert_db_shape(p: &Path) -> Vec<String> {
    std::fs::read_to_string(p)
        .unwrap()
        .lines()
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 5, "{l}");
            assert!(taky_pki::certdb::fromisoformat(f[1]).is_some(), "{l}");
            assert!(taky_pki::certdb::fromisoformat(f[2]).is_some(), "{l}");
            assert!(f[3].chars().all(|c| c.is_ascii_hexdigit()), "{l}");
            format!("{}\t<issued>\t<expires>\t<serial>\t{}", f[0], f[4])
        })
        .collect()
}

/// A p12 reduced to what does not depend on the random key / certificate.
fn p12_shape(der: &[u8], pw: &str, ca: &[u8]) -> String {
    use sha1::Digest;
    let p = pkcs12::parse(der, pw).expect("p12");
    let bags: Vec<_> = p.bags().collect();
    let cert = bags.iter().find(|b| b.is_cert()).unwrap().value.clone();
    let mut out = format!("mac_iter={} safes={}", p.mac_iterations, p.safes.len());
    for b in &bags {
        out.push_str(&format!(
            "\n bag cert={} key={} name={:?} lkid={:?} ca={} enc={:?}",
            b.is_cert(),
            b.is_key(),
            b.friendly_name(),
            b.local_key_id()
                .map(|k| k == sha1::Sha1::digest(&cert).to_vec()),
            b.value == ca,
            b.pbe.as_ref().map(|e| (e.iterations, e.salt.len()))
        ));
    }
    out
}

fn ca_der(site: &Path) -> Vec<u8> {
    let pem = std::fs::read_to_string(site.join("ssl/ca.crt")).unwrap();
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64_decode(&b64)
}

fn base64_decode(s: &str) -> Vec<u8> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut n) = (0u32, 0);
    for c in s.bytes().filter(|c| *c != b'=') {
        acc = (acc << 6) | T.iter().position(|t| *t == c).unwrap() as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
        }
    }
    out
}

fn zipinfo(python: &Path, zip: &Path) -> Value {
    let o = Command::new(python)
        .args(["-I", "-B"])
        .arg(manifest().join("tests/pyref/zipinfo.py"))
        .arg(zip)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    serde_json::from_slice(&o.stdout).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Compares two client ZIPs; returns the client p12 bytes (py, rs).
#[allow(clippy::too_many_arguments)]
fn compare_zip(
    python: &Path,
    pz: &Path,
    rz: &Path,
    psite: &Path,
    rsite: &Path,
    pw: &str,
    what: &str,
) {
    let (pi, ri) = (zipinfo(python, pz), zipinfo(python, rz));
    assert_eq!(pi["comment"], ri["comment"], "{what}");
    let sorted = |v: &Value| {
        let mut e: Vec<(String, Value)> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (mask_uuid(e["filename"].as_str().unwrap()), e.clone()))
            .collect();
        e.sort_by(|a, b| a.0.cmp(&b.0));
        e
    };
    let (pe, re) = (sorted(&pi), sorted(&ri));
    assert_eq!(
        pe.iter().map(|e| &e.0).collect::<Vec<_>>(),
        re.iter().map(|e| &e.0).collect::<Vec<_>>(),
        "{what}: entry names"
    );
    for ((name, p), (_, r)) in pe.iter().zip(&re) {
        for k in [
            "is_dir",
            "compress_type",
            "create_system",
            "create_version",
            "extract_version",
            "flag_bits",
            "internal_attr",
            "extra",
            "comment",
        ] {
            assert_eq!(p[k], r[k], "{what}: {name}: {k}");
        }
        let data = |e: &Value| unhex(e["data"].as_str().unwrap());
        let is_client = name.ends_with(".p12") && !name.contains("server-");
        if is_client {
            assert_eq!(p["external_attr"], 0o100644u64 << 16, "{what}: py client");
            assert_eq!(r["external_attr"], 0o100600u64 << 16, "{what}: D-19");
            assert_eq!(
                p12_shape(&data(p), pw, &ca_der(psite)),
                p12_shape(&data(r), pw, &ca_der(rsite)),
                "{what}: client p12"
            );
        } else {
            assert_eq!(p["external_attr"], r["external_attr"], "{what}: {name}");
            if name.contains("server-") {
                assert_eq!(
                    data(p),
                    std::fs::read(psite.join("ssl/server.p12")).unwrap()
                );
                assert_eq!(
                    data(r),
                    std::fs::read(rsite.join("ssl/server.p12")).unwrap()
                );
            } else {
                let text = |e: &Value| mask_uuid(&String::from_utf8(data(e)).unwrap());
                assert_eq!(text(p), text(r), "{what}: {name}");
            }
        }
    }
}

const SITE_ARGS: &[&str] = &[
    "setup",
    "--public-ip",
    "10.0.0.5",
    "--host",
    "srv1",
    "--user",
    "root",
    "site",
];

fn check_ssl_site(psite: &Path, rsite: &Path) {
    assert_eq!(tree(psite), tree(rsite), "site tree");
    assert!(rsite.join("ssl/cert-db.txt.lock").exists());
    assert_eq!(
        std::fs::read(psite.join("taky.conf")).unwrap(),
        std::fs::read(rsite.join("taky.conf")).unwrap()
    );
    for site in [psite, rsite] {
        verify(&site.join("ssl/ca.crt"), &site.join("ssl/server.crt"));
        verify(&site.join("ssl/ca.crt"), &site.join("ssl/ca.crt"));
        key_ok(&site.join("ssl/ca.key"));
        key_ok(&site.join("ssl/server.key"));
    }
    for f in ["ca.crt", "server.crt"] {
        assert_eq!(
            cert_fields(&psite.join("ssl").join(f)),
            cert_fields(&rsite.join("ssl").join(f)),
            "{f}"
        );
    }
    let shape = |s: &Path| {
        p12_shape(
            &std::fs::read(s.join("ssl/server.p12")).unwrap(),
            "atakatak",
            &ca_der(s),
        )
    };
    assert_eq!(shape(psite), shape(rsite));
    assert!(!shape(rsite).contains("key=true"), "server.p12 has no key");
    assert_eq!(
        cert_db_shape(&psite.join("ssl/cert-db.txt")),
        vec!["V\t<issued>\t<expires>\t<serial>\tsrv1"]
    );
    assert_eq!(
        cert_db_shape(&psite.join("ssl/cert-db.txt")),
        cert_db_shape(&rsite.join("ssl/cert-db.txt"))
    );
}

#[test]
fn setup_and_build_client_match_python_takyctl() {
    if !taky_root().join("taky/cli/__main__.py").exists() {
        eprintln!("SKIP pyref_cli: taky/ (original) not available");
        return;
    }
    let Some(python) = find_python() else {
        eprintln!("SKIP pyref_cli: no Python with cryptography + lxml (tools/pyref/venv.sh)");
        return;
    };
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("SKIP pyref_cli: openssl not available");
        return;
    }
    let env = Env {
        python: python.clone(),
    };
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();

    // 1. SSL site with --user (root: chown is exercised, owners compared).
    let (p, r) = env.both(&t.join("ssl"), SITE_ARGS);
    eprintln!("setup stdout (rust):\n{}", r.stdout);
    assert_eq!(p, r, "setup ssl");
    assert_eq!(p.rc, 0);
    assert!(r.stdout.ends_with(" - Changing ownership to root\n"));
    let (psite, rsite) = (t.join("ssl/py/site"), t.join("ssl/rs/site"));
    check_ssl_site(&psite, &rsite);

    // Same path again: refused.
    let (p, r) = (
        mask_dir(env.py(&t.join("ssl/py"), SITE_ARGS), &t.join("ssl/py")),
        mask_dir(env.rs(&t.join("ssl/rs"), SITE_ARGS), &t.join("ssl/rs")),
    );
    assert_eq!(p, r, "existing dir");
    assert_eq!(
        (r.rc, r.stderr.as_str()),
        (1, "ERROR: Directory exists, refusing to run setup\n")
    );

    // 2. build_client in the site (./taky.conf), ATAK, --dump_pem.
    let bc = ["build_client", "--dump_pem", "JENNY"];
    let (p, r) = (env.py(&psite, &bc), env.rs(&rsite, &bc));
    assert_eq!(p, r, "build_client atak");
    assert_eq!((r.rc, r.stdout.as_str(), r.stderr.as_str()), (0, "", ""));
    assert_eq!(
        tree(&psite),
        d19(tree(&rsite)),
        "site tree after build_client"
    );
    compare_zip(
        &python,
        &psite.join("JENNY.zip"),
        &rsite.join("JENNY.zip"),
        &psite,
        &rsite,
        "atakatak",
        "atak",
    );
    for site in [&psite, &rsite] {
        let crt = std::fs::read_dir(site)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "crt"))
            .unwrap();
        verify(&site.join("ssl/ca.crt"), &crt);
        key_ok(&crt.with_extension("key"));
    }
    let dumped = |s: &Path| {
        let crt = std::fs::read_dir(s)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "crt"))
            .unwrap();
        cert_fields(&crt)
    };
    assert_eq!(dumped(&psite), dumped(&rsite));
    assert_eq!(
        cert_db_shape(&rsite.join("ssl/cert-db.txt")),
        cert_db_shape(&psite.join("ssl/cert-db.txt"))
    );

    // 3. -c from the parent dir, iTAK, other password: zip lands in the cwd.
    let (pp, rp) = (t.join("ssl/py"), t.join("ssl/rs"));
    let bc = [
        "-c",
        "site/taky.conf",
        "build_client",
        "--is_itak",
        "--p12_pw",
        "pw2",
        "BOB",
    ];
    let (p, r) = (env.py(&pp, &bc), env.rs(&rp, &bc));
    assert_eq!(p, r, "build_client itak");
    assert_eq!(r.rc, 0);
    compare_zip(
        &python,
        &pp.join("BOB.zip"),
        &rp.join("BOB.zip"),
        &psite,
        &rsite,
        "pw2",
        "itak",
    );
    let db = cert_db_shape(&rsite.join("ssl/cert-db.txt"));
    assert_eq!(db, cert_db_shape(&psite.join("ssl/cert-db.txt")));
    assert_eq!(db.len(), 3);
    assert!(
        db[1].ends_with("\tJENNY") && db[2].ends_with("\tBOB"),
        "{db:?}"
    );

    // 4. Cross use (R1): each implementation issues a client on the other's site.
    let bc = ["build_client", "--dump_pem", "CROSS"];
    assert_eq!(env.rs(&psite, &bc).rc, 0, "rust on python site");
    assert_eq!(env.py(&rsite, &bc).rc, 0, "python on rust site");
    for site in [&psite, &rsite] {
        let crt = std::fs::read_dir(site)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("CROSS-")
                    && p.extension().is_some_and(|e| e == "crt")
            })
            .unwrap();
        verify(&site.join("ssl/ca.crt"), &crt);
        assert!(cert_db_shape(&site.join("ssl/cert-db.txt"))[3].ends_with("\tCROSS"));
    }
    // CROSS was dumped by the other implementation on each side.
    let no_cross = |t: Vec<String>| -> Vec<String> {
        t.into_iter().filter(|e| !e.starts_with("CROSS-")).collect()
    };
    assert_eq!(
        no_cross(tree(&psite)),
        d19(no_cross(tree(&rsite))),
        "site tree after cross"
    );

    // 5. build_client errors: '/' in the name; config not found (defaults ⇒ /etc/taky/...).
    let bc = ["build_client", "a/b"];
    let before = std::fs::read(rsite.join("ssl/cert-db.txt")).unwrap();
    let (p, r) = (env.py(&psite, &bc), env.rs(&rsite, &bc));
    assert_eq!((p.rc, r.rc), (1, 1), "{p:?} {r:?}");
    assert!(
        r.err1()
            .starts_with("build_client failed: invalid client name 'a/b'")
    );
    assert_eq!(
        std::fs::read(rsite.join("ssl/cert-db.txt")).unwrap(),
        before
    );
    if !Path::new("/etc/taky").exists() {
        let (p, r) = env.both(&t.join("nocfg"), &["-c", "none.conf", "build_client", "X"]);
        assert_eq!((p.rc, p.err1()), (r.rc, r.err1()), "missing config");
        assert_eq!(
            r.err1(),
            "build_client failed: [Errno 2] No such file or directory: '/etc/taky/ssl/server.p12'"
        );
    }

    // Config parse errors are printed as-is (exit 1); a ValueError takes the failed path.
    for (i, text) in ["garbage\n", "[cot_server]\nport = 99999\n"]
        .iter()
        .enumerate()
    {
        let base = t.join(format!("badcfg{i}"));
        for side in ["py", "rs"] {
            std::fs::create_dir_all(base.join(side)).unwrap();
            std::fs::write(base.join(side).join("bad.conf"), text).unwrap();
        }
        let (p, r) = (
            mask_dir(
                env.py(&base.join("py"), &["-c", "bad.conf", "build_client", "X"]),
                &base.join("py"),
            ),
            mask_dir(
                env.rs(&base.join("rs"), &["-c", "bad.conf", "build_client", "X"]),
                &base.join("rs"),
            ),
        );
        eprintln!("bad config {text:?}: py {:?} | rs {:?}", p.stderr, r.err1());
        assert_eq!((p.rc, p.err1()), (r.rc, r.err1()), "{text:?}");
        if i == 0 {
            assert_eq!(p, r, "{text:?}");
        }
    }

    // 6. --no-ssl site: no certificates; build_client then fails on ./ssl/server.p12.
    let args = [
        "setup",
        "--no-ssl",
        "--bind-ip",
        "127.0.0.1",
        "--p12_pw",
        "x",
        "--public-ip",
        "192.0.2.7",
        "--host",
        "nossl.example",
        "s2",
    ];
    let (p, r) = env.both(&t.join("nossl"), &args);
    assert_eq!(p, r, "setup --no-ssl");
    let (ps, rs) = (t.join("nossl/py/s2"), t.join("nossl/rs/s2"));
    assert_eq!(tree(&ps), tree(&rs));
    assert_eq!(
        std::fs::read(ps.join("taky.conf")).unwrap(),
        std::fs::read(rs.join("taky.conf")).unwrap()
    );
    let (p, r) = (
        env.py(&ps, &["build_client", "X"]),
        env.rs(&rs, &["build_client", "X"]),
    );
    assert_eq!((p.rc, p.err1()), (r.rc, r.err1()), "no-ssl build_client");
    assert_eq!(
        r.err1(),
        "build_client failed: [Errno 2] No such file or directory: './ssl/server.p12'"
    );

    // 7. setup failure paths: same exit code, first stderr line, stdout and leftover tree.
    let long = "h".repeat(64);
    let cases: Vec<Vec<&str>> = vec![
        vec!["setup", "--public-ip", "1.2.3.4", "--p12_pw", "a%b", "s"],
        vec![
            "setup",
            "--public-ip",
            "1.2.3.4",
            "--user",
            "no-such-user-x",
            "s",
        ],
        vec!["setup", "--public-ip", "1.2.3.4", "--host", &long, "s"],
        vec!["setup", "--public-ip", "1.2.3.4", "--host", "bäd", "s"],
        vec!["setup", "--public-ip", "1.2.3.4", "--p12_pw", "", "s"],
        vec!["setup", "--public-ip", "1.2.3.4", "no/such/parent"],
    ];
    for (i, args) in cases.iter().enumerate() {
        let base = t.join(format!("fail{i}"));
        let (p, r) = env.both(&base, args);
        eprintln!("case {args:?}: py {:?} | rs {:?}", p.err1(), r.err1());
        assert_eq!(
            (p.rc, &p.stdout, p.err1()),
            (r.rc, &r.stdout, r.err1()),
            "{args:?}"
        );
        assert_eq!(p.rc, 1, "{args:?}");
        assert_eq!(tree(&base.join("py")), tree(&base.join("rs")), "{args:?}");
    }

    // 8. argparse: --public-ip is required (exit 2).
    let (p, r) = env.both(&t.join("argp"), &["setup"]);
    assert_eq!((p.rc, r.rc), (2, 2));
}
