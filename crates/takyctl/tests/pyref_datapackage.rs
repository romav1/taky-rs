//! S-321 done criterion (data package part): the client package built by `takyctl::datapackage`
//! is identical to the one the ORIGINAL `takyctl build_client` writes
//! (`taky/taky/cli/build_client_cmd.py` run from the read-only source tree by
//! `tests/pyref/build_client.py`), compared through Python's own `zipfile` view
//! (`tests/pyref/zipinfo.py`):
//!
//! * the same entry names (Python's order is `os.walk` order — not normative — so names are
//!   compared as sets; ours is manifest first, then manifest `Contents` order);
//! * every ZipInfo header field equal (compression, create/extract version, system, flags, extra,
//!   comments, `external_attr`) — except the client p12 mode: 0600 in Rust (D-19), 0644 in Python;
//! * `manifest.xml`, `preference.pref` and the server p12 byte-for-byte (same UUIDs as Python);
//! * the client p12 (new certificate, so not byte-comparable): same PKCS#12 structure, names,
//!   CA certificate and localKeyId rule (via `taky_pki::pkcs12::parse`).
//!
//! Needs a Python with `cryptography` and `lxml` (env `TAKY_PYREF_PYTHON`, else
//! `tools/pyref/.state/venv/bin/python`, else `python3`); otherwise skipped with a note.
//! Python runs with `-I -B` and `TZ=UTC`.
#![allow(clippy::expect_used, clippy::unwrap_used)] // test code

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use taky_pki::certgen::{self, CertAuthority, CertKind};
use taky_pki::pkcs12;
use takyctl::datapackage::{ClientPackage, write_zip};

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn taky_pkg() -> PathBuf {
    manifest().join("../../../taky/taky")
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
            .args(["-I", "-B", "-c", "import cryptography, lxml"])
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().expect("spawn");
    assert!(
        out.status.success(),
        "{cmd:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8")
}

fn py(py: &Path, script: &Path) -> Command {
    let mut c = Command::new(py);
    c.args(["-I", "-B", "-W", "ignore"])
        .arg(script)
        .env("TZ", "UTC")
        .current_dir(std::env::temp_dir());
    c
}

fn zipinfo(python: &Path, zip: &Path) -> Value {
    let out = run(py(python, &manifest().join("tests/pyref/zipinfo.py")).arg(zip));
    serde_json::from_str(&out).expect("json")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// `<prefix><uuid><suffix>` among the entry names.
fn uuid_in(names: &[String], prefix: &str, suffix: &str) -> uuid::Uuid {
    let n = names
        .iter()
        .find(|n| n.starts_with(prefix) && n.ends_with(suffix))
        .unwrap_or_else(|| panic!("no {prefix}*{suffix} in {names:?}"));
    uuid::Uuid::parse_str(&n[prefix.len()..n.len() - suffix.len()]).expect("uuid")
}

struct Variant {
    tag: &'static str,
    is_itak: bool,
    name: &'static str,
    p12_pw: &'static str,
    hostname: &'static str,
    public_ip: Option<&'static str>,
    ssl: bool,
    port: Option<i64>,
    server_p12_pw: &'static str,
}

const VARIANTS: &[Variant] = &[
    Variant {
        tag: "atak",
        is_itak: false,
        name: "JENNY",
        p12_pw: "atakatak",
        hostname: "taky.local",
        public_ip: Some("192.0.2.1"),
        ssl: true,
        port: None,
        server_p12_pw: "atakatak",
    },
    Variant {
        tag: "itak",
        is_itak: true,
        name: "JENNY",
        p12_pw: "atakatak",
        hostname: "taky.local",
        public_ip: Some("192.0.2.1"),
        ssl: true,
        port: None,
        server_p12_pw: "atakatak",
    },
    // public_ip unset ⇒ "None:…" (QUIRK); tcp; explicit port; XML escaping and non-ASCII.
    Variant {
        tag: "quirks",
        is_itak: false,
        name: "BOB",
        p12_pw: "pä",
        hostname: "Ünï&<x>",
        public_ip: None,
        ssl: false,
        port: Some(1234),
        server_p12_pw: "s3cr&t\"",
    },
];

fn write_conf(dir: &Path, v: &Variant, certs: &Path) -> PathBuf {
    let mut s = format!("[taky]\nhostname = {}\n", v.hostname);
    if let Some(ip) = v.public_ip {
        s.push_str(&format!("public_ip = {ip}\n"));
    }
    if let Some(p) = v.port {
        s.push_str(&format!("[cot_server]\nport = {p}\n"));
    }
    s.push_str(&format!(
        "[ssl]\nenabled = {}\nca = {c}/ca.crt\nca_key = {c}/ca.key\nserver_p12 = {c}/server.p12\n\
         server_p12_pw = {}\ncert_db = {d}/cert-db.txt\n",
        if v.ssl { "true" } else { "false" },
        v.server_p12_pw,
        c = certs.display(),
        d = dir.display()
    ));
    let p = dir.join("taky.conf");
    std::fs::write(&p, s).expect("conf");
    p
}

fn by_name(info: &Value) -> Vec<(String, Value)> {
    let mut v: Vec<(String, Value)> = info["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| (e["filename"].as_str().expect("name").to_owned(), e.clone()))
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

/// The client p12 reduced to what does not depend on the (random) certificate and key.
fn p12_shape(der: &[u8], pw: &str, ca: &[u8]) -> String {
    let p = pkcs12::parse(der, pw).expect("client p12");
    let bags: Vec<_> = p.bags().collect();
    let cert = &bags[0].value;
    let mut out = format!("mac_iter={} safes={}", p.mac_iterations, p.safes.len());
    for b in &bags {
        out.push_str(&format!(
            "\n bag cert={} key={} name={:?} lkid={} ca={} enc={:?}",
            b.is_cert(),
            b.is_key(),
            b.friendly_name(),
            match b.local_key_id() {
                None => "none".to_owned(),
                Some(k) => {
                    use sha1::Digest;
                    (k == sha1::Sha1::digest(cert).to_vec()).to_string()
                }
            },
            b.value == ca,
            b.pbe.as_ref().map(|e| (e.iterations, e.salt.len()))
        ));
    }
    out
}

#[test]
fn client_package_matches_python_build_client() {
    if !taky_pkg().join("cli/build_client_cmd.py").exists() {
        eprintln!("SKIP pyref_datapackage: taky/taky (original) not available");
        return;
    }
    let Some(python) = find_python() else {
        eprintln!(
            "SKIP pyref_datapackage: no Python with `cryptography` and `lxml` (set \
             TAKY_PYREF_PYTHON or run tools/pyref/venv.sh)"
        );
        return;
    };
    let tmp = tempfile::tempdir().expect("tmp");
    let certs = tmp.path().join("certs");
    std::fs::create_dir_all(&certs).expect("mkdir");
    // CA + server.p12 by the original anc.py (S-320 helper).
    run(py(
        &python,
        &manifest().join("../taky-pki/tests/pyref/gen_certs.py"),
    )
    .arg(taky_pkg().join("util/anc.py"))
    .arg("full")
    .arg(&certs));
    let server_p12 = std::fs::read(certs.join("server.p12")).expect("server.p12");
    let ca = CertAuthority::load(&certs.join("ca.crt"), &certs.join("ca.key")).expect("ca");
    let key = certgen::generate_key().expect("key");
    let now = chrono::Utc::now().naive_utc();

    for v in VARIANTS {
        let what = v.tag;
        let (pyd, rsd) = (
            tmp.path().join(format!("py-{what}")),
            tmp.path().join(format!("rs-{what}")),
        );
        std::fs::create_dir_all(&pyd).expect("mkdir");
        std::fs::create_dir_all(&rsd).expect("mkdir");
        let conf = write_conf(&pyd, v, &certs);
        run(py(&python, &manifest().join("tests/pyref/build_client.py"))
            .arg(taky_pkg())
            .arg(&conf)
            .arg(&pyd)
            .arg(v.name)
            .arg(if v.is_itak { "1" } else { "0" })
            .arg(v.p12_pw));
        let py_zip = pyd.join(format!("{}.zip", v.name));
        let py_info = zipinfo(&python, &py_zip);
        let py_entries = by_name(&py_info);
        let names: Vec<String> = py_entries.iter().map(|e| e.0.clone()).collect();
        let dir = if v.is_itak { "" } else { "certs/" };
        let server_uuid = uuid_in(&names, &format!("{dir}server-"), ".p12");
        let client_uuid = uuid_in(&names, &format!("{dir}{}-", v.name), ".p12");
        let manifest_uid = if v.is_itak {
            uuid::Uuid::nil()
        } else {
            let m = py_entries
                .iter()
                .find(|e| e.0 == "MANIFEST/manifest.xml")
                .expect("manifest");
            let text = String::from_utf8(unhex(m.1["data"].as_str().unwrap())).expect("u8");
            let start = text.find("name=\"uid\" value=\"").expect("uid") + 18;
            uuid::Uuid::parse_str(&text[start..start + 36]).expect("uid")
        };

        // Rust: same inputs, same UUIDs.
        let client = certgen::make_cert_with_key(
            &ca,
            v.name,
            now,
            certgen::CERT_YEARS,
            CertKind::Client,
            key.clone(),
        )
        .expect("client cert");
        let client_p12 =
            pkcs12::make_cert_p12(&client, &ca, v.name, true, v.p12_pw).expect("client p12");
        let pkg = ClientPackage {
            is_itak: v.is_itak,
            hostname: Some(v.hostname.to_owned()),
            public_ip: v.public_ip.map(str::to_owned),
            port: v.port.unwrap_or(if v.ssl { 8089 } else { 8087 }),
            ssl_enabled: v.ssl,
            server_p12_pw: Some(v.server_p12_pw.to_owned()),
            p12_pw: v.p12_pw.to_owned(),
            server_p12_name: takyctl::datapackage::server_p12_pkg_name(&server_uuid),
            client_pkg_name: takyctl::datapackage::client_pkg_name(v.name, &client_uuid),
            manifest_uid,
        };
        let entries = pkg
            .entries(server_p12.clone(), client_p12)
            .expect("entries");
        let rs_zip = rsd.join(format!("{}.zip", v.name));
        write_zip(&rs_zip, &entries).expect("zip");
        let rs_info = zipinfo(&python, &rs_zip);
        let rs_entries = by_name(&rs_info);

        // Archive order (Rust): manifest first, then Contents order.
        let rs_order: Vec<&str> = rs_info["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["filename"].as_str().unwrap())
            .collect();
        eprintln!(
            "{what}: python order {:?}\n{what}: rust order   {rs_order:?}",
            py_info["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["filename"].as_str().unwrap())
                .collect::<Vec<_>>()
        );
        assert_eq!(py_info["comment"], rs_info["comment"], "{what}");
        assert_eq!(
            names,
            rs_entries.iter().map(|e| e.0.clone()).collect::<Vec<_>>(),
            "{what}: entry names"
        );
        assert_eq!(names.len(), if v.is_itak { 3 } else { 4 });

        let client_name = format!("{dir}{}-{client_uuid}.p12", v.name);
        for ((name, pe), (_, re)) in py_entries.iter().zip(&rs_entries) {
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
                assert_eq!(pe[k], re[k], "{what}: {name}: {k}");
            }
            let dt = |e: &Value| e["date_time"][0].as_i64().unwrap();
            assert!((dt(pe) - dt(re)).abs() <= 1, "{what}: {name}: date_time");
            if *name == client_name {
                assert_eq!(
                    pe["external_attr"],
                    (0o100644u64 << 16),
                    "{what}: py client mode"
                );
                assert_eq!(
                    re["external_attr"],
                    (0o100600u64 << 16),
                    "{what}: rs client mode (D-19)"
                );
                let ca_der = ca.cert_der();
                let shape =
                    |e: &Value| p12_shape(&unhex(e["data"].as_str().unwrap()), v.p12_pw, ca_der);
                let (ps, rs) = (shape(pe), shape(re));
                assert_eq!(ps, rs, "{what}: client p12 structure");
                assert!(ps.contains(&format!("name={:?}", Some(v.name))), "{ps}");
            } else {
                assert_eq!(
                    pe["external_attr"], re["external_attr"],
                    "{what}: {name}: mode"
                );
                assert_eq!(pe["file_size"], re["file_size"], "{what}: {name}: size");
                if pe["data"] != re["data"] {
                    panic!(
                        "{what}: {name} differs\n--- python ---\n{}\n--- rust ---\n{}",
                        String::from_utf8_lossy(&unhex(pe["data"].as_str().unwrap())),
                        String::from_utf8_lossy(&unhex(re["data"].as_str().unwrap()))
                    );
                }
            }
        }
        if v.tag == "quirks" {
            let pref = rs_entries
                .iter()
                .find(|e| e.0.ends_with("preference.pref"))
                .unwrap();
            let pref = String::from_utf8(unhex(pref.1["data"].as_str().unwrap())).unwrap();
            assert!(pref.contains(">None:1234:tcp<"), "{pref}");
            assert!(pref.contains(">&#220;n&#239;&amp;&lt;x&gt;<"), "{pref}");
        }
    }
}
