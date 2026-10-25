//! S-321 done criterion (PKCS#12 part): cross-import between taky-pki `pkcs12` and the ORIGINAL
//! `taky/util/anc.py` (Python `cryptography`) / OpenSSL.
//!
//! * Python → Rust: every p12 made by `anc.make_cert` is parsed by `pkcs12::parse` (MAC,
//!   decryption, bags, friendly names, localKeyId), and re-encoding the same certificate, key and
//!   CA with the **salts taken from the Python file** gives the Python file **byte for byte**.
//! * Rust → Python/OpenSSL: p12 files from `pkcs12::make_cert_p12` load with
//!   `pkcs12.load_key_and_certificates` / `load_pkcs12` and with `openssl pkcs12` (OpenSSL 3,
//!   **without `-legacy`**: 3DES and HMAC-SHA1 are in the default provider); `openssl pkcs12
//!   -info` output is identical to the Python file's after masking key material.
//!
//! Needs `openssl` and a Python with `cryptography` (env `TAKY_PYREF_PYTHON`, else
//! `tools/pyref/.state/venv/bin/python`, else `python3`); otherwise skipped with a note. Python
//! runs with `-I -B` (nothing is written into `taky/`) and `TZ=UTC`.
#![cfg(feature = "gen")]
#![allow(clippy::expect_used)] // test helpers outside #[test] fns

use std::path::{Path, PathBuf};
use std::process::Command;

use rsa::pkcs1::DecodeRsaPrivateKey;
use rustls_pki_types::PrivateKeyDer;
use sha1::{Digest, Sha1};
use taky_pki::certgen::{self, CertAuthority, CertKind, KeyCert};
use taky_pki::pkcs12::{self, P12Cert, P12Input};

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn anc_py() -> PathBuf {
    manifest().join("../../../taky/taky/util/anc.py")
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
            .args(["-I", "-B", "-c", "import cryptography"])
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

fn have_openssl() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().expect("spawn");
    assert!(
        out.status.success(),
        "{cmd:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // OpenSSL prints a BMPString friendlyName as Latin-1 bytes: not always UTF-8.
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn py_cmd(py: &Path, script: &str) -> Command {
    let mut c = Command::new(py);
    c.args(["-I", "-B", "-W", "ignore"])
        .arg(manifest().join("tests/pyref").join(script))
        .env("TZ", "UTC");
    c
}

/// A test case: a p12 made by `anc.make_cert(path, f_name, hostname, pw, …)`.
struct Case {
    f_name: &'static str,
    host: &'static str,
    pw: &'static str,
    kind: CertKind,
    key: bool,
}

const CASES: &[Case] = &[
    Case {
        f_name: "JENNY",
        host: "JENNY",
        pw: "atakatak",
        kind: CertKind::Client,
        key: true,
    },
    Case {
        f_name: "server",
        host: "taky.local",
        pw: "atakatak",
        kind: CertKind::Server,
        key: false,
    },
    // Non-ASCII / non-BMP friendlyName and password (UTF-16 surrogates in both).
    Case {
        f_name: "odd",
        host: "Ünï 😀",
        pw: "pä😀",
        kind: CertKind::Client,
        key: true,
    },
    // >= 64 characters: empty subject, friendlyName is still the hostname.
    Case {
        f_name: "srvlong",
        host: "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh",
        pw: "x",
        kind: CertKind::Server,
        key: false,
    },
];

fn kind_str(k: CertKind) -> &'static str {
    match k {
        CertKind::Server => "server",
        CertKind::Client => "client",
    }
}

fn first_cert(path: &Path) -> Vec<u8> {
    taky_pki::pem::load_certs(path).expect("crt")[0]
        .as_ref()
        .to_vec()
}

fn key_cert(dir: &Path, f_name: &str) -> KeyCert {
    let key = match taky_pki::pem::load_private_key(&dir.join(format!("{f_name}.key")), None)
        .expect("key")
    {
        PrivateKeyDer::Pkcs1(k) => {
            rsa::RsaPrivateKey::from_pkcs1_der(k.secret_pkcs1_der()).expect("pkcs1")
        }
        other => panic!("anc.py writes PKCS#1 keys, got {other:?}"),
    };
    KeyCert {
        cert_der: first_cert(&dir.join(format!("{f_name}.crt"))),
        key,
    }
}

/// `openssl pkcs12 -info -nodes` (no `-legacy`) with base64 blocks and localKeyID hex masked.
fn openssl_info(p12: &Path, pw: &str) -> String {
    let out = run(Command::new("openssl")
        .args(["pkcs12", "-info", "-nodes", "-passin", "env:P12PW", "-in"])
        .arg(p12)
        .env("P12PW", pw));
    let mut norm = Vec::new();
    for l in out.lines() {
        let t = l.trim();
        if t.starts_with("localKeyID:") {
            norm.push("    localKeyID: <HEX>".to_owned());
        } else if !t.is_empty()
            && !t.starts_with("-----")
            && !t.contains(' ')
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
        {
            if norm.last().map(String::as_str) != Some("<B64>") {
                norm.push("<B64>".into());
            }
        } else {
            norm.push(l.trim_end().to_owned());
        }
    }
    norm.join("\n")
}

/// `openssl pkcs12 -info -noout`: the algorithm/iteration summary.
fn openssl_algs(p12: &Path, pw: &str) -> String {
    let out = Command::new("openssl")
        .args(["pkcs12", "-info", "-noout", "-passin", "env:P12PW", "-in"])
        .arg(p12)
        .env("P12PW", pw)
        .output()
        .expect("openssl");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // OpenSSL prints the summary on stderr.
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn python_load(py: &Path, p12: &Path, pw: &str) -> serde_json::Value {
    let out = run(py_cmd(py, "load_p12.py").arg(p12).arg(pw));
    serde_json::from_str(&out).expect("json")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn check_parsed(p: &pkcs12::Pfx, case: &Case, cert: &[u8], ca: &[u8], key: Option<&[u8]>) {
    assert_eq!(p.mac_iterations, pkcs12::MAC_ITERATIONS);
    assert_eq!(p.mac_salt.len(), pkcs12::SALT_LEN);
    assert_eq!(p.safes.len(), if case.key { 2 } else { 1 });
    let enc = p.safes[0].pbe.as_ref().expect("certs are encrypted");
    assert_eq!((enc.iterations, enc.salt.len()), (1, 8));
    let bags: Vec<_> = p.bags().collect();
    assert_eq!(bags.len(), if case.key { 3 } else { 2 });
    assert!(bags[0].is_cert() && bags[1].is_cert());
    assert_eq!(bags[0].value, cert);
    assert_eq!(bags[1].value, ca);
    assert_eq!(bags[0].friendly_name().as_deref(), Some(case.host));
    assert_eq!(bags[1].friendly_name().as_deref(), Some("CA"));
    assert_eq!(bags[1].local_key_id(), None);
    let lkid = Sha1::digest(cert).to_vec();
    if case.key {
        assert_eq!(bags[0].local_key_id(), Some(lkid.clone()));
        assert!(p.safes[1].pbe.is_none(), "key safe is plain data");
        assert!(bags[2].is_key());
        let kp = bags[2].pbe.as_ref().expect("shrouded");
        assert_eq!((kp.iterations, kp.salt.len()), (1, 8));
        assert_eq!(Some(bags[2].value.as_slice()), key);
        assert_eq!(bags[2].friendly_name().as_deref(), Some(case.host));
        assert_eq!(bags[2].local_key_id(), Some(lkid));
    } else {
        assert_eq!(bags[0].local_key_id(), None);
    }
}

#[test]
fn p12_cross_import_with_python_and_openssl() {
    if !anc_py().exists() || !have_openssl() {
        eprintln!("SKIP pyref_p12: taky/taky/util/anc.py or openssl not available");
        return;
    }
    let Some(py) = find_python() else {
        eprintln!(
            "SKIP pyref_p12: no Python with `cryptography` (set TAKY_PYREF_PYTHON or run \
             tools/pyref/venv.sh)"
        );
        return;
    };
    let tmp = tempfile::tempdir().expect("tmp");
    let (pyd, rsd) = (tmp.path().join("py"), tmp.path().join("rs"));
    std::fs::create_dir_all(&pyd).expect("mkdir");
    std::fs::create_dir_all(&rsd).expect("mkdir");

    // Python: CA + one p12 per case (original anc.make_cert).
    run(py_cmd(&py, "gen_certs.py")
        .arg(anc_py())
        .arg("full")
        .arg(&pyd));
    for c in CASES {
        run(py_cmd(&py, "gen_certs.py")
            .arg(anc_py())
            .arg("p12")
            .arg(pyd.join("ca.crt"))
            .arg(pyd.join("ca.key"))
            .arg(&pyd)
            .arg(c.f_name)
            .arg(c.host)
            .arg(c.pw)
            .arg(kind_str(c.kind))
            .arg(if c.key { "1" } else { "0" }));
    }
    let py_ca = first_cert(&pyd.join("ca.crt"));

    // Rust: own CA; the same cases via make_cert_p12. One key for all (keygen is slow in debug).
    let now = chrono::Utc::now().naive_utc();
    let ca_kc = certgen::make_ca(now, certgen::CA_YEARS).expect("ca");
    certgen::write_certificate(&rsd.join("ca.crt"), &rsd.join("ca.key"), &ca_kc).expect("ca");
    let rs_ca = CertAuthority::load(&rsd.join("ca.crt"), &rsd.join("ca.key")).expect("ca");
    let key = certgen::generate_key().expect("key");

    for c in CASES {
        let what = c.f_name;
        // --- Python → Rust reader, and byte-exact re-encoding with the Python salts.
        let py_p12_path = pyd.join(format!("{}.p12", c.f_name));
        let py_p12 = std::fs::read(&py_p12_path).expect("py p12");
        let kc = key_cert(&pyd, c.f_name);
        let pk8 = kc.key_pkcs8_der().expect("pkcs8");
        let parsed = pkcs12::parse(&py_p12, c.pw).expect("Rust reads the Python p12");
        check_parsed(&parsed, c, &kc.cert_der, &py_ca, Some(&pk8));
        assert!(pkcs12::parse(&py_p12, "wrong").is_err());
        let cas = [P12Cert {
            der: &py_ca,
            friendly_name: Some("CA"),
        }];
        let input = P12Input {
            name: Some(c.host),
            key_pkcs8: c.key.then_some(pk8.as_slice()),
            cert: &kc.cert_der,
            cas: &cas,
        };
        let salts = parsed.salts().expect("salts");
        let again = pkcs12::serialize_with_salts(&input, c.pw, &salts).expect("encode");
        assert!(
            again == py_p12,
            "{what}: Rust re-encoding differs from the Python p12\npy: {}\nrs: {}",
            hex(&py_p12),
            hex(&again)
        );

        // --- Rust → Python / OpenSSL.
        let rs_kc = certgen::make_cert_with_key(
            &rs_ca,
            c.host,
            now,
            certgen::CERT_YEARS,
            c.kind,
            key.clone(),
        )
        .expect("cert");
        let rs_p12 = pkcs12::make_cert_p12(&rs_kc, &rs_ca, c.host, c.key, c.pw).expect("p12");
        let rs_path = rsd.join(format!("{}.p12", c.f_name));
        pkcs12::write_p12(&rs_path, &rs_p12, c.key).expect("write");
        let rs_pk8 = rs_kc.key_pkcs8_der().expect("pkcs8");
        check_parsed(
            &pkcs12::parse(&rs_p12, c.pw).expect("parse"),
            c,
            &rs_kc.cert_der,
            rs_ca.cert_der(),
            Some(&rs_pk8),
        );

        let j = python_load(&py, &rs_path, c.pw);
        assert_eq!(j["has_key"], c.key, "{what}: {j}");
        assert_eq!(j["key_matches_cert"], c.key, "{what}: {j}");
        if c.key {
            assert_eq!(j["key_pkcs8"], hex(&rs_pk8), "{what}");
        }
        // cryptography returns None for a non-BMP friendlyName (for its own files too).
        let bmp = c.host.chars().all(|ch| u32::from(ch) < 0x10000);
        let host_name = if bmp {
            serde_json::json!(c.host)
        } else {
            serde_json::Value::Null
        };
        if c.key {
            assert_eq!(j["cert"], hex(&rs_kc.cert_der), "{what}");
            assert_eq!(j["cert_name"], host_name, "{what}");
            assert_eq!(
                j["cas"],
                serde_json::json!([hex(rs_ca.cert_der())]),
                "{what}"
            );
            assert_eq!(j["ca_names"], serde_json::json!(["CA"]), "{what}");
        } else {
            // No key ⇒ no "main" certificate: both certificates come back in `cas`.
            assert_eq!(j["cert"], serde_json::Value::Null, "{what}");
            assert_eq!(
                j["cas"],
                serde_json::json!([hex(&rs_kc.cert_der), hex(rs_ca.cert_der())]),
                "{what}"
            );
            assert_eq!(
                j["ca_names"],
                serde_json::json!([host_name, "CA"]),
                "{what}"
            );
        }
        // The Python file gives the same answer shape.
        let pj = python_load(&py, &py_p12_path, c.pw);
        for k in ["has_key", "key_matches_cert", "cert_name", "ca_names"] {
            assert_eq!(j[k], pj[k], "{what}: {k}");
        }

        let algs = openssl_algs(&rs_path, c.pw);
        assert_eq!(algs, openssl_algs(&py_p12_path, c.pw), "{what}");
        assert!(algs.contains("MAC: sha1, Iteration 2048"), "{algs}");
        assert!(
            algs.contains("PKCS7 Encrypted data: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 1"),
            "{algs}"
        );
        assert_eq!(
            algs.contains("Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 1"),
            c.key
        );
        let (pi, ri) = (
            openssl_info(&py_p12_path, c.pw),
            openssl_info(&rs_path, c.pw),
        );
        assert_eq!(pi, ri, "{what}: openssl pkcs12 -info differs");
        if c.f_name == "JENNY" {
            eprintln!("normalised `openssl pkcs12 -info -nodes` (JENNY):\n{ri}");
            assert!(ri.contains("friendlyName: JENNY") && ri.contains("friendlyName: CA"));
        }
    }

    // A p12 with a key is written 0600 (D-19; Python: per umask).
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode(&rsd.join("JENNY.p12")), 0o600);
}
