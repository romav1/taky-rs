//! S-803 (ub01 P0-2): native behaviour tests for `takyctl-rs build_client` — no Python
//! original, no openssl needed (one extra check runs only where `openssl` exists).
//!
//! Each test makes a fresh site with `takyctl-rs setup` in a temp dir, then runs
//! `build_client` the way a user does — argv parsed by `takyctl::cli`, then the public entry
//! point `takyctl::build_client::build_client` (or the binary, for exit codes and stderr) — and
//! checks what the user gets: the ZIP (names, layout, modes, `preference.pref`,
//! `manifest.xml`), the client p12 (opens with the password, key + cert + CA), the cert-db
//! line, the `--dump_pem` files, and the error text / exit code of each failure branch.
//! Pins the behaviour as of S-803; the oracle for parity with Python is `pyref_cli.rs`.
#![allow(clippy::expect_used, clippy::unwrap_used)] // test code

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{NaiveDate, NaiveDateTime, TimeDelta};
use taky_common::testenv::{Prereq, prereq};
use taky_pki::pkcs12;
use takyctl::cli::{self, Command as Cmd};

const BIN: &str = env!("CARGO_BIN_EXE_takyctl-rs");

/// A fixed clock: the certificate dates in the cert-db follow from it.
fn now() -> NaiveDateTime {
    NaiveDate::from_ymd_opt(2026, 11, 13)
        .unwrap()
        .and_hms_opt(12, 0, 0)
        .unwrap()
}

/// `takyctl-rs <args>` in `cwd`: (exit code, stdout, stderr).
fn bin(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let o = Command::new(BIN)
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn");
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// A site made by `setup` (`<tmp>/site`, public IP 10.0.0.5, host srv1, SSL).
struct Site {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
}

impl Site {
    fn new() -> Site {
        let tmp = tempfile::tempdir().unwrap();
        let (rc, _, err) = bin(
            tmp.path(),
            &["setup", "--public-ip", "10.0.0.5", "--host", "srv1", "site"],
        );
        assert_eq!(rc, 0, "setup: {err}");
        let dir = tmp.path().join("site");
        Site { _tmp: tmp, dir }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }

    fn cert_db(&self) -> String {
        std::fs::read_to_string(self.path("ssl/cert-db.txt")).unwrap()
    }

    /// Replaces `from` with `to` in `taky.conf` (must be present).
    fn edit_conf(&self, from: &str, to: &str) {
        let p = self.path("taky.conf");
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(s.contains(from), "{from:?} not in taky.conf");
        std::fs::write(&p, s.replacen(from, to, 1)).unwrap();
    }
}

/// Result of one library call: `Ok(rc)` / `Err(text)` (the "build_client failed" path), stderr.
struct Run {
    res: Result<u8, String>,
    err: String,
}

/// Parses `argv` (after `takyctl-rs`) like the binary and calls `build_client` in `cwd`.
fn call(cwd: &Path, argv: &[&str]) -> Run {
    let args =
        cli::try_parse_from(std::iter::once("takyctl-rs").chain(argv.iter().copied())).unwrap();
    let Some(Cmd::BuildClient(a)) = args.command.as_ref() else {
        panic!("not build_client: {argv:?}");
    };
    let mut err = Vec::new();
    let res =
        takyctl::build_client::build_client(a, args.cfg_file.as_deref(), cwd, now(), &mut err)
            .map_err(|e| e.to_string());
    Run {
        res,
        err: String::from_utf8(err).unwrap(),
    }
}

fn ok(cwd: &Path, argv: &[&str]) {
    let r = call(cwd, argv);
    assert_eq!((r.res, r.err.as_str()), (Ok(0), ""), "{argv:?}");
}

fn failed(cwd: &Path, argv: &[&str]) -> String {
    let r = call(cwd, argv);
    assert_eq!(r.err, "", "nothing printed on the failed path");
    r.res.expect_err("expected the failed path")
}

/// One ZIP entry as the user sees it.
#[derive(Debug)]
struct Entry {
    name: String,
    mode: u32,
    data: Vec<u8>,
}

fn read_zip(p: &Path) -> Vec<Entry> {
    let mut z = zip::ZipArchive::new(std::fs::File::open(p).unwrap()).unwrap();
    (0..z.len())
        .map(|i| {
            let mut f = z.by_index(i).unwrap();
            assert_eq!(f.compression(), zip::CompressionMethod::Deflated);
            assert!(f.is_file());
            let mut data = Vec::new();
            f.read_to_end(&mut data).unwrap();
            Entry {
                name: f.name().unwrap().into_owned(),
                mode: f.unix_mode().unwrap() & 0o7777,
                data,
            }
        })
        .collect()
}

fn is_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|u| u.get_version_num() == 4 && s.len() == 36)
}

/// `<prefix><uuid4><suffix>` → the uuid.
fn uuid_in<'a>(s: &'a str, prefix: &str, suffix: &str) -> &'a str {
    let u = s
        .strip_prefix(prefix)
        .and_then(|r| r.strip_suffix(suffix))
        .unwrap_or_else(|| panic!("{s:?} is not {prefix}<uuid>{suffix}"));
    assert!(is_uuid(u), "{u:?} in {s:?}");
    u
}

fn text(e: &Entry) -> String {
    String::from_utf8(e.data.clone()).unwrap()
}

fn umask_mode() -> u32 {
    0o666 & !takyctl::fsutil::current_umask()
}

/// The expected `preference.pref`; `loc` = `caLocation`/`certificateLocation` prefix.
fn pref(conn: &str, atak: bool, server_p12: &str, client_p12: &str, pw: &str) -> String {
    let (widget, loc) = if atak {
        (
            "\n    <entry key=\"displayServerConnectionWidget\" class=\"class java.lang.Boolean\">true</entry>",
            "/storage/emulated/0/atak/cert/",
        )
    } else {
        ("", "cert/")
    };
    format!(
        "<?xml version='1.0' encoding='ASCII' standalone='yes'?>
<preferences>
  <preference version=\"1\" name=\"cot_streams\">
    <entry key=\"count\" class=\"class java.lang.Integer\">1</entry>
    <entry key=\"description0\" class=\"class java.lang.String\">srv1</entry>
    <entry key=\"enabled0\" class=\"class java.lang.Boolean\">false</entry>
    <entry key=\"connectString0\" class=\"class java.lang.String\">{conn}</entry>
  </preference>
  <preference version=\"1\" name=\"com.atakmap.app_preferences\">{widget}
    <entry key=\"caLocation\" class=\"class java.lang.String\">{loc}{server_p12}</entry>
    <entry key=\"caPassword\" class=\"class java.lang.String\">atakatak</entry>
    <entry key=\"clientPassword\" class=\"class java.lang.String\">{pw}</entry>
    <entry key=\"certificateLocation\" class=\"class java.lang.String\">{loc}{client_p12}</entry>
  </preference>
</preferences>
"
    )
}

/// Splits a cert-db line into its 5 TAB fields (the line must end in `\n`).
fn fields(line: &str) -> [String; 5] {
    let f: Vec<String> = line.split('\t').map(str::to_owned).collect();
    f.try_into()
        .unwrap_or_else(|f| panic!("not 5 fields: {f:?}"))
}

/// The client certificate in a client p12: checks the p12 shape and returns the cert DER.
/// Shape (anc.make_cert): key bag + cert bag `friendlyName=<name>`, CA cert bag `"CA"`
/// equal to `ssl/ca.crt`.
fn check_client_p12(site: &Site, p12: &[u8], pw: &str, name: &str) -> (Vec<u8>, Vec<u8>) {
    assert!(pkcs12::parse(p12, "wrong-password").is_err());
    let pfx = pkcs12::parse(p12, pw).expect("client p12 opens with its password");
    let bags: Vec<_> = pfx.bags().collect();
    let certs: Vec<_> = bags.iter().filter(|b| b.is_cert()).collect();
    let keys: Vec<_> = bags.iter().filter(|b| b.is_key()).collect();
    assert_eq!((certs.len(), keys.len(), bags.len()), (2, 1, 3));
    let ca_der = taky_pki::pem::load_certs(&site.path("ssl/ca.crt")).unwrap()[0].to_vec();
    let ca = certs
        .iter()
        .find(|b| b.friendly_name().as_deref() == Some("CA"))
        .expect("CA bag");
    assert_eq!(ca.value, ca_der, "CA in the p12 is ssl.ca");
    let client = certs
        .iter()
        .find(|b| b.friendly_name().as_deref() == Some(name))
        .expect("client cert bag named <name>");
    assert_eq!(keys[0].friendly_name().as_deref(), Some(name));
    assert!(keys[0].local_key_id().is_some());
    assert_eq!(keys[0].local_key_id(), client.local_key_id());
    let id = taky_pki::identity::identity_from_der(&client.value).unwrap();
    let ca_id = taky_pki::identity::identity_from_der(&ca_der).unwrap();
    assert_eq!(id.cn.as_deref(), Some(name));
    assert_eq!(id.issuer_cn, ca_id.cn);
    assert_eq!(id.not_before, now() - TimeDelta::days(2));
    assert_eq!(id.not_after, now() + TimeDelta::days(730));
    assert_rsa_pair(&keys[0].value, &client.value);
    (client.value.clone(), keys[0].value.clone())
}

/// Minimal DER walk: `(tag, content, rest)`.
fn tlv(d: &[u8]) -> (u8, &[u8], &[u8]) {
    let (tag, l0) = (d[0], d[1]);
    let (len, hdr) = if l0 < 0x80 {
        (l0 as usize, 2)
    } else {
        let n = (l0 & 0x7f) as usize;
        let len = d[2..2 + n]
            .iter()
            .fold(0usize, |a, b| (a << 8) | *b as usize);
        (len, 2 + n)
    };
    (tag, &d[hdr..hdr + len], &d[hdr + len..])
}

/// The RSA modulus of a PKCS#8 `PrivateKeyInfo` (or a bare PKCS#1 key) is the one in the cert.
fn assert_rsa_pair(key_der: &[u8], cert_der: &[u8]) {
    let modulus = |k: &[u8]| -> Vec<u8> {
        let (_, mut seq, _) = tlv(k);
        let (_, _version, rest) = tlv(seq);
        seq = rest;
        let (tag, c, rest) = tlv(seq);
        if tag == 0x30 {
            // PKCS#8: AlgorithmIdentifier, then OCTET STRING { RSAPrivateKey }.
            let (_, inner, _) = tlv(rest);
            return modulus_pkcs1(inner);
        }
        c.to_vec()
    };
    let n = modulus(key_der);
    assert!(n.len() >= 256, "2048-bit modulus");
    assert!(
        cert_der.windows(n.len()).any(|w| w == n.as_slice()),
        "key does not belong to the certificate"
    );
}

fn modulus_pkcs1(k: &[u8]) -> Vec<u8> {
    let (_, seq, _) = tlv(k);
    let (_, _, rest) = tlv(seq);
    tlv(rest).1.to_vec()
}

#[test]
fn atak_package_layout_pref_manifest_p12_and_cert_db_line() {
    let site = Site::new();
    let db_before = site.cert_db();
    std::fs::set_permissions(
        site.path("ssl/server.p12"),
        std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();

    ok(&site.dir, &["build_client", "JENNY"]);

    // Exactly <cwd>/JENNY.zip is new in the site (no --dump_pem files, no temp dir).
    let mut new: Vec<String> = std::fs::read_dir(&site.dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    new.sort();
    assert_eq!(new, ["JENNY.zip", "dp-user", "ssl", "taky.conf"]);

    let e = read_zip(&site.path("JENNY.zip"));
    let names: Vec<&str> = e.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names.len(), 4, "{names:?}");
    assert_eq!(names[0], "MANIFEST/manifest.xml");
    assert_eq!(names[1], "certs/preference.pref");
    let su = uuid_in(names[2], "certs/server-", ".p12");
    let cu = uuid_in(names[3], "certs/JENNY-", ".p12");
    assert_ne!(su, cu);

    // Modes: manifest/pref per umask, server p12 keeps the source mode, client p12 0600 (D-19).
    assert_eq!(
        e.iter().map(|e| e.mode).collect::<Vec<_>>(),
        [umask_mode(), umask_mode(), 0o640, 0o600]
    );

    // The server p12 is a byte copy of ssl.server_p12.
    assert_eq!(
        e[2].data,
        std::fs::read(site.path("ssl/server.p12")).unwrap()
    );

    let (server_p12, client_p12) = (format!("server-{su}.p12"), format!("JENNY-{cu}.p12"));
    assert_eq!(
        text(&e[1]),
        pref(
            "10.0.0.5:8089:ssl",
            true,
            &server_p12,
            &client_p12,
            "atakatak"
        )
    );

    let man = text(&e[0]);
    let uid = man
        .split("name=\"uid\" value=\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .unwrap();
    assert!(is_uuid(uid) && uid != su && uid != cu, "{uid}");
    assert_eq!(
        man,
        format!(
            "<MissionPackageManifest version=\"2\">
  <Configuration>
    <Parameter name=\"uid\" value=\"{uid}\"/>
    <Parameter name=\"name\" value=\"srv1_DP\"/>
    <Parameter name=\"onReceiveDelete\" value=\"true\"/>
  </Configuration>
  <Contents>
    <Content ignore=\"false\" zipEntry=\"certs/preference.pref\"/>
    <Content ignore=\"false\" zipEntry=\"certs/{server_p12}\"/>
    <Content ignore=\"false\" zipEntry=\"certs/{client_p12}\"/>
  </Contents>
</MissionPackageManifest>
"
        )
    );

    // Client p12: default password atakatak; CN=JENNY issued by the site CA.
    let (cert, _) = check_client_p12(&site, &e[3].data, "atakatak", "JENNY");
    let id = taky_pki::identity::identity_from_der(&cert).unwrap();

    // cert-db: the old lines unchanged, one new V line for this certificate (spec D-11 format:
    // status, issued, expires, serial %040x, CN — TAB separated).
    let db = site.cert_db();
    let added = db
        .strip_prefix(&db_before)
        .expect("old lines kept, line appended");
    assert_eq!(added.lines().count(), 1);
    let serial = format!("{:0>40}", id.serial_hex_upper.to_lowercase());
    assert_eq!(
        added,
        format!("V\t2026-11-11T12:00:00\t2028-11-12T12:00:00\t{serial}\tJENNY\n")
    );
    assert_eq!(fields(added)[3].len(), 40);
}

#[test]
fn itak_package_has_flat_layout_no_manifest_and_own_password() {
    let site = Site::new();
    ok(
        &site.dir,
        &["build_client", "--is_itak", "--p12_pw", "pw2", "BOB"],
    );
    let e = read_zip(&site.path("BOB.zip"));
    let names: Vec<&str> = e.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names.len(), 3, "{names:?}");
    assert_eq!(names[0], "preference.pref");
    let su = uuid_in(names[1], "server-", ".p12");
    let cu = uuid_in(names[2], "BOB-", ".p12");
    assert_eq!(
        e.iter().map(|e| e.mode).collect::<Vec<_>>(),
        [umask_mode(), 0o644, 0o600]
    );
    assert_eq!(
        text(&e[0]),
        pref(
            "10.0.0.5:8089:ssl",
            false,
            &format!("server-{su}.p12"),
            &format!("BOB-{cu}.p12"),
            "pw2"
        )
    );
    // The client password protects the client p12 only; caPassword stays ssl.server_p12_pw.
    check_client_p12(&site, &e[2].data, "pw2", "BOB");
    assert!(pkcs12::parse(&e[1].data, "atakatak").is_ok());
    assert!(site.cert_db().ends_with("\tBOB\n"));
}

#[test]
fn dump_pem_writes_p12_crt_key_into_cwd() {
    let site = Site::new();
    ok(&site.dir, &["build_client", "--dump_pem", "JENNY"]);
    let e = read_zip(&site.path("JENNY.zip"));
    let base = e[3]
        .name
        .strip_prefix("certs/")
        .and_then(|n| n.strip_suffix(".p12"))
        .unwrap();
    let mut files: Vec<String> = std::fs::read_dir(&site.dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("JENNY-"))
        .collect();
    files.sort();
    assert_eq!(
        files,
        [
            format!("{base}.crt"),
            format!("{base}.key"),
            format!("{base}.p12")
        ]
    );
    let mode = |ext: &str| {
        std::fs::metadata(site.dir.join(format!("{base}.{ext}")))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!(
        (mode("p12"), mode("key"), mode("crt")),
        (0o600, 0o600, umask_mode())
    );
    // The dumped p12 is the one in the ZIP; the .crt is its certificate, the .key its key.
    let p12 = std::fs::read(site.dir.join(format!("{base}.p12"))).unwrap();
    assert_eq!(p12, e[3].data);
    let (cert, key8) = check_client_p12(&site, &p12, "atakatak", "JENNY");
    let crt = taky_pki::pem::load_certs(&site.dir.join(format!("{base}.crt"))).unwrap();
    assert_eq!(crt.len(), 1);
    assert_eq!(crt[0].as_ref(), cert.as_slice());
    let key_pem = std::fs::read_to_string(site.dir.join(format!("{base}.key"))).unwrap();
    assert!(
        key_pem.starts_with("-----BEGIN RSA PRIVATE KEY-----\n"),
        "PKCS#1"
    );
    let blocks = taky_pki::pem::parse_pem(key_pem.as_bytes()).unwrap();
    assert_eq!(blocks.len(), 1);
    let pkcs1 = &blocks[0].der;
    assert_rsa_pair(pkcs1, &cert);
    assert_eq!(modulus_pkcs1(pkcs1), {
        let (_, seq, _) = tlv(&key8);
        let (_, _, r) = tlv(seq);
        let (_, _, r) = tlv(r);
        modulus_pkcs1(tlv(r).1)
    });
}

#[test]
fn same_name_twice_overwrites_zip_and_adds_second_cert_db_line() {
    // Python: zipfile.ZipFile(<name>.zip, "w") truncates; cert-db gets one V line per run.
    let site = Site::new();
    ok(&site.dir, &["build_client", "JENNY"]);
    let first = read_zip(&site.path("JENNY.zip"));
    let lines1 = site.cert_db().lines().count();
    ok(&site.dir, &["build_client", "--is_itak", "JENNY"]);
    let second = read_zip(&site.path("JENNY.zip"));
    assert_eq!(second.len(), 3, "replaced, not appended");
    assert!(second.iter().all(|e| !e.name.starts_with("certs/")));
    assert_ne!(first[3].data, second[2].data);
    let db = site.cert_db();
    let jenny: Vec<[String; 5]> = db
        .lines()
        .filter(|l| l.ends_with("\tJENNY"))
        .map(fields)
        .collect();
    assert_eq!((db.lines().count(), jenny.len()), (lines1 + 1, 2));
    assert_ne!(jenny[0][3], jenny[1][3], "a new certificate each time");
    assert!(jenny.iter().all(|f| f[0] == "V"));
}

#[test]
fn config_via_dash_c_from_another_dir_writes_zip_into_cwd() {
    let site = Site::new();
    let parent = site.dir.parent().unwrap().to_owned();
    ok(
        &parent,
        &["-c", "site/taky.conf", "build_client", "--is_itak", "X"],
    );
    assert!(parent.join("X.zip").exists());
    assert!(!site.path("X.zip").exists());
    let e = read_zip(&parent.join("X.zip"));
    assert_eq!(
        e[1].data,
        std::fs::read(site.path("ssl/server.p12")).unwrap()
    );
    assert!(site.cert_db().ends_with("\tX\n"));
}

#[test]
fn connect_string_follows_public_ip_port_and_ssl_flag() {
    let site = Site::new();
    site.edit_conf("port = 8089", "port = 8087");
    site.edit_conf("enabled = true", "enabled = false");
    ok(&site.dir, &["build_client", "--is_itak", "T"]);
    let p = text(&read_zip(&site.path("T.zip"))[0]);
    assert!(p.contains(">10.0.0.5:8087:tcp<"), "{p}");

    // public_ip without a value: Python's str(None) (QUIRK).
    site.edit_conf("public_ip = 10.0.0.5", "public_ip");
    ok(&site.dir, &["build_client", "--is_itak", "T"]);
    let p = text(&read_zip(&site.path("T.zip"))[0]);
    assert!(p.contains(">None:8087:tcp<"), "{p}");
}

#[test]
fn hostname_without_value_fails_after_the_cert_db_line() {
    // Order as the original: the cert-db line is written before the pref is built.
    let site = Site::new();
    site.edit_conf("hostname = srv1", "hostname");
    let before = site.cert_db().lines().count();
    assert_eq!(
        failed(&site.dir, &["build_client", "H"]),
        "Unknown preference type: <class 'NoneType'>"
    );
    assert!(!site.path("H.zip").exists());
    assert_eq!(site.cert_db().lines().count(), before + 1);
    assert!(site.cert_db().ends_with("\tH\n"));
}

#[test]
fn name_with_slash_is_refused_before_anything_is_written() {
    let site = Site::new();
    let before = site.cert_db();
    assert_eq!(
        failed(&site.dir, &["build_client", "--dump_pem", "a/b"]),
        "invalid client name 'a/b': must not contain '/'"
    );
    assert_eq!(site.cert_db(), before);
    assert!(!site.dir.join("a").exists());
    let n = std::fs::read_dir(&site.dir).unwrap().count();
    assert_eq!(n, 3, "taky.conf, ssl, dp-user only");

    // Binary: "<cmd> failed: <exc>", exit 1, nothing on stdout.
    let (rc, out, err) = bin(&site.dir, &["build_client", "a/b"]);
    assert_eq!((rc, out.as_str()), (1, ""));
    assert_eq!(
        err.lines().take(2).collect::<Vec<_>>(),
        [
            "build_client failed: invalid client name 'a/b': must not contain '/'",
            "Unhandled exception:"
        ]
    );
}

#[test]
fn bad_names_fail_without_zip() {
    let site = Site::new();
    // Empty CN: rejected by the certificate builder (Python's x509 ValueError text).
    let before = site.cert_db();
    assert_eq!(
        failed(&site.dir, &["build_client", ""]),
        "Attribute's length must be >= 1 and <= 64, but it was 0"
    );
    assert_eq!(site.cert_db(), before);
    assert!(!site.path(".zip").exists());
    // 64+ characters: certificate without CN, which the cert-db refuses.
    let long = "N".repeat(64);
    assert_eq!(
        failed(&site.dir, &["build_client", &long]),
        "Certificate must have exactly one CommonName"
    );
    assert_eq!(site.cert_db(), before);
    assert!(!site.path(&format!("{long}.zip")).exists());
}

#[test]
fn missing_setup_and_missing_files_fail_with_python_texts() {
    // No ./taky.conf and no /etc/taky: defaults ⇒ the system server p12 path.
    let tmp = tempfile::tempdir().unwrap();
    if !Path::new("/etc/taky").exists() {
        assert_eq!(
            failed(tmp.path(), &["build_client", "X"]),
            "[Errno 2] No such file or directory: '/etc/taky/ssl/server.p12'"
        );
        // -c to a file that does not exist: also defaults (configparser.read ignores it).
        assert_eq!(
            failed(tmp.path(), &["-c", "none.conf", "build_client", "X"]),
            "[Errno 2] No such file or directory: '/etc/taky/ssl/server.p12'"
        );
        let (rc, out, err) = bin(tmp.path(), &["build_client", "X"]);
        assert_eq!((rc, out.as_str()), (1, ""));
        assert_eq!(
            err.lines().next(),
            Some(
                "build_client failed: [Errno 2] No such file or directory: '/etc/taky/ssl/server.p12'"
            )
        );
    }
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);

    let site = Site::new();
    std::fs::remove_file(site.path("ssl/ca.key")).unwrap();
    let before = site.cert_db();
    let e = failed(&site.dir, &["build_client", "X"]);
    assert!(
        e.starts_with("[Errno 2] No such file or directory: '") && e.ends_with("ssl/ca.key'"),
        "{e}"
    );
    assert_eq!(site.cert_db(), before);

    std::fs::remove_file(site.path("ssl/server.p12")).unwrap();
    let e = failed(&site.dir, &["build_client", "X"]);
    assert!(e.ends_with("ssl/server.p12'"), "{e}");

    let site = Site::new();
    site.edit_conf("server_p12 = ./ssl/server.p12", "server_p12");
    assert_eq!(
        failed(&site.dir, &["build_client", "X"]),
        "expected str, bytes or os.PathLike object, not NoneType"
    );

    let site = Site::new();
    site.edit_conf("cert_db = ./ssl/cert-db.txt", "cert_db");
    assert_eq!(
        failed(&site.dir, &["build_client", "X"]),
        "expected str, bytes or os.PathLike object, not NoneType"
    );
    assert!(!site.path("X.zip").exists());
}

#[test]
fn unreadable_cert_db_fails_and_is_left_alone() {
    let site = Site::new();
    let bad = "V\tnot-a-date\t2028-01-01T00:00:00\t01\tX\n";
    std::fs::write(site.path("ssl/cert-db.txt"), bad).unwrap();
    let e = failed(&site.dir, &["build_client", "X"]);
    assert!(e.ends_with("cert-db.txt:1: bad issued date"), "{e}");
    assert_eq!(site.cert_db(), bad);
    assert!(!site.path("X.zip").exists());
}

#[test]
fn zip_that_cannot_be_written_fails_with_its_path() {
    let site = Site::new();
    std::fs::create_dir(site.path("D.zip")).unwrap();
    let e = failed(&site.dir, &["build_client", "D"]);
    assert_eq!(
        e,
        format!(
            "{}: Is a directory (os error 21)",
            site.path("D.zip").display()
        )
    );
}

#[test]
fn config_read_and_parse_errors_are_printed_with_exit_1() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    // Parse errors (configparser.ParsingError family): printed as-is, rc 1, not "failed".
    std::fs::write(t.join("g.conf"), "garbage\n").unwrap();
    let r = call(t, &["-c", "g.conf", "build_client", "X"]);
    assert_eq!(r.res, Ok(1));
    assert_eq!(
        r.err,
        "File contains no section headers.\nfile: 'g.conf', line: 1\n'garbage\\n'\n"
    );
    let (rc, out, err) = bin(t, &["-c", "g.conf", "build_client", "X"]);
    assert_eq!((rc, out.as_str(), err.as_str()), (1, "", r.err.as_str()));

    // OSError reading the config: printed, rc 1.
    std::fs::create_dir(t.join("d")).unwrap();
    let r = call(t, &["-c", "d", "build_client", "X"]);
    assert_eq!(r.res, Ok(1));
    assert_eq!(r.err, "Is a directory (os error 21)\n");

    // A ValueError in the config takes the failed path.
    std::fs::write(t.join("p.conf"), "[cot_server]\nport = 99999\n").unwrap();
    let r = call(t, &["-c", "p.conf", "build_client", "X"]);
    assert_eq!(
        (r.res, r.err.as_str()),
        (Err("Invalid port: 99999".into()), "")
    );
    assert!(!t.join("X.zip").exists());
}

#[test]
fn umask_sets_pref_and_manifest_modes() {
    let site = Site::new();
    let o = Command::new("sh")
        .args(["-c", "umask 077 && exec \"$0\" build_client U", BIN])
        .current_dir(&site.dir)
        .output()
        .unwrap();
    let (rc, out, err) = (
        o.status.code(),
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr),
    );
    assert_eq!((rc, &*out, &*err), (Some(0), "", ""));
    let e = read_zip(&site.path("U.zip"));
    assert_eq!(
        e.iter().map(|e| e.mode).collect::<Vec<_>>(),
        [0o600, 0o600, 0o644, 0o600]
    );
}

#[test]
fn client_cert_verifies_against_ca_with_openssl() {
    const T: &str = "build_client::client_cert_verifies_against_ca_with_openssl";
    let have = Command::new("openssl").arg("version").output().is_ok();
    if !prereq(Prereq::Openssl, have, T, "openssl not available") {
        return;
    }
    let site = Site::new();
    ok(&site.dir, &["build_client", "--dump_pem", "V"]);
    let crt = std::fs::read_dir(&site.dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "crt"))
        .unwrap();
    let o = Command::new("openssl")
        .args(["verify", "-purpose", "sslclient", "-CAfile"])
        .arg(site.path("ssl/ca.crt"))
        .arg(&crt)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
    assert!(
        String::from_utf8_lossy(&o.stdout)
            .trim_end()
            .ends_with(": OK")
    );
}
