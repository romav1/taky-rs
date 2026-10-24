//! S-311: CertDb read / re-read / read-modify-write (D-11, vector V052).
#![allow(clippy::expect_used)] // test helpers outside #[test] fns

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use chrono::NaiveDateTime;
use common::*;
use taky_pki::{CertDb, CertStatus, PkiError};

fn when() -> NaiveDateTime {
    taky_pki::certdb::fromisoformat("2030-01-01T00:00:00").expect("date")
}

/// A fast (ECDSA) client certificate with the taky client profile.
fn issue(ca: &Ca, cn: &str, serial: u8) -> Vec<u8> {
    let key = rcgen::KeyPair::generate().expect("key");
    let mut sn = [0x11u8; 20];
    sn[19] = serial;
    make_cert(ca, &key, cn, false, &sn).as_ref().to_vec()
}

fn status_by_name(path: &Path) -> BTreeMap<String, String> {
    CertDb::open(path)
        .expect("open")
        .records()
        .iter()
        .map(|r| (r.name.clone(), r.status.as_str().to_owned()))
        .collect()
}

fn ca() -> Ca {
    make_ca("CA", rcgen::KeyPair::generate().expect("key"))
}

/// V052 `final_rust_expect`: carol, issued after startup, is revoked by kickban and its line is
/// not lost when alice is kicked.
#[test]
fn v052_reread_by_mtime_and_rmw() {
    let v: serde_json::Value =
        serde_json::from_str(&taky_common::vectors::read_vector("cot/V052.json")).expect("json");
    let expect: BTreeMap<String, String> = v["final_rust_expect"]["cert_db_status"]
        .as_object()
        .expect("obj")
        .iter()
        .map(|(k, s)| (k.clone(), s.as_str().expect("str").to_owned()))
        .collect();

    let ca = ca();
    let d = tempfile::tempdir().expect("tmp");
    let path = d.path().join("cert-db.txt");
    // takyctl setup + build_client alice, before the server starts.
    let mut takyctl = CertDb::open(&path).expect("open");
    takyctl.add(&issue(&ca, "localhost", 1)).expect("add");
    takyctl.add(&issue(&ca, "alice", 2)).expect("add");
    // Server starts.
    let mut server = CertDb::open(&path).expect("open");
    assert_eq!(server.records().len(), 2);
    assert!(!server.reload_if_changed().expect("noop"));
    // issue_cert carol while the server runs (another process).
    CertDb::open(&path)
        .expect("open")
        .add(&issue(&ca, "carol", 3))
        .expect("add");
    // kickban carol: the server re-reads by mtime first and finds carol.
    assert!(server.reload_if_changed().expect("reload"));
    let carol: Vec<Vec<u8>> = server.by_name("carol").map(|r| r.serial.clone()).collect();
    assert_eq!(carol.len(), 1);
    server.revoke(&carol[0], when()).expect("revoke carol");
    // kickban alice.
    let alice: Vec<Vec<u8>> = server.by_name("alice").map(|r| r.serial.clone()).collect();
    server.revoke(&alice[0], when()).expect("revoke alice");
    assert!(server.is_revoked(&alice[0]) && server.is_revoked(&carol[0]));
    assert_eq!(status_by_name(&path), expect);
}

/// Even without a re-read, a stale instance does not drop lines written by others (RMW).
#[test]
fn stale_instance_keeps_foreign_lines() {
    let ca = ca();
    let d = tempfile::tempdir().expect("tmp");
    let path = d.path().join("cert-db.txt");
    let alice = issue(&ca, "alice", 2);
    let mut a = CertDb::open(&path).expect("open");
    a.add(&alice).expect("add");
    let mut stale = CertDb::open(&path).expect("open");
    a.add(&issue(&ca, "carol", 3)).expect("add");
    let sn = stale.records()[0].serial.clone();
    stale.revoke(&sn, when()).expect("revoke");
    assert_eq!(stale.records().len(), 2, "stale instance refreshed by RMW");
    let st = status_by_name(&path);
    assert_eq!(st.get("alice").map(String::as_str), Some("R"));
    assert_eq!(st.get("carol").map(String::as_str), Some("V"));
    // The line format is Python's.
    let text = std::fs::read_to_string(&path).expect("read");
    let first = text.lines().next().expect("line");
    assert_eq!(
        first,
        "R\t2024-03-04T00:00:00\t2030-01-01T00:00:00\t1111111111111111111111111111111111111102\talice"
    );
}

#[test]
fn add_requires_exactly_one_cn_and_replaces_same_serial() {
    let ca = ca();
    let d = tempfile::tempdir().expect("tmp");
    let path = d.path().join("cert-db.txt");
    let mut db = CertDb::open(&path).expect("open");
    // A CA cert has CN=CA (one CN) — fine; a cert without CN is rejected.
    let key = rcgen::KeyPair::generate().expect("k");
    let mut p = rcgen::CertificateParams::new(vec!["x.example".to_owned()]).expect("p");
    p.distinguished_name = rcgen::DistinguishedName::new();
    let no_cn = p.signed_by(&key, &ca.issuer).expect("sign");
    assert!(matches!(db.add(no_cn.der()), Err(PkiError::Invalid(_))));
    assert!(matches!(db.add(b"junk"), Err(PkiError::Invalid(_))));
    db.add(&issue(&ca, "bob", 9)).expect("add");
    db.add(&issue(&ca, "bob2", 9)).expect("add same serial");
    assert_eq!(db.records().len(), 1);
    assert_eq!(db.records()[0].name, "bob2");
    assert_eq!(db.records()[0].status, CertStatus::Valid);
}

/// Concurrent writers (separate instances, as separate processes would be) lose nothing.
#[test]
fn concurrent_writers_under_flock() {
    let ca = std::sync::Arc::new(ca());
    let d = tempfile::tempdir().expect("tmp");
    let path = d.path().join("cert-db.txt");
    let certs: Vec<Vec<u8>> = (0..40u8).map(|i| issue(&ca, &format!("u{i}"), i)).collect();
    std::thread::scope(|s| {
        for chunk in certs.chunks(10) {
            let path = path.clone();
            s.spawn(move || {
                for c in chunk {
                    CertDb::open(&path).expect("open").add(c).expect("add");
                }
            });
        }
    });
    assert_eq!(CertDb::open(&path).expect("open").records().len(), 40);
}
