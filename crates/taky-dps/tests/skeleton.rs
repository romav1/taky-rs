#![allow(clippy::expect_used, clippy::unwrap_used)] // test helpers outside #[test] fns
//! S-316: DPS vectors D003, D015, D017 + skeleton behaviour (identity, version, routing quirks).

mod common;

use common::{Harness, HttpRequest, run_vector};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn d003_plain_x_user_loopback_only() {
    run_vector("dps/D003.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d015_404_405() {
    run_vector("dps/D015.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d017_tls_spoof_ignored() {
    run_vector("dps/D017.json").await;
}

fn get(target: &str) -> HttpRequest {
    HttpRequest {
        method: "GET".into(),
        target: target.into(),
        host: "taky.example:8443".into(),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_identity_revocation_and_version() {
    let cfg =
        json!({"taky": {"hostname": "taky.example", "node_id": "N"}, "ssl": {"enabled": "true"}});
    let mut h = Harness::new(&cfg).await;

    let r = h.send(get("/Marti/api/version"), None, None).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
    assert_eq!(
        r.body,
        format!("taky-rs-{}", taky_common::VERSION).into_bytes()
    );

    let r = h.send(get("/Marti/api/version/config"), None, None).await;
    assert_eq!(
        String::from_utf8(r.body).unwrap(),
        format!(
            "{{\"data\":{{\"api\":\"2\",\"hostname\":\"taky.example\",\"version\":\"taky-rs-{}\"}},\"nodeId\":\"N\",\"type\":\"ServerConfig\",\"version\":\"2\"}}\n",
            taky_common::VERSION
        )
    );

    // Valid cert ⇒ 200; revoked cert (R in cert-db) ⇒ 403; no cert ⇒ 401.
    let r = h
        .send(
            get("/Marti/api/clientEndPoints"),
            Some(("carol", false)),
            None,
        )
        .await;
    assert_eq!(r.status, 200);
    let r = h
        .send(
            get("/Marti/api/clientEndPoints"),
            Some(("dave", true)),
            None,
        )
        .await;
    assert_eq!(r.status, 403);
    let mut spoof = get("/Marti/api/clientEndPoints");
    spoof.headers.push(("X-SERIAL-NUMBER".into(), "1".into()));
    spoof.headers.push(("x_user".into(), "eve".into()));
    let r = h.send(spoof, None, None).await;
    assert_eq!(r.status, 401);
    // The external X-REVOKED of a valid user is dropped too.
    let mut rv = get("/Marti/api/clientEndPoints");
    rv.headers.push(("X-REVOKED".into(), "1".into()));
    let r = h.send(rv, Some(("carol", false)), None).await;
    assert_eq!(r.status, 200);

    // Leading double slash (url_for quirk) is served; an inner one redirects (Werkzeug 308).
    let r = h.send(get("//Marti/api/version"), None, None).await;
    assert_eq!(r.status, 200);
    let r = h.send(get("/Marti//api/version?a=1"), None, None).await;
    assert_eq!(r.status, 308);
    assert_eq!(
        r.header("location"),
        Some("https://taky.example:8443/Marti/api/version?a=1")
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_mode_policy_options_and_errors() {
    let cfg = json!({"taky": {"hostname": "h"}});
    let mut h = Harness::new(&cfg).await;
    let remote: std::net::IpAddr = "192.0.2.7".parse().unwrap();

    let mut u = get("/Marti/api/clientEndPoints");
    u.headers.push(("X_USER".into(), "alice".into()));
    // Underscore spelling is never trusted, even from loopback.
    assert_eq!(h.send(u.clone(), None, None).await.status, 401);
    // Loopback: trusted (ServerConnectString tcp, default cot port 8087).
    let r = h
        .send(
            get("/Marti/api/clientEndPoints"),
            Some(("alice", false)),
            None,
        )
        .await;
    assert_eq!(r.status, 200);
    assert!(String::from_utf8_lossy(&r.body).contains("\"tcp:h:8087\""));
    // Loopback X-REVOKED ⇒ 403; non-loopback ⇒ headers dropped ⇒ 401.
    let r = h
        .send(
            get("/Marti/api/clientEndPoints"),
            Some(("alice", true)),
            None,
        )
        .await;
    assert_eq!(r.status, 403);
    let r = h
        .send(
            get("/Marti/api/clientEndPoints"),
            Some(("alice", false)),
            Some(remote),
        )
        .await;
    assert_eq!(r.status, 401);
    // Public endpoints from a remote peer.
    let r = h.send(get("/"), None, Some(remote)).await;
    assert_eq!((r.status, r.body.as_slice()), (200, &b"Hello, world!"[..]));

    // Automatic OPTIONS and Allow on 405, before auth.
    let mut o = get("/Marti/vcm");
    o.method = "OPTIONS".into();
    let r = h.send(o, None, None).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("allow"), Some("GET, HEAD, OPTIONS, POST"));
    assert!(r.body.is_empty());
    let mut p = get("/Marti/sync/search");
    p.method = "DELETE".into();
    let r = h.send(p, None, None).await;
    assert_eq!(r.status, 405);
    assert_eq!(r.header("allow"), Some("GET, HEAD, OPTIONS"));
    assert_eq!(r.header("content-length"), Some("153"));

    // 404 body byte-exact with Werkzeug (207 bytes), trailing slash not matched.
    let r = h.send(get("/Marti/api/version/"), None, None).await;
    assert_eq!(r.status, 404);
    assert_eq!(r.body.len(), 207);
    let r = h.send(get("/Marti/api/clientEndPoints"), None, None).await;
    assert_eq!((r.status, r.body.len()), (401, 317));
    h.stop().await;
}
