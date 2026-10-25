#![allow(clippy::expect_used, clippy::unwrap_used)] // test helpers outside #[test] fns
//! S-317: DPS vectors for upload / download / metadata / missionquery (+ D-22) and send_file
//! behaviour (Range, conditional, HEAD) not pinned by vectors.

mod common;

use common::{Harness, HttpRequest, encode_multipart, run_vector};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn d004_upload_layout() {
    run_vector("dps/D004.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d005_upload_invalid_arguments() {
    run_vector("dps/D005.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d006_reupload_new_hash() {
    run_vector("dps/D006.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d008_download() {
    run_vector("dps/D008.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d009_download_missing_file() {
    run_vector("dps/D009.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d010_missionquery() {
    run_vector("dps/D010.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d011_metadata_tool() {
    run_vector("dps/D011.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d018_hash_traversal_rejected() {
    run_vector("dps/D018.json").await;
}

fn cfg() -> serde_json::Value {
    json!({"taky": {"hostname": "taky.example", "node_id": "N"}, "ssl": {"enabled": "true"}})
}

fn req(method: &str, target: &str) -> HttpRequest {
    HttpRequest {
        method: method.into(),
        target: target.into(),
        host: "taky.example:8443".into(),
        ..Default::default()
    }
}

const ALICE: Option<(&str, bool)> = Some(("alice", false));

#[tokio::test(flavor = "multi_thread")]
async fn send_file_range_conditional_head() {
    let mut h = Harness::new(&cfg()).await;
    std::fs::write(h.upload_path.join("U_f.txt"), "0123456789").unwrap();
    std::fs::write(
        h.upload_path.join("meta/U_f.txt.json"),
        r#"{"UID": "U_f.txt", "Name": "f ü.txt", "Hash": "hh"}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink("U_f.txt.json", h.upload_path.join("meta/hh.json")).unwrap();

    let r = h
        .send(req("GET", "/Marti/sync/content?hash=hh"), ALICE, None)
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"0123456789");
    assert_eq!(r.header("content-type"), Some("text/plain; charset=utf-8"));
    assert_eq!(
        r.header("content-disposition"),
        Some("attachment; filename=\"f u.txt\"; filename*=UTF-8''f%20%C3%BC.txt")
    );
    assert_eq!(r.header("cache-control"), Some("no-cache"));
    assert_eq!(r.header("accept-ranges"), Some("bytes"));
    let etag = r.header("etag").unwrap().to_owned();
    assert!(etag.starts_with('"') && etag.contains("-10-"), "{etag}");
    let lm = r.header("last-modified").unwrap().to_owned();

    // Leading-double-slash URL from url_for is served too.
    let r = h
        .send(req("GET", "//Marti/sync/content?hash=hh"), ALICE, None)
        .await;
    assert_eq!(r.status, 200);

    let mut rq = req("GET", "/Marti/sync/content?hash=hh");
    rq.headers.push(("Range".into(), "bytes=2-4".into()));
    let r = h.send(rq, ALICE, None).await;
    assert_eq!(r.status, 206);
    assert_eq!(r.body, b"234");
    assert_eq!(r.header("content-range"), Some("bytes 2-4/10"));

    let mut rq = req("GET", "/Marti/sync/content?hash=hh");
    rq.headers.push(("Range".into(), "bytes=20-".into()));
    let r = h.send(rq, ALICE, None).await;
    assert_eq!(r.status, 416);
    assert_eq!(r.header("content-range"), Some("bytes */10"));

    let mut rq = req("GET", "/Marti/sync/content?hash=hh");
    rq.headers.push(("If-None-Match".into(), etag.clone()));
    let r = h.send(rq, ALICE, None).await;
    assert_eq!(r.status, 304);
    assert!(r.body.is_empty());
    assert_eq!(r.header("content-type"), None);

    let mut rq = req("GET", "/Marti/sync/content?hash=hh");
    rq.headers.push(("If-Modified-Since".into(), lm));
    assert_eq!(h.send(rq, ALICE, None).await.status, 304);

    let r = h
        .send(req("HEAD", "/Marti/sync/content?hash=hh"), ALICE, None)
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-length"), Some("10"));
    assert!(r.body.is_empty());

    // No certificate ⇒ 401 before anything else.
    let r = h
        .send(req("GET", "/Marti/sync/content?hash=hh"), None, None)
        .await;
    assert_eq!(r.status, 401);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d22_upload_and_tool_reject_bad_hash() {
    let mut h = Harness::new(&cfg()).await;
    let (ct, body) = encode_multipart(&[json!({
        "name": "assetfile", "filename": "a.zip", "content_type": "application/zip", "data": "X"
    })]);
    for q in [
        "hash=../../planted&creatorUid=U",
        "hash=a%2Fb&creatorUid=U",
        "hash=&creatorUid=U",
    ] {
        let mut rq = req("POST", &format!("/Marti/sync/missionupload?{q}"));
        rq.headers.push(("Content-Type".into(), ct.clone()));
        rq.body = body.clone();
        let r = h.send(rq, ALICE, None).await;
        assert_eq!(
            (r.status, r.body.as_slice()),
            (400, &b"Invalid hash"[..]),
            "{q}"
        );
    }
    let mut rq = req("PUT", "/Marti/api/sync/metadata/..%2F..%2Fx/tool");
    rq.body = b"public".to_vec();
    let r = h.send(rq, ALICE, None).await;
    assert_eq!((r.status, r.body.as_slice()), (400, &b"Invalid hash"[..]));
    let mut rq = req("PUT", "/Marti/api/sync/metadata/../tool");
    rq.body = b"public".to_vec();
    let r = h.send(rq, ALICE, None).await;
    assert_eq!(r.status, 400);
    // Nothing was written anywhere.
    assert_eq!(common::snapshot_files(&h.upload_path), json!({}));
    assert!(!h.dir.path().join("planted.json").exists());
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_streams_large_file_and_part_limit() {
    let mut h = Harness::new(&cfg()).await;
    // > axum's 2 MiB default body limit: Flask has none.
    let big = "z".repeat(3 * 1024 * 1024);
    let (ct, body) = encode_multipart(&[
        json!({"name": "other", "filename": "x", "data": "ignored"}),
        json!({"name": "assetfile", "filename": "big.bin", "data": big}),
        json!({"name": "assetfile", "filename": "second.bin", "data": "2"}),
    ]);
    let mut rq = req("POST", "/Marti/sync/missionupload?hash=hb&creatorUid=C");
    rq.headers.push(("Content-Type".into(), ct));
    rq.body = body;
    let r = h.send(rq, ALICE, None).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(
        std::fs::metadata(h.upload_path.join("C_big.bin"))
            .unwrap()
            .len(),
        3 * 1024 * 1024
    );
    let meta = std::fs::read_to_string(h.upload_path.join("meta/C_big.bin.json")).unwrap();
    assert!(
        meta.contains("\"MIMEType\": \"application/octet-stream\""),
        "{meta}"
    );
    assert!(!h.upload_path.join("C_second.bin").exists());

    let parts: Vec<_> = (0..1001)
        .map(|i| json!({"name": format!("f{i}"), "filename": "x", "data": "v"}))
        .collect();
    let (ct, body) = encode_multipart(&parts);
    let mut rq = req("POST", "/Marti/sync/missionupload?hash=h2&creatorUid=C");
    rq.headers.push(("Content-Type".into(), ct));
    rq.body = body;
    assert_eq!(h.send(rq, ALICE, None).await.status, 413);
    h.stop().await;
}
