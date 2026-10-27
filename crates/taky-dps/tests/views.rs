#![allow(clippy::expect_used, clippy::unwrap_used)] // test helpers outside #[test] fns
//! S-318: DPS vectors for the public/version endpoints, clientEndPoints, search visibility, KML
//! stubs and video feeds (D001 D002 D007 D012 D013 D014 D016) + vcm behaviour not pinned by
//! vectors.

mod common;

use common::{Harness, HttpRequest, run_vector};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn d001_public_endpoints() {
    run_vector("dps/D001.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d002_protected_endpoint() {
    run_vector("dps/D002.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d007_search_visibility() {
    run_vector("dps/D007.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d012_video_feeds() {
    run_vector("dps/D012.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d013_video_feed_errors() {
    run_vector("dps/D013.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d014_kml_stubs() {
    run_vector("dps/D014.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d016_vcm_doctype_rejected() {
    run_vector("dps/D016.json").await;
}

fn cfg() -> serde_json::Value {
    json!({"taky": {"hostname": "taky.example", "node_id": "N"}, "ssl": {"enabled": "true"}})
}

fn post(body: &str, headers: Vec<(String, String)>) -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        target: "/Marti/vcm".into(),
        host: "taky.example:8443".into(),
        headers,
        body: body.as_bytes().to_vec(),
    }
}

fn get() -> HttpRequest {
    HttpRequest {
        method: "GET".into(),
        target: "/Marti/vcm".into(),
        host: "taky.example:8443".into(),
        ..Default::default()
    }
}

const ALICE: Option<(&str, bool)> = Some(("alice", false));

#[tokio::test(flavor = "multi_thread")]
async fn vcm_namespaces_tail_comments_and_form_body() {
    let mut h = Harness::new(&cfg()).await;
    let feeds = h.upload_path.join("video_feed");

    // Root declarations are copied onto the stored feed (tostring of a sub-element); the tail
    // after the feed is part of `tostring(feed)`.
    let r = h
        .send(
            post(
                "<videoConnections xmlns:p=\"urn:p\"><feed p:a=\"1\"><uid>N1</uid><p:x/></feed>\n</videoConnections>",
                vec![],
            ),
            ALICE,
            None,
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        std::fs::read_to_string(feeds.join("N1.xml")).unwrap(),
        "<?xml version='1.0' encoding='ASCII'?>\n<feed xmlns:p=\"urn:p\" p:a=\"1\"><uid>N1</uid><p:x/></feed>\n"
    );

    // A comment child is not a <feed> (iterchildren includes comments) ⇒ 400.
    let r = h
        .send(
            post("<videoConnections><!--c--></videoConnections>", vec![]),
            ALICE,
            None,
        )
        .await;
    assert_eq!(
        (r.status, r.body.as_slice()),
        (400, &b"Invalid XML document"[..])
    );

    // Unknown entity / form content type (request.data is empty) ⇒ Malformed XML.
    for (body, ct) in [
        (
            "<videoConnections><feed><uid>&e;</uid></feed></videoConnections>",
            "application/xml",
        ),
        (
            "<videoConnections><feed><uid>F9</uid></feed></videoConnections>",
            "application/x-www-form-urlencoded",
        ),
    ] {
        let r = h
            .send(
                post(body, vec![("Content-Type".into(), ct.into())]),
                ALICE,
                None,
            )
            .await;
        assert_eq!(
            (r.status, r.body.as_slice()),
            (400, &b"Malformed XML"[..]),
            "{ct}"
        );
    }
    assert!(!feeds.join("F9.xml").exists());

    // secure_filename of the stripped uid.
    let r = h
        .send(
            post(
                "<videoConnections><feed><uid> ../a b </uid></feed></videoConnections>",
                vec![],
            ),
            ALICE,
            None,
        )
        .await;
    assert_eq!(r.status, 200);
    assert!(feeds.join("a_b.xml").is_file());

    // GET skips broken files, non-.xml files, non-feed roots and directories.
    std::fs::write(feeds.join("broken.xml"), "<feed>").unwrap();
    std::fs::write(feeds.join("other.xml"), "<x/>").unwrap();
    std::fs::write(feeds.join("note.txt"), "<feed><uid>T</uid></feed>").unwrap();
    std::fs::write(feeds.join("dtd.xml"), "<!DOCTYPE feed><feed/>").unwrap();
    std::fs::create_dir(feeds.join("d.xml")).unwrap();
    let r = h.send(get(), ALICE, None).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("text/xml; charset=utf-8"));
    let body = String::from_utf8(r.body).unwrap();
    assert!(body.starts_with("<?xml version='1.0' encoding='ASCII'?>\n<videoConnections>"));
    assert!(body.contains("<feed xmlns:p=\"urn:p\" p:a=\"1\"><uid>N1</uid><p:x/></feed>"));
    assert!(body.contains("<feed><uid> ../a b </uid></feed>"));
    assert_eq!(body.matches("<feed").count(), 2, "{body}");

    // Auth first, as @requires_auth.
    let r = h.send(post("<<", vec![]), None, None).await;
    assert_eq!(r.status, 401);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vcm_namespace_uri_with_brace() {
    // S-410 / D-30: Rust accepts a namespace URI containing `}` (Python: 400 Malformed XML); the
    // declaration copied onto the detached feed for a prefixed attribute must keep the whole URI.
    let mut h = Harness::new(&cfg()).await;
    let r = h
        .send(
            post(
                "<videoConnections xmlns:p=\"urn:c}d\"><feed p:a=\"1\"><uid>B1</uid></feed></videoConnections>",
                vec![],
            ),
            ALICE,
            None,
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        std::fs::read_to_string(h.upload_path.join("video_feed").join("B1.xml")).unwrap(),
        "<?xml version='1.0' encoding='ASCII'?>\n<feed xmlns:p=\"urn:c}d\" p:a=\"1\"><uid>B1</uid></feed>"
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vcm_without_upload_path_is_sever_error() {
    let mut h = Harness::new(&cfg()).await;
    std::fs::remove_dir_all(&h.upload_path).unwrap();
    let r = h
        .send(post("<videoConnections/>", vec![]), ALICE, None)
        .await;
    assert_eq!((r.status, r.body.as_slice()), (500, &b"Sever error"[..]));
    h.stop().await;
}
