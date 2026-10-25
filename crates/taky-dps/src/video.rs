//! Video feed views (`taky/taky/dps/views/video.py`, spec dps-cli-config §3.4): `POST /Marti/vcm`
//! stores every `<feed>` as `video_feed/<secure_filename(uid + ".xml")>`, `GET /Marti/vcm` returns
//! them aggregated in `<videoConnections>`.
//!
//! XML is parsed with `taky_xml::parse_element` (ADR-002): no DTD, no entity expansion.
//! Deviations: D-1 (any DOCTYPE / unknown entity ⇒ `400 Malformed XML`, nothing written; the
//! original expands entities — XXE), D-15 (`<uid>` without text ⇒ `400 Invalid XML document`
//! instead of the original's AttributeError 500).

// Early-return `Err(Response)` mirrors Flask's `return "…", 4xx` and is a cold path.
#![allow(clippy::result_large_err)]

use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use taky_xml::{Element, Limits, Node, SerOpts, parse_element, serialize};

use crate::app::{AppState, RequireAuth, error_page, text};
use crate::storage::secure_filename;

type St = State<Arc<AppState>>;

/// Feed directory below `upload_path`.
pub(crate) const FEEDS_DIR: &str = "video_feed";

fn ser_decl() -> SerOpts {
    SerOpts {
        xml_declaration: true,
        ..SerOpts::default()
    }
}

/// Flask `request.data`: empty for the content types Werkzeug parses as a form (the form parser
/// consumes the stream), otherwise the raw body.
pub(crate) fn request_data<'a>(headers: &HeaderMap, body: &'a [u8]) -> &'a [u8] {
    let ct = headers
        .get(CONTENT_TYPE)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default();
    let (mime, _) = crate::werkzeug::parse_options_header(&ct);
    match mime.as_str() {
        "multipart/form-data" | "application/x-www-form-urlencoded" => &[],
        _ => body,
    }
}

/// Read the whole body, at most `Limits::DEFAULT.max_bytes + 1` bytes: a larger document fails
/// the parser's size limit anyway (`Malformed XML`, D-2), so nothing more is buffered.
pub(crate) async fn read_body(body: Body, limit: usize) -> Option<Vec<u8>> {
    axum::body::to_bytes(body, limit).await.ok().map(Vec::from)
}

/// `str.strip()` (Python whitespace: Unicode White_Space plus U+001C..U+001F).
fn py_strip(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// `etree.tostring(feed)` of a child of `root`: a detached copy carries the namespace
/// declarations in scope (`_copyParentNamespaces`, as `taky_xml::TreeBuilder` does for events):
/// prefixes used by its attributes first, then the remaining declarations of `root`.
fn detach_with_ns(feed: &Element, root: &Element) -> Element {
    let mut e = feed.clone();
    for (i, (k, _)) in feed.attrs.iter().enumerate() {
        if let (Some(p), Some(uri)) = (feed.attr_prefix(i), clark_uri(k))
            && e.nsmap.iter().all(|(q, _)| q.as_deref() != Some(p))
        {
            e.nsmap.push((Some(p.to_owned()), uri.to_owned()));
        }
    }
    for (p, uri) in &root.nsmap {
        if e.nsmap.iter().all(|(q, _)| q != p) {
            e.nsmap.push((p.clone(), uri.clone()));
        }
    }
    e
}

fn clark_uri(name: &str) -> Option<&str> {
    name.strip_prefix('{')?.split_once('}').map(|(u, _)| u)
}

/// POST `/Marti/vcm` (`marti_video_upload`).
pub(crate) async fn upload(
    _auth: RequireAuth,
    State(s): St,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let lim = Limits::DEFAULT;
    let Some(raw) = read_body(body, lim.max_bytes + 1).await else {
        return text(StatusCode::BAD_REQUEST, "Malformed XML");
    };
    let root = match parse_element(request_data(&headers, &raw), &lim) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!("/Marti/vcm: {e}");
            return text(StatusCode::BAD_REQUEST, "Malformed XML");
        }
    };
    if root.tag != "videoConnections" {
        return text(StatusCode::BAD_REQUEST, "Invalid XML document");
    }
    let dir = s.store.root.join(FEEDS_DIR);
    tokio::task::spawn_blocking(move || store_feeds(&root, &dir))
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Exception in DPS view: {e}");
            error_page(StatusCode::INTERNAL_SERVER_ERROR)
        })
}

fn store_feeds(root: &Element, dir: &Path) -> Response {
    // `os.path.exists` follows symlinks; a dangling one makes `mkdir` fail ⇒ 500.
    if !dir.exists() && std::fs::create_dir(dir).is_err() {
        return text(StatusCode::INTERNAL_SERVER_ERROR, "Sever error");
    }
    // `elm.iterchildren()` includes comments and PIs, whose tag is never "feed".
    for node in &root.children {
        let Node::Element(feed) = node else {
            return text(StatusCode::BAD_REQUEST, "Invalid XML document");
        };
        if feed.tag != "feed" {
            return text(StatusCode::BAD_REQUEST, "Invalid XML document");
        }
        let Some(uid) = feed.find("uid") else {
            continue;
        };
        // D-15: the original raises AttributeError (`None.strip()`) ⇒ 500.
        let Some(uid) = uid.text.as_deref().filter(|t| !t.is_empty()) else {
            return text(StatusCode::BAD_REQUEST, "Invalid XML document");
        };
        let name = secure_filename(&format!("{}.xml", py_strip(uid)));
        let bytes = serialize(&detach_with_ns(feed, root), &ser_decl());
        if let Err(e) = std::fs::write(dir.join(&name), bytes) {
            tracing::debug!("/Marti/vcm: {name}: {e}");
            return text(StatusCode::INTERNAL_SERVER_ERROR, "Server error");
        }
    }
    text(StatusCode::OK, "")
}

/// GET `/Marti/vcm` (`marti_video_index`).
pub(crate) async fn index(_auth: RequireAuth, State(s): St) -> Response {
    let dir = s.store.root.join(FEEDS_DIR);
    tokio::task::spawn_blocking(move || feed_index(&dir))
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Exception in DPS view: {e}");
            error_page(StatusCode::INTERNAL_SERVER_ERROR)
        })
}

fn feed_index(dir: &Path) -> Response {
    let mut doc = Element::new("videoConnections");
    if !dir.exists() {
        // `return etree.tostring(...)` — bytes from a view ⇒ Flask's default `text/html`.
        return (
            StatusCode::OK,
            [(CONTENT_TYPE, crate::app::TEXT_HTML)],
            serialize(&doc, &ser_decl()),
        )
            .into_response();
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            // `os.listdir` raising ⇒ uncaught ⇒ 500.
            tracing::error!("Exception in DPS view: {}: {e}", dir.display());
            return error_page(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    for ent in entries {
        let Ok(ent) = ent else { continue };
        let path = ent.path();
        if !path.is_file() || !path.as_os_str().as_encoded_bytes().ends_with(b".xml") {
            continue;
        }
        let xml = match std::fs::read(&path) {
            Ok(x) => x,
            Err(e) => {
                // `print(exc)` (stdout in the original).
                tracing::warn!("{}: {e}", path.display());
                continue;
            }
        };
        match parse_element(&xml, &Limits::DEFAULT) {
            Ok(mut elm) if elm.tag == "feed" => {
                elm.reconcile_moved_ns();
                doc.append(elm);
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("{}: {e}", path.display()),
        }
    }
    (
        StatusCode::OK,
        [(CONTENT_TYPE, "text/xml; charset=utf-8")],
        serialize(&doc, &ser_decl()),
    )
        .into_response()
}
