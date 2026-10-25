//! Data package views (`taky/taky/dps/views/datapackage.py`, spec dps-cli-config §2.4, §3):
//! search, content (download), missionupload, metadata `tool`, missionquery.
//!
//! Deviations: D-15 (content, unknown hash ⇒ 404 `File not found`), D-22 (`hash` validated ⇒
//! 400 `Invalid hash` before any filesystem access).

// Early-return `Err(Response)` mirrors Flask's `return "…", 4xx` and is a cold path.
#![allow(clippy::result_large_err)]

use std::ffi::OsStr;
use std::io::{Seek, SeekFrom, Write};
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::multipart::{Multipart, MultipartRejection};
use axum::extract::{Path, State};
use axum::http::header::{
    ACCEPT_RANGES, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE,
    ETAG, HOST, IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, LAST_MODIFIED, RANGE,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use tokio::io::AsyncReadExt;

use crate::app::{AppState, RequireAuth, error_page, jsonify, text};
use crate::mimetypes;
use crate::storage::{self, Store, py_truthy, valid_hash};
use crate::werkzeug::{self, CondHeaders, Conditional, arg, parse_args};

type St = State<Arc<AppState>>;

/// Werkzeug/Flask `max_form_parts` (Flask 2.3 `MAX_FORM_PARTS` default).
const MAX_FORM_PARTS: usize = 1000;

fn internal_error(what: impl std::fmt::Display) -> Response {
    tracing::error!("Exception in DPS view: {what}");
    error_page(StatusCode::INTERNAL_SERVER_ERROR)
}

/// `url_for(hash)` = `f"{request.host_url}/Marti/sync/content?hash={hash}"` (double slash, QUIRK).
fn url_for(s: &AppState, headers: &HeaderMap, hash: &str) -> String {
    let scheme = if s.tls { "https" } else { "http" };
    let host = headers.get(HOST).and_then(|h| h.to_str().ok());
    format!(
        "{}/Marti/sync/content?hash={hash}",
        werkzeug::host_url(scheme, host)
    )
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Response> + Send + 'static,
) -> Result<T, Response> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|e| Err(internal_error(e)))
}

fn get_meta(store: &Store, stem: &str) -> Result<Value, Response> {
    store
        .get_meta(OsStr::new(stem))
        .map_err(|e| internal_error(e.0))
}

/// The `hash` query argument: missing ⇒ `400 Must supply hash`; D-22 ⇒ `400 Invalid hash`.
fn query_hash(uri: &Uri) -> Result<String, Response> {
    let args = parse_args(uri.query());
    let Some(h) = arg(&args, "hash") else {
        return Err(text(StatusCode::BAD_REQUEST, "Must supply hash"));
    };
    if !valid_hash(h) {
        return Err(text(StatusCode::BAD_REQUEST, "Invalid hash"));
    }
    Ok(h.to_owned())
}

/// `GET /Marti/sync/search`: every regular file (symlinks followed) at the top of
/// `upload_path` whose `meta/<name>.json` is non-empty and `Visibility` (default `public`) is
/// `public`, in `listdir` order.
pub(crate) async fn search(_auth: RequireAuth, State(s): St) -> Response {
    let store = s.store.clone();
    let r = blocking(move || {
        let rd = std::fs::read_dir(&store.root).map_err(internal_error)?;
        let mut out = Vec::new();
        for ent in rd {
            let ent = ent.map_err(internal_error)?;
            let name = ent.file_name();
            if !std::fs::metadata(store.root.join(&name)).is_ok_and(|m| m.is_file()) {
                continue;
            }
            let meta = store.get_meta(&name).map_err(|e| internal_error(e.0))?;
            if !py_truthy(&meta) {
                continue;
            }
            let Value::Object(m) = &meta else {
                return Err(internal_error("AttributeError: meta has no .get"));
            };
            let public = match m.get("Visibility") {
                None => true,
                Some(v) => v.as_str() == Some("public"),
            };
            if public {
                out.push(meta);
            }
        }
        Ok(out)
    })
    .await;
    match r {
        Ok(results) => jsonify(&json!({"resultCount": results.len(), "results": results})),
        Err(e) => e,
    }
}

/// `GET /Marti/sync/content?hash=…`: the file as an attachment named `meta["Name"]`
/// (Flask `send_file`: Content-Type by name, ETag, Last-Modified, conditional + Range).
pub(crate) async fn content(
    _auth: RequireAuth,
    State(s): St,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let hash = match query_hash(&uri) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let cond = cond_headers(&headers);
    let store = s.store.clone();
    let r = blocking(move || {
        let meta = get_meta(&store, &hash)?;
        let Value::Object(m) = meta else {
            return Err(internal_error("TypeError: meta is not a dict"));
        };
        // D-15: no meta (Python: KeyError 'UID' ⇒ 500) ⇒ 404 like missionquery.
        let Some(uid) = m.get("UID") else {
            return Err(text(StatusCode::NOT_FOUND, "File not found"));
        };
        let Some(uid) = uid.as_str() else {
            return Err(internal_error("TypeError: UID is not a str"));
        };
        let path = store.file_path(uid);
        if std::fs::metadata(&path).is_err() {
            return Err(text(
                StatusCode::NOT_FOUND,
                format!("Can't find {}", path.display()),
            ));
        }
        let Some(name) = m.get("Name").and_then(Value::as_str) else {
            return Err(internal_error("KeyError/TypeError: Name"));
        };
        let disposition = werkzeug::attachment_disposition(name)
            .ok_or_else(|| internal_error("ValueError: newline in header value"))?;
        let mimetype = mimetypes::guess_type(name)
            .map_err(|_| internal_error("ValueError: Invalid IPv6 URL"))?
            .0
            .unwrap_or_else(|| "application/octet-stream".into());
        let file = std::fs::File::open(&path).map_err(internal_error)?;
        let md = file.metadata().map_err(internal_error)?;
        if md.is_dir() {
            return Err(internal_error("IsADirectoryError"));
        }
        Ok((file, md, path, disposition, mimetype))
    })
    .await;
    let (file, md, path, disposition, mimetype) = match r {
        Ok(v) => v,
        Err(e) => return e,
    };
    send_file(file, &md, &path, &disposition, &mimetype, &cond)
}

fn cond_headers(h: &HeaderMap) -> CondHeaders {
    let g = |n: HeaderName| {
        h.get(n)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
    };
    CondHeaders {
        range: g(RANGE),
        if_range: g(IF_RANGE),
        if_modified_since: g(IF_MODIFIED_SINCE),
        if_none_match: g(IF_NONE_MATCH),
        if_match: g(IF_MATCH),
    }
}

/// `os.path.abspath` of an absolute path (lexical normalization), for the ETag checksum.
fn normpath(p: &std::path::Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    let b = p.as_os_str().as_bytes();
    let lead = if b.starts_with(b"//") && !b.starts_with(b"///") {
        2
    } else {
        1
    };
    let mut parts: Vec<&[u8]> = Vec::new();
    for seg in b.split(|&c| c == b'/') {
        match seg {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    let mut out = b"/".repeat(lead);
    out.extend_from_slice(&parts.join(&b'/'));
    out
}

fn send_file(
    file: std::fs::File,
    md: &std::fs::Metadata,
    path: &std::path::Path,
    disposition: &str,
    mimetype: &str,
    cond: &CondHeaders,
) -> Response {
    use std::os::unix::fs::MetadataExt;
    let size = md.len();
    let mtime = md.mtime() as f64 + md.mtime_nsec() as f64 * 1e-9;
    let etag = format!(
        "\"{}-{size}-{}\"",
        taky_common::pyjson::float_repr(mtime),
        werkzeug::adler32(&normpath(path))
    );
    let lm: DateTime<Utc> = DateTime::from_timestamp(md.mtime(), 0).unwrap_or_default();
    let mut hm = HeaderMap::new();
    let mut put = |n: HeaderName, v: &str| {
        if let Ok(v) = HeaderValue::from_str(v) {
            hm.insert(n, v);
        }
    };
    if HeaderValue::from_str(disposition).is_err() {
        return internal_error("invalid Content-Disposition header value");
    }
    put(CONTENT_DISPOSITION, disposition);
    put(CONTENT_TYPE, &werkzeug::content_type_with_charset(mimetype));
    put(CONTENT_LENGTH, &size.to_string());
    put(LAST_MODIFIED, &werkzeug::http_date(lm));
    put(CACHE_CONTROL, "no-cache");
    put(ETAG, &etag);
    put(ACCEPT_RANGES, "bytes");

    let (status, start, len) = match werkzeug::conditional(cond, &etag, lm, size) {
        Conditional::Full => (StatusCode::OK, 0, size),
        Conditional::PreconditionFailed => (StatusCode::PRECONDITION_FAILED, 0, size),
        Conditional::Partial(a, b) => {
            put(CONTENT_LENGTH, &(b - a).to_string());
            put(CONTENT_RANGE, &format!("bytes {a}-{}/{size}", b - 1));
            (StatusCode::PARTIAL_CONTENT, a, b - a)
        }
        Conditional::NotModified => {
            for n in [CONTENT_TYPE, CONTENT_LENGTH, LAST_MODIFIED] {
                hm.remove(n);
            }
            return (StatusCode::NOT_MODIFIED, hm, Body::empty()).into_response();
        }
        Conditional::RangeNotSatisfiable => {
            let mut r = error_page(StatusCode::RANGE_NOT_SATISFIABLE);
            if let Ok(v) = HeaderValue::from_str(&format!("bytes */{size}")) {
                r.headers_mut().insert(CONTENT_RANGE, v);
            }
            return r;
        }
    };
    let mut file = file;
    if start > 0
        && let Err(e) = file.seek(SeekFrom::Start(start))
    {
        return internal_error(e);
    }
    let reader = tokio::fs::File::from_std(file).take(len);
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(reader));
    (status, hm, body).into_response()
}

/// `GET /Marti/sync/missionquery?hash=…`: meta exists ⇒ 200 URL, else 404 `File not found`.
pub(crate) async fn missionquery(
    _auth: RequireAuth,
    State(s): St,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let hash = match query_hash(&uri) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let store = s.store.clone();
    let h2 = hash.clone();
    match blocking(move || get_meta(&store, &h2)).await {
        Ok(m) if py_truthy(&m) => text(StatusCode::OK, url_for(&s, &headers, &hash)),
        Ok(_) => text(StatusCode::NOT_FOUND, "File not found"),
        Err(e) => e,
    }
}

/// `PUT /Marti/api/sync/metadata/<hash>/tool`: body exactly `public` ⇒ public, else private;
/// written only on change.
pub(crate) async fn metadata_tool(
    _auth: RequireAuth,
    State(s): St,
    Path(hash): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !valid_hash(&hash) {
        return text(StatusCode::BAD_REQUEST, "Invalid hash");
    }
    let store = s.store.clone();
    let h2 = hash.clone();
    let r = blocking(move || {
        let meta = get_meta(&store, &h2)?;
        if !py_truthy(&meta) {
            return Err(text(
                StatusCode::NOT_FOUND,
                format!("Could not find file matching {h2}"),
            ));
        }
        let body = std::str::from_utf8(&body)
            .map_err(|e| internal_error(format!("UnicodeDecodeError: {e}")))?;
        let visibility = if body == "public" {
            "public"
        } else {
            "private"
        };
        let Value::Object(mut m) = meta else {
            return Err(internal_error("AttributeError: meta has no .get"));
        };
        let current = m.get("Visibility").map_or(Some("private"), Value::as_str);
        if current != Some(visibility) {
            m.insert("Visibility".into(), Value::from(visibility));
            store.put_meta(&m).map_err(internal_error)?;
        }
        Ok(())
    })
    .await;
    match r {
        Ok(()) => text(StatusCode::OK, url_for(&s, &headers, &hash)),
        Err(e) => e,
    }
}

/// The first `assetfile` file part, spooled to an anonymous temp file (Werkzeug spools to
/// `TMPDIR` too).
struct Asset {
    filename: String,
    mimetype: String,
    data: std::fs::File,
}

enum Form {
    /// Parsed; `None` = no `assetfile` file part.
    Ok(Option<Asset>),
    /// Werkzeug silently drops a malformed form (⇒ `request.files` empty).
    Malformed,
    /// More than `MAX_FORM_PARTS` parts ⇒ 413.
    TooManyParts,
    /// Local I/O failure while spooling ⇒ 500.
    Io(std::io::Error),
}

async fn read_form(mut mp: Multipart) -> Form {
    let mut asset: Option<Asset> = None;
    let mut parts = 0usize;
    loop {
        let mut field = match mp.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => return Form::Ok(asset),
            Err(_) => return Form::Malformed,
        };
        parts += 1;
        if parts > MAX_FORM_PARTS {
            return Form::TooManyParts;
        }
        let hdr = |n: HeaderName| -> Result<Option<String>, ()> {
            match field.headers().get(n) {
                None => Ok(None),
                Some(v) => std::str::from_utf8(v.as_bytes())
                    .map(|s| Some(s.trim_matches([' ', '\t']).to_owned()))
                    .map_err(|_| ()),
            }
        };
        if field
            .headers()
            .values()
            .any(|v| std::str::from_utf8(v.as_bytes()).is_err())
        {
            return Form::Malformed;
        }
        let Ok(Some(cd)) = hdr(CONTENT_DISPOSITION) else {
            return Form::Malformed; // "Missing Content-Disposition header"
        };
        let ct = hdr(CONTENT_TYPE).ok().flatten();
        let (_, opts) = werkzeug::parse_options_header(&cd);
        let get = |k: &str| opts.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());
        let take = asset.is_none() && get("name").as_deref() == Some("assetfile");
        let filename = get("filename");
        match (take, filename) {
            (true, Some(filename)) => {
                let mut tmp = match tempfile::tempfile() {
                    Ok(f) => f,
                    Err(e) => return Form::Io(e),
                };
                loop {
                    match field.chunk().await {
                        Ok(Some(c)) => {
                            if let Err(e) = tmp.write_all(&c) {
                                return Form::Io(e);
                            }
                        }
                        Ok(None) => break,
                        Err(_) => return Form::Malformed,
                    }
                }
                let mimetype = match ct {
                    Some(ct) => werkzeug::parse_options_header(&ct).0.to_lowercase(),
                    None => String::new(),
                };
                asset = Some(Asset {
                    filename,
                    mimetype,
                    data: tmp,
                });
            }
            _ => loop {
                match field.chunk().await {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => return Form::Malformed,
                }
            },
        }
    }
}

/// `POST /Marti/sync/missionupload?hash=…&creatorUid=…` with multipart `assetfile`
/// (algorithm: spec dps-cli-config §3.2).
pub(crate) async fn upload(
    auth: RequireAuth,
    State(s): St,
    uri: Uri,
    headers: HeaderMap,
    mp: Result<Multipart, MultipartRejection>,
) -> Response {
    let form = match mp {
        Ok(mp) => read_form(mp).await,
        Err(_) => Form::Ok(None),
    };
    let asset = match form {
        Form::Ok(a) => a,
        Form::Malformed => None,
        Form::TooManyParts => return error_page(StatusCode::PAYLOAD_TOO_LARGE),
        Form::Io(e) => return internal_error(e),
    };
    let args = parse_args(uri.query());
    let (Some(asset), Some(creator_uid), Some(hash)) =
        (asset, arg(&args, "creatorUid"), arg(&args, "hash"))
    else {
        return text(StatusCode::BAD_REQUEST, "Invalid arguments");
    };
    if !valid_hash(hash) {
        return text(StatusCode::BAD_REQUEST, "Invalid hash");
    }
    let (creator_uid, hash) = (creator_uid.to_owned(), hash.to_owned());
    let store = s.store.clone();
    let clock = s.clock.clone();
    let user = auth.user;
    let h2 = hash.clone();
    let r = blocking(move || {
        let Asset {
            filename: name,
            mimetype,
            data: mut tmp,
        } = asset;
        let uid = storage::secure_filename(&format!("{creator_uid}_{name}"));
        // Delete / unlink the old hash link.
        let old = get_meta(&store, &uid)?;
        let Value::Object(old) = old else {
            return Err(internal_error("AttributeError: meta has no .get"));
        };
        let old_hash = old.get("Hash");
        if old_hash.and_then(Value::as_str) != Some(h2.as_str()) {
            match storage::py_str(old_hash) {
                Some(oh) if valid_hash(&oh) => {
                    storage::unlink_quiet(&store.meta_path(OsStr::new(&oh)))
                }
                _ => {}
            }
        }
        // Save the uploaded file (`open(path, "wb")`, through an existing file/symlink).
        let file_path = store.file_path(&uid);
        tmp.seek(SeekFrom::Start(0)).map_err(internal_error)?;
        let mut dst = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)
            .map_err(internal_error)?;
        std::io::copy(&mut tmp, &mut dst).map_err(internal_error)?;
        drop(dst);
        let size = std::fs::metadata(&file_path).map_err(internal_error)?.len();
        let mut meta = Map::new();
        meta.insert("UID".into(), Value::from(uid.clone()));
        meta.insert("Name".into(), Value::from(name));
        meta.insert("Hash".into(), Value::from(h2.clone()));
        meta.insert("PrimaryKey".into(), Value::from(1));
        meta.insert(
            "SubmissionDateTime".into(),
            Value::from(format!(
                "{}Z",
                taky_common::pyfmt::isoformat(clock.utc_now())
            )),
        );
        meta.insert("SubmissionUser".into(), Value::from(user));
        meta.insert("CreatorUid".into(), Value::from(creator_uid));
        meta.insert("Keywords".into(), Value::from("kw"));
        meta.insert("MIMEType".into(), Value::from(mimetype));
        meta.insert("Size".into(), Value::from(size));
        meta.insert("Visibility".into(), Value::from("private"));
        store.put_meta(&meta).map_err(internal_error)?;
        Ok(())
    })
    .await;
    match r {
        Ok(()) => text(StatusCode::OK, url_for(&s, &headers, &hash)),
        Err(e) => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normpath_like_abspath() {
        assert_eq!(normpath(std::path::Path::new("/a/b/../c/./d")), b"/a/c/d");
        assert_eq!(normpath(std::path::Path::new("/a/../../x")), b"/x");
        assert_eq!(normpath(std::path::Path::new("//a")), b"//a");
    }
}
