//! HTTP application: route table, Flask/Werkzeug-compatible framework responses, `requires_auth`
//! (ADR-004, spec dps-cli-config §2.2–§2.4).
//!
//! Routing is axum, built from one static table ([`ROUTES`]) that also drives the Werkzeug quirks
//! axum does not have: `Allow` on 405, automatic `OPTIONS`, leading-slash stripping and the
//! merge-slashes 308 redirect ([`pre_route`]).

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::{FromRequestParts, State};
use axum::http::header::{ALLOW, CONTENT_TYPE, HOST, LOCATION};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get, post, put};
use serde_json::{Value, json};
use taky_common::SharedClock;

/// Flask's default content type for `str` responses and framework error pages.
pub const TEXT_HTML: &str = "text/html; charset=utf-8";

/// Version string served by `/Marti/api/version` (ADR-008 G-3: `taky-rs-<semver>`).
pub fn version_string() -> String {
    format!("taky-rs-{}", taky_common::VERSION)
}

/// Per-process application data (Python `app.config`).
#[derive(Clone)]
pub(crate) struct AppState {
    pub hostname: String,
    pub node_id: String,
    /// `ssl:<hostname>:<cot port>` or `tcp:<hostname>:<cot port>`.
    pub cot_conn_str: String,
    /// `dp_server.upload_path` (S-317).
    #[allow(dead_code)]
    pub upload_path: PathBuf,
    /// Clock for `SubmissionDateTime` (S-317).
    #[allow(dead_code)]
    pub clock: SharedClock,
}

/// Every Flask rule of the original: path pattern (`{x}` = one non-empty segment, Werkzeug's
/// default converter) and the declared methods (HEAD is implied by GET, OPTIONS is automatic).
pub(crate) const ROUTES: &[(&str, &[&str])] = &[
    ("/", &["GET"]),
    ("/Marti/api/version", &["GET"]),
    ("/Marti/api/version/config", &["GET"]),
    ("/Marti/api/clientEndPoints", &["GET"]),
    ("/Marti/sync/search", &["GET"]),
    ("/Marti/sync/content", &["GET"]),
    ("/Marti/sync/missionupload", &["POST"]),
    ("/Marti/api/sync/metadata/{hash}/tool", &["PUT"]),
    ("/Marti/sync/missionquery", &["GET"]),
    ("/Marti/TracksKML", &["POST"]),
    ("/Marti/ExportMissionKML", &["GET"]),
    ("/Marti/vcm", &["GET", "POST"]),
];

/// Declared methods of the rule matching `path`, if any.
pub(crate) fn route_methods(path: &str) -> Option<&'static [&'static str]> {
    let segs: Vec<&str> = path.split('/').collect();
    ROUTES.iter().find_map(|(pat, methods)| {
        let pats: Vec<&str> = pat.split('/').collect();
        let ok = pats.len() == segs.len()
            && pats.iter().zip(&segs).all(|(p, s)| {
                if p.starts_with('{') {
                    !s.is_empty()
                } else {
                    p == s
                }
            });
        ok.then_some(*methods)
    })
}

/// Werkzeug `Allow` value: declared methods + HEAD (with GET) + OPTIONS. Werkzeug emits a set in
/// arbitrary order; we sort for determinism (the order is not normative).
pub(crate) fn allow_header(methods: &[&str]) -> String {
    let mut all: Vec<&str> = methods.to_vec();
    if methods.contains(&"GET") {
        all.push("HEAD");
    }
    all.push("OPTIONS");
    all.sort_unstable();
    all.dedup();
    all.join(", ")
}

fn method_allowed(methods: &[&str], m: &Method) -> bool {
    methods.contains(&m.as_str())
        || (*m == Method::HEAD && methods.contains(&"GET"))
        || *m == Method::OPTIONS
}

/// A `str` view result: `200`-style text with Flask's content type.
pub(crate) fn text(status: StatusCode, body: impl Into<String>) -> Response {
    (status, [(CONTENT_TYPE, TEXT_HTML)], body.into()).into_response()
}

/// Werkzeug `HTTPException` page (`<!doctype html>` body as Werkzeug 2.x/3.x renders it).
pub(crate) fn error_page(status: StatusCode) -> Response {
    let (name, desc) = match status {
        StatusCode::UNAUTHORIZED => (
            "Unauthorized",
            "The server could not verify that you are authorized to access the URL requested. You \
             either supplied the wrong credentials (e.g. a bad password), or your browser \
             doesn&#39;t understand how to supply the credentials required.",
        ),
        StatusCode::FORBIDDEN => (
            "Forbidden",
            "You don&#39;t have the permission to access the requested resource. It is either \
             read-protected or not readable by the server.",
        ),
        StatusCode::NOT_FOUND => (
            "Not Found",
            "The requested URL was not found on the server. If you entered the URL manually \
             please check your spelling and try again.",
        ),
        StatusCode::METHOD_NOT_ALLOWED => (
            "Method Not Allowed",
            "The method is not allowed for the requested URL.",
        ),
        _ => (
            "Internal Server Error",
            "The server encountered an internal error and was unable to complete your request. \
             Either the server is overloaded or there is an error in the application.",
        ),
    };
    let code = status.as_u16();
    text(
        status,
        format!(
            "<!doctype html>\n<html lang=en>\n<title>{code} {name}</title>\n<h1>{name}</h1>\n<p>{desc}</p>\n"
        ),
    )
}

fn method_not_allowed(allow: &str) -> Response {
    let mut r = error_page(StatusCode::METHOD_NOT_ALLOWED);
    if let Ok(v) = HeaderValue::from_str(allow) {
        r.headers_mut().insert(ALLOW, v);
    }
    r
}

fn auto_options(allow: &str) -> Response {
    let mut r = text(StatusCode::OK, "");
    if let Ok(v) = HeaderValue::from_str(allow) {
        r.headers_mut().insert(ALLOW, v);
    }
    r
}

/// Flask 2.x `jsonify` of a dict: `application/json`, sorted keys, compact separators,
/// `ensure_ascii`, trailing `\n`.
// TODO(dev02): switch to `taky_common::pyjson::dumps` once T-21 implements it (still todo!()).
pub(crate) fn jsonify(v: &Value) -> Response {
    let mut s = String::new();
    write_json(v, &mut s);
    s.push('\n');
    (StatusCode::OK, [(CONTENT_TYPE, "application/json")], s).into_response()
}

fn write_json(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_json_str(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_str(k, out);
                out.push(':');
                if let Some(x) = m.get(k) {
                    write_json(x, out);
                }
            }
            out.push('}');
        }
    }
}

fn write_json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `@requires_auth`: decided **only from headers** (one code path for TLS and plain mode; the
/// connection layer has already applied the identity header policy).
/// No non-empty `X-USER` ⇒ 401; a non-empty `X-REVOKED` ⇒ 403.
#[derive(Debug, Clone)]
pub struct RequireAuth {
    /// `X-USER` (several header lines joined with `,`, as WSGI does).
    pub user: String,
}

fn joined(h: &HeaderMap, name: &str) -> String {
    h.get_all(name)
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .collect::<Vec<_>>()
        .join(",")
}

impl<S: Send + Sync> FromRequestParts<S> for RequireAuth {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let user = joined(&parts.headers, "x-user");
        if user.is_empty() {
            return Err(error_page(StatusCode::UNAUTHORIZED));
        }
        if !joined(&parts.headers, "x-revoked").is_empty() {
            return Err(error_page(StatusCode::FORBIDDEN));
        }
        Ok(RequireAuth { user })
    }
}

type St = State<Arc<AppState>>;

async fn index() -> Response {
    text(StatusCode::OK, "Hello, world!")
}

async fn version() -> Response {
    text(StatusCode::OK, version_string())
}

async fn version_config(State(s): St) -> Response {
    jsonify(&json!({
        "version": "2",
        "type": "ServerConfig",
        "data": {"version": version_string(), "api": "2", "hostname": s.hostname},
        "nodeId": s.node_id,
    }))
}

async fn client_endpoints(_auth: RequireAuth, State(s): St) -> Response {
    jsonify(&json!({
        "Matcher": "com.bbn.marti.remote.ClientEndpoint",
        "BaseUrl": "",
        "ServerConnectString": s.cot_conn_str,
        "NotificationId": "",
        "type": "com.bbn.marti.remote.ClientEndpoint",
        "data": [],
    }))
}

/// Placeholder for the endpoints of S-317/S-318 (auth is checked first, as in the original).
async fn not_implemented(_auth: RequireAuth) -> Response {
    text(StatusCode::NOT_IMPLEMENTED, "Not implemented")
}

fn handlers(pat: &str, m: &str) -> MethodRouter<Arc<AppState>> {
    match (pat, m) {
        ("/", _) => get(index),
        ("/Marti/api/version", _) => get(version),
        ("/Marti/api/version/config", _) => get(version_config),
        ("/Marti/api/clientEndPoints", _) => get(client_endpoints),
        (_, "POST") => post(not_implemented),
        (_, "PUT") => put(not_implemented),
        _ => get(not_implemented),
    }
}

/// The axum router: every rule of [`ROUTES`] with automatic OPTIONS, Werkzeug 405 (+ `Allow`)
/// for other methods, Werkzeug 404 for unknown paths.
pub(crate) fn router(state: Arc<AppState>) -> Router {
    let mut r = Router::new();
    for (pat, methods) in ROUTES {
        let mut mr: MethodRouter<Arc<AppState>> = MethodRouter::new();
        for m in *methods {
            mr = mr.merge(handlers(pat, m));
        }
        let allow = allow_header(methods);
        let allow2 = allow.clone();
        mr = mr
            .options(move || {
                let a = allow.clone();
                async move { auto_options(&a) }
            })
            .fallback(move || {
                let a = allow2.clone();
                async move { method_not_allowed(&a) }
            });
        r = r.route(pat, mr);
    }
    r.fallback(|| async { error_page(StatusCode::NOT_FOUND) })
        .with_state(state)
}

/// Werkzeug path handling before routing:
/// * leading slashes are stripped (`//Marti/x` is served as `/Marti/x` — the `url_for` double
///   slash ATAK requests, spec §2.3);
/// * any other `//` (merge_slashes): the merged path matches a rule and the method is allowed
///   ⇒ `308` to `<scheme>://<Host><merged>[?query]`; method not allowed ⇒ 405; no rule ⇒ 404.
pub(crate) fn pre_route<B>(mut req: Request<B>, scheme: &str) -> Result<Request<B>, Box<Response>> {
    let path = req.uri().path();
    let stripped = format!("/{}", path.trim_start_matches('/'));
    let query = req.uri().query().map(str::to_owned);
    if stripped.contains("//") {
        let mut merged = String::with_capacity(stripped.len());
        for c in stripped.chars() {
            if !(c == '/' && merged.ends_with('/')) {
                merged.push(c);
            }
        }
        let Some(methods) = route_methods(&merged) else {
            return Err(Box::new(error_page(StatusCode::NOT_FOUND)));
        };
        if !method_allowed(methods, req.method()) {
            return Err(Box::new(method_not_allowed(&allow_header(methods))));
        }
        let host = req
            .headers()
            .get(HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost");
        let mut loc = format!("{scheme}://{host}{merged}");
        if let Some(q) = query.as_deref().filter(|q| !q.is_empty()) {
            loc.push('?');
            loc.push_str(q);
        }
        let esc = html_escape(&loc);
        let mut r = text(
            StatusCode::PERMANENT_REDIRECT,
            format!(
                "<!doctype html>\n<html lang=en>\n<title>Redirecting...</title>\n<h1>Redirecting...</h1>\n\
                 <p>You should be redirected automatically to the target URL: <a href=\"{esc}\">{esc}</a>. \
                 If not, click the link.\n"
            ),
        );
        if let Ok(v) = HeaderValue::from_str(&loc) {
            r.headers_mut().insert(LOCATION, v);
        }
        return Err(Box::new(r));
    }
    if stripped != path {
        let pq = match &query {
            Some(q) => format!("{stripped}?{q}"),
            None => stripped,
        };
        let mut parts = req.uri().clone().into_parts();
        parts.path_and_query = pq.parse().ok();
        match Uri::from_parts(parts) {
            Ok(u) => *req.uri_mut() = u,
            Err(_) => return Err(Box::new(error_page(StatusCode::NOT_FOUND))),
        }
    }
    Ok(req)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonify_like_flask() {
        let v = json!({"b": 1, "a": "\u{fc}\n\u{1f600}\u{7f}", "c": [true, null]});
        let mut s = String::new();
        write_json(&v, &mut s);
        assert_eq!(
            s,
            "{\"a\":\"\\u00fc\\n\\ud83d\\ude00\\u007f\",\"b\":1,\"c\":[true,null]}"
        );
    }

    #[test]
    fn allow_and_route_table() {
        assert_eq!(allow_header(&["GET"]), "GET, HEAD, OPTIONS");
        assert_eq!(allow_header(&["POST"]), "OPTIONS, POST");
        assert_eq!(allow_header(&["GET", "POST"]), "GET, HEAD, OPTIONS, POST");
        assert_eq!(
            route_methods("/Marti/api/sync/metadata/abc/tool"),
            Some(&["PUT"][..])
        );
        assert_eq!(route_methods("/Marti/api/sync/metadata//tool"), None);
        assert_eq!(route_methods("/Marti/api/version/"), None);
        assert_eq!(route_methods("/"), Some(&["GET"][..]));
    }

    fn req(m: Method, uri: &str) -> Request<()> {
        Request::builder()
            .method(m)
            .uri(uri)
            .header(HOST, "h:8443")
            .body(())
            .unwrap()
    }

    #[test]
    fn leading_slashes_stripped() {
        let r = pre_route(req(Method::GET, "//Marti/sync/content?hash=x"), "https").unwrap();
        assert_eq!(r.uri().path(), "/Marti/sync/content");
        assert_eq!(r.uri().query(), Some("hash=x"));
        let r = pre_route(req(Method::GET, "///"), "https").unwrap();
        assert_eq!(r.uri().path(), "/");
    }

    #[test]
    fn merge_slashes_redirect_405_404() {
        let r = pre_route(req(Method::GET, "/Marti//api/version?x=1&y=%20"), "https").unwrap_err();
        assert_eq!(r.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            r.headers()[LOCATION],
            "https://h:8443/Marti/api/version?x=1&y=%20"
        );
        let r = pre_route(req(Method::POST, "/Marti//api/version"), "http").unwrap_err();
        assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(r.headers()[ALLOW], "GET, HEAD, OPTIONS");
        let r = pre_route(req(Method::GET, "/Marti/api/version//"), "http").unwrap_err();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }
}
