//! KML stubs (`taky/taky/dps/views/kml.py`, spec dps-cli-config §2.4, vector D014).

use std::fmt::Write as _;

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;

use crate::app::{RequireAuth, text};
use crate::video::{read_body, request_data};
use crate::werkzeug::parse_args;

/// Body of `GET /Marti/ExportMissionKML` (byte-exact with the original).
pub(crate) const EMPTY_KML: &str = "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\
<kml xmlns=\"http://www.opengis.net/kml/2.2\" xmlns:gx=\"http://www.google.com/kml/ext/2.2\"></kml>";

/// Upper bound for the body we read just to echo it (the original prints the whole body).
const TRACKS_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// POST `/Marti/TracksKML`: prints `request.args` and `request.data` to stdout (Python `print`),
/// answers `200` empty.
pub(crate) async fn tracks_kml(
    _auth: RequireAuth,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let raw = read_body(body, TRACKS_BODY_LIMIT).await.unwrap_or_default();
    if crate::stdout_enabled() {
        let args = parse_args(uri.query());
        crate::stdout_line(&format!(
            "{}\n{}",
            multidict_repr(&args),
            bytes_repr(request_data(&headers, &raw))
        ));
    }
    text(StatusCode::OK, "")
}

/// GET `/Marti/ExportMissionKML`: a fixed empty KML document as `text/html`.
pub(crate) async fn export_mission_kml(_auth: RequireAuth) -> Response {
    text(StatusCode::OK, EMPTY_KML)
}

/// `repr(ImmutableMultiDict(...))`.
fn multidict_repr(args: &[(String, String)]) -> String {
    let items: Vec<String> = args
        .iter()
        .map(|(k, v)| format!("({}, {})", str_repr(k), str_repr(v)))
        .collect();
    format!("ImmutableMultiDict([{}])", items.join(", "))
}

/// Python `repr(str)` (printable approximated as "not a control character").
fn str_repr(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => {
                let n = u32::from(c);
                let _ = if n < 0x100 {
                    write!(out, "\\x{n:02x}")
                } else {
                    write!(out, "\\u{n:04x}")
                };
            }
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

/// Python `repr(bytes)`.
fn bytes_repr(b: &[u8]) -> String {
    let q = if b.contains(&b'\'') && !b.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = String::from("b");
    out.push(char::from(q));
    for &c in b {
        match c {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(char::from(c));
            }
            0x20..=0x7e => out.push(char::from(c)),
            c => {
                let _ = write!(out, "\\x{c:02x}");
            }
        }
    }
    out.push(char::from(q));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_reprs() {
        assert_eq!(bytes_repr(b"x"), "b'x'");
        assert_eq!(bytes_repr(b"a'b\n\xff"), "b\"a'b\\n\\xff\"");
        assert_eq!(bytes_repr(b"'\""), "b'\\'\"'");
        assert_eq!(
            multidict_repr(&[
                ("format".into(), "kmz".into()),
                ("k".into(), "é\u{1}".into())
            ]),
            "ImmutableMultiDict([('format', 'kmz'), ('k', 'é\\x01')])"
        );
        assert_eq!(multidict_repr(&[]), "ImmutableMultiDict([])");
    }
}
