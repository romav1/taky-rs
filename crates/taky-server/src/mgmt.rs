//! Management socket (`taky/cot/mgmt.py`, spec §13): `{"cmd": ...}\0` → JSON reply `\0` on
//! the unix socket `{root_dir}/taky-mgmt.sock`.
//!
//! * Framing: requests are split at `\0`; several per connection, replies in order; the server
//!   never closes a connection on its own (except shutdown and the [`MGMT_MAX_FRAME`] guard).
//! * Replies are Python `json.dumps` (default separators, `ensure_ascii`) via
//!   [`taky_common::pyjson::dumps`]; `revoked_sns` are big integers (`arbitrary_precision`).
//! * D-9 (V046): the mgmt task only talks to the Hub through [`HubCmd::Mgmt`]; an open mgmt
//!   connection has no effect on CoT traffic.
//! * D-10 (V051): valid JSON that is not an object → `{"error": "Invalid cmd: None"}`.
//! * D-24 (V045): invalid UTF-8 / JSON → `{"error": "<serde_json error Display>"}`.
//!
//! `status` / `kickban` are answered by the Hub (it owns the client table and the cert-db);
//! see `Hub::mgmt`.

use std::path::Path;

use serde_json::Value;
use taky_common::pyjson::{DumpOpts, dumps};
use taky_common::{Shutdown, pylog};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tokio_util::task::TaskTracker;
use tracing::Level;

use crate::hub::{HubCmd, HubHandle};

const LGR: &str = "MgmtClient@unix:";

/// Upper bound of one request frame (Python buffers without a limit). A peer that sends more
/// without a `\0` is disconnected; real requests are a few dozen bytes.
pub const MGMT_MAX_FRAME: usize = 1024 * 1024;

/// A decoded mgmt request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MgmtRequest {
    /// `{"cmd": "status"}` → `uptime`, `num_clients`, `clients[]`.
    Status,
    /// `{"cmd": "ping"}` → `{"pong": "taky"}`.
    Ping,
    /// `{"cmd": "kickban", "user": ...}` → `{"revoked_sns": [int...]}` (big integers).
    Kickban {
        /// CN to revoke (`None` if the key is missing or not a string: matches no record).
        user: Option<String>,
    },
    /// Anything else → `{"error": "Invalid cmd: <cmd>"}`; `cmd` is the Python `str()` of the value.
    Invalid {
        /// Rendered `msg.get('cmd')`.
        cmd: String,
    },
}

impl MgmtRequest {
    /// Decode one message (without the trailing NUL). `Err` carries the text for
    /// `{"error": "<exc>"}` (UTF-8 / JSON errors: the serde_json error `Display`, D-24).
    pub fn parse(msg: &[u8]) -> Result<MgmtRequest, String> {
        let v: Value = serde_json::from_slice(msg).map_err(|e| e.to_string())?;
        // D-10: a non-object has no `.get`; Python crashed, Rust treats `cmd` as missing.
        let obj = v.as_object();
        let cmd = obj.and_then(|o| o.get("cmd"));
        Ok(match cmd {
            Some(Value::String(s)) if s == "status" => MgmtRequest::Status,
            Some(Value::String(s)) if s == "ping" => MgmtRequest::Ping,
            Some(Value::String(s)) if s == "kickban" => MgmtRequest::Kickban {
                user: obj
                    .and_then(|o| o.get("user"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            },
            other => MgmtRequest::Invalid {
                cmd: other.map_or_else(|| "None".to_owned(), py_str),
            },
        })
    }

    /// The reply to an [`MgmtRequest::Invalid`] request.
    pub fn invalid_reply(cmd: &str) -> Value {
        serde_json::json!({ "error": format!("Invalid cmd: {cmd}") })
    }
}

/// One reply frame: `json.dumps(v)` + `\0`.
pub fn reply_frame(v: &Value) -> Vec<u8> {
    let mut out = dumps(v, &DumpOpts::default()).into_bytes();
    out.push(0);
    out
}

/// Python `str(v)` of a `json.loads` value.
fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => py_repr(other),
    }
}

/// Python `repr(v)` of a `json.loads` value.
fn py_repr(v: &Value) -> String {
    match v {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Number(_) => dumps(v, &DumpOpts::default()),
        Value::String(s) => py_str_repr(s),
        Value::Array(a) => {
            let items: Vec<String> = a.iter().map(py_repr).collect();
            format!("[{}]", items.join(", "))
        }
        Value::Object(m) => {
            let items: Vec<String> = m
                .iter()
                .map(|(k, x)| format!("{}: {}", py_str_repr(k), py_repr(x)))
                .collect();
            format!("{{{}}}", items.join(", "))
        }
    }
}

/// Python `repr(str)`: single quotes unless the text has `'` and no `"`; escapes `\\`, the
/// quote, `\t\n\r`, other non-printable characters as `\xNN`/`\uNNNN`/`\UNNNNNNNN`.
fn py_str_repr(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c if is_py_printable(c) => out.push(c),
            c if (c as u32) < 0x100 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push(q);
    out
}

/// Approximation of `str.isprintable` (ASCII exact; non-ASCII: not a control/format/separator
/// other than the space, which covers the realistic `cmd` values).
fn is_py_printable(c: char) -> bool {
    if c.is_ascii() {
        return (' '..='~').contains(&c);
    }
    !(c.is_control()
        || c.is_whitespace()
        || matches!(c as u32, 0xad | 0x200b..=0x200f | 0x2028..=0x202e | 0x2060..=0x206f | 0xfeff | 0xd800..=0xdfff | 0xe000..=0xf8ff))
}

/// Accept mgmt connections until shutdown; one task per connection. The socket file is removed
/// when the loop ends.
pub(crate) async fn accept_loop(
    listener: UnixListener,
    hub: HubHandle,
    shutdown: Shutdown,
    conns: TaskTracker,
) {
    let path = listener
        .local_addr()
        .ok()
        .and_then(|a| a.as_pathname().map(Path::to_path_buf));
    loop {
        let accepted = tokio::select! {
            () = shutdown.wait() => break,
            r = listener.accept() => r,
        };
        match accepted {
            Ok((sock, _)) => {
                pylog!(LGR, Level::DEBUG, "New mgmt client");
                conns.spawn(serve(sock, hub.clone(), shutdown.clone()));
            }
            Err(e) => {
                pylog!(LGR, Level::INFO, "Mgmt connect failed ({e})");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
    drop(listener);
    if let Some(p) = path {
        let _ = std::fs::remove_file(p);
    }
}

/// Serve one mgmt connection: frames in, replies out, until EOF / error / shutdown.
async fn serve(mut sock: UnixStream, hub: HubHandle, shutdown: Shutdown) {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 4096];
    let reason = loop {
        let n = tokio::select! {
            () = shutdown.wait() => break "Server shutting down".to_owned(),
            r = sock.read(&mut chunk) => match r {
                Ok(0) => break "Client disconnected".to_owned(),
                Ok(n) => n,
                Err(e) => break e.to_string(),
            },
        };
        let scan_from = buf.len();
        buf.extend_from_slice(&chunk[..n]);
        let mut start = 0;
        let mut out = Vec::new();
        let mut from = scan_from;
        while let Some(i) = buf[from..].iter().position(|&b| b == 0) {
            let end = from + i;
            let reply = handle(&buf[start..end], &hub).await;
            out.extend_from_slice(&reply_frame(&reply));
            start = end + 1;
            from = start;
        }
        buf.drain(..start);
        if !out.is_empty()
            && let Err(e) = sock.write_all(&out).await
        {
            break e.to_string();
        }
        if buf.len() > MGMT_MAX_FRAME {
            break "Request too large".to_owned();
        }
    };
    pylog!(LGR, Level::DEBUG, "Socket disconnect: {reason}");
    let _ = sock.shutdown().await;
}

/// One request → its reply (the Hub answers everything that needs server state).
async fn handle(msg: &[u8], hub: &HubHandle) -> Value {
    let req = match MgmtRequest::parse(msg) {
        Ok(r) => r,
        Err(e) => return serde_json::json!({ "error": e }),
    };
    if let MgmtRequest::Invalid { cmd } = &req {
        return MgmtRequest::invalid_reply(cmd);
    }
    let (reply, rx) = oneshot::channel();
    if hub.send(HubCmd::Mgmt { req, reply }).await.is_err() {
        return serde_json::json!({ "error": "Server shutting down" });
    }
    rx.await
        .unwrap_or_else(|_| serde_json::json!({ "error": "Server shutting down" }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<MgmtRequest, String> {
        MgmtRequest::parse(s.as_bytes())
    }

    fn inv(s: &str) -> Result<MgmtRequest, String> {
        Ok(MgmtRequest::Invalid { cmd: s.to_owned() })
    }

    #[test]
    fn commands() {
        assert_eq!(p(r#"{"cmd": "ping"}"#), Ok(MgmtRequest::Ping));
        assert_eq!(p(r#"{"cmd":"status","x":1}"#), Ok(MgmtRequest::Status));
        assert_eq!(
            p(r#"{"cmd": "kickban", "user": "bob"}"#),
            Ok(MgmtRequest::Kickban {
                user: Some("bob".into())
            })
        );
        assert_eq!(
            p(r#"{"cmd": "kickban", "user": 5}"#),
            Ok(MgmtRequest::Kickban { user: None })
        );
        assert_eq!(
            p(r#"{"cmd": "kickban"}"#),
            Ok(MgmtRequest::Kickban { user: None })
        );
    }

    #[test]
    fn invalid_cmd_is_python_str() {
        assert_eq!(p(r#"{"cmd": "frobnicate"}"#), inv("frobnicate"));
        assert_eq!(p("{}"), inv("None"));
        assert_eq!(p(r#"{"cmd": null}"#), inv("None"));
        assert_eq!(p(r#"{"cmd": true}"#), inv("True"));
        assert_eq!(
            p(r#"{"cmd": 12345678901234567890123}"#),
            inv("12345678901234567890123")
        );
        assert_eq!(p(r#"{"cmd": 1.50}"#), inv("1.5"));
        assert_eq!(
            p(r#"{"cmd": ["a", 1, null, {"k": "it's"}]}"#),
            inv(r#"['a', 1, None, {'k': "it's"}]"#)
        );
        assert_eq!(p(r#"{"cmd": "STATUS"}"#), inv("STATUS"));
        // D-10: non-objects do not crash.
        assert_eq!(p("[]"), inv("None"));
        assert_eq!(p("1"), inv("None"));
        assert_eq!(p(r#""ping""#), inv("None"));
    }

    #[test]
    fn json_errors_are_serde_display() {
        // D-24 (V045 step 6, serde_json 1.0.154).
        assert_eq!(
            p("{not json"),
            Err("key must be a string at line 1 column 2".into())
        );
        assert!(MgmtRequest::parse(b"\xff").is_err());
        assert!(p("").is_err());
    }

    #[test]
    fn reply_is_python_json_dumps() {
        let v: Value = serde_json::from_str(
            r#"{"revoked_sns": [730750818665451459101842416358141509827966271488], "e": "é"}"#,
        )
        .unwrap();
        assert_eq!(
            reply_frame(&v),
            b"{\"revoked_sns\": [730750818665451459101842416358141509827966271488], \"e\": \"\\u00e9\"}\0"
        );
        assert_eq!(
            reply_frame(&MgmtRequest::invalid_reply("None")),
            b"{\"error\": \"Invalid cmd: None\"}\0"
        );
    }
}
