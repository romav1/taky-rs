//! mgmt socket client shared by `status` and `kickban` (`cli/status_cmd.py`,
//! `cli/kickban_cmd.py`; spec dps-cli-config §7.4–§7.5, server side `cot-server.md` §13).
//!
//! Protocol as the original: connect to the unix socket, send `json.dumps(req)` + `\0`, read
//! (1 s recv timeout, 5 s overall, counted from before the connect) until a `\0` is seen or the
//! peer closes; the reply is `data[:-1]` (everything but the last byte) decoded as UTF-8 JSON.
//! Error reporting (streams and texts) is the original's; JSON/UTF-8 error details come from
//! `serde_json` / a CPython-like UTF-8 message (not normative, like D-24).

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;
use taky_common::pyjson::{DumpOpts, dumps};
use taky_config::load_config_in;

use crate::build_client::printed_config_error;
use crate::pyerr::none_path;

/// Overall reply deadline (`while (time.time() - start) < 5`).
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-recv timeout (`sock.settimeout(1)`).
pub const RECV_TIMEOUT: Duration = Duration::from_secs(1);

/// Socket file name inside `taky.root_dir`.
pub const MGMT_SOCKET: &str = "taky-mgmt.sock";

/// Outcome of a mgmt exchange that did not produce a JSON reply.
#[derive(Debug)]
pub enum MgmtError {
    /// `socket.error` (connect/send/recv); `ENOENT` is the "Is taky running?" case.
    Io(io::Error),
    /// No `\0` before the peer closed or the deadline passed.
    NoResponse,
    /// `UnicodeDecodeError` / `JSONDecodeError` text.
    InvalidData(String),
}

/// `str(UnicodeDecodeError)` for `bytes.decode()` (CPython-like; single-byte form).
fn utf8_error_text(data: &[u8], e: &std::str::Utf8Error) -> String {
    let pos = e.valid_up_to();
    let b = data.get(pos).copied().unwrap_or(0);
    let reason = match e.error_len() {
        None => "unexpected end of data",
        Some(_) if (0xc2..=0xf4).contains(&b) => "invalid continuation byte",
        Some(_) => "invalid start byte",
    };
    format!("'utf-8' codec can't decode byte 0x{b:02x} in position {pos}: {reason}")
}

/// Sends `req` and returns the parsed reply.
pub fn request(socket: &Path, req: &Value) -> Result<Value, MgmtError> {
    let start = Instant::now();
    let mut sock = UnixStream::connect(socket).map_err(|e| {
        if e.kind() == io::ErrorKind::InvalidInput {
            // CPython: `OSError("AF_UNIX path too long")` (no errno).
            MgmtError::Io(io::Error::other("AF_UNIX path too long"))
        } else {
            MgmtError::Io(e)
        }
    })?;
    let mut frame = dumps(req, &DumpOpts::default()).into_bytes();
    frame.push(0);
    sock.write_all(&frame).map_err(MgmtError::Io)?;
    sock.set_read_timeout(Some(RECV_TIMEOUT))
        .map_err(MgmtError::Io)?;

    let (mut data, mut done, mut buf) = (Vec::new(), false, [0u8; 4096]);
    while start.elapsed() < TOTAL_TIMEOUT {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                if data.contains(&0) {
                    done = true;
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(MgmtError::Io(e)),
        }
    }
    let _ = sock.shutdown(std::net::Shutdown::Both);
    if !done {
        return Err(MgmtError::NoResponse);
    }
    data.pop(); // `data[:-1]`
    let text = std::str::from_utf8(&data)
        .map_err(|e| MgmtError::InvalidData(utf8_error_text(&data, &e)))?;
    serde_json::from_str(text).map_err(|e| MgmtError::InvalidData(e.to_string()))
}

/// Prints `e` the way the original's `except` clauses do; returns the exit code (1).
pub fn report(
    e: &MgmtError,
    socket: &Path,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<u8> {
    match e {
        MgmtError::NoResponse => writeln!(err, "ERROR: No response from server")?,
        MgmtError::InvalidData(m) => writeln!(err, "ERROR: Invalid data in response: {m}")?,
        MgmtError::Io(io) if io.raw_os_error() == Some(2) => {
            writeln!(
                err,
                "ERROR: Unable to connect to mgmt socket: {}",
                socket.display()
            )?;
            writeln!(err, "       Is taky running?")?;
        }
        MgmtError::Io(io) => {
            let text = match io.raw_os_error() {
                Some(n) => format!("[Errno {n}] {}", nix::errno::Errno::from_raw(n).desc()),
                None => io.to_string(),
            };
            writeln!(out, "ERROR: Socket error: {text}")?;
            if matches!(io.raw_os_error(), Some(2 | 111)) {
                writeln!(err, "       Is taky running?")?;
            }
        }
    }
    Ok(1)
}

/// `load_config(args.cfg_file)` + the default socket path; `Ok(Err(code))` = printed config
/// error (exit code), `Err` = the "failed" path.
pub fn resolve_socket(
    socket: Option<&Path>,
    cfg_file: Option<&Path>,
    cwd: &Path,
    err: &mut dyn Write,
) -> anyhow::Result<Result<PathBuf, u8>> {
    let cfg = match load_config_in(cfg_file, false, cwd) {
        Ok(c) => c,
        Err(e) if printed_config_error(&e) => {
            writeln!(err, "{e}")?;
            return Ok(Err(1));
        }
        Err(e) => return Err(e.into()),
    };
    // `-U` is used as given (relative to the process cwd); `root_dir` is absolute here.
    if let Some(s) = socket {
        return Ok(Ok(s.to_path_buf()));
    }
    let root = cfg.raw().get("taky", "root_dir")?.ok_or_else(none_path)?;
    Ok(Ok(PathBuf::from(crate::fsutil::join(&root, MGMT_SOCKET))))
}

/// Python `type(v).__name__` of a JSON value.
pub fn py_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_i64() || n.is_u64() || is_int_text(&n.to_string()) => "int",
        Value::Number(_) => "float",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

fn is_int_text(s: &str) -> bool {
    let d = s.strip_prefix('-').unwrap_or(s);
    !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())
}

/// `f"{v:040x}"` for a JSON integer of any size (`arbitrary_precision`).
pub fn hex040(v: &Value) -> anyhow::Result<String> {
    let text = match v {
        Value::Bool(b) => u8::from(*b).to_string(),
        Value::Number(n) if is_int_text(&n.to_string()) => n.to_string(),
        other => anyhow::bail!(
            "Unknown format code 'x' for object of type '{}'",
            py_type(other)
        ),
    };
    let (neg, digits) = match text.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, text.as_str()),
    };
    // Decimal → base 2^32 limbs (little endian).
    let mut limbs: Vec<u32> = vec![0];
    for d in digits.bytes() {
        let mut carry = u64::from(d - b'0');
        for l in &mut limbs {
            let x = u64::from(*l) * 10 + carry;
            *l = (x & 0xffff_ffff) as u32;
            carry = x >> 32;
        }
        if carry > 0 {
            limbs.push(carry as u32);
        }
    }
    let mut hex: String = limbs.iter().rev().map(|l| format!("{l:08x}")).collect();
    let trimmed = hex.trim_start_matches('0');
    hex = if trimmed.is_empty() {
        "0".into()
    } else {
        trimmed.into()
    };
    let neg = neg && hex != "0";
    let width = if neg { 39 } else { 40 };
    Ok(format!("{}{hex:0>width$}", if neg { "-" } else { "" }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hex040_bigint() {
        let v: Value =
            serde_json::from_str("1148112432542345069093428530316431016766373781528").unwrap();
        assert_eq!(
            hex040(&v).unwrap(),
            "c91b245c67e94578f256a66fbd3190c75ea26018"
        );
        assert_eq!(hex040(&json!(255)).unwrap(), format!("{:0>40}", "ff"));
        assert_eq!(hex040(&json!(0)).unwrap(), "0".repeat(40));
        assert_eq!(hex040(&json!(-5)).unwrap(), format!("-{:0>39}", "5"));
        assert!(hex040(&json!(1.5)).is_err());
        assert!(hex040(&json!("ab")).is_err());
    }

    #[test]
    fn utf8_text() {
        let d: Vec<u8> = vec![0xff];
        let e = std::str::from_utf8(&d).unwrap_err();
        assert_eq!(
            utf8_error_text(&d, &e),
            "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"
        );
    }

    #[test]
    fn missing_socket_and_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("none.sock");
        let e = request(&p, &json!({"cmd": "status"})).unwrap_err();
        let (mut o, mut er) = (Vec::new(), Vec::new());
        assert_eq!(report(&e, &p, &mut o, &mut er).unwrap(), 1);
        assert!(o.is_empty());
        assert_eq!(
            String::from_utf8(er).unwrap(),
            format!(
                "ERROR: Unable to connect to mgmt socket: {}\n       Is taky running?\n",
                p.display()
            )
        );

        // A stale socket file nobody listens on: ECONNREFUSED on stdout + hint on stderr.
        drop(std::os::unix::net::UnixListener::bind(&p).unwrap());
        let e = request(&p, &json!({"cmd": "status"})).unwrap_err();
        let (mut o, mut er) = (Vec::new(), Vec::new());
        report(&e, &p, &mut o, &mut er).unwrap();
        assert_eq!(
            String::from_utf8(o).unwrap(),
            "ERROR: Socket error: [Errno 111] Connection refused\n"
        );
        assert_eq!(String::from_utf8(er).unwrap(), "       Is taky running?\n");
    }

    #[test]
    fn reply_framing() {
        use std::os::unix::net::UnixListener;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("m.sock");
        let l = UnixListener::bind(&p).unwrap();
        let t = std::thread::spawn(move || {
            for reply in [&b"{\"a\": 1}\0"[..], b"{\"a\"", b"\xff\0", b"[1,\0"] {
                let (mut s, _) = l.accept().unwrap();
                let mut buf = [0u8; 64];
                let n = s.read(&mut buf).unwrap();
                assert_eq!(
                    &buf[..n],
                    b"{\"cmd\": \"kickban\", \"user\": \"\\u00e9\"}\0"
                );
                s.write_all(reply).unwrap();
            }
        });
        let req = json!({"cmd": "kickban", "user": "é"});
        assert_eq!(request(&p, &req).unwrap(), json!({"a": 1}));
        assert!(matches!(request(&p, &req), Err(MgmtError::NoResponse)));
        assert!(matches!(request(&p, &req), Err(MgmtError::InvalidData(m)) if m.contains("0xff")));
        assert!(matches!(request(&p, &req), Err(MgmtError::InvalidData(_))));
        t.join().unwrap();
    }
}
