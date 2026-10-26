//! `takyctl-rs status` (`cli/status_cmd.py`, `util/__init__.py` `seconds_to_human` /
//! `pprinttable`; spec dps-cli-config §7.4, compat 1.4.10).
//!
//! Output byte for byte as the original. D-17 (OQ-L3): where `pprinttable` would raise
//! `TypeError` (a column whose longest `str()` value is not a string — `None` IPs of
//! anonymous clients), the `None` cells of that column are printed empty instead. When Python
//! does not crash (some IP is longer than `"None"`), an anonymous client's IP is `None`, as in
//! the original.

use std::io::Write;
use std::path::Path;

use serde_json::Value;
use taky_common::pyjson::{DumpOpts, dumps, float_repr};

use crate::cli::StatusArgs;
use crate::mgmt::{self, py_type};

/// Python `float(v)` of a JSON number (`TypeError` text otherwise).
fn num(v: &Value, op: &str) -> anyhow::Result<f64> {
    match v {
        Value::Number(n) => n
            .to_string()
            .parse::<f64>()
            .map_err(|e| anyhow::anyhow!("{e}")),
        Value::Bool(b) => Ok(f64::from(u8::from(*b))),
        other => anyhow::bail!(
            "unsupported operand type(s) for {op}: '{}' and 'int'",
            py_type(other)
        ),
    }
}

/// CPython `float.__floordiv__` (`float_floor_div` / `_float_div_mod`).
fn floordiv(a: f64, b: f64) -> f64 {
    let m = a % b;
    let mut div = (a - m) / b;
    if m != 0.0 && ((b < 0.0) != (m < 0.0)) {
        div -= 1.0;
    }
    if div != 0.0 {
        let f = div.floor();
        if div - f > 0.5 { f + 1.0 } else { f }
    } else {
        0.0_f64.copysign(a / b)
    }
}

/// `"%d" % x` for a float (`int(x)`, truncation).
fn pct_d(x: f64) -> String {
    format!("{}", x.trunc() as i128)
}

/// `seconds_to_human(sec)` (`util/__init__.py:6-29`).
pub fn seconds_to_human(sec: f64) -> String {
    let mut sec = sec;
    let days = floordiv(sec, 86400.0);
    sec -= days * 86400.0;
    let hours = floordiv(sec, 3600.0);
    sec -= hours * 3600.0;
    let minutes = floordiv(sec, 60.0);
    sec -= minutes * 60.0;
    let mut ret = format!("{:0>2}h {:0>2}m {sec:06.3}s", pct_d(hours), pct_d(minutes));
    if days > 0.0 {
        ret = format!("{}d {ret}", pct_d(days));
    }
    ret
}

/// One table cell: `str(x)` and whether `len(x)` works (a Python `str`).
#[derive(Debug, Clone, PartialEq)]
pub struct Cell {
    text: String,
    sized: bool,
    none: bool,
}

impl Cell {
    /// A Python `str`.
    pub fn s(t: impl Into<String>) -> Cell {
        Cell {
            text: t.into(),
            sized: true,
            none: false,
        }
    }

    /// `str()` of an arbitrary JSON value as a cell.
    pub fn of(v: &Value) -> Cell {
        match v {
            Value::String(s) => Cell::s(s.clone()),
            Value::Null => Cell {
                text: "None".into(),
                sized: false,
                none: true,
            },
            Value::Bool(b) => Cell {
                text: if *b { "True" } else { "False" }.into(),
                sized: false,
                none: false,
            },
            Value::Number(n) => {
                let t = n.to_string();
                let text = if py_type(v) == "int" {
                    t
                } else {
                    t.parse::<f64>().map(float_repr).unwrap_or(t)
                };
                Cell {
                    text,
                    sized: false,
                    none: false,
                }
            }
            other => Cell {
                // list/dict: sized in Python; repr approximated by json.dumps.
                text: dumps(other, &DumpOpts::default()),
                sized: true,
                none: false,
            },
        }
    }
}

/// `pprinttable(rows)` (`util/__init__.py:32-63`) with the D-17 fix; returns the lines.
pub fn pprinttable(headers: &[&str], rows: &[Vec<Cell>]) -> Vec<String> {
    let ncol = headers.len();
    let mut rows: Vec<Vec<Cell>> = rows.to_vec();
    let mut lens = Vec::with_capacity(ncol);
    for i in 0..ncol {
        // `max(column + [header], key=lambda x: len(str(x)))` — the first maximum wins.
        let width = |rows: &[Vec<Cell>]| -> (usize, bool) {
            let mut best: Option<&Cell> = None;
            let hdr = Cell::s(headers[i]);
            for c in rows.iter().map(|r| &r[i]).chain(std::iter::once(&hdr)) {
                if best.is_none_or(|b| c.text.chars().count() > b.text.chars().count()) {
                    best = Some(c);
                }
            }
            best.map_or((0, true), |b| (b.text.chars().count(), b.sized))
        };
        let (mut n, sized) = width(&rows);
        if !sized {
            // Python: `len(None)` → TypeError. D-17: print None cells empty.
            for r in &mut rows {
                if r[i].none {
                    r[i] = Cell::s("");
                }
            }
            n = rows
                .iter()
                .map(|r| r[i].text.chars().count())
                .chain(std::iter::once(headers[i].chars().count()))
                .max()
                .unwrap_or(0);
        }
        lens.push(n);
    }
    let line = |cells: Vec<&str>| -> String {
        cells
            .iter()
            .zip(&lens)
            .map(|(c, w)| format!("{c:<w$}"))
            .collect::<Vec<_>>()
            .join(" | ")
    };
    let mut out = vec![
        line(headers.to_vec()),
        lens.iter()
            .map(|n| "-".repeat(*n))
            .collect::<Vec<_>>()
            .join("-+-"),
    ];
    for r in &rows {
        out.push(line(r.iter().map(|c| c.text.as_str()).collect()));
    }
    out
}

fn get<'a>(obj: &'a Value, k: &str) -> anyhow::Result<Option<&'a Value>> {
    match obj {
        Value::Object(m) => Ok(m.get(k)),
        other => anyhow::bail!("'{}' object has no attribute 'get'", py_type(other)),
    }
}

/// `print_status(stat)`; `now` = `time.time()`.
pub fn print_status(stat: &Value, now: f64, out: &mut dyn Write) -> anyhow::Result<()> {
    let minus1 = Value::from(-1);
    let uptime = get(stat, "uptime")?.unwrap_or(&minus1);
    writeln!(out, "Uptime: {}", seconds_to_human(num(uptime, "//")?))?;
    let nc = get(stat, "num_clients")?.unwrap_or(&minus1);
    let nc = num(nc, "%d")?;
    writeln!(out, "Num Clients: {}", pct_d(nc))?;
    writeln!(out)?;

    let clients = match get(stat, "clients")? {
        Some(Value::Array(a)) => a,
        Some(Value::Object(m)) if m.is_empty() => return Ok(()),
        Some(Value::String(s)) if s.is_empty() => return Ok(()),
        Some(other) => anyhow::bail!("object of type '{}' has no len()", py_type(other)),
        None => anyhow::bail!("object of type 'NoneType' has no len()"),
    };
    if clients.is_empty() {
        return Ok(());
    }
    let zero = Value::from(0);
    let mut table = Vec::new();
    for c in clients {
        let conn_len = now - num(get(c, "connected")?.unwrap_or(&zero), "-")?;
        let (cs, uid) = if get(c, "anonymous")? == Some(&Value::Bool(true)) {
            (Cell::s("(anonymous)"), Cell::s("(anonymous)"))
        } else {
            (
                Cell::of(get(c, "callsign")?.unwrap_or(&Value::Null)),
                Cell::of(get(c, "uid")?.unwrap_or(&Value::Null)),
            )
        };
        let last_rx = num(get(c, "last_rx")?.unwrap_or(&zero), ">")?;
        let last_rx = if last_rx > 0.0 {
            seconds_to_human(now - last_rx)
        } else {
            "never".to_owned()
        };
        table.push(vec![
            cs,
            uid,
            Cell::s(seconds_to_human(conn_len)),
            Cell::of(get(c, "ip")?.unwrap_or(&Value::Null)),
            Cell::s(last_rx),
        ]);
    }
    for l in pprinttable(&["Callsign", "UID", "Connected", "IP", "LastRx"], &table) {
        writeln!(out, "{l}")?;
    }
    Ok(())
}

/// `time.time()`.
pub fn now_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// Runs `status`; returns the exit code. `Err` ⇒ the "failed" path.
pub fn status(
    args: &StatusArgs,
    cfg_file: Option<&Path>,
    cwd: &Path,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    let socket = match mgmt::resolve_socket(args.socket.as_deref(), cfg_file, cwd, err)? {
        Ok(s) => s,
        Err(code) => return Ok(code),
    };
    let stat = match mgmt::request(&socket, &serde_json::json!({"cmd": "status"})) {
        Ok(v) => v,
        Err(e) => return Ok(mgmt::report(&e, &socket, out, err)?),
    };
    if args.json {
        writeln!(out, "{}", dumps(&stat, &DumpOpts::default()))?;
    } else {
        print_status(&stat, now_epoch(), out)?;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn seconds_to_human_like_python() {
        // Values from `python3 -c 'from taky.util import seconds_to_human as f; ...'`.
        assert_eq!(seconds_to_human(2.959), "00h 00m 02.959s");
        assert_eq!(seconds_to_human(142.0), "00h 02m 22.000s");
        assert_eq!(seconds_to_human(86400.0 + 3661.5), "1d 01h 01m 01.500s");
        assert_eq!(seconds_to_human(3.0 * 86400.0), "3d 00h 00m 00.000s");
        assert_eq!(seconds_to_human(-1.0), "23h 59m 59.000s");
        assert_eq!(seconds_to_human(59.9996), "00h 00m 60.000s");
    }

    fn render(stat: &Value, now: f64) -> String {
        let mut o = Vec::new();
        print_status(stat, now, &mut o).unwrap();
        String::from_utf8(o).unwrap()
    }

    #[test]
    fn table_golden() {
        let stat = json!({"uptime": 2.959, "num_clients": 2, "clients": [
            {"last_rx": 997.0, "num_rx": 3, "connected": 935.0, "ip": "127.0.0.1",
             "uid": "ANDROID-A", "callsign": "ALPHA", "group": "Teams.CYAN"},
            {"last_rx": 0, "num_rx": 0, "connected": 990.0, "anonymous": true}]});
        assert_eq!(
            render(&stat, 1000.0),
            "Uptime: 00h 00m 02.959s\nNum Clients: 2\n\n\
             Callsign    | UID         | Connected       | IP        | LastRx         \n\
             ------------+-------------+-----------------+-----------+----------------\n\
             ALPHA       | ANDROID-A   | 00h 01m 05.000s | 127.0.0.1 | 00h 00m 03.000s\n\
             (anonymous) | (anonymous) | 00h 00m 10.000s | None      | never          \n"
        );
    }

    #[test]
    fn d17_all_anonymous() {
        let stat = json!({"uptime": 1.0, "num_clients": 1, "clients": [
            {"last_rx": 0, "num_rx": 0, "connected": 999.0, "anonymous": true}]});
        assert_eq!(
            render(&stat, 1000.0),
            "Uptime: 00h 00m 01.000s\nNum Clients: 1\n\n\
             Callsign    | UID         | Connected       | IP | LastRx\n\
             ------------+-------------+-----------------+----+-------\n\
             (anonymous) | (anonymous) | 00h 00m 01.000s |    | never \n"
        );
    }

    #[test]
    fn no_clients_and_bad_shapes() {
        assert_eq!(
            render(
                &json!({"uptime": 0.5, "num_clients": 0, "clients": []}),
                0.0
            ),
            "Uptime: 00h 00m 00.500s\nNum Clients: 0\n\n"
        );
        let mut o = Vec::new();
        assert!(print_status(&json!([1]), 0.0, &mut o).is_err());
        assert!(print_status(&json!({"error": "x"}), 0.0, &mut o).is_err());
    }
}
