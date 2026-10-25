//! JSON output compatible with Python `json.dumps` / Flask `jsonify` (ARCHITECTURE §12).
//!
//! Byte-exact with CPython 3 `json.dumps(obj, sort_keys=?, separators=?, ensure_ascii=?)` for any
//! [`serde_json::Value`] (as Python would see it after `json.loads`):
//!
//! * strings: `\"`, `\\`, `\n`, `\r`, `\t`, `\b`, `\f`; other C0 controls as `\u00XX`; with
//!   `ensure_ascii` also everything outside `' '..='~'` (incl. DEL) as lowercase `\uXXXX`, astral
//!   characters as a UTF-16 surrogate pair;
//! * integers verbatim (any length — `arbitrary_precision`; `-0` is Python `int` `0`);
//! * floats as Python `float.__repr__` (shortest round-trip digits, exponent when the decimal
//!   point position is `<= -4` or `> 16`: `1e-05`, `1e+16`, `1.5`, `100.0`); a literal that
//!   overflows (`1e400`) is `Infinity`/`-Infinity` like `json.loads` + `json.dumps`;
//! * objects in insertion order (`preserve_order`) or sorted by key (code-point order, as
//!   Python `sorted` on `str`); `{}`/`[]` for empty containers.

use serde_json::{Number, Value};

/// Serialization parameters (a subset of the `json.dumps` arguments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpOpts {
    /// `sort_keys=True` (Flask `jsonify`); otherwise insertion order (`preserve_order`).
    pub sort_keys: bool,
    /// Compact separators `(",", ":")` (Flask) instead of `(", ", ": ")` (`json.dumps` default).
    pub compact: bool,
    /// `ensure_ascii=True`: everything outside ASCII as `\uXXXX`.
    pub ensure_ascii: bool,
    /// Trailing newline (Flask `jsonify` appends `\n`).
    pub trailing_newline: bool,
}

impl Default for DumpOpts {
    /// `json.dumps` defaults: `", "`/`": "`, `ensure_ascii`, no sorting.
    fn default() -> Self {
        DumpOpts {
            sort_keys: false,
            compact: false,
            ensure_ascii: true,
            trailing_newline: false,
        }
    }
}

impl DumpOpts {
    /// Flask 2.0 `jsonify` (`JSON_SORT_KEYS`, `JSON_AS_ASCII`, compact separators, `\n`).
    pub fn flask() -> Self {
        DumpOpts {
            sort_keys: true,
            compact: true,
            ensure_ascii: true,
            trailing_newline: true,
        }
    }
}

/// Serialize like Python (float as `repr`, arbitrary-length integers without loss).
pub fn dumps(v: &Value, opts: &DumpOpts) -> String {
    let mut out = String::new();
    write_value(v, opts, &mut out);
    if opts.trailing_newline {
        out.push('\n');
    }
    out
}

/// The body of a Flask 2.0 `jsonify(v)` response (`dumps(v, &DumpOpts::flask())`).
pub fn jsonify(v: &Value) -> String {
    dumps(v, &DumpOpts::flask())
}

fn write_value(v: &Value, opts: &DumpOpts, out: &mut String) {
    let (item_sep, key_sep) = if opts.compact {
        (",", ":")
    } else {
        (", ", ": ")
    };
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write_number(n, out),
        Value::String(s) => write_str(s, opts.ensure_ascii, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                write_value(x, opts, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut items: Vec<(&String, &Value)> = m.iter().collect();
            if opts.sort_keys {
                items.sort_by(|a, b| a.0.cmp(b.0));
            }
            out.push('{');
            for (i, (k, x)) in items.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(item_sep);
                }
                write_str(k, opts.ensure_ascii, out);
                out.push_str(key_sep);
                write_value(x, opts, out);
            }
            out.push('}');
        }
    }
}

fn write_number(n: &Number, out: &mut String) {
    let text = n.to_string();
    if text.contains(['.', 'e', 'E']) {
        // A JSON float literal: Python `float(text)`, then `float.__repr__`.
        match text.parse::<f64>() {
            Ok(f) => out.push_str(&float_repr(f)),
            Err(_) => out.push_str(&text),
        }
    } else if text.trim_start_matches('-').bytes().all(|b| b == b'0') {
        out.push('0'); // int("-0") == 0
    } else {
        out.push_str(&text);
    }
}

/// `float.__repr__` as `json.dumps` prints it (`NaN`, `Infinity`, `-Infinity` for non-finite).
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    // CPython `repr` = dtoa mode 0: the shortest digit string that round-trips and, among those,
    // the one closest to `f`. Rust `{:e}` gives the shortest *length* k but not always the closest
    // k-digit string (e.g. 178282446750899.12 → …13); the correctly rounded k-digit value
    // (`{:.(k-1)e}`, exact) is the closest and round-trips whenever some k-digit string does.
    let shortest = format!("{f:e}");
    let k = shortest
        .split_once('e')
        .map_or(shortest.as_str(), |(m, _)| m)
        .chars()
        .filter(char::is_ascii_digit)
        .count();
    let e = format!("{f:.prec$e}", prec = k.saturating_sub(1));
    let e = if e.parse::<f64>() == Ok(f) {
        e
    } else {
        shortest
    };
    let (mant, exp) = e.split_once('e').unwrap_or((e.as_str(), "0"));
    let neg = mant.starts_with('-');
    let mut digits: String = mant.chars().filter(char::is_ascii_digit).collect();
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    let exp: i64 = exp.parse().unwrap_or(0);
    let decpt = exp + 1; // value = 0.DIGITS × 10^decpt
    let nd = digits.len() as i64;
    let mut s = String::new();
    if neg {
        s.push('-');
    }
    if decpt <= -4 || decpt > 16 {
        s.push_str(&digits[..1]);
        if nd > 1 {
            s.push('.');
            s.push_str(&digits[1..]);
        }
        let x = decpt - 1;
        s.push_str(&format!("e{}{:02}", if x < 0 { '-' } else { '+' }, x.abs()));
    } else if decpt <= 0 {
        s.push_str("0.");
        s.extend(std::iter::repeat_n('0', (-decpt) as usize));
        s.push_str(&digits);
    } else if decpt >= nd {
        s.push_str(&digits);
        s.extend(std::iter::repeat_n('0', (decpt - nd) as usize));
        s.push_str(".0");
    } else {
        s.push_str(&digits[..decpt as usize]);
        s.push('.');
        s.push_str(&digits[decpt as usize..]);
    }
    s
}

fn write_str(s: &str, ensure_ascii: bool, out: &mut String) {
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
            c if (c as u32) < 0x20 || (ensure_ascii && (c as u32) > 0x7e) => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn py(v: &Value) -> String {
        dumps(v, &DumpOpts::default())
    }

    #[test]
    fn defaults_like_json_dumps() {
        let v = json!({"b": 1, "a": [true, null, "x"], "c": {}, "d": []});
        assert_eq!(
            py(&v),
            r#"{"b": 1, "a": [true, null, "x"], "c": {}, "d": []}"#
        );
        let sorted = DumpOpts {
            sort_keys: true,
            ..DumpOpts::default()
        };
        assert_eq!(
            dumps(&v, &sorted),
            r#"{"a": [true, null, "x"], "b": 1, "c": {}, "d": []}"#
        );
    }

    #[test]
    fn flask_jsonify() {
        // Same expectation as dev02's interim writer test (taky-dps app.rs).
        let v = json!({"b": 1, "a": "\u{fc}\n\u{1f600}\u{7f}", "c": [true, null]});
        assert_eq!(
            jsonify(&v),
            "{\"a\":\"\\u00fc\\n\\ud83d\\ude00\\u007f\",\"b\":1,\"c\":[true,null]}\n"
        );
    }

    #[test]
    fn strings() {
        let v = json!("\"\\/\u{0}\u{1f}\u{8}\u{c}\t\r\u{7f}\u{e9}\u{4e2d}");
        assert_eq!(py(&v), r#""\"\\/\u0000\u001f\b\f\t\r\u007f\u00e9\u4e2d""#);
        let raw = DumpOpts {
            ensure_ascii: false,
            ..DumpOpts::default()
        };
        assert_eq!(
            dumps(&v, &raw),
            "\"\\\"\\\\/\\u0000\\u001f\\b\\f\\t\\r\u{7f}\u{e9}\u{4e2d}\""
        );
    }

    #[test]
    fn numbers() {
        for (lit, want) in [
            ("0", "0"),
            ("-0", "0"),
            (
                "123456789012345678901234567890",
                "123456789012345678901234567890",
            ),
            ("-17", "-17"),
            ("1.0", "1.0"),
            ("-0.0", "-0.0"),
            ("1E2", "100.0"),
            ("0.1", "0.1"),
            ("1e16", "1e+16"),
            ("1e15", "1000000000000000.0"),
            ("123456789012345680000", "123456789012345680000"),
            ("1.2345678901234567e16", "1.2345678901234568e+16"),
            ("0.0001", "0.0001"),
            ("0.00001", "1e-05"),
            ("1.5e-7", "1.5e-07"),
            ("1e400", "Infinity"),
            ("-1e400", "-Infinity"),
            ("5e-324", "5e-324"),
            ("1.7976931348623157e308", "1.7976931348623157e+308"),
        ] {
            let v: Value = serde_json::from_str(lit).unwrap();
            assert_eq!(py(&v), want, "{lit}");
        }
        assert_eq!(float_repr(f64::NAN), "NaN");
        assert_eq!(py(&json!(2.5)), "2.5");
        assert_eq!(py(&json!(1e22)), "1e+22");
        // shortest length 17 with two candidates: Python picks the closest (scratch differential)
        assert_eq!(float_repr(178282446750899.12), "178282446750899.12");
        assert_eq!(float_repr(15207777803985.562), "15207777803985.562");
    }
}
