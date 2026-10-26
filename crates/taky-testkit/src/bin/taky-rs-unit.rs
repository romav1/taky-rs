//! `taky-rs-unit` — Rust unit-vector adapter of the difftest harness (qa01, S-402; test-only).
//!
//! Same contract as `tools/difftest/harness/pyunit.py` (the Python side):
//!
//! ```text
//! taky-rs-unit <vector.json>...   →   stdout: {"<vector id>": [observation per case], ...}
//! ```
//!
//! Observations use the schema of an01's `run_python_unit.py`, produced by the public taky-rs
//! code paths the server uses:
//! * `isoparse` — [`taky_cot::isoparse::isoparse`] (what `Event::from_element` reads) →
//!   `{"ok": "%Y-%m-%dT%H:%M:%S.ffffff", "cot": isoformat_ms + "Z"}`;
//! * `float` — [`taky_common::pyparse::py_float`] (what `Point::from_element` reads) →
//!   `{"ok": repr, "f6": "%.6f", "f1": "%.1f"}`;
//! * `ini` — the case text written to `<tmp>/conf/taky.conf`, loaded with
//!   [`taky_config::load_config_in`] (`explicit = false`, cwd `<tmp>`) → `{"values": {...}}`
//!   (`$CFG_DIR` = the realpath of `<tmp>/conf`), or on error `{"error": <Python class>,
//!   "taky_exit": n, "taky_output": label}` where `n` and the text come from
//!   [`ConfigFailure`] — the exact functions the `taky-rs` binary calls after a failed
//!   `load_config`.
//!
//! Two fields name Python-internal facts that have no Rust counterpart, so they are derived by a
//! fixed rule (documented in qa01/reports/difftest-random.md, S-402):
//! * `python_exception` of an `UnmarshalError`: `TypeError` when the attribute is missing
//!   (`input: null`), otherwise `ValueError`;
//! * `taky_output` of a `Configuration file error: …` line (taky-rs prints the same line for
//!   every config error, D-13): `config_error_message` for the configparser parse/interpolation
//!   classes (`ParsingError`, `MissingSectionHeaderError`, `Interpolation*Error`), `message` for
//!   the others (`Duplicate*Error`, `ValueError`, `AttributeError`); `argparse_error` for the
//!   usage failure (exit 2).

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::{Map, Value, json};
use taky_common::pyfmt::{fmt_f1, fmt_f6, isoformat_ms};
use taky_common::pyjson::float_repr;
use taky_common::pyparse::py_float;
use taky_cot::isoparse::isoparse;
use taky_server::cli::ConfigFailure;

fn main() -> ExitCode {
    let mut out = Map::new();
    for path in std::env::args().skip(1) {
        match run_vector(Path::new(&path)) {
            Ok((id, obs)) => {
                out.insert(id, Value::Array(obs));
            }
            Err(e) => {
                eprintln!("taky-rs-unit: {path}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    println!("{}", Value::Object(out));
    ExitCode::SUCCESS
}

fn run_vector(path: &Path) -> Result<(String, Vec<Value>), String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let vec: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let id = vec["id"].as_str().ok_or("no id")?.to_owned();
    let kind = vec["kind"].as_str().unwrap_or_default();
    let cases = vec["cases"].as_array().ok_or("no cases")?;
    let mut obs = Vec::with_capacity(cases.len());
    for case in cases {
        let input = case["input"].as_str();
        obs.push(match kind {
            "isoparse" => run_isoparse(input),
            "float" => run_float(input),
            "ini" => run_ini(case)?,
            other => json!({"adapter_error": format!("unknown kind {other}")}),
        });
    }
    Ok((id, obs))
}

fn unmarshal_error(input: Option<&str>) -> Value {
    let exc = if input.is_none() {
        "TypeError"
    } else {
        "ValueError"
    };
    json!({"error": "UnmarshalError", "python_exception": exc})
}

fn run_isoparse(input: Option<&str>) -> Value {
    match input.and_then(isoparse) {
        Some(t) => json!({
            "ok": t.format("%Y-%m-%dT%H:%M:%S%.6f").to_string(),
            "cot": format!("{}Z", isoformat_ms(t)),
        }),
        None => unmarshal_error(input),
    }
}

/// `repr(float)`: like `json.dumps` except for the non-finite spellings.
fn py_repr(f: f64) -> String {
    if f.is_nan() {
        "nan".into()
    } else if f.is_infinite() {
        if f > 0.0 { "inf" } else { "-inf" }.into()
    } else {
        float_repr(f)
    }
}

fn run_float(input: Option<&str>) -> Value {
    match input.and_then(py_float) {
        Some(f) => json!({"ok": py_repr(f), "f6": fmt_f6(f), "f1": fmt_f1(f)}),
        None => unmarshal_error(input),
    }
}

fn scratch_dir() -> Result<PathBuf, String> {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("taky-rs-unit-{}-{n}", std::process::id()));
    std::fs::create_dir_all(d.join("conf")).map_err(|e| e.to_string())?;
    d.canonicalize().map_err(|e| e.to_string())
}

const PARSE_CLASSES: &[&str] = &[
    "ParsingError",
    "MissingSectionHeaderError",
    "InterpolationSyntaxError",
    "InterpolationMissingOptionError",
    "InterpolationDepthError",
];

fn run_ini(case: &Value) -> Result<Value, String> {
    let input = case["input"].as_str().ok_or("ini case without input")?;
    let tmp = scratch_dir()?;
    let dir = tmp.join("conf");
    let file = dir.join("taky.conf");
    std::fs::write(&file, input).map_err(|e| e.to_string())?;
    let cfg_dir = dir.to_string_lossy().into_owned();
    let res = match taky_config::load_config_in(Some(&file), false, &tmp) {
        Ok(cfg) => {
            let mut vals = Map::new();
            for key in case["keys"].as_array().into_iter().flatten() {
                let key = key.as_str().ok_or("non-string key")?;
                let (s, k) = key.split_once('.').ok_or("key without section")?;
                let v = match cfg.raw().get(s, k) {
                    Ok(Some(v)) => Value::String(v.replace(&cfg_dir, "$CFG_DIR")),
                    Ok(None) => Value::Null,
                    Err(e) => json!({"get_error": e.py_class()}),
                };
                vals.insert(key.to_owned(), v);
            }
            json!({"values": vals})
        }
        Err(e) => {
            let class = e.py_class();
            let failure = ConfigFailure::classify(Some(&file), &e);
            let text = failure.render(Some("taky-rs"));
            let label = match &failure {
                ConfigFailure::Usage(_) => "argparse_error",
                ConfigFailure::Config(_) if !text.starts_with("Configuration file error: ") => {
                    "unexpected_output"
                }
                ConfigFailure::Config(_) if PARSE_CLASSES.contains(&class) => {
                    "config_error_message"
                }
                ConfigFailure::Config(_) => "message",
            };
            json!({"error": class, "taky_exit": failure.exit_code(), "taky_output": label})
        }
    };
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(res)
}
