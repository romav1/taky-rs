//! U003 (an01 vectors): the INI-level cases (configparser semantics on top of `DEFAULT_CFG`).
//!
//! The load_config-level cases of U003 (port/ttl/ssl normalization, path absolutization) are
//! covered by `u003_load.rs` (S-302, all cases through `load_config`); they are skipped here.
//!
//! Vectors are located by `taky_common::vectors` (`<workspace>/tests/vectors`, then
//! `../shared/spec/vectors`); the test fails when neither exists.

// Test code: helpers outside #[test] fns are not covered by clippy.toml allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use serde_json::Value;
use taky_config::defaults::DEFAULT_CFG;
use taky_config::{Ini, IniError, default_ini};

/// Python exception classes raised by configparser itself (parse / interpolation).
const INI_ERRORS: &[&str] = &[
    "ParsingError",
    "MissingSectionHeaderError",
    "MultilineContinuationError",
    "DuplicateSectionError",
    "DuplicateOptionError",
    "InterpolationSyntaxError",
    "InterpolationMissingOptionError",
    "InterpolationDepthError",
];

/// Keys whose final value is decided by `load_config` (normalization), not by the parser:
/// the `DEFAULT_CFG` keys of `[cot_server]`/`[ssl]`, plus `taky.root_dir`/`dp_server.upload_path`.
fn normalized_key(key: &str) -> bool {
    let (s, k) = key.split_once('.').unwrap();
    matches!(s, "cot_server" | "ssl")
        && DEFAULT_CFG
            .iter()
            .any(|(ds, keys)| *ds == s && keys.iter().any(|(dk, _)| *dk == k))
        || key == "taky.root_dir"
        || key == "dp_server.upload_path"
}

/// Outcome of a case: values of the requested keys or the Python error class.
#[derive(Debug, PartialEq)]
enum Outcome {
    Values(Vec<(String, Option<String>)>),
    Error(String),
}

fn run(input: &str, keys: &[String]) -> Outcome {
    let mut ini: Ini = default_ini();
    if let Err(e) = ini.read_str(input, "<vector>") {
        return Outcome::Error(e.py_class().to_string());
    }
    let mut values = Vec::new();
    for key in keys {
        let (s, k) = key.split_once('.').unwrap();
        match ini.get(s, k) {
            Ok(v) => values.push((key.clone(), v)),
            // An unknown section/option would not be a configparser-level answer.
            Err(e @ (IniError::NoSection(_) | IniError::NoOption { .. })) => {
                panic!("{key}: {e}")
            }
            Err(e) => return Outcome::Error(e.py_class().to_string()),
        }
    }
    Outcome::Values(values)
}

fn expected(exp: &Value, keys: &[String]) -> Outcome {
    if let Some(err) = exp.get("error") {
        return Outcome::Error(err.as_str().unwrap().to_string());
    }
    let vals = &exp["values"];
    Outcome::Values(
        keys.iter()
            .map(|k| (k.clone(), vals[k].as_str().map(str::to_string)))
            .collect(),
    )
}

#[test]
fn u003_ini_cases() {
    let text = taky_common::vectors::read_vector("unit/U003.json");
    let doc: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["id"], "U003");
    let cases = doc["cases"].as_array().unwrap();
    let (mut total, mut passed, mut skipped) = (0, 0, 0);
    let mut failures = Vec::new();
    for (i, case) in cases.iter().enumerate() {
        let input = case["input"].as_str().unwrap();
        let keys: Vec<String> = case["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k.as_str().unwrap().to_string())
            .collect();
        let exp = case.get("rust_expect").unwrap_or(&case["expect"]);
        let ini_level = match exp.get("error").and_then(Value::as_str) {
            Some(err) => INI_ERRORS.contains(&err),
            None => !keys.iter().any(|k| normalized_key(k)),
        };
        if !ini_level {
            skipped += 1;
            continue;
        }
        total += 1;
        let want = expected(exp, &keys);
        let got = run(input, &keys);
        if got == want {
            passed += 1;
        } else {
            failures.push(format!("case {i} {input:?}: want {want:?}, got {got:?}"));
        }
    }
    eprintln!(
        "U003 INI cases: {passed}/{total} passed ({skipped} load_config-level cases skipped)"
    );
    assert!(
        failures.is_empty(),
        "U003 failures:\n{}",
        failures.join("\n")
    );
    assert_eq!(
        total, 23,
        "INI-level case count changed: re-check the selection"
    );
}
