//! U003 (an01 vectors): **all** cases through `load_config` (S-302).
//!
//! Each case input is written to `<tmp>/conf/taky.conf` and loaded with
//! `load_config_in(Some(path), explicit = false, cwd = <tmp>)`, as the vector notes say. Values are
//! compared on the final INI (`TakyConfig::raw`, the original's `app_config`); `$CFG_DIR` is the
//! realpath of the config directory. Errors are compared by Python exception class. `rust_expect`
//! overrides `expect` where Rust deviates (D-13, D-14).

// Test code: helpers outside #[test] fns are not covered by clippy.toml allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use serde_json::Value;
use taky_config::load_config_in;

#[derive(Debug, PartialEq)]
enum Outcome {
    Values(Vec<(String, Option<String>)>),
    Error(String),
}

fn run(input: &str, keys: &[String]) -> (Outcome, String) {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().canonicalize().unwrap();
    let dir = cwd.join("conf");
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("taky.conf");
    std::fs::write(&file, input).unwrap();
    let cfg_dir = dir.to_string_lossy().into_owned();
    let out = match load_config_in(Some(&file), false, &cwd) {
        Err(e) => Outcome::Error(e.py_class().to_string()),
        Ok(cfg) => Outcome::Values(
            keys.iter()
                .map(|key| {
                    let (s, k) = key.split_once('.').unwrap();
                    (key.clone(), cfg.raw().get(s, k).unwrap())
                })
                .collect(),
        ),
    };
    (out, cfg_dir)
}

fn expected(exp: &Value, keys: &[String], cfg_dir: &str) -> Outcome {
    if let Some(err) = exp.get("error") {
        return Outcome::Error(err.as_str().unwrap().to_string());
    }
    let vals = &exp["values"];
    Outcome::Values(
        keys.iter()
            .map(|k| {
                let v = vals[k].as_str().map(|s| s.replace("$CFG_DIR", cfg_dir));
                (k.clone(), v)
            })
            .collect(),
    )
}

#[test]
fn u003_all_cases_via_load_config() {
    let text = taky_common::vectors::read_vector("unit/U003.json");
    let doc: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["id"], "U003");
    let cases = doc["cases"].as_array().unwrap();
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
        let (got, cfg_dir) = run(input, &keys);
        let want = expected(exp, &keys, &cfg_dir);
        if got != want {
            failures.push(format!("case {i} {input:?}: want {want:?}, got {got:?}"));
        }
    }
    let total = cases.len();
    eprintln!(
        "U003 load_config cases: {}/{total} passed",
        total - failures.len()
    );
    assert!(
        failures.is_empty(),
        "U003 failures:\n{}",
        failures.join("\n")
    );
    assert_eq!(total, 41, "U003 case count changed");
}
