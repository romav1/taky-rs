//! DPS storage in `upload_path` — byte-compatible with Python taky (spec dps-cli-config §3.1–§3.2a,
//! §3.5): `<UID>` files, `meta/<UID>.json` (`json.dump` format, key order kept),
//! `meta/<Hash>.json -> <UID>.json` relative symlinks.
//!
//! All functions are blocking (std::fs); handlers call them from `spawn_blocking`.

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use unicode_normalization::UnicodeNormalization;

use taky_common::pyjson::{self, DumpOpts};

/// Werkzeug `secure_filename` (POSIX), byte-for-byte (spec §3.5).
pub fn secure_filename(name: &str) -> String {
    let ascii: String = name.nfkd().filter(char::is_ascii).collect();
    let spaced = ascii.replace('/', " ");
    // Python str.split(): ASCII whitespace plus \x1c-\x1f.
    let joined = spaced
        .split(|c: char| {
            matches!(
                c,
                ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r' | '\x1c'..='\x1f'
            )
        })
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    let kept: String = joined
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        .collect();
    kept.trim_matches(['.', '_']).to_owned()
}

/// D-22 (ADR-008/G-8): a `hash` must match `^[A-Za-z0-9._-]+$` and must not contain `..`.
pub fn valid_hash(h: &str) -> bool {
    !h.is_empty()
        && !h.contains("..")
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `get_meta` raised (not one of the swallowed `JSONDecodeError`/`OSError`), e.g. a meta file
/// that is not valid UTF-8 (`UnicodeDecodeError`) ⇒ Flask 500.
#[derive(Debug)]
pub struct MetaError(pub String);

/// `str(x)` of a JSON value as Python would format it into a path (`f"{x}.json"`);
/// `None` for containers (not reproduced).
pub fn py_str(v: Option<&Value>) -> Option<String> {
    Some(match v {
        None | Some(Value::Null) => "None".into(),
        Some(Value::Bool(true)) => "True".into(),
        Some(Value::Bool(false)) => "False".into(),
        Some(Value::Number(n)) => pyjson::dumps(&Value::Number(n.clone()), &DumpOpts::default()),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return None,
    })
}

/// Python truthiness of a JSON value (`if meta:`).
pub fn py_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => py_number_nonzero(n),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}

fn py_number_nonzero(n: &serde_json::Number) -> bool {
    !matches!(n.to_string().parse::<f64>(), Ok(f) if f == 0.0)
}

/// The storage root (`dp_server.upload_path`).
#[derive(Debug, Clone)]
pub struct Store {
    /// `upload_path` exactly as configured (used verbatim in the D009 404 message).
    pub root: PathBuf,
}

impl Store {
    /// `<upload_path>/meta`.
    pub fn meta_dir(&self) -> PathBuf {
        self.root.join("meta")
    }

    /// `meta/<stem>.json` (stem as raw bytes: listdir names need not be UTF-8).
    pub fn meta_path(&self, stem: &OsStr) -> PathBuf {
        let mut n = stem.as_bytes().to_vec();
        n.extend_from_slice(b".json");
        self.meta_dir().join(OsStr::from_bytes(&n))
    }

    /// `get_meta(f_hash=…)` / `get_meta(f_name=…)`: an empty stem ⇒ `{}` without any access;
    /// unreadable file or invalid JSON ⇒ `{}`; non-UTF-8 content ⇒ [`MetaError`] (500).
    /// Python's `json` also accepts `NaN`/`Infinity` and lone surrogates; serde_json does not
    /// (such a file reads as `{}` here).
    pub fn get_meta(&self, stem: &OsStr) -> Result<Value, MetaError> {
        let empty = Value::Object(Map::new());
        if stem.is_empty() {
            return Ok(empty);
        }
        let p = self.meta_path(stem);
        let bytes = match std::fs::read(&p) {
            Ok(b) => b,
            Err(_) => return Ok(empty),
        };
        let text = String::from_utf8(bytes)
            .map_err(|e| MetaError(format!("{}: UnicodeDecodeError: {e}", p.display())))?;
        Ok(serde_json::from_str(&text).unwrap_or(empty))
    }

    /// `put_meta(meta)`: write `meta/<UID>.json` (truncate, through symlinks), then symlink
    /// `meta/<Hash>.json -> <UID>.json` unless that name already exists. A `Hash` taken from the
    /// meta that fails [`valid_hash`] gets no symlink (D-22: nothing is created outside `meta/`).
    pub fn put_meta(&self, meta: &Map<String, Value>) -> io::Result<()> {
        let bad = |w: &str| io::Error::other(format!("unsupported {w} value in meta"));
        let uid = py_str(meta.get("UID")).ok_or_else(|| bad("UID"))?;
        let hash = py_str(meta.get("Hash")).ok_or_else(|| bad("Hash"))?;
        let text = pyjson::dumps(&Value::Object(meta.clone()), &DumpOpts::default());
        std::fs::write(self.meta_path(OsStr::new(&uid)), text)?;
        if valid_hash(&hash) {
            match std::os::unix::fs::symlink(
                format!("{uid}.json"),
                self.meta_path(OsStr::new(&hash)),
            ) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        } else {
            tracing::warn!(hash = %hash, "meta Hash fails D-22 validation; no hash symlink");
        }
        Ok(())
    }

    /// `os.path.join(upload_path, uid)` (an absolute `uid` replaces the root, as in Python).
    pub fn file_path(&self, uid: &str) -> PathBuf {
        self.root.join(uid)
    }
}

/// `os.unlink(path)` with every error ignored (`except: pass`).
pub fn unlink_quiet(p: &Path) {
    let _ = std::fs::remove_file(p);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_filename_spec_examples() {
        assert_eq!(
            secure_filename("ANDROID-1_my pkg \u{fc}.zip"),
            "ANDROID-1_my_pkg_u.zip"
        );
        assert_eq!(secure_filename("U_../../etc/passwd"), "U_.._.._etc_passwd");
        assert_eq!(
            secure_filename("U_\u{442}\u{435}\u{441}\u{442}.zip"),
            "U_.zip"
        );
        assert_eq!(secure_filename("U_a b\tc.zip"), "U_a_b_c.zip");
        assert_eq!(secure_filename("../.."), "");
        assert_eq!(secure_filename("_a\x1fb\x0bc_"), "a_b_c");
    }

    /// Werkzeug 3.1.9 `secure_filename` outputs (Python 3.13, an01 venv, S-317).
    const WERKZEUG_CASES: &str = r#"[["ANDROID-1_my pkg \u00fc.zip", "ANDROID-1_my_pkg_u.zip"], ["U_../../etc/passwd", "U_.._.._etc_passwd"], ["U_\u0442\u0435\u0441\u0442.zip", "U_.zip"], ["U_a b\tc.zip", "U_a_b_c.zip"], ["", ""], ["...", ""], ["__a__", "a"], ["\ufb01le.zip", "file.zip"], ["\u00c5.zip", "A.zip"], ["x\u00a0y", "x_y"], ["a\u001cb\u001dc\u001ed\u001ff", "a_b_c_d_f"], ["a\u000bb\fc\rd\ne", "a_b_c_d_e"], ["a\u0085b", "ab"], ["\u00bd.zip", "12.zip"], ["\u2460\u2461.zip", "12.zip"], ["\uff21\uff22\uff23.zip", "ABC.zip"], ["a\\b.zip", "ab.zip"], ["a:b*c?.zip", "abc.zip"], [".hidden", "hidden"], ["-dash-", "-dash-"], ["U_ .zip", "U__.zip"], ["U_\u00e9\u00e9\u00e9", "U_eee"], ["a\u0301", "a"], ["\u2028x", "x"], ["CON.txt", "CON.txt"], ["x/y/z", "x_y_z"], ["  lead  trail  ", "lead_trail"], ["\u3000ideo", "ideo"], ["\u00df.zip", "zip"], ["\u0149", "n"], ["\u01c5", "Dz"], ["\ufeffbom", "bom"], ["a\u0000b", "ab"], ["tab\t\tx", "tab_x"], ["\ufdfa", ""]]"#;

    #[test]
    fn secure_filename_matches_werkzeug() {
        let cases: Vec<(String, String)> = serde_json::from_str(WERKZEUG_CASES).unwrap();
        for (input, want) in cases {
            assert_eq!(secure_filename(&input), want, "{input:?}");
        }
    }

    #[test]
    fn hash_validation_d22() {
        for ok in ["h1", "abc123", "A.b_c-d", ".", "a.b", &"f".repeat(64)] {
            assert!(valid_hash(ok), "{ok}");
        }
        for bad in [
            "",
            "..",
            "../X_evil",
            "a/b",
            "a..b",
            "a b",
            "/etc",
            "a\\b",
            "\u{fc}",
            "a%2e",
        ] {
            assert!(!valid_hash(bad), "{bad}");
        }
    }

    #[test]
    fn py_helpers() {
        assert_eq!(py_str(None).as_deref(), Some("None"));
        assert_eq!(py_str(Some(&Value::from(5))).as_deref(), Some("5"));
        assert_eq!(py_str(Some(&Value::from("h"))).as_deref(), Some("h"));
        assert!(py_str(Some(&serde_json::json!([1]))).is_none());
        assert!(!py_truthy(&serde_json::json!({})));
        assert!(py_truthy(&serde_json::json!([0])));
        assert!(!py_truthy(&serde_json::json!(0)));
    }
}
