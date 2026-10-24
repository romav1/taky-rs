//! JSON output compatible with Python `json.dumps` / Flask `jsonify` (ARCHITECTURE §12).
//!
//! **T-10 scaffold:** signatures fixed, implementation — T-21/T-24.

use serde_json::Value;

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

/// Serialize like Python (float as `repr`, arbitrary-length integers without loss).
pub fn dumps(v: &Value, opts: &DumpOpts) -> String {
    let _ = (v, opts);
    todo!("T-21: json.dumps-compatible writer")
}
