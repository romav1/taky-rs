//! Formatting "like Python" (ARCHITECTURE §1, qa01 §1.1 taky-common).
//!
//! **T-10 scaffold:** signatures fixed, implementation — T-21 (dev01).

use chrono::NaiveDateTime;

/// `"%.6f" % x` (coordinates `lat`/`lon`/`hae`/`ce`/`le` in `Point`), including `nan`, `inf`, `-0.0`.
pub fn fmt_f6(x: f64) -> String {
    let _ = x;
    todo!("T-21")
}

/// `"%.1f" % x` (`course`/`speed`).
pub fn fmt_f1(x: f64) -> String {
    let _ = x;
    todo!("T-21")
}

/// Python 3 built-in `round(x)`: banker's rounding (half-even) to an integer.
pub fn round_half_even(x: f64) -> i64 {
    let _ = x;
    todo!("T-21")
}

/// `dt.isoformat(timespec="milliseconds")` (milliseconds truncated, as in Python), without `"Z"` —
/// the caller appends the suffix (`Event::to_element`: `time`/`start`/`stale`).
pub fn isoformat_ms(t: NaiveDateTime) -> String {
    let _ = t;
    todo!("T-21")
}

/// `dt.isoformat()` (without `.000000` when microseconds are zero) — DPS meta, mgmt.
pub fn isoformat(t: NaiveDateTime) -> String {
    let _ = t;
    todo!("T-21")
}
