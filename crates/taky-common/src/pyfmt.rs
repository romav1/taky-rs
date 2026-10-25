//! Formatting "like Python" (ARCHITECTURE §1, qa01 §1.1 taky-common).
//!
//! Rust's `{:.N}` float formatting is exact-decimal with round-half-even, which is what CPython's
//! `"%.Nf"` does (`2.675` → `2.67`/`2.7`, `0.125` → `0.12`); only the special values differ in
//! spelling (`NaN` vs `nan`; a negative NaN is printed as plain `nan` by Python).

use chrono::{Datelike, NaiveDateTime, Timelike};

fn fmt_fixed(x: f64, prec: usize) -> String {
    if x.is_nan() {
        "nan".to_string()
    } else if x.is_infinite() {
        if x > 0.0 { "inf" } else { "-inf" }.to_string()
    } else {
        format!("{x:.prec$}")
    }
}

/// `"%.6f" % x` (coordinates `lat`/`lon` in `Point`), including `nan`, `inf`, `-0.0`.
pub fn fmt_f6(x: f64) -> String {
    fmt_fixed(x, 6)
}

/// `"%.1f" % x` (`hae`/`ce`/`le` in `Point`, `course`/`speed`).
pub fn fmt_f1(x: f64) -> String {
    fmt_fixed(x, 1)
}

/// Python 3 built-in `round(x)`: banker's rounding (half-even) to an integer
/// (saturating at the `i64` range; NaN → 0 — Python raises there, callers never pass one).
pub fn round_half_even(x: f64) -> i64 {
    // `as` saturates and maps NaN to 0.
    x.round_ties_even() as i64
}

/// Microseconds of `t` (Python `datetime` has microsecond resolution: extra nanoseconds are
/// truncated; a chrono leap-second value is folded into the same second).
fn micros(t: NaiveDateTime) -> u32 {
    (t.nanosecond() % 1_000_000_000) / 1_000
}

fn date_time(t: NaiveDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// `dt.isoformat(timespec="milliseconds")` (milliseconds truncated, as in Python), without `"Z"` —
/// the caller appends the suffix (`Event::to_element`: `time`/`start`/`stale`).
pub fn isoformat_ms(t: NaiveDateTime) -> String {
    format!("{}.{:03}", date_time(t), micros(t) / 1_000)
}

/// `dt.isoformat()` (without `.000000` when microseconds are zero) — DPS meta, mgmt.
pub fn isoformat(t: NaiveDateTime) -> String {
    match micros(t) {
        0 => date_time(t),
        us => format!("{}.{us:06}", date_time(t)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    #[test]
    fn floats_like_python() {
        assert_eq!(fmt_f6(1.23456789), "1.234568");
        assert_eq!(fmt_f6(-0.0), "-0.000000");
        assert_eq!(fmt_f1(2.675), "2.7");
        assert_eq!(fmt_f1(1.25), "1.2");
        assert_eq!(fmt_f1(0.05), "0.1");
        assert_eq!(fmt_f1(f64::NAN), "nan");
        assert_eq!(fmt_f1(-f64::NAN), "nan");
        assert_eq!(fmt_f6(f64::NEG_INFINITY), "-inf");
        assert_eq!(fmt_f1(9_999_999.0), "9999999.0");
    }

    #[test]
    fn round_is_half_even() {
        assert_eq!(round_half_even(0.5), 0);
        assert_eq!(round_half_even(1.5), 2);
        assert_eq!(round_half_even(2.5), 2);
        assert_eq!(round_half_even(-2.5), -2);
        assert_eq!(round_half_even(-2.6), -3);
        assert_eq!(round_half_even(599.999999), 600);
    }

    #[test]
    fn isoformat_variants() {
        let t = NaiveDate::from_ymd_opt(1, 2, 3)
            .unwrap()
            .and_hms_nano_opt(4, 5, 6, 999_999_999)
            .unwrap();
        assert_eq!(isoformat_ms(t), "0001-02-03T04:05:06.999");
        assert_eq!(isoformat(t), "0001-02-03T04:05:06.999999");
        let t0 = NaiveDate::from_ymd_opt(2030, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        assert_eq!(isoformat_ms(t0), "2030-01-01T00:00:00.000");
        assert_eq!(isoformat(t0), "2030-01-01T00:00:00");
    }
}
