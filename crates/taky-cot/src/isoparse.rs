//! `dateutil.parser.isoparse(s).replace(tzinfo=None)` (python-dateutil 3.0.0, `isoparser.py`),
//! as used for `time`/`start`/`stale` (`event.py:52-54`) and `remarks/@time` (`geochat.py`).
//!
//! A line-by-line port, including the quirks that follow from it (spec §7.1 QUIRK, OQ-06):
//! * the timezone offset is validated and then **dropped without conversion**;
//! * any single character separates date and time (`sep=None`);
//! * every numeric field goes through Python `int()` on a byte slice, so a field may carry
//!   surrounding ASCII whitespace, a sign or `_` between digits (`"+999"` is year 999);
//! * Python slices clamp, so short fields are accepted (`T000` = 00:00);
//! * `24:00:00` is midnight of the next day; fractions are truncated to microseconds.
//!
//! Python raises `ValueError`, `TypeError` (missing attribute) or, for a date pushed past
//! year 9999 (`9999-W53-7`, `9999-12-31T24:00`), `OverflowError`; all of them are `None` here
//! (the event is dropped either way — §6 items 2 and 9).

use chrono::{Datelike, NaiveDate, NaiveDateTime, TimeDelta};

/// Parse like `isoparse(s).replace(tzinfo=None)`; `None` where Python raises.
pub fn isoparse(s: &str) -> Option<NaiveDateTime> {
    // `_takes_ascii`: non-ASCII → ValueError.
    if !s.is_ascii() {
        return None;
    }
    let b = s.as_bytes();
    let (date, pos) = parse_isodate(b)?;
    let mut time = [0i64; 4];
    if b.len() > pos {
        time = parse_isotime(&b[pos + 1..])?;
    }
    let [y, mo, d] = date;
    let [h, mi, sec, us] = time;
    if h == 24 {
        let t = datetime(y, mo, d, 0, mi, sec, us)?;
        return t.checked_add_signed(TimeDelta::days(1)).filter(in_range);
    }
    datetime(y, mo, d, h, mi, sec, us)
}

fn in_range(t: &NaiveDateTime) -> bool {
    (1..=9999).contains(&t.year())
}

/// `datetime(y, m, d, h, mi, s, us)` with Python's range checks.
fn datetime(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64, us: i64) -> Option<NaiveDateTime> {
    let date = date(y, mo, d)?;
    if !(0..24).contains(&h) || !(0..60).contains(&mi) || !(0..60).contains(&s) {
        return None;
    }
    if !(0..1_000_000).contains(&us) {
        return None;
    }
    date.and_hms_micro_opt(h as u32, mi as u32, s as u32, us as u32)
}

/// `date(y, m, d)` (`MINYEAR=1`, `MAXYEAR=9999`).
fn date(y: i64, m: i64, d: i64) -> Option<NaiveDate> {
    if !(1..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    NaiveDate::from_ymd_opt(y as i32, m as u32, d as u32)
}

/// Python slice `b[a:e]` (clamped).
fn sl(b: &[u8], a: usize, e: usize) -> &[u8] {
    let a = a.min(b.len());
    let e = e.clamp(a, b.len());
    &b[a..e]
}

/// Python `int(bytes)` in base 10: ASCII whitespace around, optional sign, digits with single
/// `_` between them. (Fields are at most a few digits; longer input saturates harmlessly.)
fn py_int(b: &[u8]) -> Option<i64> {
    let is_space = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r');
    let start = b.iter().position(|c| !is_space(c))?;
    let end = b.len() - b.iter().rev().position(|c| !is_space(c))?;
    let mut t = &b[start..end];
    let neg = match t.first() {
        Some(b'-') => {
            t = &t[1..];
            true
        }
        Some(b'+') => {
            t = &t[1..];
            false
        }
        _ => false,
    };
    let mut v: i64 = 0;
    let mut prev_digit = false;
    for &c in t {
        if c.is_ascii_digit() {
            v = v.saturating_mul(10).saturating_add(i64::from(c - b'0'));
            prev_digit = true;
        } else if c == b'_' && prev_digit {
            prev_digit = false;
        } else {
            return None;
        }
    }
    if !prev_digit {
        return None;
    }
    Some(if neg { -v } else { v })
}

fn parse_isodate(b: &[u8]) -> Option<([i64; 3], usize)> {
    parse_isodate_common(b).or_else(|| parse_isodate_uncommon(b))
}

fn parse_isodate_common(b: &[u8]) -> Option<([i64; 3], usize)> {
    let len = b.len();
    let mut c = [1i64, 1, 1];
    if len < 4 {
        return None;
    }
    c[0] = py_int(&b[0..4])?;
    let mut pos = 4;
    if pos >= len {
        return Some((c, pos));
    }
    let has_sep = b[pos] == b'-';
    if has_sep {
        pos += 1;
    }
    if len - pos < 2 {
        return None;
    }
    c[1] = py_int(&b[pos..pos + 2])?;
    pos += 2;
    if pos >= len {
        return has_sep.then_some((c, pos));
    }
    if has_sep {
        if b[pos] != b'-' {
            return None;
        }
        pos += 1;
    }
    if len - pos < 2 {
        return None;
    }
    c[2] = py_int(&b[pos..pos + 2])?;
    Some((c, pos + 2))
}

fn parse_isodate_uncommon(b: &[u8]) -> Option<([i64; 3], usize)> {
    if b.len() < 4 {
        return None;
    }
    let year = py_int(&b[0..4])?;
    let has_sep = sl(b, 4, 5) == b"-";
    let mut pos = 4 + usize::from(has_sep);
    let base = if sl(b, pos, pos + 1) == b"W" {
        pos += 1;
        let weekno = py_int(sl(b, pos, pos + 2))?;
        pos += 2;
        let mut dayno = 1;
        if b.len() > pos {
            if (sl(b, pos, pos + 1) == b"-") != has_sep {
                return None;
            }
            pos += usize::from(has_sep);
            dayno = py_int(sl(b, pos, pos + 1))?;
            pos += 1;
        }
        weekdate(year, weekno, dayno)?
    } else {
        if b.len().saturating_sub(pos) < 3 {
            return None;
        }
        let ordinal = py_int(&b[pos..pos + 3])?;
        pos += 3;
        let jan1 = date(year, 1, 1)?;
        let days = if jan1.leap_year() { 366 } else { 365 };
        if !(1..=days).contains(&ordinal) {
            return None;
        }
        jan1.checked_add_signed(TimeDelta::days(ordinal - 1))?
    };
    Some((
        [
            i64::from(base.year()),
            i64::from(base.month()),
            i64::from(base.day()),
        ],
        pos,
    ))
}

/// `_calculate_weekdate` (week 1 contains January 4th).
fn weekdate(year: i64, week: i64, day: i64) -> Option<NaiveDate> {
    if !(1..54).contains(&week) || !(1..8).contains(&day) {
        return None;
    }
    let jan4 = date(year, 1, 4)?;
    let wd = i64::from(jan4.weekday().number_from_monday());
    let week1 = jan4.checked_add_signed(TimeDelta::days(1 - wd))?;
    let d = week1.checked_add_signed(TimeDelta::days((week - 1) * 7 + (day - 1)))?;
    // Python's `date` arithmetic raises OverflowError outside years 1..=9999.
    (1..=9999).contains(&d.year()).then_some(d)
}

/// `_parse_isotime` → `[hour, minute, second, microsecond]` (the tz is validated and dropped).
fn parse_isotime(t: &[u8]) -> Option<[i64; 4]> {
    let len = t.len();
    let mut c = [0i64; 4];
    let mut pos = 0;
    let mut comp: i32 = -1;
    if len < 2 {
        return None;
    }
    let mut has_sep = false;
    while pos < len && comp < 5 {
        comp += 1;
        if matches!(t[pos], b'-' | b'+' | b'Z' | b'z') {
            parse_tzstr(&t[pos..])?;
            pos = len;
            break;
        }
        if comp == 1 && t[pos] == b':' {
            has_sep = true;
            pos += 1;
        } else if comp == 2 && has_sep {
            if sl(t, pos, pos + 1) != b":" {
                return None;
            }
            pos += 1;
        }
        if comp < 3 {
            c[comp as usize] = py_int(sl(t, pos, pos + 2))?;
            pos += 2;
        }
        if comp == 3 {
            // _FRACTION_REGEX = b'[\.,]([0-9]+)', matched at `pos`.
            let rest = sl(t, pos, len);
            let ndig = rest
                .iter()
                .skip(1)
                .take_while(|c| c.is_ascii_digit())
                .count();
            if rest.is_empty() || !matches!(rest[0], b'.' | b',') || ndig == 0 {
                continue;
            }
            let us_str = &rest[1..1 + ndig.min(6)];
            let mut us = py_int(us_str)?;
            for _ in us_str.len()..6 {
                us *= 10;
            }
            c[3] = us;
            pos += 1 + ndig;
        }
    }
    if pos < len {
        return None;
    }
    if c[0] == 24 && c[1..].iter().any(|v| *v != 0) {
        return None;
    }
    Some(c)
}

/// `_parse_tzstr` — validation only (the offset is discarded by `.replace(tzinfo=None)`).
fn parse_tzstr(tz: &[u8]) -> Option<()> {
    if tz == b"Z" || tz == b"z" {
        return Some(());
    }
    if !matches!(tz.len(), 3 | 5 | 6) {
        return None;
    }
    if !matches!(tz[0], b'-' | b'+') {
        return None;
    }
    let hours = py_int(&tz[1..3])?;
    let minutes = if tz.len() == 3 {
        0
    } else {
        py_int(&tz[if tz[3] == b':' { 4 } else { 3 }..])?
    };
    if hours == 0 && minutes == 0 {
        return Some(());
    }
    if minutes > 59 || hours > 23 {
        return None;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iso(s: &str) -> Option<String> {
        isoparse(s).map(|t| t.format("%Y-%m-%dT%H:%M:%S%.6f").to_string())
    }

    #[test]
    fn quirks() {
        assert_eq!(iso("+999").as_deref(), Some("0999-01-01T00:00:00.000000"));
        assert_eq!(
            iso("2030-01-01T000").as_deref(),
            Some("2030-01-01T00:00:00.000000")
        );
        assert_eq!(
            iso("2030-01-01x01").as_deref(),
            Some("2030-01-01T01:00:00.000000")
        );
        assert_eq!(
            iso("2030-01-01T 1").as_deref(),
            Some("2030-01-01T01:00:00.000000")
        );
        assert_eq!(
            iso("2030-01-01T01:00+05:30").as_deref(),
            Some("2030-01-01T01:00:00.000000")
        );
        assert_eq!(iso("9999-12-31T24:00"), None);
        assert_eq!(iso("9999-W53-7"), None);
        assert_eq!(iso("2030-01-01T01:00+24"), None);
        assert_eq!(iso("2030-01-01T01:-1"), None);
        assert_eq!(iso("2030-ü"), None);
    }
}
