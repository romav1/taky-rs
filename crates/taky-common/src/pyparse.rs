//! Parsing "like Python": `float(str)` and the character classes CPython uses for `int()`/`float()`.

/// First code points (digit zero) of the Unicode `Nd` blocks; every block has 10 contiguous
/// digits (Unicode 15.1, as in CPython 3.13 `unicodedata`).
const ND_ZEROS: [u32; 68] = [
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66,
    0xDE6, 0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90,
    0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
    0x104A0, 0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650,
    0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50, 0x11DA0, 0x11F50, 0x16A60, 0x16AC0,
    0x16B50, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E4F0, 0x1E950,
    0x1FBF0,
];

/// Decimal value of a Unicode `Nd` character (`unicodedata.decimal`).
pub fn py_decimal(c: char) -> Option<u8> {
    let n = c as u32;
    let i = ND_ZEROS.partition_point(|z| *z <= n).checked_sub(1)?;
    let d = n - ND_ZEROS[i];
    (d < 10).then_some(d as u8)
}

/// `str.isspace` (Unicode `White_Space` plus the ASCII separators U+001C..U+001F).
pub fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Python `float(s)` for a `str` argument; `None` where Python raises `ValueError`.
///
/// CPython (`PyFloat_FromString`): Unicode whitespace → space and `Nd` digits → ASCII, any other
/// non-ASCII character is an error; surrounding whitespace stripped; `_` allowed only between two
/// digits; then `[sign] (inf | infinity | nan | decimal[exponent])`, case-insensitive. Overflow
/// gives `±inf`, underflow `0.0` (as `strtod`). Rust's `f64::from_str` has exactly that grammar.
pub fn py_float(s: &str) -> Option<f64> {
    let mut ascii = String::with_capacity(s.len());
    for c in s.chars() {
        if py_isspace(c) {
            ascii.push(' ');
        } else if let Some(d) = py_decimal(c) {
            ascii.push(char::from(b'0' + d));
        } else if c.is_ascii() {
            ascii.push(c);
        } else {
            return None;
        }
    }
    let t = ascii.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\u{b}');
    let mut clean = String::with_capacity(t.len());
    let mut prev = '\0';
    for c in t.chars() {
        if c == '_' {
            if !prev.is_ascii_digit() {
                return None;
            }
        } else {
            if prev == '_' && !c.is_ascii_digit() {
                return None;
            }
            clean.push(c);
        }
        prev = c;
    }
    if prev == '_' || clean.is_empty() {
        return None;
    }
    // Rust accepts exactly `[+-]` + inf/infinity/nan (any case) or a decimal with optional
    // exponent; it rejects whitespace, hex, `1.5e`, `.`, `1,5`.
    clean.parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_grammar() {
        assert_eq!(py_float(" 1_000.5\n"), Some(1000.5));
        assert_eq!(py_float("\u{663}"), Some(3.0));
        assert_eq!(py_float("\u{ff11}.5"), Some(1.5));
        assert_eq!(py_float("\u{3000}2\u{1c}"), Some(2.0));
        assert!(py_float("-nan").is_some_and(f64::is_nan));
        assert_eq!(py_float("-Infinity"), Some(f64::NEG_INFINITY));
        for bad in [
            "", " ", "1__0", "_1", "1_", "1_.5", "0x10", "1,5", "infinite", "1.5e", "é1",
        ] {
            assert_eq!(py_float(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn decimal_digits() {
        assert_eq!(py_decimal('7'), Some(7));
        assert_eq!(py_decimal('\u{669}'), Some(9));
        assert_eq!(py_decimal('a'), None);
    }
}
