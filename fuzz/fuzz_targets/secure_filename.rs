//! `secure_filename` (S-407): `taky_dps::storage::{secure_filename, valid_hash}` (Werkzeug port).
//! Invariants: no panic; the result is ASCII `[A-Za-z0-9_.-]` only, never `.`/`..`, has no leading
//! `.`/`_`, and is a fixed point (`secure_filename(r) == r`); an accepted hash has no `/` or `..`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use taky_dps::storage::{secure_filename, valid_hash};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let r = secure_filename(s);
    assert!(
        r.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
        "{s:?} -> {r:?}"
    );
    assert!(r != "." && r != "..", "{s:?} -> {r:?}");
    assert!(!r.starts_with('.') && !r.starts_with('_'), "{s:?} -> {r:?}");
    assert_eq!(secure_filename(&r), r, "not a fixed point: {s:?}");
    if valid_hash(s) {
        assert!(
            !s.contains('/') && !s.contains(".."),
            "valid_hash accepted {s:?}"
        );
    }
});
