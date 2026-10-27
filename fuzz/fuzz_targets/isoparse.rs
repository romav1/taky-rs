//! `isoparse` (S-407): `taky_cot::isoparse::isoparse` (U001 grammar, `event.py:52-56`).
//! Invariants: no panic; an accepted value re-parses from its canonical microsecond form to
//! the same instant.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(dt) = taky_cot::isoparse::isoparse(s) {
        let canon = dt.format("%Y-%m-%dT%H:%M:%S%.6f").to_string();
        assert_eq!(
            taky_cot::isoparse::isoparse(&canon),
            Some(dt),
            "canonical form {canon:?} of {s:?}"
        );
    }
});
