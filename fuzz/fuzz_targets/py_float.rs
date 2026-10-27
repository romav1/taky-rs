//! `py_float` (S-407): `taky_common::pyparse::py_float` (Python `float()`, U002) and the
//! `%.6f`/`%.1f`/repr formatting used for `<point>`. Invariants: no panic; a finite value round-trips
//! through `float_repr` bit-exactly (Python `float(repr(x)) == x`).
#![no_main]
use libfuzzer_sys::fuzz_target;
use taky_common::pyjson::float_repr;
use taky_common::pyparse::py_float;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(f) = py_float(s) {
        let r = float_repr(f);
        if f.is_finite() {
            let back = py_float(&r);
            assert_eq!(
                back.map(f64::to_bits),
                Some(f.to_bits()),
                "repr {r:?} of {s:?}"
            );
        }
        let _ = format!("{f:.6}");
        let _ = format!("{f:.1}");
    }
});
