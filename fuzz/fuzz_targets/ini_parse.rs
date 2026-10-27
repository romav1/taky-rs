//! `ini_parse` (S-407): `taky_config::Ini` (configparser port, ADR-005) and `load_config_in`
//! (`config.py` normalisation, U003). Invariants: no panic in parse / interpolating `get` of every
//! key / `getboolean` / `write`; `load_config_in` on the same text returns Ok or Err, never panics.
#![no_main]
use std::io::Write;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use taky_config::{Ini, load_config_in};

fn dir() -> &'static tempfile::TempDir {
    static D: OnceLock<tempfile::TempDir> = OnceLock::new();
    D.get_or_init(|| tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}")))
}

fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(ini) = Ini::parse(src, "<fuzz>") else {
        return;
    };
    let secs: Vec<String> = ini.sections().map(str::to_owned).collect();
    for s in &secs {
        let keys: Vec<String> = ini
            .section_items(s)
            .map(|it| it.iter().map(|(k, _)| k.clone()).collect())
            .unwrap_or_default();
        for k in keys {
            let _ = ini.get(s, &k);
            let _ = ini.get_raw(s, &k);
            let _ = ini.getboolean(s, &k);
        }
    }
    let _ = ini.write();
    // Full load path (defaults merge, normalisation, port/path checks) from a real file.
    let d = dir().path();
    let p = d.join("taky.conf");
    if let Ok(mut f) = std::fs::File::create(&p) {
        if f.write_all(data).is_ok() {
            drop(f);
            let _ = load_config_in(Some(&p), true, d);
        }
    }
});
