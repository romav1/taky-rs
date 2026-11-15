//! `ini_parse` (S-407): `taky_config::Ini` (configparser port, ADR-005) and `load_config_in`
//! (`config.py` normalisation, U003). Invariants: no panic in parse / interpolating `get` of every
//! key / `getboolean` / `write`; `load_config_in` on the same text returns Ok or Err, never panics.
#![cfg_attr(not(test), no_main)]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use taky_config::{Ini, load_config_in};

const PREFIX: &str = "taky-fuzz-ini-";

/// Scratch directory for the config file written on every run. Prefer tmpfs (`/dev/shm`): a
/// disk-backed temp dir makes each run do real file I/O, and a stall of the CI runner's disk
/// turned into a false libFuzzer timeout (S-510). Falls back to the default temp dir.
///
/// libFuzzer leaves through `exit()`, so a static is never dropped (S-822 N-4: one leftover dir per
/// fuzz process). Instead the path is fixed per process, `<base>/taky-fuzz-ini-<pid>`, and every
/// start removes it and the dirs of processes that no longer run: at most one dir per live fuzz
/// process plus the last one that exited remain.
fn dir() -> &'static Path {
    static D: OnceLock<PathBuf> = OnceLock::new();
    D.get_or_init(|| {
        let alive = |pid: u32| Path::new(&format!("/proc/{pid}")).exists();
        scratch_in(Path::new("/dev/shm"), std::process::id(), &alive)
            .or_else(|_| scratch_in(&std::env::temp_dir(), std::process::id(), &alive))
            .unwrap_or_else(|e| panic!("scratch dir: {e}"))
    })
}

/// Remove `<base>/taky-fuzz-ini-<n>` for our own `pid` and for every `n` that is not `alive`, then
/// create our own (empty) dir and return it.
fn scratch_in(base: &Path, pid: u32, alive: &dyn Fn(u32) -> bool) -> std::io::Result<PathBuf> {
    for ent in std::fs::read_dir(base)?.flatten() {
        let name = ent.file_name();
        let stale = name
            .to_str()
            .and_then(|n| n.strip_prefix(PREFIX))
            .and_then(|n| n.parse::<u32>().ok())
            .is_some_and(|n| n == pid || !alive(n));
        if stale {
            let _ = std::fs::remove_dir_all(ent.path());
        }
    }
    let own = base.join(format!("{PREFIX}{pid}"));
    std::fs::create_dir(&own)?;
    Ok(own)
}

#[cfg(not(test))]
libfuzzer_sys::fuzz_target!(|data: &[u8]| run_one(data));

fn run_one(data: &[u8]) {
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
    let d = dir();
    let p = d.join("taky.conf");
    if let Ok(mut f) = std::fs::File::create(&p) {
        if f.write_all(data).is_ok() {
            drop(f);
            let _ = load_config_in(Some(&p), true, d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_removes_own_and_dead_dirs_and_keeps_the_rest() {
        let base = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let b = base.path();
        for d in [
            "taky-fuzz-ini-7",
            "taky-fuzz-ini-8",
            "taky-fuzz-ini-9",
            "taky-fuzz-ini-x",
            "other",
        ] {
            std::fs::create_dir(b.join(d)).unwrap_or_else(|e| panic!("{e}"));
        }
        std::fs::write(b.join("taky-fuzz-ini-7/taky.conf"), "old")
            .unwrap_or_else(|e| panic!("{e}"));
        // pid 7 = us (stale dir from an earlier process with the same pid), 8 alive, 9 dead.
        let own = scratch_in(b, 7, &|n| n == 8).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(own, b.join("taky-fuzz-ini-7"));
        assert_eq!(
            std::fs::read_dir(&own).map(Iterator::count).ok(),
            Some(0),
            "own dir is fresh"
        );
        let mut left: Vec<String> = std::fs::read_dir(b)
            .unwrap_or_else(|e| panic!("{e}"))
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "other",
                "taky-fuzz-ini-7",
                "taky-fuzz-ini-8",
                "taky-fuzz-ini-x"
            ]
        );
    }

    /// The committed corpus runs through the target without a panic, in this process's dir.
    #[test]
    fn corpus_replays() {
        let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/ini_parse");
        let mut n = 0;
        for ent in std::fs::read_dir(&d).unwrap_or_else(|e| panic!("{}: {e}", d.display())) {
            let p = ent.unwrap_or_else(|e| panic!("{e}")).path();
            run_one(&std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())));
            n += 1;
        }
        assert!(n > 0, "empty corpus");
        assert!(dir().ends_with(format!("{PREFIX}{}", std::process::id())));
    }

    #[test]
    fn missing_base_is_an_error_so_dir_falls_back() {
        let base = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        assert!(scratch_in(&base.path().join("nope"), 1, &|_| true).is_err());
    }
}
