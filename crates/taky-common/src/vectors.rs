//! Location of the an01 test vectors for vector-driven tests (feature `testkit`).
//!
//! Lookup order (pm01 decision, S-302):
//! 1. `<workspace>/tests/vectors` — the copy mirrored into the taky-rs repo (refreshed by pm01
//!    on each commit; this is what a taky-rs CI checkout has);
//! 2. `<workspace>/../shared/spec/vectors` — the source of truth in the office tree.
//!
//! If neither exists the helpers **panic**: a vector test must fail, never skip silently.

use std::path::{Path, PathBuf};

/// Root of the taky-rs workspace (the directory with the workspace `Cargo.toml`).
pub fn workspace_root() -> PathBuf {
    // This crate lives at `<workspace>/crates/taky-common`.
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Candidate vector directories, in lookup order.
pub fn candidates() -> [PathBuf; 2] {
    let root = workspace_root();
    [
        root.join("tests/vectors"),
        root.join("../shared/spec/vectors"),
    ]
}

/// The first existing vector directory; panics when there is none.
pub fn vectors_dir() -> PathBuf {
    let cands = candidates();
    for c in &cands {
        if c.is_dir() {
            return c.clone();
        }
    }
    panic!(
        "test vectors not found: neither {} nor {} exists",
        cands[0].display(),
        cands[1].display()
    );
}

/// Read a vector file by its path relative to the vector directory (e.g. `unit/U003.json`);
/// panics when it cannot be read.
pub fn read_vector(rel: &str) -> String {
    let path = vectors_dir().join(rel);
    match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => panic!("cannot read vector {}: {e}", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vectors_dir_is_found() {
        let d = vectors_dir();
        assert!(d.join("unit").is_dir(), "{}", d.display());
    }
}
