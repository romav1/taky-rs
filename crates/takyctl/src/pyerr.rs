//! Python-style error texts for the `"<cmd> failed: <exc>"` path of `takyctl-rs`
//! (`cli/__main__.py:55-59`). Exact texts are not normative (stderr only, exit code 1 either
//! way), but the common ones read like the original's.

use std::io;

use taky_config::error::py_repr;
use taky_pki::PkiError;

/// `str(OSError)`: `[Errno 2] No such file or directory: '<path>'`.
pub fn os_error(e: &io::Error, path: &str) -> anyhow::Error {
    match e.raw_os_error() {
        Some(n) => anyhow::anyhow!(
            "[Errno {n}] {}: {}",
            nix::errno::Errno::from_raw(n).desc(),
            py_repr(path)
        ),
        None => anyhow::anyhow!("{e}: {}", py_repr(path)),
    }
}

/// `PkiError` as the matching Python exception text (`ValueError` message, `OSError`).
pub fn pki(e: PkiError) -> anyhow::Error {
    match e {
        PkiError::Io { path, source } => os_error(&source, &path.to_string_lossy()),
        PkiError::Invalid(m) => anyhow::anyhow!(m),
        other => anyhow::anyhow!(other.to_string()),
    }
}

/// `open(None)` / `os.path.join(None, …)` for a config option without a value.
pub fn none_path() -> anyhow::Error {
    anyhow::anyhow!("expected str, bytes or os.PathLike object, not NoneType")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_error_text() {
        let e = io::Error::from_raw_os_error(2);
        assert_eq!(
            os_error(&e, "/x/server.p12").to_string(),
            "[Errno 2] No such file or directory: '/x/server.p12'"
        );
        let e = io::Error::from_raw_os_error(17);
        assert_eq!(
            os_error(&e, "a'b").to_string(),
            "[Errno 17] File exists: \"a'b\""
        );
    }
}
