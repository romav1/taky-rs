//! Product version.
//!
//! Python: `taky/__init__.py:__version__`. Customer decision ADR-008 G-3:
//! `--version` prints `"<prog> version <semver>"`, `/Marti/api/version` returns `taky-rs-<semver>`.

use std::path::Path;

/// Semantic version of taky-rs (taken from `[workspace.package] version`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// String for `--version`, like argparse `"%(prog)s version %s"`.
///
/// `argv0` is the process `argv[0]`; `prog` is its basename (as in argparse). If the basename
/// cannot be obtained, `fallback` is used.
///
/// ```
/// assert_eq!(
///     taky_common::version_line(Some("/usr/bin/taky-rs"), "taky-rs"),
///     format!("taky-rs version {}", taky_common::VERSION)
/// );
/// ```
pub fn version_line(argv0: Option<&str>, fallback: &str) -> String {
    let prog = prog_name(argv0, fallback);
    format!("{prog} version {VERSION}")
}

/// argparse `prog`: basename of `argv0`, or `fallback` if it cannot be obtained.
///
/// ```
/// assert_eq!(taky_common::prog_name(Some("/usr/bin/takyctl-rs"), "x"), "takyctl-rs");
/// assert_eq!(taky_common::prog_name(None, "taky-rs"), "taky-rs");
/// ```
pub fn prog_name<'a>(argv0: Option<&'a str>, fallback: &'a str) -> &'a str {
    argv0
        .and_then(|a| Path::new(a).file_name())
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_semver_0_1_0() {
        assert_eq!(VERSION, "0.1.0");
    }

    #[test]
    fn version_line_uses_basename() {
        assert_eq!(
            version_line(Some("./target/debug/takyctl-rs"), "x"),
            "takyctl-rs version 0.1.0"
        );
        assert_eq!(version_line(None, "taky-rs"), "taky-rs version 0.1.0");
    }
}
