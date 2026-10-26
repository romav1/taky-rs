//! Small `os` / `os.path` / `shutil` equivalents used by `setup` and `build_client`.

use std::path::{Component, Path, PathBuf};

use crate::pyerr::os_error;

/// `os.path.abspath(p)` relative to `cwd`: join, then lexical `normpath` (no symlink
/// resolution; `..` above `/` stays at `/`).
pub fn abspath(p: &Path, cwd: &Path) -> PathBuf {
    let joined = cwd.join(p);
    let mut out = PathBuf::from("/");
    for c in joined.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    out
}

/// `os.path.join(a, b)` on strings (`b` absolute ⇒ `b`).
pub fn join(a: &str, b: &str) -> String {
    if b.starts_with('/') || a.is_empty() {
        b.to_owned()
    } else if a.ends_with('/') {
        format!("{a}{b}")
    } else {
        format!("{a}/{b}")
    }
}

/// `os.mkdir(path)` (mode 0777 & ~umask, non-recursive). `shown` is the path in messages.
pub fn mkdir(fs: &Path, shown: &str) -> anyhow::Result<()> {
    std::fs::create_dir(fs).map_err(|e| os_error(&e, shown))
}

/// `shutil.chown(path, user=user, group=user)`: names resolved like `pwd.getpwnam` /
/// `grp.getgrnam` (user first), then `os.chown` (follows symlinks).
pub fn chown(fs: &Path, shown: &str, user: &str) -> anyhow::Result<()> {
    use taky_config::error::py_repr;
    let uid = nix::unistd::User::from_name(user)
        .ok()
        .flatten()
        .ok_or_else(|| anyhow::anyhow!("no such user: {}", py_repr(user)))?
        .uid;
    let gid = nix::unistd::Group::from_name(user)
        .ok()
        .flatten()
        .ok_or_else(|| anyhow::anyhow!("no such group: {}", py_repr(user)))?
        .gid;
    nix::unistd::chown(fs, Some(uid), Some(gid))
        .map_err(|e| os_error(&std::io::Error::from(e), shown))
}

/// The process umask without changing it (Linux `/proc/self/status`; `0o022` if unavailable).
/// Used for the mode bits of package entries Python would create as files in its temp dir.
pub fn current_umask() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Umask:"))
                .and_then(|v| u32::from_str_radix(v.trim(), 8).ok())
        })
        .unwrap_or(0o022)
}

/// `socket.gethostname()`, `"taky"` if it fails (`setup --host` default).
pub fn default_hostname() -> String {
    nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "taky".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abspath_like_python() {
        let cwd = Path::new("/home/u");
        assert_eq!(abspath(Path::new("site"), cwd), Path::new("/home/u/site"));
        assert_eq!(abspath(Path::new("./a/../b/"), cwd), Path::new("/home/u/b"));
        assert_eq!(abspath(Path::new("/x//y/."), cwd), Path::new("/x/y"));
        assert_eq!(abspath(Path::new("../../.."), cwd), Path::new("/"));
    }

    #[test]
    fn join_like_python() {
        assert_eq!(join("./dp-user", "meta"), "./dp-user/meta");
        assert_eq!(join("/var/taky/", "meta"), "/var/taky/meta");
        assert_eq!(join("x", "/abs"), "/abs");
    }

    #[test]
    fn chown_unknown_user() {
        let d = tempfile::tempdir().unwrap();
        let e = chown(d.path(), "d", "no-such-user-taky").unwrap_err();
        assert_eq!(e.to_string(), "no such user: 'no-such-user-taky'");
    }

    #[test]
    fn umask_and_hostname() {
        assert_eq!(current_umask() & !0o777, 0);
        assert!(!default_hostname().is_empty());
    }
}
