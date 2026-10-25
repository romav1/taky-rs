//! CoT log (`cot_server.log_cot`, spec §15): one append-mode file per connection with every
//! routed event and every event dropped with an error (`taky/cot/client.py:log_event`).
//!
//! Driven by the connection task (taky-server), never by the Hub. The logger is self-contained
//! (review-3B N-1, ARCHITECTURE §14):
//! * it mirrors `handle_atom` (spec §10: `type` starting with `a`, non-monitor, TAKUser detail)
//!   to pick the file name — `<uid>-<callsign>.cot` once identified, otherwise
//!   `anonymous-<ip>.cot` / `monitor-<ip>.cot`; the first identification closes the anonymous
//!   file, later callsign changes keep the open file;
//! * [`CotLogger::on_event`] skips empty types, pings (`t-x-c-t`) and `*-ping` uids (spec §6
//!   items 4/5, §15); it logs a **clone** of the event with [`apply_max_ttl`] applied (Python
//!   logs after `route`), so the event given to the Router keeps its original stale (V047);
//! * if the event cannot be serialized (D-8), the original element is logged with
//!   `<__taky_err>` instead, as Python's `feed` does for exceptions raised by `route` (§6 item 9);
//! * D-12: `/` and NUL in the file name become `_`, a name equal to `.`/`..` becomes `_`, so the
//!   file always stays inside `log_cot` (V053).
//!
//! Record format (MUST, V044): `etree.tostring(elm, pretty_print=True)` — see
//! [`taky_xml::serialize`]. The directory is not created: an open error is a WARNING and
//! disables logging for the connection; a write error closes the file and disables it too.
//!
//! All methods do blocking file I/O: call them from `spawn_blocking` (ARCHITECTURE §5).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use taky_common::{SharedClock, pylog};
use taky_xml::{Element, Node, SerOpts};
use tracing::Level;

use crate::client::ClientKind;
use crate::models::{Event, EventDetail, TakUser};
use crate::router::apply_max_ttl;

/// Child element carrying the error text (`client.py:265`).
pub const TAKY_ERR: &str = "__taky_err";

/// Per-connection CoT logger. With `log_cot` unset every call is a no-op.
#[derive(Debug)]
pub struct CotLogger {
    dir: Option<PathBuf>,
    kind: ClientKind,
    addr: Option<IpAddr>,
    max_persist_ttl: i64,
    clock: SharedClock,
    lgr: String,
    /// The identified user as `handle_atom` would have set it.
    user: Option<TakUser>,
    file: Option<File>,
}

impl CotLogger {
    /// Logger for one connection writing into `dir` (`None` — disabled). `addr` is the peer IP
    /// (`None` — an in-process client: Python cannot name the file and logs nothing until the
    /// client identifies). `max_persist_ttl` and `clock` are the Router's.
    pub fn new(
        dir: Option<&Path>,
        kind: ClientKind,
        addr: Option<IpAddr>,
        max_persist_ttl: i64,
        clock: SharedClock,
    ) -> CotLogger {
        CotLogger {
            dir: dir.map(Path::to_path_buf),
            kind,
            addr,
            max_persist_ttl,
            clock,
            lgr: "TAKClient".to_owned(),
            user: None,
            file: None,
        }
    }

    /// Use `lgr` as the logger name of WARNING/DEBUG messages (`SocketTAKClient@ip:port`).
    pub fn with_logger_name(mut self, lgr: impl Into<String>) -> CotLogger {
        self.lgr = lgr.into();
        self
    }

    /// `true` while `log_cot` is configured and logging was not disabled by an I/O error.
    pub fn enabled(&self) -> bool {
        self.dir.is_some()
    }

    /// The current file path (opened or to be opened), `None` if no name can be derived yet.
    pub fn file_name(&self) -> Option<PathBuf> {
        let dir = self.dir.as_ref()?;
        let name = match &self.user {
            Some(u) if u.uid.as_deref().is_some_and(|s| !s.is_empty()) => format!(
                "{}-{}.cot",
                u.uid.as_deref().unwrap_or_default(),
                u.callsign.as_deref().unwrap_or("None")
            ),
            _ => {
                let what = match self.kind {
                    ClientKind::Monitor => "monitor",
                    ClientKind::Cot => "anonymous",
                };
                format!("{what}-{}.cot", self.addr?)
            }
        };
        Some(dir.join(sanitize_file_name(&name)))
    }

    /// One parsed event (after `Event::from_element` succeeded); `elm` is the element as
    /// received. See the module docs for what is skipped and what is written.
    pub fn on_event(&mut self, elm: &Element, evt: &Event) {
        let Some(etype) = evt.etype.as_deref().filter(|t| !t.is_empty()) else {
            return;
        };
        if etype == "t-x-c-t" {
            return;
        }
        // handle_atom (client.py:319-339).
        if etype.starts_with('a')
            && self.kind != ClientKind::Monitor
            && let Some(EventDetail::TakUser(u)) = &evt.detail
        {
            if self.user.is_none() {
                self.file = None; // close_cot(): the anonymous log
            }
            self.user = Some(u.clone());
        }
        if !self.enabled() || evt.uid.as_deref().is_some_and(|u| u.ends_with("-ping")) {
            return;
        }
        let mut clone = evt.clone();
        apply_max_ttl(self.max_persist_ttl, &mut clone, self.clock.as_ref());
        match clone.to_wire_element() {
            Ok(e) => self.write(&e),
            Err(e) => self.on_error(elm, &format!("SerializeError: {e}\n")),
        }
    }

    /// An element that was dropped with an error (`UnmarshalError`, or D-8 from
    /// [`CotLogger::on_event`]): the original element plus `<__taky_err><!--exc--></__taky_err>`.
    /// An `exc` that is not a valid XML comment (contains `--` or ends with `-`, lxml
    /// `ValueError`) skips the record with a WARNING, like Python.
    pub fn on_error(&mut self, elm: &Element, exc: &str) {
        if !self.enabled() {
            return;
        }
        if exc.contains("--") || exc.ends_with('-') || !taky_xml::is_xml_compatible(exc) {
            pylog!(
                self.lgr,
                Level::WARN,
                "Unable to build packet string for logfile"
            );
            return;
        }
        let mut e = elm.clone();
        let mut err = Element::new(TAKY_ERR);
        err.children.push(Node::Comment {
            text: exc.to_owned(),
            tail: None,
        });
        e.append(err);
        self.write(&e);
    }

    fn write(&mut self, elm: &Element) {
        if self.file.is_none() {
            let Some(name) = self.file_name() else {
                return; // no way to determine the file name
            };
            pylog!(self.lgr, Level::DEBUG, "Opening logfile {}", name.display());
            match OpenOptions::new().append(true).create(true).open(&name) {
                Ok(f) => self.file = Some(f),
                Err(e) => {
                    pylog!(self.lgr, Level::WARN, "Unable to open COT log: {e}");
                    self.dir = None;
                    return;
                }
            }
        }
        let doc = taky_xml::serialize(
            elm,
            &SerOpts {
                pretty_print: true,
                ..SerOpts::default()
            },
        );
        if let Some(f) = self.file.as_mut()
            && let Err(e) = f.write_all(&doc).and_then(|()| f.flush())
        {
            pylog!(self.lgr, Level::WARN, "Unable to write to COT log: {e}");
            self.file = None;
            self.dir = None;
        }
    }
}

/// D-12: `/` and NUL → `_`; a name equal to `.` or `..` → `_`. Everything else is unchanged.
pub fn sanitize_file_name(name: &str) -> String {
    if name == "." || name == ".." {
        return "_".to_owned();
    }
    name.replace(['/', '\0'], "_")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use taky_common::SystemClock;

    #[test]
    fn disabled_without_dir() {
        let c = SystemClock::shared();
        assert!(!CotLogger::new(None, ClientKind::Cot, None, -1, c.clone()).enabled());
        assert!(CotLogger::new(Some(Path::new("/tmp")), ClientKind::Cot, None, -1, c).enabled());
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_file_name("../escape-X.cot"), ".._escape-X.cot");
        assert_eq!(sanitize_file_name("a\0b/c"), "a_b_c");
        assert_eq!(sanitize_file_name(".."), "_");
        assert_eq!(sanitize_file_name("."), "_");
        assert_eq!(sanitize_file_name("...-x.cot"), "...-x.cot");
    }

    #[test]
    fn anonymous_and_monitor_names() {
        let c = SystemClock::shared();
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        let d = Path::new("/l");
        let a = CotLogger::new(Some(d), ClientKind::Cot, Some(ip), -1, c.clone());
        assert_eq!(a.file_name().unwrap(), d.join("anonymous-10.0.0.7.cot"));
        let m = CotLogger::new(Some(d), ClientKind::Monitor, Some(ip), -1, c.clone());
        assert_eq!(m.file_name().unwrap(), d.join("monitor-10.0.0.7.cot"));
        assert!(
            CotLogger::new(Some(d), ClientKind::Cot, None, -1, c)
                .file_name()
                .is_none()
        );
    }
}
