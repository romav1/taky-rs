//! CoT log (`cot_server.log_cot`): one file per client, events and unmarshal errors
//! (`taky/cot/client.py:log_event`). Used by connection tasks (dev02), not by the Hub.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use taky_xml::Element;

use crate::client::ClientKind;
use crate::models::{Event, TakUser};

/// Per-connection CoT logger. With `log_cot` unset every call is a no-op.
#[derive(Debug, Default)]
pub struct CotLogger {
    dir: Option<PathBuf>,
}

impl CotLogger {
    /// Logger writing into `dir` (`None` — disabled). Files are opened lazily, once the
    /// client's callsign/uid is known (path-traversal-safe names, an01 vector "traversal log_cot").
    pub fn new(dir: Option<&Path>) -> CotLogger {
        CotLogger {
            dir: dir.map(Path::to_path_buf),
        }
    }

    /// `true` if `log_cot` is configured.
    pub fn enabled(&self) -> bool {
        self.dir.is_some()
    }

    /// Log a received event. Blocking file I/O: call from the connection task.
    pub fn on_event(
        &mut self,
        user: Option<&TakUser>,
        addr: Option<IpAddr>,
        kind: ClientKind,
        evt: &Event,
    ) {
        let _ = (user, addr, kind, evt);
        todo!("S-309")
    }

    /// Log an element that failed `Event::from_element` (`__taky_err`).
    pub fn on_error(&mut self, elm: &Element, exc: &str) {
        let _ = (elm, exc);
        todo!("S-309")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_without_dir() {
        assert!(!CotLogger::new(None).enabled());
        assert!(CotLogger::new(Some(Path::new("/tmp"))).enabled());
    }
}
