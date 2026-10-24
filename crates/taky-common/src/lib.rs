//! Common primitives for taky-rs (owner: dev01).
//!
//! * [`version`] — product version (`taky/__init__.py:__version__`, ADR-008 G-3);
//! * [`log`] — logging in Python `logging.basicConfig()` format (ARCHITECTURE §8);
//! * [`pyjson`] — `json.dumps`-compatible output (mgmt, DPS meta);
//! * [`pyfmt`] — number and date formatting as in Python (`%.6f`, `round`, `isoformat`);
//! * [`clock`] — injectable clock [`clock::Clock`] (qa01 requirement, test-strategy §4.6);
//! * [`shutdown`] — shutdown signal [`shutdown::Shutdown`].
//!
//! Status: T-10 scaffold. Implementation: T-20..T-22.

pub mod clock;
pub mod log;
pub mod pyfmt;
pub mod pyjson;
pub mod shutdown;
pub mod version;

pub use clock::{Clock, SharedClock, SystemClock};
pub use shutdown::Shutdown;
pub use version::{VERSION, prog_name, version_line};
