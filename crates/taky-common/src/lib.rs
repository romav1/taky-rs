//! Common primitives for taky-rs (owner: dev01).
//!
//! * [`version`] — product version (`taky/__init__.py:__version__`, ADR-008 G-3);
//! * [`log`] — logging in Python `logging.basicConfig()` format (ARCHITECTURE §8);
//! * [`pyjson`] — `json.dumps`-compatible output (mgmt, DPS meta);
//! * [`pyfmt`] — number and date formatting as in Python (`%.6f`, `round`, `isoformat`);
//! * [`pyparse`] — `float()` and the `Nd`/whitespace classes of CPython `int()`/`float()`;
//! * [`clock`] — injectable clock [`clock::Clock`] (qa01 requirement, test-strategy §4.6);
//! * [`shutdown`] — shutdown signal [`shutdown::Shutdown`];
//! * `vectors` (feature `testkit`) — location of the an01 test vectors for tests.
//!
//! Status: T-10 scaffold. Implementation: T-20..T-22.

pub mod clock;
pub mod log;
pub mod pyfmt;
pub mod pyjson;
pub mod pyparse;
pub mod shutdown;
#[cfg(feature = "testkit")]
pub mod vectors;
pub mod version;

pub use clock::{Clock, SharedClock, SystemClock};
pub use shutdown::Shutdown;
pub use version::{VERSION, prog_name, version_line};
