//! CoT server for taky-rs (owner: dev02): TCP/TLS listeners, monitor port, `Hub` actor,
//! mgmt unix socket, signals and shutdown; binary `taky-rs` (ARCHITECTURE §1, §2, §5, §10).
//!
//! Seams (S-202; implemented in block 3C S-312..S-314, dev01 since 2026-10-25):
//! * [`hub`] — [`HubCmd`], [`Hub`], [`HubHandle`] (the only caller of `taky_cot::Router`) — S-312;
//! * [`conn`] — [`ConnOutbox`] (the `taky_cot::Outbox` implementation) and the connection
//!   task (plain/TLS, ban check via the Hub, backpressure) — S-312;
//! * [`mgmt`] — [`MgmtRequest`] (NUL-terminated JSON on `{root_dir}/taky-mgmt.sock`; status /
//!   kickban answered by the Hub) — S-313;
//! * [`server`] — [`start`] on ready-made listeners (qa01 request A.3; CoT + monitor accept
//!   S-312, mgmt `UnixListener` + `log_cot` S-313), [`Listeners::bind`] (stale mgmt socket
//!   takeover, S-314);
//! * [`cli`] — `taky-rs` arguments and config-error reporting; the binary `src/bin/taky-rs.rs`
//!   (signals, graceful shutdown, exit codes) — S-314;
//! * [`limits`] — backpressure constants (ARCHITECTURE §6).
//!
//! Feature `testkit`: [`HubHandle::settle`] and everything from `taky-cot/testkit`.

pub mod cli;
pub mod conn;
pub mod hub;
pub mod limits;
pub mod mgmt;
pub mod server;

pub use conn::ConnOutbox;
pub use hub::{ConnectVerdict, Hub, HubCmd, HubHandle};
pub use mgmt::MgmtRequest;
pub use server::{Listeners, RunningServer, ServerOptions, start};
