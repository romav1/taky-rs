//! CoT server for taky-rs (owner: dev02): TCP/TLS listeners, monitor port, `Hub` actor,
//! mgmt unix socket, signals and shutdown; binary `taky-rs` (ARCHITECTURE §1, §2, §5, §10).
//!
//! Seams (S-202, signatures defined by dev01; bodies `todo!()` — dev02, block 3C S-312..S-314):
//! * [`hub`] — [`HubCmd`], [`Hub`], [`HubHandle`] (the only caller of `taky_cot::Router`);
//! * [`mgmt`] — [`MgmtRequest`] (NUL-terminated JSON on `{root_dir}/taky-mgmt.sock`);
//! * [`server`] — [`start`] on ready-made listeners (qa01 request A.3), [`Listeners::bind`];
//! * [`limits`] — backpressure constants (ARCHITECTURE §6).
//!
//! Feature `testkit`: [`HubHandle::settle`] and everything from `taky-cot/testkit`.

pub mod cli;
pub mod hub;
pub mod limits;
pub mod mgmt;
pub mod server;

pub use hub::{ConnectVerdict, Hub, HubCmd, HubHandle};
pub use mgmt::MgmtRequest;
pub use server::{Listeners, RunningServer, ServerOptions, start};
