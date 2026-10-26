//! Test-only harness binaries for taky-rs (qa01; never shipped, not part of any release build).
//!
//! * `taky-rs-difftest` (feature `difftest`) — the Rust CoT target of `tools/difftest`: runs the
//!   real server ([`taky_server::start`] on [`taky_server::Listeners::bind`], i.e. the same code
//!   path as the `taky-rs` binary) with a frozen [`FakeClock`](taky_common::clock) and the control
//!   channel of `tools/difftest/harness/pylaunch_cot.py` (see the binary's docs).
