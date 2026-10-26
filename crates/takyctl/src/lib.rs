//! `takyctl-rs` library part (owner: dev02): the subcommands and their building blocks, kept
//! out of the binary so that integration tests (`tests/pyref_*.rs`) can drive them.
//!
//! S-321: [`datapackage`] (client data package). S-322: [`setup`](mod@setup),
//! [`build_client`](mod@build_client). S-323: [`systemd`](mod@systemd),
//! [`status`](mod@status), [`kickban`](mod@kickban) (mgmt client: [`mgmt`]).

pub mod build_client;
pub mod cli;
pub mod datapackage;
pub mod fsutil;
pub mod kickban;
pub mod mgmt;
pub mod pyerr;
pub mod setup;
pub mod status;
pub mod systemd;
