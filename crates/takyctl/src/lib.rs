//! `takyctl-rs` library part (owner: dev02): the subcommands and their building blocks, kept
//! out of the binary so that integration tests (`tests/pyref_*.rs`) can drive them.
//!
//! S-321: [`datapackage`] (client data package). S-322: [`setup`](mod@setup),
//! [`build_client`](mod@build_client). `systemd`, `status`, `kickban` — S-323.

pub mod build_client;
pub mod cli;
pub mod datapackage;
pub mod fsutil;
pub mod pyerr;
pub mod setup;
