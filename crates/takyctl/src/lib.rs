//! `takyctl-rs` library part (owner: dev02): building blocks of the subcommands, kept out of the
//! binary so that integration tests (`tests/pyref_datapackage.rs`) can use them.
//!
//! S-321: [`datapackage`] (client data package). The subcommands themselves are S-322+.

pub mod datapackage;
