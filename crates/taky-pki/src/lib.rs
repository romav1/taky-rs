//! PKI for taky-rs (owner: dev02): `cert-db.txt`, PEM/keys, rustls configs, `PeerIdentity`,
//! CA/certificate and PKCS#12 generation (ARCHITECTURE §1, §11, §14, ADR-003, ADR-006).
//!
//! Status: S-202 seams (types and signatures defined by dev01; bodies `todo!()`).
//! Implementation — dev02, S-311, S-320, S-321. Certificate/PKCS#12 generation (`make_ca`,
//! `make_cert`, `pkcs12::write`) is internal to dev02 (takyctl) and not a seam; dev02 adds it behind the `gen` feature
//! (enabled only by takyctl, so `rsa` is not linked into taky-rs / taky_dps-rs).

pub mod certdb;
pub mod error;
pub mod identity;
pub mod tls;

pub use certdb::{CertDb, CertRecord, CertStatus};
pub use error::PkiError;
pub use identity::{PeerIdentity, peer_identity};
pub use tls::{TlsMode, server_config};
