//! PKI for taky-rs (owner: dev02): `cert-db.txt`, PEM/keys, rustls configs, `PeerIdentity`,
//! CA/certificate and PKCS#12 generation (ARCHITECTURE §1, §11, §14, ADR-003, ADR-006).
//!
//! Status: S-311 implemented `pem` (certificate/key loading), `tls`, `identity`, `certdb` (D-11).
//! S-320: `certgen` (CA/server/client certificate generation, anc.py profiles). Still to come —
//! S-321 `pkcs12::write`. Generation is internal to dev02 (takyctl), not a seam, and lives
//! behind the `gen` feature (enabled only by takyctl, so `rsa` is not linked into taky-rs /
//! taky_dps-rs).

pub mod certdb;
#[cfg(feature = "gen")]
pub mod certgen;
pub mod error;
pub mod identity;
pub mod pem;
pub mod tls;

pub use certdb::{CertDb, CertRecord, CertStatus};
pub use error::PkiError;
pub use identity::{PeerIdentity, peer_identity};
pub use tls::{TlsMode, load_roots, provider, server_config};
