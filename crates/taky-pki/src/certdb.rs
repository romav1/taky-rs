//! `cert-db.txt` (`taky/util/anc.py:CertificateDatabase`): TAB-separated lines
//! `status, issued.isoformat(), expires.isoformat(), serial %040x, CN`; lines with ≠5 fields are
//! skipped. D-11: re-read on mtime change; writes are read-modify-write under `flock` + tmp+rename.

use std::path::Path;

use chrono::NaiveDateTime;

use crate::PkiError;

/// Record status column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    /// `V` — valid.
    Valid,
    /// `R` — revoked (banned: connections with this serial are refused).
    Revoked,
}

/// One cert-db line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRecord {
    /// Status.
    pub status: CertStatus,
    /// `notBefore` (naive).
    pub issued: NaiveDateTime,
    /// `notAfter`, or the revocation time for revoked records.
    pub expires: NaiveDateTime,
    /// Serial number, big-endian, without leading zero bytes.
    pub serial: Vec<u8>,
    /// Subject CN.
    pub name: String,
}

/// The certificate database, records in file order.
#[derive(Debug)]
pub struct CertDb {
    _private: (),
}

impl CertDb {
    /// Load `path` (a missing file is an empty database).
    pub fn open(path: &Path) -> Result<CertDb, PkiError> {
        let _ = path;
        todo!("dev02: S-311")
    }

    /// `get_certificate_by_serial`.
    pub fn by_serial(&self, sn: &[u8]) -> Option<&CertRecord> {
        let _ = sn;
        todo!("dev02: S-311")
    }

    /// `get_certificates_by_name` (stub: empty until S-311).
    pub fn by_name<'a>(&'a self, cn: &'a str) -> impl Iterator<Item = &'a CertRecord> + 'a {
        let _ = cn;
        std::iter::empty::<&'a CertRecord>()
    }

    /// `revoke_certificate`: status `R`, `expires = when`; persisted immediately.
    /// `when` comes from the injected clock (`Clock::utc_now`) at the call site.
    pub fn revoke(&mut self, sn: &[u8], when: NaiveDateTime) -> Result<(), PkiError> {
        let _ = (sn, when);
        todo!("dev02: S-311")
    }

    /// `add_certificate` from DER (exactly one CN required); persisted immediately.
    pub fn add(&mut self, cert_der: &[u8]) -> Result<(), PkiError> {
        let _ = cert_der;
        todo!("dev02: S-311")
    }

    /// `true` if `sn` is present with status `R` (connect-time ban check by the Hub).
    pub fn is_revoked(&self, sn: &[u8]) -> bool {
        self.by_serial(sn)
            .is_some_and(|r| r.status == CertStatus::Revoked)
    }
}
