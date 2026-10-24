//! `cert-db.txt` (`taky/util/anc.py:CertificateDatabase`): TAB-separated lines
//! `status, issued.isoformat(), expires.isoformat(), serial %040x, CN`; lines with ≠5 fields are
//! skipped. D-11: re-read on mtime change; writes are read-modify-write under `flock` + tmp+rename.
//!
//! Locking: an exclusive `flock` on the sidecar `<cert_db>.lock` (the data file itself is
//! replaced by rename, so it cannot carry the lock). Readers do not lock: rename is atomic.
//! Python takyctl does not lock at all, so it can still race with us (OQ-C3).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::NaiveDateTime;
use nix::fcntl::{Flock, FlockArg};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::PkiError;
use crate::identity::{common_names, strip_leading_zeros};

/// Record status column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertStatus {
    /// `V` — valid.
    Valid,
    /// `R` — revoked (banned: connections with this serial are refused).
    Revoked,
    /// Any other value: read and written back unchanged, not a revocation (spec §5).
    Other(String),
}

impl CertStatus {
    fn parse(s: &str) -> CertStatus {
        match s {
            "V" => CertStatus::Valid,
            "R" => CertStatus::Revoked,
            o => CertStatus::Other(o.to_owned()),
        }
    }

    /// The column text.
    pub fn as_str(&self) -> &str {
        match self {
            CertStatus::Valid => "V",
            CertStatus::Revoked => "R",
            CertStatus::Other(s) => s,
        }
    }
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

impl CertRecord {
    /// The line as Python `write_cert_db` writes it (with the trailing `\n`).
    pub fn to_line(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\n",
            self.status.as_str(),
            isoformat(&self.issued),
            isoformat(&self.expires),
            serial_hex40(&self.serial),
            self.name
        )
    }
}

/// File identity used for the D-11 change check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    mtime: SystemTime,
    len: u64,
    ino: u64,
}

fn stamp(path: &Path) -> Option<Stamp> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(path).ok()?;
    Some(Stamp {
        mtime: m.modified().ok()?,
        len: m.len(),
        ino: m.ino(),
    })
}

/// The certificate database, records in file order.
#[derive(Debug)]
pub struct CertDb {
    path: PathBuf,
    records: Vec<CertRecord>,
    stamp: Option<Stamp>,
}

impl CertDb {
    /// Load `path` (a missing file is an empty database).
    pub fn open(path: &Path) -> Result<CertDb, PkiError> {
        let mut db = CertDb {
            path: path.to_owned(),
            records: Vec::new(),
            stamp: None,
        };
        db.reload()?;
        Ok(db)
    }

    /// The file this database reads and writes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// All records, in file order (duplicates collapsed: first position, last value).
    pub fn records(&self) -> &[CertRecord] {
        &self.records
    }

    /// D-11: re-read the file if its mtime/size/inode changed since the last read or write.
    /// Returns `true` if it was re-read. On error the in-memory records are kept.
    pub fn reload_if_changed(&mut self) -> Result<bool, PkiError> {
        if stamp(&self.path) == self.stamp {
            return Ok(false);
        }
        self.reload()?;
        Ok(true)
    }

    /// Unconditional re-read.
    pub fn reload(&mut self) -> Result<(), PkiError> {
        let before = stamp(&self.path);
        let records = read_file(&self.path)?;
        self.records = records;
        self.stamp = before;
        Ok(())
    }

    /// `get_certificate_by_serial` (integer comparison: leading zero bytes are ignored).
    pub fn by_serial(&self, sn: &[u8]) -> Option<&CertRecord> {
        let sn = strip_leading_zeros(sn);
        self.records.iter().find(|r| r.serial == sn)
    }

    /// `get_certificates_by_name`.
    pub fn by_name<'a>(&'a self, cn: &'a str) -> impl Iterator<Item = &'a CertRecord> + 'a {
        self.records.iter().filter(move |r| r.name == cn)
    }

    /// `revoke_certificate`: status `R`, `expires = when`; persisted immediately.
    /// `when` comes from the injected clock (`Clock::utc_now`) at the call site.
    /// D-11: done as read-modify-write under the lock, so lines added by other writers since
    /// the last read are kept and can be revoked.
    pub fn revoke(&mut self, sn: &[u8], when: NaiveDateTime) -> Result<(), PkiError> {
        let sn = strip_leading_zeros(sn);
        self.modify(|records| {
            let r = records
                .iter_mut()
                .find(|r| r.serial == sn)
                .ok_or(PkiError::NotFound)?;
            r.status = CertStatus::Revoked;
            r.expires = when;
            Ok(())
        })
    }

    /// `add_certificate` from DER (exactly one CN required); persisted immediately.
    /// An existing record with the same serial is replaced in place (Python dict semantics).
    pub fn add(&mut self, cert_der: &[u8]) -> Result<(), PkiError> {
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| PkiError::Invalid(format!("certificate: {e}")))?;
        let mut names = common_names(cert.subject());
        if names.len() != 1 {
            return Err(PkiError::Invalid(
                "Certificate must have exactly one CommonName".into(),
            ));
        }
        let ts = |t: x509_parser::time::ASN1Time| {
            chrono::DateTime::from_timestamp(t.timestamp(), 0)
                .map(|d| d.naive_utc())
                .ok_or_else(|| PkiError::Invalid("certificate validity out of range".into()))
        };
        let rec = CertRecord {
            status: CertStatus::Valid,
            issued: ts(cert.validity().not_before)?,
            expires: ts(cert.validity().not_after)?,
            serial: strip_leading_zeros(cert.raw_serial()),
            name: names.pop().unwrap_or_default(),
        };
        self.modify(move |records| {
            upsert(records, rec);
            Ok(())
        })
    }

    /// `true` if `sn` is present with status `R` (connect-time ban check by the Hub).
    pub fn is_revoked(&self, sn: &[u8]) -> bool {
        self.by_serial(sn)
            .is_some_and(|r| r.status == CertStatus::Revoked)
    }

    /// Read-modify-write under the lock: re-read, apply `f`, write tmp + rename.
    fn modify(
        &mut self,
        f: impl FnOnce(&mut Vec<CertRecord>) -> Result<(), PkiError>,
    ) -> Result<(), PkiError> {
        let _lock = lock(&self.path)?;
        let mut records = read_file(&self.path)?;
        f(&mut records)?;
        write_file(&self.path, &records)?;
        self.records = records;
        self.stamp = stamp(&self.path);
        Ok(())
    }
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> PkiError + '_ {
    move |source| PkiError::Io {
        path: path.to_owned(),
        source,
    }
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn lock(path: &Path) -> Result<Flock<File>, PkiError> {
    let lp = sidecar(path, ".lock");
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lp)
        .map_err(io_err(&lp))?;
    Flock::lock(f, FlockArg::LockExclusive).map_err(|(_, e)| PkiError::Io {
        path: lp,
        source: std::io::Error::from(e),
    })
}

fn upsert(records: &mut Vec<CertRecord>, rec: CertRecord) {
    match records.iter_mut().find(|r| r.serial == rec.serial) {
        Some(slot) => *slot = rec,
        None => records.push(rec),
    }
}

fn read_file(path: &Path) -> Result<Vec<CertRecord>, PkiError> {
    let text = match fs::read(path) {
        Ok(b) => String::from_utf8(b)
            .map_err(|_| PkiError::Invalid(format!("{}: not UTF-8", path.display())))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_err(path)(e)),
    };
    let mut records = Vec::new();
    for (no, line) in text.lines().enumerate() {
        let fields: Vec<&str> = line.trim().split('\t').collect();
        let [status, issued, expires, serial, name] = fields[..] else {
            continue;
        };
        let bad =
            |what: &str| PkiError::Invalid(format!("{}:{}: bad {what}", path.display(), no + 1));
        let rec = CertRecord {
            status: CertStatus::parse(status),
            issued: fromisoformat(issued).ok_or_else(|| bad("issued date"))?,
            expires: fromisoformat(expires).ok_or_else(|| bad("expires date"))?,
            serial: parse_serial(serial).ok_or_else(|| bad("serial"))?,
            name: name.to_owned(),
        };
        upsert(&mut records, rec);
    }
    Ok(records)
}

fn write_file(path: &Path, records: &[CertRecord]) -> Result<(), PkiError> {
    let tmp = sidecar(path, &format!(".tmp.{}", std::process::id()));
    let res = (|| {
        let mut f = File::create(&tmp).map_err(io_err(&tmp))?;
        // Keep the permissions of the file being replaced (Python rewrites it in place).
        if let Ok(m) = fs::metadata(path) {
            f.set_permissions(m.permissions()).map_err(io_err(&tmp))?;
        }
        let body: String = records.iter().map(CertRecord::to_line).collect();
        f.write_all(body.as_bytes()).map_err(io_err(&tmp))?;
        f.sync_all().map_err(io_err(&tmp))?;
        fs::rename(&tmp, path).map_err(io_err(path))
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

/// Python `int(x, 16)`: optional `0x` prefix, `_` separators, any case/length.
fn parse_serial(s: &str) -> Option<Vec<u8>> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.is_empty() || s.starts_with('_') || s.ends_with('_') || s.contains("__") {
        return None;
    }
    let digits: String = s.chars().filter(|&c| c != '_').collect();
    if !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let padded = if digits.len() % 2 == 1 {
        format!("0{digits}")
    } else {
        digits
    };
    Some(strip_leading_zeros(&crate::pem::hex_decode(&padded)?))
}

/// `f"{serial:040x}"`.
fn serial_hex40(serial: &[u8]) -> String {
    let hex: String = serial.iter().map(|b| format!("{b:02x}")).collect();
    let hex = hex.trim_start_matches('0');
    format!("{hex:0>40}")
}

/// Python `datetime.isoformat()` for naive values: microseconds only when non-zero.
pub fn isoformat(t: &NaiveDateTime) -> String {
    if t.and_utc().timestamp_subsec_micros() == 0 {
        t.format("%Y-%m-%dT%H:%M:%S").to_string()
    } else {
        t.format("%Y-%m-%dT%H:%M:%S%.6f").to_string()
    }
}

/// The subset of Python `datetime.fromisoformat` that cert-db writers produce: `T` or space
/// separator, optional fraction, or a bare date. Offsets are not accepted (no writer emits them).
pub fn fromisoformat(s: &str) -> Option<NaiveDateTime> {
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M",
    ] {
        if let Ok(t) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(t);
        }
    }
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt(s: &str) -> NaiveDateTime {
        fromisoformat(s).expect("date")
    }

    const SAMPLE: &str = "V\t2026-10-16T19:03:45\t2028-10-17T19:03:45\t5982ef37f6f0770260ac07dbf3ad1ff3e2410018\tsrv1\n\
R\t2026-10-16T19:03:45\t2026-10-18T19:04:40.195511\t3674ed1632305d915641de2431915664c236d2a2\tJENNY\n";

    #[test]
    fn spec_sample_roundtrip_byte_for_byte() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("cert-db.txt");
        fs::write(&p, SAMPLE).expect("write");
        let mut db = CertDb::open(&p).expect("open");
        assert_eq!(db.records().len(), 2);
        assert_eq!(db.records()[1].status, CertStatus::Revoked);
        assert_eq!(db.records()[1].name, "JENNY");
        let out: String = db.records().iter().map(CertRecord::to_line).collect();
        assert_eq!(out, SAMPLE);
        // A no-op RMW keeps the bytes.
        let sn = db.records()[1].serial.clone();
        db.revoke(&sn, dt("2026-10-18T19:04:40.195511"))
            .expect("revoke");
        assert_eq!(fs::read_to_string(&p).expect("read"), SAMPLE);
    }

    #[test]
    fn python_read_quirks() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("cert-db.txt");
        let text = "  V\t2026-01-01T00:00:00\t2027-01-01T00:00:00\t00000000000000000000000000000000000000ff\ta  \r\n\
            bad line\n\
            X\t2026-01-01 00:00:00\t2027-01-01\t0xABC\tb\n\
            V\t2026-01-01T00:00:00\t2027-01-01T00:00:00\tFF\ta2\n\
            V\t2026-01-01T00:00:00\t2027-01-01T00:00:00\t1\t\n";
        fs::write(&p, text).expect("write");
        let db = CertDb::open(&p).expect("open");
        // dup serial ff: first position, last value; trailing empty CN ⇒ strip ⇒ 4 fields ⇒ skipped.
        assert_eq!(db.records().len(), 2);
        assert_eq!(db.records()[0].name, "a2");
        assert_eq!(db.records()[1].status, CertStatus::Other("X".into()));
        assert_eq!(db.records()[1].serial, vec![0x0a, 0xbc]);
        assert!(db.by_serial(&[0, 0, 0xff]).is_some());
        assert!(!db.is_revoked(&[0x0a, 0xbc]));
        assert_eq!(db.by_name("b").count(), 1);
        assert_eq!(
            db.records()[1].to_line(),
            "X\t2026-01-01T00:00:00\t2027-01-01T00:00:00\t0000000000000000000000000000000000000abc\tb\n"
        );
    }

    #[test]
    fn bad_date_is_error_and_missing_file_empty() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("cert-db.txt");
        assert!(CertDb::open(&p).expect("open").records().is_empty());
        fs::write(&p, "V\tnope\t2027-01-01T00:00:00\t01\tx\n").expect("write");
        assert!(matches!(CertDb::open(&p), Err(PkiError::Invalid(_))));
    }

    #[test]
    fn revoke_unknown_is_not_found() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("cert-db.txt");
        let mut db = CertDb::open(&p).expect("open");
        assert!(matches!(
            db.revoke(&[1], dt("2030-01-01T00:00:00")),
            Err(PkiError::NotFound)
        ));
        assert!(!p.exists());
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_keeps_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("cert-db.txt");
        fs::write(&p, SAMPLE).expect("write");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).expect("chmod");
        let mut db = CertDb::open(&p).expect("open");
        let sn = db.records()[0].serial.clone();
        db.revoke(&sn, dt("2030-01-01T00:00:00")).expect("revoke");
        let mode = fs::metadata(&p).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        assert!(db.is_revoked(&sn));
    }

    #[test]
    fn isoformat_like_python() {
        assert_eq!(
            isoformat(&dt("2026-10-18T19:04:40.195511")),
            "2026-10-18T19:04:40.195511"
        );
        assert_eq!(
            isoformat(&dt("2026-10-18T19:04:40.000001")),
            "2026-10-18T19:04:40.000001"
        );
        assert_eq!(
            isoformat(&dt("2026-10-18T19:04:40.5")),
            "2026-10-18T19:04:40.500000"
        );
        assert_eq!(isoformat(&dt("2026-10-18T19:04:40")), "2026-10-18T19:04:40");
        assert_eq!(serial_hex40(&[]), "0".repeat(40));
    }
}
