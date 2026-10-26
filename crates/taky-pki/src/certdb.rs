//! `cert-db.txt` (`taky/util/anc.py:CertificateDatabase`): TAB-separated lines
//! `status, issued.isoformat(), expires.isoformat(), serial %040x, CN`; lines with ≠5 fields are
//! skipped. D-11: re-read on mtime change; writes are read-modify-write under `flock` + tmp+rename.
//!
//! Locking: an exclusive `flock` on the sidecar `<cert_db>.lock` (the data file itself is
//! replaced by rename, so it cannot carry the lock). Readers do not lock: rename is atomic.
//! Python takyctl does not lock at all, so it can still race with us (OQ-C3, risk R5).
//! The wait for the lock is bounded by [`LOCK_WAIT`] (ADR-003 errata §5(c)): after it a write fails
//! with `PkiError::Io` (`EWOULDBLOCK`) instead of blocking the caller (the CoT Hub's kickban).
//!
//! Ownership (ADR-003 errata §4, review-3D B-1): Python rewrites the file in place, so its owner
//! never changes. We replace it, so as root (`sudo takyctl-rs`) the tmp file and a newly created
//! lock file are `fchown`ed to the data file's uid/gid (the directory's when the data file does
//! not exist yet); an existing lock that is not writable is opened read-only (`flock` needs no
//! write access). A symlinked `ssl.cert_db` is resolved first, so the link target is replaced and
//! the link is kept (Python writes through the link; review-3D N-3).

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use chrono::NaiveDateTime;
use nix::errno::Errno;
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
    /// The last error returned by [`CertDb::refresh`] and the stamp it was seen at.
    reported: Option<(Option<Stamp>, String)>,
}

impl CertDb {
    /// Load `path` (a missing file is an empty database).
    pub fn open(path: &Path) -> Result<CertDb, PkiError> {
        let mut db = CertDb {
            path: path.to_owned(),
            records: Vec::new(),
            stamp: None,
            reported: None,
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

    /// [`CertDb::reload_if_changed`] for per-request / per-connect callers that log: the file is
    /// re-read on every call while it keeps failing (so a `chmod`/`chown` fix is picked up), but a
    /// given error is returned only once per file stamp (mtime/size/inode); later calls return
    /// `None` until the file changes or the error text changes. Success clears the memory.
    /// On error the in-memory records are kept (review-3D N-2).
    pub fn refresh(&mut self) -> Option<PkiError> {
        match self.reload_if_changed() {
            Ok(_) => {
                self.reported = None;
                None
            }
            Err(e) => {
                let key = (stamp(&self.path), e.to_string());
                if self.reported.as_ref() == Some(&key) {
                    None
                } else {
                    self.reported = Some(key);
                    Some(e)
                }
            }
        }
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
        let target = resolve_symlinks(&self.path);
        let _lock = lock(&target)?;
        let mut records = read_file(&target)?;
        f(&mut records)?;
        write_file(&target, &records)?;
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

/// Follow a symlink chain (≤ 40 hops, like `ELOOP`) to the file that is actually written, so the
/// rename replaces the target and keeps the link. A dangling link resolves to its (missing)
/// target, which is then created, as Python `open(path, "w")` does.
fn resolve_symlinks(path: &Path) -> PathBuf {
    let mut p = path.to_owned();
    for _ in 0..40 {
        let Ok(m) = fs::symlink_metadata(&p) else {
            return p;
        };
        if !m.file_type().is_symlink() {
            return p;
        }
        let Ok(next) = fs::read_link(&p) else {
            return p;
        };
        p = match p.parent() {
            Some(dir) if next.is_relative() => dir.join(next),
            _ => next,
        };
    }
    p
}

/// uid/gid that files written next to `path` must get: the data file's, or its directory's when
/// the data file does not exist yet.
fn owner_of(path: &Path) -> Option<(u32, u32)> {
    let m = fs::metadata(path).ok().or_else(|| {
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        fs::metadata(dir).ok()
    })?;
    Some((m.uid(), m.gid()))
}

/// Give a file we just created the owner of the cert-db (B-1). As root: `fchown` to uid/gid
/// (errors are reported). Otherwise only the group is attempted, best effort (EPERM ignored).
fn adopt_owner(f: &File, owner: Option<(u32, u32)>, path: &Path) -> Result<(), PkiError> {
    let Some((uid, gid)) = owner else {
        return Ok(());
    };
    let cur = f.metadata().map_err(io_err(path))?;
    if (cur.uid(), cur.gid()) == (uid, gid) {
        return Ok(());
    }
    if nix::unistd::geteuid().is_root() {
        std::os::unix::fs::fchown(f, Some(uid), Some(gid)).map_err(io_err(path))
    } else {
        if cur.gid() != gid {
            let _ = std::os::unix::fs::fchown(f, None, Some(gid));
        }
        Ok(())
    }
}

/// Open the sidecar lock: an existing one read-write, or read-only when it is not writable for
/// us; a missing one is created (`O_EXCL`) and given the cert-db owner.
fn open_lock(lp: &Path, owner: Option<(u32, u32)>) -> Result<File, PkiError> {
    for _ in 0..2 {
        match OpenOptions::new().read(true).write(true).open(lp) {
            Ok(f) => return Ok(f),
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                return OpenOptions::new().read(true).open(lp).map_err(io_err(lp));
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(io_err(lp)(e)),
        }
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(lp)
        {
            Ok(f) => {
                adopt_owner(&f, owner, lp)?;
                return Ok(f);
            }
            // Another writer created it in between: open the existing one.
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_err(lp)(e)),
        }
    }
    OpenOptions::new().read(true).open(lp).map_err(io_err(lp))
}

/// Upper bound of the exclusive `flock` wait (ADR-003 errata §5(c), review-3C N-3): the CoT Hub
/// awaits kickban, so a stalled lock holder (e.g. a suspended `takyctl-rs`) must not stop routing.
pub const LOCK_WAIT: Duration = Duration::from_secs(5);
/// Poll interval of the non-blocking `flock` retries.
const LOCK_POLL: Duration = Duration::from_millis(50);

fn lock(path: &Path) -> Result<Flock<File>, PkiError> {
    lock_within(path, LOCK_WAIT)
}

/// Poll `LOCK_EX|LOCK_NB` until `wait` has elapsed, then fail with `PkiError::Io` whose source is
/// `EWOULDBLOCK` (`ErrorKind::WouldBlock`); the callers log it as ERROR. `EINTR` is retried.
fn lock_within(path: &Path, wait: Duration) -> Result<Flock<File>, PkiError> {
    let lp = sidecar(path, ".lock");
    let mut f = open_lock(&lp, owner_of(path))?;
    let deadline = Instant::now() + wait;
    loop {
        match Flock::lock(f, FlockArg::LockExclusiveNonblock) {
            Ok(l) => return Ok(l),
            Err((back, e)) if e == Errno::EWOULDBLOCK || e == Errno::EINTR => {
                let now = Instant::now();
                if e == Errno::EWOULDBLOCK && now >= deadline {
                    return Err(PkiError::Io {
                        path: lp,
                        source: std::io::Error::from(e),
                    });
                }
                f = back;
                if e == Errno::EWOULDBLOCK {
                    std::thread::sleep(LOCK_POLL.min(deadline - now));
                }
            }
            Err((_, e)) => {
                return Err(PkiError::Io {
                    path: lp,
                    source: std::io::Error::from(e),
                });
            }
        }
    }
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
        // Keep the owner (B-1) and the permissions of the file being replaced (Python rewrites it
        // in place). chown first: it may clear set-id bits that the chmod then restores.
        adopt_owner(&f, owner_of(path), &tmp)?;
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
    fn symlinked_db_keeps_link() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tmp");
        fs::create_dir(dir.path().join("real")).expect("mkdir");
        let target = dir.path().join("real/cert-db.txt");
        fs::write(&target, SAMPLE).expect("write");
        let link = dir.path().join("cert-db.txt");
        symlink("real/cert-db.txt", &link).expect("symlink");
        let mut db = CertDb::open(&link).expect("open");
        let sn = db.records()[0].serial.clone();
        db.revoke(&sn, dt("2030-01-01T00:00:00")).expect("revoke");
        assert!(
            fs::symlink_metadata(&link)
                .expect("meta")
                .file_type()
                .is_symlink()
        );
        assert!(
            fs::read_to_string(&target)
                .expect("read")
                .starts_with("R\t")
        );
        assert!(dir.path().join("real/cert-db.txt.lock").exists());
        assert!(!dir.path().join("cert-db.txt.lock").exists());
        assert!(!db.reload_if_changed().expect("stamp"));

        // Dangling link: the target is created, the link stays.
        let dangling = dir.path().join("dangling.txt");
        symlink("real/new-db.txt", &dangling).expect("symlink");
        let mut db = CertDb::open(&dangling).expect("open");
        db.add(&self_signed()).expect("add");
        assert!(
            fs::symlink_metadata(&dangling)
                .expect("meta")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            CertDb::open(&dir.path().join("real/new-db.txt"))
                .expect("open")
                .records()
                .len(),
            1
        );
    }

    #[test]
    fn refresh_reports_an_error_once_per_stamp() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("cert-db.txt");
        fs::write(&p, SAMPLE).expect("write");
        let mut db = CertDb::open(&p).expect("open");
        assert!(db.refresh().is_none());
        fs::write(&p, "V\tnope\t2027-01-01T00:00:00\t01\tx\n").expect("write");
        assert!(matches!(db.refresh(), Some(PkiError::Invalid(_))));
        for _ in 0..3 {
            assert!(db.refresh().is_none(), "same stamp, same error: silent");
        }
        // Records are kept while the file is bad.
        assert_eq!(db.records().len(), 2);
        // A different broken content (new stamp) is reported again.
        fs::write(&p, "V\t2026-01-01T00:00:00\tnope-nope\t01\tx\n").expect("write");
        assert!(db.refresh().is_some());
        assert!(db.refresh().is_none());
        // Fixed: re-read, and a later failure is reported again.
        fs::write(&p, SAMPLE).expect("write");
        assert!(db.refresh().is_none());
        assert_eq!(db.records().len(), 2);
        fs::write(&p, "V\tnope\t2027-01-01T00:00:00\t01\tx\n").expect("write");
        assert!(db.refresh().is_some());
    }

    /// Holds the exclusive lock on `<p>.lock` through a separate open file description (as another
    /// writer process would).
    fn hold_lock(p: &Path) -> Flock<File> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(sidecar(p, ".lock"))
            .expect("open lock");
        Flock::lock(f, FlockArg::LockExclusiveNonblock).expect("hold lock")
    }

    /// review-3C N-3: a revoke against a lock held elsewhere fails with `Io(WouldBlock)` after
    /// [`LOCK_WAIT`] instead of blocking forever; the database is left untouched.
    #[test]
    fn held_lock_bounds_revoke_wait() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("cert-db.txt");
        fs::write(&p, SAMPLE).expect("write");
        let mut db = CertDb::open(&p).expect("open");
        let sn = db.records()[0].serial.clone();
        let held = hold_lock(&p);
        let (tx, rx) = std::sync::mpsc::channel();
        let start = Instant::now();
        std::thread::spawn(move || {
            let r = db.revoke(&sn, dt("2030-01-01T00:00:00"));
            let _ = tx.send((r, start.elapsed()));
        });
        let (r, took) = rx
            .recv_timeout(LOCK_WAIT + Duration::from_secs(10))
            .expect("revoke did not return: unbounded flock wait");
        drop(held);
        match r {
            Err(PkiError::Io { path, source }) => {
                assert_eq!(source.kind(), ErrorKind::WouldBlock, "{source}");
                assert_eq!(path, sidecar(&p, ".lock"));
            }
            other => panic!("expected Io(WouldBlock), got {other:?}"),
        }
        assert!(took >= LOCK_WAIT, "gave up early: {took:?}");
        assert_eq!(fs::read_to_string(&p).expect("read"), SAMPLE);
    }

    /// A lock released while a writer polls is taken (the wait is a retry loop, not a single try).
    #[test]
    fn lock_released_during_wait_is_taken() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("cert-db.txt");
        let held = hold_lock(&p);
        assert!(lock_within(&p, Duration::ZERO).is_err(), "lock is held");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            drop(held);
        });
        lock_within(&p, Duration::from_secs(3)).expect("lock after release");
        releaser.join().expect("join");
    }

    fn self_signed() -> Vec<u8> {
        rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("cert")
            .cert
            .der()
            .to_vec()
    }

    fn uid_gid(p: &Path) -> (u32, u32) {
        let m = fs::metadata(p).expect("meta");
        (m.uid(), m.gid())
    }

    /// B-1: a lock file this user cannot write (e.g. created by `sudo takyctl-rs` before the fix)
    /// does not prevent a revoke. Non-root: chmod 0444. Root (no EACCES for root): re-run this
    /// test binary as `nobody` against a root-owned 0644 lock.
    #[test]
    fn readonly_lock_does_not_block_revoke() {
        use std::os::unix::fs::{PermissionsExt, chown};
        use std::os::unix::process::CommandExt;
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("cert-db.txt");
        fs::write(&p, SAMPLE).expect("write");
        let lp = dir.path().join("cert-db.txt.lock");
        fs::write(&lp, "").expect("lock");
        fs::set_permissions(&lp, fs::Permissions::from_mode(0o644)).expect("chmod");
        let sn = CertDb::open(&p).expect("open").records()[0].serial.clone();
        if !nix::unistd::geteuid().is_root() {
            fs::set_permissions(&lp, fs::Permissions::from_mode(0o444)).expect("chmod");
            let mut db = CertDb::open(&p).expect("open");
            db.revoke(&sn, dt("2030-01-01T00:00:00"))
                .expect("revoke via ro lock");
            assert!(CertDb::open(&p).expect("open").is_revoked(&sn));
            return;
        }
        const NOBODY: u32 = 65534;
        chown(dir.path(), Some(NOBODY), Some(NOBODY)).expect("chown dir");
        chown(&p, Some(NOBODY), Some(NOBODY)).expect("chown db");
        // The lock stays root:root 0644, as `sudo takyctl-rs` left it before the fix.
        let exe = std::env::current_exe().expect("exe");
        let out = std::process::Command::new(exe)
            .args([
                "--ignored",
                "--exact",
                "certdb::tests::child_revoke_first",
                "--nocapture",
            ])
            .env("TAKY_CERTDB_CHILD", &p)
            .uid(NOBODY)
            .gid(NOBODY)
            .output()
            .expect("spawn child as nobody");
        assert!(
            out.status.success() && String::from_utf8_lossy(&out.stdout).contains("1 passed"),
            "child: {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(CertDb::open(&p).expect("open").is_revoked(&sn));
        assert_eq!(uid_gid(&p), (NOBODY, NOBODY));
        assert_eq!(uid_gid(&lp), (0, 0));
    }

    /// Helper of [`readonly_lock_does_not_block_revoke`] (runs as `nobody`).
    #[test]
    #[ignore = "spawned by readonly_lock_does_not_block_revoke"]
    fn child_revoke_first() {
        let p = PathBuf::from(std::env::var_os("TAKY_CERTDB_CHILD").expect("env"));
        assert!(!nix::unistd::geteuid().is_root());
        assert!(
            OpenOptions::new()
                .write(true)
                .open(sidecar(&p, ".lock"))
                .is_err()
        );
        let mut db = CertDb::open(&p).expect("open");
        let sn = db.records()[0].serial.clone();
        db.revoke(&sn, dt("2030-01-01T00:00:00")).expect("revoke");
    }

    /// B-1: as root, the replaced data file and a new lock keep/get the cert-db owner (the
    /// directory's for a new database). Skipped when not root (CI): the non-root path is the
    /// plain one, covered by the other tests.
    #[test]
    fn root_writes_keep_db_owner() {
        use std::os::unix::fs::{PermissionsExt, chown};
        if !nix::unistd::geteuid().is_root() {
            eprintln!("root_writes_keep_db_owner: skipped (not root)");
            return;
        }
        let dir = tempfile::tempdir().expect("tmp");
        chown(dir.path(), Some(1000), Some(1001)).expect("chown dir");
        // Existing database owned by the service user, 0600.
        let p = dir.path().join("cert-db.txt");
        fs::write(&p, SAMPLE).expect("write");
        chown(&p, Some(2000), Some(2001)).expect("chown db");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).expect("chmod");
        let mut db = CertDb::open(&p).expect("open");
        let sn = db.records()[0].serial.clone();
        db.revoke(&sn, dt("2030-01-01T00:00:00")).expect("revoke");
        db.add(&self_signed()).expect("add");
        assert_eq!(uid_gid(&p), (2000, 2001));
        assert_eq!(
            fs::metadata(&p).expect("meta").permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(uid_gid(&dir.path().join("cert-db.txt.lock")), (2000, 2001));
        assert!(CertDb::open(&p).expect("open").is_revoked(&sn));
        // No tmp left behind.
        let names: Vec<_> = fs::read_dir(dir.path())
            .expect("ls")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");

        // New database: owner of the directory.
        let q = dir.path().join("new-db.txt");
        let mut db = CertDb::open(&q).expect("open");
        db.add(&self_signed()).expect("add");
        assert_eq!(uid_gid(&q), (1000, 1001));
        assert_eq!(uid_gid(&dir.path().join("new-db.txt.lock")), (1000, 1001));

        // An existing root-owned lock (left by an older build) is reused as is.
        let r = dir.path().join("third.txt");
        fs::write(&r, SAMPLE).expect("write");
        chown(&r, Some(2000), Some(2001)).expect("chown");
        let rl = dir.path().join("third.txt.lock");
        fs::write(&rl, "").expect("lock");
        let mut db = CertDb::open(&r).expect("open");
        db.revoke(&sn, dt("2030-01-01T00:00:00")).expect("revoke");
        assert_eq!(uid_gid(&r), (2000, 2001));
        assert_eq!(uid_gid(&rl), (0, 0));
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
