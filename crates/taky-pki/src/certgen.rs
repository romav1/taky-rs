//! CA / server / client certificate generation (`taky/util/anc.py` `make_ca`, `make_cert`,
//! `write_certificate`, `load_certificate`; spec dps-cli-config §4, ADR-006). Behind the `gen`
//! feature (takyctl only).
//!
//! Profiles are those of Python `cryptography` as used by anc.py, including the **extension
//! order** (CA: SKI, BC, EKU, KU; certificates: BC, SKI, AKI, EKU, KU, [SAN]), so that
//! `openssl x509 -text` of a Rust and a Python certificate differs only in keys, serials and
//! dates. rcgen is used for the TBS / signature; every extension is written by this module as a
//! raw custom extension (rcgen's own extension writer has a fixed, different order).
//!
//! Time: the caller passes `now` as naive **UTC** (`Clock::utc_now`); ADR-006 / D-18 "honest
//! UTC" (Python writes local time as if it were UTC; identical on TZ=UTC hosts).
//!
//! PKCS#12 output (`make_cert`'s `.p12`) is S-321; the p12 writer takes [`KeyCert`] from here.

use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use chrono::{NaiveDateTime, TimeDelta};
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, DnType, Issuer, KeyPair};
use rsa::RsaPrivateKey;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha1::{Digest, Sha1};
use x509_parser::prelude::{FromDer, ParsedExtension, X509Certificate};

use crate::PkiError;

/// `make_ca(n_years=10)` default.
pub const CA_YEARS: u32 = 10;
/// `make_cert(n_years=2)` default.
pub const CERT_YEARS: u32 = 2;
/// RSA modulus size (`rsa.generate_private_key(65537, 2048)`).
pub const RSA_BITS: usize = 2048;

const OID_SKI: &[u64] = &[2, 5, 29, 14];
const OID_KU: &[u64] = &[2, 5, 29, 15];
const OID_SAN: &[u64] = &[2, 5, 29, 17];
const OID_BC: &[u64] = &[2, 5, 29, 19];
const OID_AKI: &[u64] = &[2, 5, 29, 35];
const OID_EKU: &[u64] = &[2, 5, 29, 37];
/// id-kp-serverAuth, DER content octets of 1.3.6.1.5.5.7.3.1.
const KP_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
/// id-kp-clientAuth, 1.3.6.1.5.5.7.3.2.
const KP_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

/// Which `make_cert` profile (`is_server_cert`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertKind {
    /// `is_server_cert=True`: EKU server+client, KU digitalSignature+keyEncipherment, SAN.
    Server,
    /// `is_server_cert=False`: EKU clientAuth, KU digitalSignature+nonRepudiation+keyEncipherment.
    Client,
}

/// A freshly generated certificate with its RSA key.
pub struct KeyCert {
    /// Certificate DER.
    pub cert_der: Vec<u8>,
    /// Private key.
    pub key: RsaPrivateKey,
}

impl std::fmt::Debug for KeyCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyCert")
            .field("cert_der", &self.cert_der.len())
            .finish_non_exhaustive()
    }
}

impl KeyCert {
    /// Certificate PEM (`Encoding.PEM`: 64-column base64, LF, trailing newline).
    pub fn cert_pem(&self) -> String {
        pem_encode("CERTIFICATE", &self.cert_der)
    }

    /// Key as `TraditionalOpenSSL` PEM (`-----BEGIN RSA PRIVATE KEY-----`, unencrypted).
    pub fn key_pkcs1_pem(&self) -> Result<String, PkiError> {
        self.key
            .to_pkcs1_pem(LineEnding::LF)
            .map(|z| z.to_string())
            .map_err(|e| PkiError::Invalid(format!("PKCS#1 encode: {e}")))
    }

    /// Key as PKCS#8 `PrivateKeyInfo` DER (what a PKCS#12 ShroudedKeyBag wraps).
    pub fn key_pkcs8_der(&self) -> Result<Vec<u8>, PkiError> {
        self.key
            .to_pkcs8_der()
            .map(|d| d.as_bytes().to_vec())
            .map_err(|e| PkiError::Invalid(format!("PKCS#8 encode: {e}")))
    }

    /// Serial number, big-endian, minimal (as in cert-db).
    pub fn serial(&self) -> Result<Vec<u8>, PkiError> {
        let (_, c) = parse(&self.cert_der)?;
        Ok(crate::identity::strip_leading_zeros(c.raw_serial()))
    }
}

/// A loaded CA (`load_certificate(ca_crt, ca_key)`), ready to issue certificates.
pub struct CertAuthority {
    cert_der: Vec<u8>,
    ski: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
}

impl std::fmt::Debug for CertAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertAuthority")
            .field("cert_der", &self.cert_der.len())
            .finish_non_exhaustive()
    }
}

impl CertAuthority {
    /// `load_certificate(crt_path, key_path)`: the first certificate of `crt_path`, the first
    /// unencrypted private key of `key_path` (PKCS#1, PKCS#8).
    pub fn load(crt_path: &Path, key_path: &Path) -> Result<CertAuthority, PkiError> {
        let cert = crate::pem::load_certs(crt_path)?
            .into_iter()
            .next()
            .ok_or_else(|| PkiError::Invalid("no CA certificate".into()))?;
        let key = crate::pem::load_private_key(key_path, None)?;
        CertAuthority::from_der(cert.as_ref(), &key)
    }

    /// From a CA certificate DER and its private key. The CA must carry a SubjectKeyIdentifier
    /// (Python: `ExtensionNotFound` otherwise) and the key must match the certificate.
    pub fn from_der(cert_der: &[u8], key: &PrivateKeyDer<'_>) -> Result<CertAuthority, PkiError> {
        let kp = keypair_from(key)?;
        let (_, c) = parse(cert_der)?;
        let ski = c
            .extensions()
            .iter()
            .find_map(|e| match e.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(k) => Some(k.0.to_vec()),
                _ => None,
            })
            .ok_or_else(|| {
                PkiError::Invalid("CA certificate has no SubjectKeyIdentifier extension".into())
            })?;
        if c.public_key().raw != rcgen::PublicKeyData::subject_public_key_info(&kp).as_slice() {
            return Err(PkiError::Invalid(
                "CA private key does not match the CA certificate".into(),
            ));
        }
        let issuer = Issuer::from_ca_cert_der(&CertificateDer::from(cert_der.to_vec()), kp)
            .map_err(|e| PkiError::Invalid(format!("CA certificate: {e}")))?;
        Ok(CertAuthority {
            cert_der: cert_der.to_vec(),
            ski,
            issuer,
        })
    }

    /// The CA certificate DER (for the p12 `CA` bag).
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }
}

/// `x509.random_serial_number()`: uniform in `[1, 2^159)`, 20 bytes big-endian.
pub fn random_serial() -> [u8; 20] {
    loop {
        let mut sn: [u8; 20] = rand::random();
        sn[0] &= 0x7f;
        if sn.iter().any(|b| *b != 0) {
            return sn;
        }
    }
}

/// `rsa.generate_private_key(public_exponent=65537, key_size=2048)`.
pub fn generate_key() -> Result<RsaPrivateKey, PkiError> {
    RsaPrivateKey::new(&mut rand::rngs::OsRng, RSA_BITS)
        .map_err(|e| PkiError::Invalid(format!("RSA key generation: {e}")))
}

/// `make_ca`: self-signed `CN=CA, O=taky`, validity `now-1d … now+365*n_years d`.
pub fn make_ca(now: NaiveDateTime, n_years: u32) -> Result<KeyCert, PkiError> {
    make_ca_with_key(now, n_years, generate_key()?)
}

/// [`make_ca`] with a given key (tests, key reuse).
pub fn make_ca_with_key(
    now: NaiveDateTime,
    n_years: u32,
    key: RsaPrivateKey,
) -> Result<KeyCert, PkiError> {
    let kp = rsa_keypair(&key)?;
    let spki = rcgen::PublicKeyData::subject_public_key_info(&kp);
    let mut p = base_params(now, 1, n_years)?;
    p.distinguished_name.push(DnType::CommonName, "CA");
    p.distinguished_name.push(DnType::OrganizationName, "taky");
    p.custom_extensions = vec![
        ext(OID_SKI, false, octet_string(&key_id(&spki)?)),
        ext(OID_BC, true, basic_constraints(true)),
        ext(OID_EKU, false, eku(&[KP_SERVER_AUTH, KP_CLIENT_AUTH])),
        // digitalSignature(0), keyCertSign(5), cRLSign(6)
        ext(OID_KU, true, key_usage(&[0, 5, 6])),
    ];
    let cert = p
        .self_signed(&kp)
        .map_err(|e| PkiError::Invalid(format!("CA signing: {e}")))?;
    Ok(KeyCert {
        cert_der: cert.der().to_vec(),
        key,
    })
}

/// `make_cert` (certificate part): issued by `ca`, subject `CN=<hostname>` if the name is
/// shorter than 64 characters (empty subject otherwise), validity `now-2d … now+365*n_years d`.
/// Server certificates get `SAN = IP:<hostname>` or `DNS:<hostname>` (critical iff the subject
/// is empty). Errors as Python: empty CN, non-ASCII DNS name.
pub fn make_cert(
    ca: &CertAuthority,
    hostname: &str,
    now: NaiveDateTime,
    n_years: u32,
    kind: CertKind,
) -> Result<KeyCert, PkiError> {
    make_cert_with_key(ca, hostname, now, n_years, kind, generate_key()?)
}

/// [`make_cert`] with a given key (tests, key reuse).
pub fn make_cert_with_key(
    ca: &CertAuthority,
    hostname: &str,
    now: NaiveDateTime,
    n_years: u32,
    kind: CertKind,
    key: RsaPrivateKey,
) -> Result<KeyCert, PkiError> {
    let kp = rsa_keypair(&key)?;
    let spki = rcgen::PublicKeyData::subject_public_key_info(&kp);
    let mut p = base_params(now, 2, n_years)?;
    let n_chars = hostname.chars().count();
    let valid_cn = n_chars < 64;
    if valid_cn {
        if n_chars == 0 {
            // x509.NameAttribute(COMMON_NAME, "")
            return Err(PkiError::Invalid(
                "Attribute's length must be >= 1 and <= 64, but it was 0".into(),
            ));
        }
        p.distinguished_name.push(DnType::CommonName, hostname);
    }
    let mut exts = vec![
        ext(OID_BC, true, basic_constraints(false)),
        ext(OID_SKI, false, octet_string(&key_id(&spki)?)),
        ext(OID_AKI, false, authority_key_id(&ca.ski)),
    ];
    match kind {
        CertKind::Server => {
            exts.push(ext(OID_EKU, false, eku(&[KP_SERVER_AUTH, KP_CLIENT_AUTH])));
            // digitalSignature(0), keyEncipherment(2)
            exts.push(ext(OID_KU, true, key_usage(&[0, 2])));
            exts.push(ext(OID_SAN, !valid_cn, subject_alt_name(hostname)?));
        }
        CertKind::Client => {
            exts.push(ext(OID_EKU, false, eku(&[KP_CLIENT_AUTH])));
            // digitalSignature(0), nonRepudiation(1), keyEncipherment(2)
            exts.push(ext(OID_KU, true, key_usage(&[0, 1, 2])));
        }
    }
    p.custom_extensions = exts;
    let cert = p
        .signed_by(&kp, &ca.issuer)
        .map_err(|e| PkiError::Invalid(format!("certificate signing: {e}")))?;
    let der = cert.der().to_vec();
    // Python copies the CA subject Name object (DER bytes); rcgen re-encodes it. Refuse to
    // emit a certificate whose issuer would not chain byte-for-byte.
    let (_, issued) = parse(&der)?;
    let (_, ca_cert) = parse(&ca.cert_der)?;
    if issued.issuer().as_raw() != ca_cert.subject().as_raw() {
        return Err(PkiError::Invalid(
            "CA subject cannot be re-encoded byte-for-byte as issuer".into(),
        ));
    }
    Ok(KeyCert { cert_der: der, key })
}

/// `write_certificate(crt_path, key_path, crt, key)`: key first (PKCS#1 PEM, mode 0600 —
/// Python creates it under umask 077; an existing file is also forced to 0600), then the
/// certificate PEM (mode per process umask).
pub fn write_certificate(crt_path: &Path, key_path: &Path, kc: &KeyCert) -> Result<(), PkiError> {
    let key_pem = kc.key_pkcs1_pem()?;
    let io = |path: &Path| {
        let path = path.to_owned();
        move |source| PkiError::Io { path, source }
    };
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(key_path)
        .map_err(io(key_path))?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(io(key_path))?;
    f.write_all(key_pem.as_bytes()).map_err(io(key_path))?;
    drop(f);
    std::fs::write(crt_path, kc.cert_pem()).map_err(io(crt_path))?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------

fn parse(der: &[u8]) -> Result<(&[u8], X509Certificate<'_>), PkiError> {
    X509Certificate::from_der(der).map_err(|e| PkiError::Invalid(format!("certificate: {e}")))
}

fn rsa_keypair(key: &RsaPrivateKey) -> Result<KeyPair, PkiError> {
    let der = key
        .to_pkcs8_der()
        .map_err(|e| PkiError::Invalid(format!("PKCS#8 encode: {e}")))?;
    KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(der.as_bytes()),
        &rcgen::PKCS_RSA_SHA256,
    )
    .map_err(|e| PkiError::Invalid(format!("RSA key: {e}")))
}

fn keypair_from(key: &PrivateKeyDer<'_>) -> Result<KeyPair, PkiError> {
    match key {
        PrivateKeyDer::Pkcs1(k) => {
            let rsa = RsaPrivateKey::from_pkcs1_der(k.secret_pkcs1_der())
                .map_err(|e| PkiError::Invalid(format!("RSA key: {e}")))?;
            rsa_keypair(&rsa)
        }
        PrivateKeyDer::Pkcs8(_) => {
            KeyPair::try_from(key).map_err(|e| PkiError::Invalid(format!("CA key: {e}")))
        }
        _ => Err(PkiError::Invalid(
            "unsupported CA key format (use PKCS#1 or PKCS#8)".into(),
        )),
    }
}

fn base_params(
    now: NaiveDateTime,
    back_days: i64,
    n_years: u32,
) -> Result<CertificateParams, PkiError> {
    let mut p = CertificateParams::default();
    p.distinguished_name = DistinguishedName::new();
    p.serial_number = Some(rcgen::SerialNumber::from_slice(&random_serial()));
    // rcgen takes `time::OffsetDateTime`: epoch + whole seconds (sub-second part dropped, as
    // cryptography does).
    let epoch = rcgen::date_time_ymd(1970, 1, 1);
    p.not_before = epoch + epoch_secs(now - TimeDelta::days(back_days))?;
    p.not_after = epoch + epoch_secs(now + TimeDelta::days(365 * i64::from(n_years)))?;
    Ok(p)
}

fn epoch_secs(t: NaiveDateTime) -> Result<std::time::Duration, PkiError> {
    u64::try_from(t.and_utc().timestamp())
        .map(std::time::Duration::from_secs)
        .map_err(|_| PkiError::Invalid(format!("validity date before 1970: {t}")))
}

fn ext(oid: &[u64], critical: bool, content: Vec<u8>) -> CustomExtension {
    let mut e = CustomExtension::from_oid_content(oid, content);
    e.set_criticality(critical);
    e
}

/// RFC 5280 §4.2.1.2 method 1 (what `SubjectKeyIdentifier.from_public_key` does):
/// SHA-1 of the subjectPublicKey BIT STRING value.
fn key_id(spki_der: &[u8]) -> Result<Vec<u8>, PkiError> {
    let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(spki_der)
        .map_err(|e| PkiError::Invalid(format!("SPKI: {e}")))?;
    Ok(Sha1::digest(&spki.subject_public_key.data).to_vec())
}

fn basic_constraints(ca: bool) -> Vec<u8> {
    // cA DEFAULT FALSE is omitted in DER; no pathLenConstraint.
    if ca {
        tlv(0x30, &tlv(0x01, &[0xff]))
    } else {
        tlv(0x30, &[])
    }
}

fn eku(purposes: &[&[u8]]) -> Vec<u8> {
    let body: Vec<u8> = purposes.iter().flat_map(|p| tlv(0x06, p)).collect();
    tlv(0x30, &body)
}

/// KeyUsage BIT STRING, DER: trailing zero bits trimmed (named bit list).
fn key_usage(bits: &[u8]) -> Vec<u8> {
    let v: u16 = bits.iter().fold(0, |acc, b| acc | (0x8000 >> b));
    let used = 16 - v.trailing_zeros() as usize;
    let n_bytes = used.div_ceil(8);
    let mut body = vec![(n_bytes * 8 - used) as u8];
    body.extend_from_slice(&v.to_be_bytes()[..n_bytes]);
    tlv(0x03, &body)
}

fn authority_key_id(keyid: &[u8]) -> Vec<u8> {
    // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING }
    tlv(0x30, &tlv(0x80, keyid))
}

fn octet_string(v: &[u8]) -> Vec<u8> {
    tlv(0x04, v)
}

/// `ipaddress.ip_address(x)` → iPAddress, else dNSName (must be an A-label, i.e. ASCII).
fn subject_alt_name(hostname: &str) -> Result<Vec<u8>, PkiError> {
    let gn = match parse_ip(hostname) {
        Some(IpAddr::V4(a)) => tlv(0x87, &a.octets()),
        Some(IpAddr::V6(a)) => tlv(0x87, &a.octets()),
        None => {
            if !hostname.is_ascii() {
                return Err(PkiError::Invalid(
                    "DNSName values should be passed as an A-label string. This means unicode \
                     characters should be encoded via a library like idna."
                        .into(),
                ));
            }
            tlv(0x82, hostname.as_bytes())
        }
    };
    Ok(tlv(0x30, &gn))
}

/// Python `ip_address` also accepts an IPv6 scope id (`fe80::1%eth0`); the packed form drops it.
fn parse_ip(s: &str) -> Option<IpAddr> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    let (addr, scope) = s.split_once('%')?;
    if scope.is_empty() || scope.contains('%') || scope.contains('/') {
        return None;
    }
    addr.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6)
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let len = n.to_be_bytes();
        let skip = len.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (len.len() - skip) as u8);
        out.extend_from_slice(&len[skip..]);
    }
    out.extend_from_slice(content);
    out
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::with_capacity(der.len() * 4 / 3 + 4);
    for chunk in der.chunks(3) {
        let n = chunk.len();
        let v = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= n {
                b64.push(B64[((v >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                b64.push('=');
            }
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use rsa::Pkcs1v15Sign;
    use sha2::Sha256;
    use x509_parser::prelude::GeneralName;

    use super::*;

    /// RSA keygen is slow in debug builds: generate a few keys once and reuse them.
    fn key(i: usize) -> RsaPrivateKey {
        static KEYS: OnceLock<Vec<RsaPrivateKey>> = OnceLock::new();
        KEYS.get_or_init(|| (0..3).map(|_| generate_key().expect("keygen")).collect())[i].clone()
    }

    fn now() -> NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2026, 10, 25)
            .and_then(|d| d.and_hms_micro_opt(12, 34, 56, 789_012))
            .expect("date")
    }

    fn ca() -> (KeyCert, CertAuthority) {
        let kc = make_ca_with_key(now(), CA_YEARS, key(0)).expect("ca");
        let k8 = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kc.key_pkcs8_der().expect("k8")));
        let ca = CertAuthority::from_der(&kc.cert_der, &k8).expect("authority");
        (kc, ca)
    }

    /// (oid, critical, value) in certificate order.
    fn exts(der: &[u8]) -> Vec<(String, bool, Vec<u8>)> {
        let (_, c) = parse(der).expect("parse");
        c.extensions()
            .iter()
            .map(|e| (e.oid.to_id_string(), e.critical, e.value.to_vec()))
            .collect()
    }

    fn verify_sig(cert_der: &[u8], signer: &RsaPrivateKey) {
        let (_, c) = parse(cert_der).expect("parse");
        assert_eq!(
            c.signature_algorithm.algorithm.to_id_string(),
            "1.2.840.113549.1.1.11"
        );
        // DigestInfo prefix of SHA-256 (RFC 8017 §9.2 note 1)
        let scheme = Pkcs1v15Sign {
            hash_len: Some(32),
            prefix: [
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ]
            .into(),
        };
        let hash = Sha256::digest(c.tbs_certificate.as_ref());
        signer
            .to_public_key()
            .verify(scheme, &hash, &c.signature_value.data)
            .expect("signature verifies");
    }

    fn ts(t: NaiveDateTime) -> i64 {
        t.and_utc().timestamp()
    }

    #[test]
    fn der_helpers() {
        assert_eq!(key_usage(&[0, 5, 6]), [0x03, 0x02, 0x01, 0x86]);
        assert_eq!(key_usage(&[0, 2]), [0x03, 0x02, 0x05, 0xa0]);
        assert_eq!(key_usage(&[0, 1, 2]), [0x03, 0x02, 0x05, 0xe0]);
        assert_eq!(key_usage(&[8]), [0x03, 0x03, 0x07, 0x00, 0x80]);
        assert_eq!(basic_constraints(true), [0x30, 0x03, 0x01, 0x01, 0xff]);
        assert_eq!(basic_constraints(false), [0x30, 0x00]);
        let long = tlv(0x04, &[7; 300]);
        assert_eq!(&long[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(long.len(), 304);
        assert_eq!(&tlv(0x04, &[1; 200])[..3], &[0x04, 0x81, 200]);
    }

    #[test]
    fn pem_encoding() {
        assert_eq!(
            pem_encode("X", b"abcd"),
            "-----BEGIN X-----\nYWJjZA==\n-----END X-----\n"
        );
        let der: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let pem = pem_encode("CERTIFICATE", &der);
        assert!(pem.lines().skip(1).take(20).all(|l| l.len() == 64));
        let blocks = crate::pem::parse_pem(pem.as_bytes()).expect("parse");
        assert_eq!(blocks[0].der, der);
    }

    #[test]
    fn serial_and_ip() {
        for _ in 0..200 {
            let s = random_serial();
            assert!(s[0] < 0x80 && s.iter().any(|b| *b != 0));
        }
        assert_eq!(parse_ip("10.0.0.1"), Some("10.0.0.1".parse().expect("ip")));
        assert_eq!(
            parse_ip("fe80::1%eth0"),
            Some("fe80::1".parse().expect("ip"))
        );
        assert_eq!(
            parse_ip("::ffff:1.2.3.4"),
            Some("::ffff:1.2.3.4".parse().expect("ip"))
        );
        assert_eq!(parse_ip("1.2.3.04"), None);
        assert_eq!(parse_ip("1.2.3.4%x"), None);
        assert_eq!(parse_ip("fe80::1%"), None);
        assert_eq!(parse_ip("taky.local"), None);
    }

    #[test]
    fn ca_profile() {
        let (kc, _) = ca();
        let (_, c) = parse(&kc.cert_der).expect("parse");
        assert_eq!(c.version().0, 2);
        assert_eq!(c.subject().to_string(), "CN=CA, O=taky");
        assert_eq!(c.subject().as_raw(), c.issuer().as_raw());
        // UTF8String CN/O, as cryptography writes them
        assert!(
            c.subject()
                .iter_attributes()
                .all(|a| a.attr_value().header.tag().0 == 12)
        );
        assert_eq!(c.validity().not_before.timestamp(), ts(now()) - 86_400);
        assert_eq!(
            c.validity().not_after.timestamp(),
            ts(now()) + 3650 * 86_400
        );
        let spki_bits = c.public_key().subject_public_key.data.to_vec();
        let e = exts(&kc.cert_der);
        let order: Vec<(&str, bool)> = e.iter().map(|(o, c, _)| (o.as_str(), *c)).collect();
        assert_eq!(
            order,
            [
                ("2.5.29.14", false),
                ("2.5.29.19", true),
                ("2.5.29.37", false),
                ("2.5.29.15", true)
            ]
        );
        assert_eq!(e[0].2, octet_string(&Sha1::digest(&spki_bits)));
        assert_eq!(e[1].2, basic_constraints(true));
        assert_eq!(e[2].2, eku(&[KP_SERVER_AUTH, KP_CLIENT_AUTH]));
        assert_eq!(e[3].2, key_usage(&[0, 5, 6]));
        assert_eq!(
            c.public_key().parsed().map(|k| k.key_size()).ok(),
            Some(2048)
        );
        assert!(c.raw_serial().len() <= 20 && c.raw_serial()[0] < 0x80);
        verify_sig(&kc.cert_der, &kc.key);
    }

    #[test]
    fn server_profile() {
        let (cakc, ca) = ca();
        let kc = make_cert_with_key(
            &ca,
            "taky.local",
            now(),
            CERT_YEARS,
            CertKind::Server,
            key(1),
        )
        .expect("server");
        let (_, c) = parse(&kc.cert_der).expect("parse");
        let (_, cac) = parse(&cakc.cert_der).expect("parse");
        assert_eq!(c.subject().to_string(), "CN=taky.local");
        assert_eq!(c.issuer().as_raw(), cac.subject().as_raw());
        assert_eq!(c.validity().not_before.timestamp(), ts(now()) - 2 * 86_400);
        assert_eq!(c.validity().not_after.timestamp(), ts(now()) + 730 * 86_400);
        let e = exts(&kc.cert_der);
        let order: Vec<(&str, bool)> = e.iter().map(|(o, c, _)| (o.as_str(), *c)).collect();
        assert_eq!(
            order,
            [
                ("2.5.29.19", true),
                ("2.5.29.14", false),
                ("2.5.29.35", false),
                ("2.5.29.37", false),
                ("2.5.29.15", true),
                ("2.5.29.17", false)
            ]
        );
        assert_eq!(e[0].2, [0x30, 0x00]);
        assert_eq!(e[2].2, authority_key_id(&ca.ski));
        assert_eq!(octet_string(&ca.ski), exts(&cakc.cert_der)[0].2);
        assert_eq!(e[4].2, key_usage(&[0, 2]));
        let san = c.subject_alternative_name().expect("san").expect("san");
        assert_eq!(
            san.value.general_names,
            [GeneralName::DNSName("taky.local")]
        );
        verify_sig(&kc.cert_der, &cakc.key);
        assert!(kc.serial().expect("sn").len() <= 20);
    }

    #[test]
    fn server_ip_and_long_names() {
        let (_, ca) = ca();
        let kc = make_cert_with_key(&ca, "192.168.1.10", now(), 2, CertKind::Server, key(1))
            .expect("ip");
        assert_eq!(
            exts(&kc.cert_der)[5].2,
            [0x30, 0x06, 0x87, 0x04, 192, 168, 1, 10]
        );
        let kc = make_cert_with_key(&ca, "::1", now(), 2, CertKind::Server, key(1)).expect("ip6");
        let san = &exts(&kc.cert_der)[5].2;
        assert_eq!(&san[..4], &[0x30, 0x12, 0x87, 0x10]);

        let n63 = "a".repeat(63);
        let kc = make_cert_with_key(&ca, &n63, now(), 2, CertKind::Server, key(1)).expect("63");
        let (_, c) = parse(&kc.cert_der).expect("parse");
        assert_eq!(c.subject().to_string(), format!("CN={n63}"));
        assert!(!exts(&kc.cert_der)[5].1);

        let n64 = "b".repeat(64);
        let kc = make_cert_with_key(&ca, &n64, now(), 2, CertKind::Server, key(1)).expect("64");
        let (_, c) = parse(&kc.cert_der).expect("parse");
        assert_eq!(c.subject().as_raw(), [0x30, 0x00]);
        let e = exts(&kc.cert_der);
        assert_eq!((e[5].0.as_str(), e[5].1), ("2.5.29.17", true));
        // 64 *characters* (not bytes) decide, like Python len()
        let u = "é".repeat(40);
        let kc = make_cert_with_key(&ca, &u, now(), 2, CertKind::Client, key(1)).expect("utf8");
        let (_, c) = parse(&kc.cert_der).expect("parse");
        assert_eq!(c.subject().to_string(), format!("CN={u}"));
    }

    #[test]
    fn client_profile_and_errors() {
        let (cakc, ca) = ca();
        let kc =
            make_cert_with_key(&ca, "JENNY", now(), 2, CertKind::Client, key(2)).expect("client");
        let e = exts(&kc.cert_der);
        let oids: Vec<&str> = e.iter().map(|(o, _, _)| o.as_str()).collect();
        assert_eq!(
            oids,
            [
                "2.5.29.19",
                "2.5.29.14",
                "2.5.29.35",
                "2.5.29.37",
                "2.5.29.15"
            ]
        );
        assert_eq!(e[3].2, eku(&[KP_CLIENT_AUTH]));
        assert_eq!(e[4].2, key_usage(&[0, 1, 2]));
        verify_sig(&kc.cert_der, &cakc.key);

        let err = make_cert_with_key(&ca, "", now(), 2, CertKind::Client, key(2));
        assert!(format!("{:?}", err.err()).contains("length must be >= 1"));
        let err = make_cert_with_key(&ca, "тест", now(), 2, CertKind::Server, key(2));
        assert!(format!("{:?}", err.err()).contains("A-label"));
        // a key that is not the CA's
        let k8 = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kc.key_pkcs8_der().expect("k8")));
        let err = CertAuthority::from_der(&cakc.cert_der, &k8);
        assert!(format!("{:?}", err.err()).contains("does not match"));
        assert!(CertAuthority::from_der(b"junk", &k8).is_err());
    }

    #[test]
    fn write_load_and_cert_db() {
        let dir = tempfile::tempdir().expect("tmp");
        let (cakc, _) = ca();
        let (crt, keyp) = (dir.path().join("ca.crt"), dir.path().join("ca.key"));
        std::fs::write(&keyp, "old").expect("pre-existing key");
        std::fs::set_permissions(&keyp, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        write_certificate(&crt, &keyp, &cakc).expect("write");
        let key_pem = std::fs::read_to_string(&keyp).expect("read");
        assert!(key_pem.starts_with("-----BEGIN RSA PRIVATE KEY-----\n"));
        assert!(key_pem.ends_with("-----END RSA PRIVATE KEY-----\n"));
        let mode = std::fs::metadata(&keyp).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&crt).expect("crt"), cakc.cert_pem());

        // load_certificate on PKCS#1 PEM, then issue and record in cert-db
        let ca = CertAuthority::load(&crt, &keyp).expect("load");
        assert_eq!(ca.cert_der(), cakc.cert_der.as_slice());
        let kc =
            make_cert_with_key(&ca, "JENNY", now(), 2, CertKind::Client, key(2)).expect("client");
        let mut db = crate::CertDb::open(&dir.path().join("cert-db.txt")).expect("db");
        db.add(&kc.cert_der).expect("add");
        let text = std::fs::read_to_string(dir.path().join("cert-db.txt")).expect("db text");
        let sn: String = kc
            .serial()
            .expect("sn")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            text,
            format!("V\t2026-10-23T12:34:56\t2028-10-24T12:34:56\t{sn:0>40}\tJENNY\n")
        );
    }
}
