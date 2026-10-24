//! Client certificate identity (ARCHITECTURE §11).

use chrono::{DateTime, NaiveDateTime};
use x509_parser::prelude::{FromDer, X509Certificate, X509Name};

/// What the server/DPS knows about a TLS peer from `peer_certificates()[0]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Serial, big-endian, without leading zero bytes (key for [`crate::CertDb::by_serial`]).
    pub serial: Vec<u8>,
    /// Serial as upper-case hex (DPS `X-SERIAL_NUMBER`).
    pub serial_hex_upper: String,
    /// Subject CN (DPS `X-USER`).
    pub cn: Option<String>,
    /// Issuer CN (DPS `X-ISSUER`).
    pub issuer_cn: Option<String>,
    /// `notBefore`.
    pub not_before: NaiveDateTime,
    /// `notAfter`.
    pub not_after: NaiveDateTime,
}

/// Identity of the peer of an established TLS connection; `None` without a client cert.
pub fn peer_identity(conn: &rustls::ServerConnection) -> Option<PeerIdentity> {
    identity_from_der(conn.peer_certificates()?.first()?.as_ref())
}

/// Identity from a DER certificate (shared by [`peer_identity`] and tests).
///
/// * `serial` — the integer with leading zero bytes removed (`0` ⇒ empty);
/// * `serial_hex_upper` — like Python `getpeercert()["serialNumber"]` (OpenSSL
///   `i2a_ASN1_INTEGER`): two upper-case hex digits per byte, so an even number of digits
///   (`0` ⇒ `"00"`);
/// * `cn`/`issuer_cn` — the **last** CN of the name, as Python's `dict(...)["commonName"]`;
/// * `not_before`/`not_after` — UTC, naive (seconds).
pub fn identity_from_der(cert_der: &[u8]) -> Option<PeerIdentity> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let serial = strip_leading_zeros(cert.raw_serial());
    let serial_hex_upper = if serial.is_empty() {
        "00".to_owned()
    } else {
        serial.iter().map(|b| format!("{b:02X}")).collect()
    };
    let to_naive = |t: x509_parser::time::ASN1Time| {
        DateTime::from_timestamp(t.timestamp(), 0).map(|d| d.naive_utc())
    };
    Some(PeerIdentity {
        serial,
        serial_hex_upper,
        cn: last_cn(cert.subject()),
        issuer_cn: last_cn(cert.issuer()),
        not_before: to_naive(cert.validity().not_before)?,
        not_after: to_naive(cert.validity().not_after)?,
    })
}

/// All CN values of a name, in order (non-string CNs are skipped).
pub(crate) fn common_names(name: &X509Name<'_>) -> Vec<String> {
    name.iter_common_name()
        .filter_map(|a| a.as_str().ok().map(str::to_owned))
        .collect()
}

fn last_cn(name: &X509Name<'_>) -> Option<String> {
    common_names(name).pop()
}

/// Big-endian integer bytes without leading zero bytes.
pub(crate) fn strip_leading_zeros(b: &[u8]) -> Vec<u8> {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    b[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_zeros() {
        assert_eq!(strip_leading_zeros(&[0, 0, 1, 0]), vec![1, 0]);
        assert!(strip_leading_zeros(&[0, 0]).is_empty());
    }

    #[test]
    fn garbage_is_none() {
        assert!(identity_from_der(b"not a cert").is_none());
    }
}
