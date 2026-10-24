//! Client certificate identity (ARCHITECTURE §11).

use chrono::NaiveDateTime;

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
    let _ = conn;
    todo!("dev02: S-311")
}

/// Identity from a DER certificate (shared by [`peer_identity`] and tests).
pub fn identity_from_der(cert_der: &[u8]) -> Option<PeerIdentity> {
    let _ = cert_der;
    todo!("dev02: S-311")
}
