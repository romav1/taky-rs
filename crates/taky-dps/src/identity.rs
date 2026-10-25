//! Identity header policy (ADR-004, ADR-008 G-6 / D-21, spec dps-cli-config §2.2).
//!
//! * **TLS**: the six identity headers are always removed — case-insensitively and in every
//!   `_`/`-` spelling — and, if the client presented a certificate, set from it
//!   ([`tls_header_policy`]). An external `X-USER` is never trusted.
//! * **Plain**: `X-USER`/`X-REVOKED` (and the other four) are passed through only when the peer
//!   is loopback (a reverse proxy on the same host); from any other peer they are removed (⇒ 401).
//!   Spellings other than the canonical ones (e.g. `X_USER`) are always removed
//!   ([`plain_header_policy`]).

use std::net::IpAddr;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use taky_pki::PeerIdentity;

/// The header names gunicorn's `ClientCertificateWorker` controls (lower case, as `http` stores them).
pub const IDENTITY_HEADERS: [&str; 6] = [
    "x-user",
    "x-serial_number",
    "x-issuer",
    "x-revoked",
    "x-not_before",
    "x-not_after",
];

fn fold(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

/// `true` if `name` is any spelling (case, `_` vs `-`) of an identity header.
pub fn is_identity_header(name: &str) -> bool {
    let f = fold(name);
    IDENTITY_HEADERS.iter().any(|c| fold(c) == f)
}

fn remove_where(headers: &mut HeaderMap, pred: impl Fn(&str) -> bool) {
    let names: Vec<HeaderName> = headers
        .keys()
        .filter(|n| pred(n.as_str()))
        .cloned()
        .collect();
    for n in names {
        headers.remove(&n);
    }
}

/// Loopback peer: `127.0.0.0/8`, `::1`, or IPv4-mapped `::ffff:127.x.y.z`.
pub fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Plain mode (G-6): keep canonical identity headers only from a loopback peer.
pub fn plain_header_policy(headers: &mut HeaderMap, peer: IpAddr) {
    let trusted = is_loopback(peer);
    remove_where(headers, |n| {
        is_identity_header(n) && !(trusted && IDENTITY_HEADERS.contains(&n))
    });
}

/// TLS mode: drop every spelling of the identity headers, then set them from `id`
/// (`X-USER`=CN, `X-SERIAL_NUMBER`=upper hex serial, `X-REVOKED: 1` if `revoked`, `X-ISSUER`=issuer
/// CN, `X-NOT_BEFORE`/`X-NOT_AFTER`=epoch seconds). A value that is not a valid header value is
/// left out.
pub fn tls_header_policy(headers: &mut HeaderMap, id: Option<&PeerIdentity>, revoked: bool) {
    remove_where(headers, is_identity_header);
    let Some(id) = id else { return };
    let mut set = |name: &'static str, v: String| {
        if let Ok(v) = HeaderValue::from_bytes(v.as_bytes()) {
            headers.insert(HeaderName::from_static(name), v);
        }
    };
    if let Some(cn) = &id.cn {
        set("x-user", cn.clone());
    }
    set("x-serial_number", id.serial_hex_upper.clone());
    if revoked {
        set("x-revoked", "1".to_owned());
    }
    if let Some(cn) = &id.issuer_cn {
        set("x-issuer", cn.clone());
    }
    set(
        "x-not_before",
        id.not_before.and_utc().timestamp().to_string(),
    );
    set(
        "x-not_after",
        id.not_after.and_utc().timestamp().to_string(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;

    fn spoofed() -> HeaderMap {
        let mut h = HeaderMap::new();
        for n in [
            "X-USER",
            "X_USER",
            "x-Revoked",
            "X-SERIAL-NUMBER",
            "X-NOT_AFTER",
            "Host",
        ] {
            h.append(
                HeaderName::from_bytes(n.as_bytes()).unwrap(),
                HeaderValue::from_static("m"),
            );
        }
        h
    }

    #[test]
    fn spellings() {
        assert!(is_identity_header("X_USER"));
        assert!(is_identity_header("x-serial-number"));
        assert!(is_identity_header("X-NOT_BEFORE"));
        assert!(!is_identity_header("x-users"));
    }

    #[test]
    fn plain_loopback_keeps_only_canonical() {
        let mut h = spoofed();
        plain_header_policy(&mut h, "127.0.0.1".parse().unwrap());
        let mut names: Vec<_> = h.keys().map(|k| k.as_str().to_owned()).collect();
        names.sort();
        assert_eq!(names, ["host", "x-not_after", "x-revoked", "x-user"]);
        let mut h = spoofed();
        plain_header_policy(&mut h, "::ffff:127.0.0.2".parse().unwrap());
        assert!(h.contains_key("x-user"));
    }

    #[test]
    fn plain_remote_drops_all() {
        let mut h = spoofed();
        plain_header_policy(&mut h, "10.9.9.9".parse().unwrap());
        assert_eq!(h.len(), 1);
        assert!(h.contains_key("host"));
    }

    #[test]
    fn tls_sets_from_certificate() {
        let mut h = spoofed();
        tls_header_policy(&mut h, None, false);
        assert_eq!(h.len(), 1);
        let id = PeerIdentity {
            serial: vec![0x0a, 0xbc],
            serial_hex_upper: "0ABC".into(),
            cn: Some("bob".into()),
            issuer_cn: Some("CA".into()),
            not_before: DateTime::from_timestamp(1_600_000_000, 0)
                .unwrap()
                .naive_utc(),
            not_after: DateTime::from_timestamp(1_700_000_000, 0)
                .unwrap()
                .naive_utc(),
        };
        let mut h = spoofed();
        tls_header_policy(&mut h, Some(&id), true);
        assert_eq!(h["x-user"], "bob");
        assert_eq!(h.get_all("x-user").iter().count(), 1);
        assert_eq!(h["x-serial_number"], "0ABC");
        assert_eq!(h["x-revoked"], "1");
        assert_eq!(h["x-issuer"], "CA");
        assert_eq!(h["x-not_before"], "1600000000");
        assert_eq!(h["x-not_after"], "1700000000");
        assert!(!h.contains_key("x-serial-number"));
    }
}
