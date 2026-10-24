//! Test PKI generated at test time (no keys in the repo): certificate profiles as in
//! `taky/util/anc.py` (spec dps-cli-config §4). RSA keys come from the `rsa` crate (rcgen/ring
//! cannot generate RSA) and are written as PKCS#1 `RSA PRIVATE KEY`, like takyctl does.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SerialNumber, date_time_ymd,
};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

pub struct Rsa {
    pub key: rsa::RsaPrivateKey,
}

impl Rsa {
    pub fn pkcs8_der(&self) -> Vec<u8> {
        self.key.to_pkcs8_der().expect("pkcs8").as_bytes().to_vec()
    }
    pub fn pkcs1_der(&self) -> Vec<u8> {
        self.key.to_pkcs1_der().expect("pkcs1").as_bytes().to_vec()
    }
    pub fn pkcs1_pem(&self) -> String {
        self.key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .expect("pem")
            .to_string()
    }
    pub fn keypair(&self) -> KeyPair {
        KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(self.pkcs8_der()),
            &rcgen::PKCS_RSA_SHA256,
        )
        .expect("rcgen rsa keypair")
    }
}

fn rsa2048() -> Rsa {
    let mut rng = rand::thread_rng();
    Rsa {
        key: rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen"),
    }
}

/// A CA in the `make_ca` profile.
pub struct Ca {
    pub cert: CertificateDer<'static>,
    pub pem: String,
    pub issuer: Issuer<'static, KeyPair>,
}

pub fn make_ca(cn: &str, key: KeyPair) -> Ca {
    let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
    p.distinguished_name.push(DnType::CommonName, cn);
    p.distinguished_name.push(DnType::OrganizationName, "taky");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    p.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    p.not_before = date_time_ymd(2020, 1, 1);
    p.not_after = date_time_ymd(2090, 1, 1);
    let cert = p.self_signed(&key).expect("ca");
    Ca {
        cert: cert.der().clone(),
        pem: cert.pem(),
        issuer: Issuer::new(p, key),
    }
}

/// Server (`is_server_cert=True`) or client profile, signed by `ca`.
pub fn make_cert(
    ca: &Ca,
    key: &KeyPair,
    cn: &str,
    server: bool,
    serial: &[u8],
) -> CertificateDer<'static> {
    let sans = if server {
        vec![cn.to_owned()]
    } else {
        Vec::new()
    };
    let mut p = CertificateParams::new(sans).expect("params");
    p.distinguished_name.push(DnType::CommonName, cn);
    p.is_ca = IsCa::ExplicitNoCa;
    p.use_authority_key_identifier_extension = true;
    p.serial_number = Some(SerialNumber::from_slice(serial));
    p.not_before = date_time_ymd(2024, 3, 4);
    p.not_after = date_time_ymd(2080, 5, 6);
    if server {
        p.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        p.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
    } else {
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::ContentCommitment,
            KeyUsagePurpose::KeyEncipherment,
        ];
    }
    p.signed_by(key, &ca.issuer).expect("sign").der().clone()
}

pub fn cert_pem(der: &[u8]) -> String {
    pem_wrap("CERTIFICATE", der)
}

pub fn pem_wrap(label: &str, der: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for c in der.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                b64.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                b64.push('=');
            }
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

pub const ALICE_SERIAL: [u8; 20] = [
    0x8f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13,
];

/// The shared fixture: taky-style CA + server (RSA, PKCS#1 key file), clients.
pub struct Pki {
    pub dir: tempfile::TempDir,
    pub ca_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub server_rsa: Rsa,
    pub server_cert: CertificateDer<'static>,
    pub ca_cert: CertificateDer<'static>,
    pub alice: (CertificateDer<'static>, PrivateKeyDer<'static>),
    /// Valid-looking client from a different CA (same CN `CA`).
    pub mallory: (CertificateDer<'static>, PrivateKeyDer<'static>),
}

pub fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let ca_rsa = rsa2048();
        let server_rsa = rsa2048();
        let ca = make_ca("CA", ca_rsa.keypair());
        let server_cert = make_cert(&ca, &server_rsa.keypair(), "localhost", true, &[0x42, 1]);
        let alice_key = KeyPair::generate().expect("ec key");
        let alice_cert = make_cert(&ca, &alice_key, "alice", false, &ALICE_SERIAL);
        let other = make_ca("CA", KeyPair::generate().expect("ec key"));
        let m_key = KeyPair::generate().expect("ec key");
        let m_cert = make_cert(&other, &m_key, "alice", false, &ALICE_SERIAL);

        let dir = tempfile::tempdir().expect("tmp");
        let ca_path = dir.path().join("ca.crt");
        let cert_path = dir.path().join("server.crt");
        let key_path = dir.path().join("server.key");
        std::fs::write(&ca_path, &ca.pem).expect("w");
        std::fs::write(&cert_path, cert_pem(&server_cert)).expect("w");
        std::fs::write(&key_path, server_rsa.pkcs1_pem()).expect("w");
        let ec = |k: &KeyPair| PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k.serialize_der()));
        Pki {
            ca_cert: ca.cert.clone(),
            alice: (alice_cert, ec(&alice_key)),
            mallory: (m_cert, ec(&m_key)),
            dir,
            ca_path,
            cert_path,
            key_path,
            server_rsa,
            server_cert,
        }
    })
}

pub fn ssl(pki: &Pki, required: bool) -> taky_config::SslSect {
    taky_config::SslSect {
        enabled: true,
        client_cert_required: required,
        ca: Some(pki.ca_path.clone()),
        ca_key: None,
        server_p12: None,
        server_p12_pw: None,
        cert: Some(pki.cert_path.clone()),
        key: Some(pki.key_path.clone()),
        key_pw: None,
        cert_db: pki.dir.path().join("cert-db.txt"),
    }
}

pub fn write(dir: &Path, name: &str, body: impl AsRef<[u8]>) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).expect("write");
    p
}

/// Client config trusting the fixture CA; with `client` — presents that certificate.
pub fn client_config(
    pki: &Pki,
    client: Option<&(CertificateDer<'static>, PrivateKeyDer<'static>)>,
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pki.ca_cert.clone()).expect("root");
    let b = rustls::ClientConfig::builder_with_provider(taky_pki::provider())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots);
    Arc::new(match client {
        Some((c, k)) => b
            .with_client_auth_cert(vec![c.clone()], k.clone_key())
            .expect("client cert"),
        None => b.with_no_client_auth(),
    })
}

/// In-memory handshake; returns the server side on success.
pub fn handshake(
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
) -> Result<rustls::ServerConnection, rustls::Error> {
    let name = ServerName::try_from("localhost").expect("name");
    let mut c = rustls::ClientConnection::new(client, name)?;
    let mut s = rustls::ServerConnection::new(server)?;
    for _ in 0..20 {
        let mut buf = Vec::new();
        while c.wants_write() {
            c.write_tls(&mut buf).expect("write");
        }
        let mut rd = &buf[..];
        while !rd.is_empty() {
            s.read_tls(&mut rd).expect("read");
            s.process_new_packets()?;
        }
        let mut buf = Vec::new();
        while s.wants_write() {
            s.write_tls(&mut buf).expect("write");
        }
        let mut rd = &buf[..];
        while !rd.is_empty() {
            c.read_tls(&mut rd).expect("read");
            c.process_new_packets()?;
        }
        if !c.is_handshaking() && !s.is_handshaking() {
            return Ok(s);
        }
    }
    Err(rustls::Error::General("handshake did not finish".into()))
}

/// `openssl` CLI available (interop checks are skipped otherwise).
pub fn openssl() -> bool {
    std::process::Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}
