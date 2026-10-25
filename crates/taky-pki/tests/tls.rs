//! S-311: rustls server configs (ADR-003), PEM/key loading, PeerIdentity — with a PKI generated
//! at test time (`common`).
#![allow(clippy::expect_used)] // test helpers outside #[test] fns

mod common;

use std::process::Command;

use common::*;
use pkcs8::der::Decode;
use taky_pki::{PkiError, TlsMode, identity::identity_from_der, peer_identity, server_config};

fn cfg(required: bool, mode: TlsMode) -> std::sync::Arc<rustls::ServerConfig> {
    server_config(&ssl(pki(), required), mode).expect("server config")
}

#[test]
fn cot_required_accepts_taky_client_and_extracts_identity() {
    let p = pki();
    let s = handshake(cfg(true, TlsMode::Cot), client_config(p, Some(&p.alice))).expect("tls");
    let id = peer_identity(&s).expect("identity");
    assert_eq!(id.serial, ALICE_SERIAL.to_vec());
    assert_eq!(
        id.serial_hex_upper,
        "8F0102030405060708090A0B0C0D0E0F10111213"
    );
    assert_eq!(id.cn.as_deref(), Some("alice"));
    assert_eq!(id.issuer_cn.as_deref(), Some("CA"));
    assert_eq!(id.not_before.to_string(), "2024-03-04 00:00:00");
    assert_eq!(id.not_after.to_string(), "2080-05-06 00:00:00");
}

#[test]
fn cot_required_rejects_client_without_cert() {
    let p = pki();
    let err = handshake(cfg(true, TlsMode::Cot), client_config(p, None)).expect_err("no cert");
    assert!(
        matches!(err, rustls::Error::NoCertificatesPresented),
        "{err:?}"
    );
}

#[test]
fn foreign_ca_client_rejected_in_both_modes() {
    let p = pki();
    for required in [true, false] {
        let r = handshake(
            cfg(required, TlsMode::Cot),
            client_config(p, Some(&p.mallory)),
        );
        assert!(r.is_err(), "required={required}");
    }
}

#[test]
fn cot_optional_and_dps_allow_no_cert() {
    let p = pki();
    for (required, mode) in [
        (false, TlsMode::Cot),
        (true, TlsMode::Dps),
        (false, TlsMode::Dps),
    ] {
        let s = handshake(cfg(required, mode), client_config(p, None)).expect("tls");
        assert!(peer_identity(&s).is_none(), "{mode:?}");
        let s = handshake(cfg(required, mode), client_config(p, Some(&p.alice))).expect("tls");
        assert_eq!(
            peer_identity(&s).and_then(|i| i.cn).as_deref(),
            Some("alice")
        );
    }
}

#[test]
fn server_cert_identity_and_tls_versions() {
    let p = pki();
    let id = identity_from_der(p.server_cert.as_ref()).expect("id");
    assert_eq!(id.serial, vec![0x42, 1]);
    assert_eq!(id.serial_hex_upper, "4201");
    assert_eq!(id.cn.as_deref(), Some("localhost"));
    for v in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(p.ca_cert.clone()).expect("root");
        let c = rustls::ClientConfig::builder_with_provider(taky_pki::provider())
            .with_protocol_versions(&[v])
            .expect("v")
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![p.alice.0.clone()], p.alice.1.clone_key())
            .expect("c");
        let s = handshake(cfg(true, TlsMode::Cot), std::sync::Arc::new(c)).expect("tls");
        assert_eq!(s.protocol_version(), Some(v.version));
    }
}

#[test]
fn key_inside_cert_file_and_pkcs8_plain() {
    let p = pki();
    let d = tempfile::tempdir().expect("tmp");
    let both = format!("{}{}", cert_pem(&p.server_cert), p.server_rsa.pkcs1_pem());
    let mut s = ssl(p, true);
    s.cert = Some(write(d.path(), "both.pem", both));
    s.key = None;
    handshake(
        server_config(&s, TlsMode::Cot).expect("cfg"),
        client_config(p, Some(&p.alice)),
    )
    .expect("tls");
    s.key = Some(write(
        d.path(),
        "k8.pem",
        pem_wrap("PRIVATE KEY", &p.server_rsa.pkcs8_der()),
    ));
    server_config(&s, TlsMode::Cot).expect("pkcs8 key");
}

fn with_key(body: impl AsRef<[u8]>, pw: Option<&str>) -> Result<(), PkiError> {
    let p = pki();
    let d = tempfile::tempdir().expect("tmp");
    let mut s = ssl(p, false);
    s.key = Some(write(d.path(), "key.pem", body));
    s.key_pw = pw.map(str::to_owned);
    let c = server_config(&s, TlsMode::Cot)?;
    handshake(c, client_config(p, None)).map_err(PkiError::Tls)?;
    Ok(())
}

#[test]
fn encrypted_pkcs8_pbes2() {
    let p = pki();
    let der = p.server_rsa.pkcs8_der();
    let info = pkcs8::PrivateKeyInfo::from_der(&der).expect("pki");
    let params =
        pkcs8::pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(2048, b"saltsalt", &[7u8; 16])
            .expect("params");
    let enc = info.encrypt_with_params(params, b"s3cret").expect("enc");
    let pem = pem_wrap("ENCRYPTED PRIVATE KEY", enc.as_bytes());
    with_key(&pem, Some("s3cret")).expect("decrypts");
    assert!(matches!(
        with_key(&pem, Some("wrong")),
        Err(PkiError::Invalid(_))
    ));
    assert!(matches!(with_key(&pem, None), Err(PkiError::Invalid(_))));
}

/// Legacy `Proc-Type: 4,ENCRYPTED` made here with the same KDF the loader uses.
fn legacy_pem(der: &[u8], pw: &str, alg: &str) -> String {
    use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
    let iv: Vec<u8> = (1..=if alg.starts_with("DES") { 8 } else { 16 }).collect();
    let key_len = match alg {
        "AES-128-CBC" => 16,
        "AES-256-CBC" => 32,
        _ => 24,
    };
    let key = taky_pki::pem::evp_bytes_to_key_md5(pw.as_bytes(), &iv[..8], key_len);
    let mut buf = der.to_vec();
    let n = der.len();
    buf.resize(n + 16, 0);
    let ct = match alg {
        "AES-128-CBC" => cbc::Encryptor::<aes::Aes128>::new_from_slices(&key, &iv)
            .expect("k")
            .encrypt_padded_mut::<Pkcs7>(&mut buf, n)
            .expect("e")
            .to_vec(),
        "AES-256-CBC" => cbc::Encryptor::<aes::Aes256>::new_from_slices(&key, &iv)
            .expect("k")
            .encrypt_padded_mut::<Pkcs7>(&mut buf, n)
            .expect("e")
            .to_vec(),
        _ => cbc::Encryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
            .expect("k")
            .encrypt_padded_mut::<Pkcs7>(&mut buf, n)
            .expect("e")
            .to_vec(),
    };
    let ivh: String = iv.iter().map(|b| format!("{b:02X}")).collect();
    let body = pem_wrap("RSA PRIVATE KEY", &ct);
    body.replacen(
        "-----\n",
        &format!("-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: {alg},{ivh}\n\n"),
        1,
    )
}

#[test]
fn encrypted_legacy_pem() {
    let der = pki().server_rsa.pkcs1_der();
    for alg in ["DES-EDE3-CBC", "AES-128-CBC", "AES-256-CBC"] {
        let pem = legacy_pem(&der, "pw", alg);
        with_key(&pem, Some("pw")).unwrap_or_else(|e| panic!("{alg}: {e}"));
        assert!(with_key(&pem, Some("nope")).is_err(), "{alg}");
        assert!(with_key(&pem, None).is_err(), "{alg}");
    }
}

/// Interop: keys encrypted by the real OpenSSL CLI (skipped if `openssl` is absent).
#[test]
fn openssl_encrypted_keys_interop() {
    if !openssl() {
        eprintln!("SKIP: openssl CLI not found");
        return;
    }
    let p = pki();
    let d = tempfile::tempdir().expect("tmp");
    let plain = write(d.path(), "plain.key", p.server_rsa.pkcs1_pem());
    let run = |args: &[&str], out: &str| {
        let o = d.path().join(out);
        let st = Command::new("openssl")
            .args(args)
            .arg("-in")
            .arg(&plain)
            .arg("-out")
            .arg(&o)
            .output()
            .expect("openssl");
        assert!(
            st.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&st.stderr)
        );
        std::fs::read(o).expect("read")
    };
    let cases = [
        (
            vec!["rsa", "-traditional", "-aes256", "-passout", "pass:pw"],
            "legacy-aes",
        ),
        (
            vec!["rsa", "-traditional", "-des3", "-passout", "pass:pw"],
            "legacy-3des",
        ),
        (
            vec![
                "pkcs8",
                "-topk8",
                "-v2",
                "aes-256-cbc",
                "-passout",
                "pass:pw",
            ],
            "p8-aes",
        ),
        (
            vec!["pkcs8", "-topk8", "-v2", "des3", "-passout", "pass:pw"],
            "p8-3des",
        ),
    ];
    for (args, name) in cases {
        let pem = run(&args, name);
        with_key(&pem, Some("pw")).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(with_key(&pem, Some("bad")).is_err(), "{name}");
    }
    // PBES1 / PKCS#12-PBE (ADR-003 errata §1): a clear error naming the scheme and the remedy
    // (review-3D N-1), not "bad key_pw".
    let pem = run(
        &[
            "pkcs8",
            "-topk8",
            "-v1",
            "PBE-SHA1-3DES",
            "-passout",
            "pass:pw",
        ],
        "p8-pbe-sha1-3des",
    );
    let msg = with_key(&pem, Some("pw"))
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        msg.contains("unsupported PKCS#8 encryption 1.2.840.113549.1.12.1.3")
            && msg.contains("openssl pkcs8 -topk8 -v2 aes-256-cbc"),
        "{msg}"
    );
}

#[test]
fn config_errors() {
    let p = pki();
    let mut s = ssl(p, true);
    s.cert = Some(p.dir.path().join("missing.crt"));
    assert!(matches!(
        server_config(&s, TlsMode::Cot),
        Err(PkiError::Io { .. })
    ));
    let mut s = ssl(p, true);
    s.cert = None;
    assert!(server_config(&s, TlsMode::Cot).is_err());
    let mut s = ssl(p, true);
    s.key = Some(p.ca_path.clone()); // a PEM without a key
    assert!(matches!(
        server_config(&s, TlsMode::Cot),
        Err(PkiError::Invalid(_))
    ));
    // Key that does not match the certificate.
    let d = tempfile::tempdir().expect("tmp");
    let other = rcgen::KeyPair::generate().expect("k");
    let mut s = ssl(p, true);
    s.key = Some(write(
        d.path(),
        "o.key",
        pem_wrap("PRIVATE KEY", &other.serialize_der()),
    ));
    assert!(server_config(&s, TlsMode::Cot).is_err());
}

#[test]
fn empty_ca_uses_system_roots() {
    let p = pki();
    let mut s = ssl(p, false);
    s.ca = None;
    // Optional mode always builds; a client without a cert connects.
    let c = server_config(&s, TlsMode::Dps).expect("cfg");
    handshake(c, client_config(p, None)).expect("tls");
    // System roots never contain the test CA ⇒ alice is rejected if a verifier is active,
    // or not asked for a cert at all without system roots; either way no identity.
    let c = server_config(&s, TlsMode::Cot).expect("cfg");
    if let Ok(conn) = handshake(c, client_config(p, Some(&p.alice))) {
        assert!(peer_identity(&conn).is_none());
    }
    let roots = taky_pki::load_roots(None).expect("roots");
    s.client_cert_required = true;
    assert_eq!(server_config(&s, TlsMode::Cot).is_ok(), !roots.is_empty());
}
