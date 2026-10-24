//! PEM certificates and private keys in the formats the original accepts (`ssl.load_cert_chain`,
//! `anc.load_certificate`) — ADR-003:
//! * `RSA PRIVATE KEY` (PKCS#1, what takyctl writes), `PRIVATE KEY` (PKCS#8), `EC PRIVATE KEY` (SEC1);
//! * `ENCRYPTED PRIVATE KEY` (PKCS#8 PBES2: PBKDF2 + AES-CBC / DES-EDE3-CBC) with `ssl.key_pw`;
//! * legacy OpenSSL `Proc-Type: 4,ENCRYPTED` + `DEK-Info:` (DES-EDE3-CBC, AES-128/192/256-CBC,
//!   `EVP_BytesToKey` with MD5, one iteration) on PKCS#1/SEC1 blocks.
//!
//! Not supported (error): PKCS#8 PBES1 (`pbeWithMD5AndDES` …) and PKCS#12-PBE inside PKCS#8.

use std::path::Path;

use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use md5::{Digest, Md5};
use rustls_pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};

use crate::PkiError;

/// One PEM block: label, RFC 1421 headers (`Proc-Type`, `DEK-Info`), decoded body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemBlock {
    /// Text between `BEGIN ` and `-----`.
    pub label: String,
    /// `Name: value` header lines (legacy encryption), in order.
    pub headers: Vec<(String, String)>,
    /// Base64-decoded contents.
    pub der: Vec<u8>,
}

/// Parse all PEM blocks in `text` (text outside blocks is ignored, as OpenSSL does).
pub fn parse_pem(text: &[u8]) -> Result<Vec<PemBlock>, PkiError> {
    let text = String::from_utf8_lossy(text);
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
        else {
            continue;
        };
        let end = format!("-----END {label}-----");
        let mut headers = Vec::new();
        let mut b64 = String::new();
        let mut in_headers = true;
        let mut closed = false;
        for body in lines.by_ref() {
            let body = body.trim();
            if body == end {
                closed = true;
                break;
            }
            if in_headers {
                if let Some((k, v)) = body.split_once(':') {
                    headers.push((k.trim().to_owned(), v.trim().to_owned()));
                    continue;
                }
                in_headers = false;
                if body.is_empty() {
                    continue;
                }
            }
            b64.push_str(body);
        }
        if !closed {
            return Err(PkiError::Invalid(format!(
                "PEM block {label}: missing END line"
            )));
        }
        let der = base64_decode(&b64)
            .ok_or_else(|| PkiError::Invalid(format!("PEM block {label}: bad base64")))?;
        out.push(PemBlock {
            label: label.to_owned(),
            headers,
            der,
        });
    }
    Ok(out)
}

/// Standard base64 (with `=` padding, whitespace ignored).
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    }
    let bytes: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let data = bytes
        .strip_suffix(b"==")
        .or_else(|| bytes.strip_suffix(b"="));
    let pad = bytes.len() - data.map_or(bytes.len(), <[u8]>::len);
    let data = data.unwrap_or(&bytes);
    if !(data.len() + pad).is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    for chunk in data.chunks(4) {
        let mut acc = 0u32;
        for &c in chunk {
            acc = (acc << 6) | val(c)?;
        }
        match chunk.len() {
            4 => out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]),
            3 => out.extend_from_slice(&[(acc >> 10) as u8, (acc >> 2) as u8]),
            2 => out.push((acc >> 4) as u8),
            _ => return None,
        }
    }
    Some(out)
}

fn read(path: &Path) -> Result<Vec<u8>, PkiError> {
    std::fs::read(path).map_err(|source| PkiError::Io {
        path: path.to_owned(),
        source,
    })
}

/// All `CERTIFICATE` blocks of a PEM file, in order (error if there are none).
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, PkiError> {
    let certs: Vec<_> = parse_pem(&read(path)?)?
        .into_iter()
        .filter(|b| b.label == "CERTIFICATE")
        .map(|b| CertificateDer::from(b.der))
        .collect();
    if certs.is_empty() {
        return Err(PkiError::Invalid(format!(
            "{}: no CERTIFICATE in PEM",
            path.display()
        )));
    }
    Ok(certs)
}

/// The first private key of a PEM file (it may also contain certificates), decrypted with
/// `password` if encrypted. An unencrypted key ignores `password` (as Python `ssl` does).
pub fn load_private_key(
    path: &Path,
    password: Option<&str>,
) -> Result<PrivateKeyDer<'static>, PkiError> {
    let blocks = parse_pem(&read(path)?)?;
    for b in blocks {
        if let Some(key) = key_from_block(&b, password)? {
            return Ok(key);
        }
    }
    Err(PkiError::Invalid(format!(
        "{}: no private key in PEM",
        path.display()
    )))
}

/// Decode one PEM block as a private key; `Ok(None)` if it is not a key block.
pub fn key_from_block(
    b: &PemBlock,
    password: Option<&str>,
) -> Result<Option<PrivateKeyDer<'static>>, PkiError> {
    let need_pw =
        || password.ok_or_else(|| PkiError::Invalid("encrypted private key and no key_pw".into()));
    let key = match b.label.as_str() {
        "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
            let der = if is_legacy_encrypted(b) {
                legacy_decrypt(b, need_pw()?.as_bytes())?
            } else {
                b.der.clone()
            };
            if b.label.starts_with("RSA") {
                PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der))
            } else {
                PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der))
            }
        }
        "PRIVATE KEY" => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(b.der.clone())),
        "ENCRYPTED PRIVATE KEY" => {
            let pw = need_pw()?;
            let info = pkcs8::EncryptedPrivateKeyInfo::try_from(b.der.as_slice())
                .map_err(|e| PkiError::Invalid(format!("encrypted PKCS#8: {e}")))?;
            let doc = info
                .decrypt(pw.as_bytes())
                .map_err(|e| PkiError::Invalid(format!("encrypted PKCS#8 (bad key_pw?): {e}")))?;
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(doc.as_bytes().to_vec()))
        }
        _ => return Ok(None),
    };
    Ok(Some(key))
}

fn is_legacy_encrypted(b: &PemBlock) -> bool {
    b.headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("Proc-Type") && v.contains("ENCRYPTED"))
}

/// OpenSSL `EVP_BytesToKey(cipher, MD5, salt, pw, count=1)`: key bytes only.
pub fn evp_bytes_to_key_md5(password: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        h.update(salt);
        prev = h.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(key_len);
    out
}

fn legacy_decrypt(b: &PemBlock, password: &[u8]) -> Result<Vec<u8>, PkiError> {
    let dek = b
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("DEK-Info"))
        .map(|(_, v)| v.as_str())
        .ok_or_else(|| PkiError::Invalid("encrypted PEM without DEK-Info".into()))?;
    let (alg, iv_hex) = dek
        .split_once(',')
        .ok_or_else(|| PkiError::Invalid(format!("bad DEK-Info: {dek}")))?;
    let iv = hex_decode(iv_hex.trim())
        .ok_or_else(|| PkiError::Invalid(format!("bad DEK-Info IV: {dek}")))?;
    let alg = alg.trim().to_ascii_uppercase();
    let (key_len, iv_len) = match alg.as_str() {
        "DES-EDE3-CBC" => (24, 8),
        "AES-128-CBC" => (16, 16),
        "AES-192-CBC" => (24, 16),
        "AES-256-CBC" => (32, 16),
        other => {
            return Err(PkiError::Invalid(format!(
                "unsupported PEM encryption {other}"
            )));
        }
    };
    if iv.len() != iv_len {
        return Err(PkiError::Invalid(format!("bad DEK-Info IV length: {dek}")));
    }
    let key = evp_bytes_to_key_md5(password, &iv[..8], key_len);
    let pt = match alg.as_str() {
        "DES-EDE3-CBC" => cbc_decrypt::<des::TdesEde3>(&key, &iv, &b.der)?,
        "AES-128-CBC" => cbc_decrypt::<aes::Aes128>(&key, &iv, &b.der)?,
        "AES-192-CBC" => cbc_decrypt::<aes::Aes192>(&key, &iv, &b.der)?,
        _ => cbc_decrypt::<aes::Aes256>(&key, &iv, &b.der)?,
    };
    // A wrong password usually fails the padding check; otherwise the result is not a DER
    // SEQUENCE (rustls rejects it later), so check the outer tag here for a clearer error.
    if pt.first() != Some(&0x30) {
        return Err(PkiError::Invalid(
            "legacy encrypted PEM: bad key_pw or corrupt data".into(),
        ));
    }
    Ok(pt)
}

fn cbc_decrypt<C>(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, PkiError>
where
    C: aes::cipher::BlockDecryptMut + aes::cipher::BlockCipher + aes::cipher::KeyInit,
{
    let dec = cbc::Decryptor::<C>::new_from_slices(key, iv)
        .map_err(|_| PkiError::Invalid("legacy encrypted PEM: key/IV length".into()))?;
    let mut buf = ct.to_vec();
    let n = dec
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| PkiError::Invalid("legacy encrypted PEM: bad key_pw or corrupt data".into()))?
        .len();
    buf.truncate(n);
    Ok(buf)
}

/// Hex string → bytes (even length, any case).
pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_known() {
        assert_eq!(base64_decode("aGVsbG8=").as_deref(), Some(&b"hello"[..]));
        assert_eq!(base64_decode("aGVsbG8h").as_deref(), Some(&b"hello!"[..]));
        assert_eq!(base64_decode("aGVsbA==").as_deref(), Some(&b"hell"[..]));
        assert_eq!(base64_decode("aGVs\nbA==").as_deref(), Some(&b"hell"[..]));
        assert_eq!(base64_decode("").as_deref(), Some(&b""[..]));
        assert!(base64_decode("aGVsbA=").is_none());
        assert!(base64_decode("a*==").is_none());
    }

    #[test]
    fn parse_headers_and_garbage() {
        let text = b"junk\n-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\
            DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\naGVsbA==\n\
            -----END RSA PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\naGk=\n-----END CERTIFICATE-----\n";
        let blocks = parse_pem(text).expect("parse");
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].label, "RSA PRIVATE KEY");
        assert_eq!(blocks[0].headers.len(), 2);
        assert!(is_legacy_encrypted(&blocks[0]));
        assert_eq!(blocks[0].der, b"hell");
        assert_eq!(blocks[1].der, b"hi");
        assert!(parse_pem(b"-----BEGIN X-----\naGk=\n").is_err());
    }

    #[test]
    fn evp_bytes_to_key_matches_openssl() {
        // D1 = MD5(pw||salt), D2 = MD5(D1||pw||salt). Interop with real OpenSSL output is
        // checked end-to-end in tests (openssl CLI, when available).
        let k = evp_bytes_to_key_md5(b"pw", b"saltsalt", 32);
        let d1 = Md5::digest(b"pwsaltsalt").to_vec();
        let mut h = Md5::new();
        h.update(&d1);
        h.update(b"pwsaltsalt");
        let d2 = h.finalize().to_vec();
        assert_eq!(&k[..16], &d1[..]);
        assert_eq!(&k[16..], &d2[..]);
    }

    #[test]
    fn unencrypted_key_kinds() {
        let mk = |label: &str| PemBlock {
            label: label.into(),
            headers: vec![],
            der: vec![0x30, 0],
        };
        assert!(matches!(
            key_from_block(&mk("RSA PRIVATE KEY"), None),
            Ok(Some(PrivateKeyDer::Pkcs1(_)))
        ));
        assert!(matches!(
            key_from_block(&mk("EC PRIVATE KEY"), Some("ignored")),
            Ok(Some(PrivateKeyDer::Sec1(_)))
        ));
        assert!(matches!(
            key_from_block(&mk("PRIVATE KEY"), None),
            Ok(Some(PrivateKeyDer::Pkcs8(_)))
        ));
        assert!(matches!(key_from_block(&mk("CERTIFICATE"), None), Ok(None)));
        assert!(key_from_block(&mk("ENCRYPTED PRIVATE KEY"), None).is_err());
    }
}
