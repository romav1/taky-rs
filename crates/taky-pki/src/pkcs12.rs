//! PKCS#12 (RFC 7292) encoder and a minimal reader — the `.p12` files of `anc.make_cert`
//! (`pkcs12.serialize_key_and_certificates` of Python `cryptography` ≥ 43, ADR-006, spec
//! dps-cli-config §4). Behind the `gen` feature (takyctl only).
//!
//! The encoder reproduces `cryptography`'s structure **byte for byte** (given the same salts —
//! verified by `tests/pyref_p12.rs` against p12 files made by the original `anc.py`):
//!
//! ```text
//! PFX v3
//!  └ authSafe = data { AuthenticatedSafe [
//!      encryptedData (pbeWithSHA1And3-KeyTripleDES-CBC, salt 8, 1 iteration) {
//!        certBag(cert)  attrs: friendlyName=name (BMPString), localKeyId=SHA-1(cert) if key
//!        certBag(ca_i)  attrs: friendlyName=ca_i.friendly_name (if any)
//!      },
//!      data { pkcs8ShroudedKeyBag (same PBE, salt 8, 1 iteration)  attrs: as the cert bag }
//!    ] }
//!  └ macData: HMAC-SHA1, salt 8, 2048 iterations
//! ```
//!
//! Attributes are a DER `SET OF` (sorted by encoding; friendlyName sorts first); a bag without
//! attributes omits the field. Passwords are UTF-16BE + `00 00` (RFC 7292 B.1; characters outside
//! the BMP become surrogate pairs, as in `cryptography`); an empty password is rejected like
//! Python (`Password must be 1 or more bytes.`). `friendly_name` is any UTF-8 string, written as
//! UTF-16 code units (an empty name gives an empty BMPString attribute; `None` — no attribute).
//!
//! The reader ([`parse`]) understands exactly what this encoder and `cryptography` produce
//! (DER, 3DES PBE, HMAC-SHA1 MAC): it is used by tests and by takyctl to check a p12.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};

use crate::PkiError;
use crate::certgen::{CertAuthority, KeyCert};

/// MAC iterations written by `cryptography` (shown by `openssl pkcs12 -info`).
pub const MAC_ITERATIONS: u32 = 2048;
/// PBE iterations for certificates and key (`kdf_rounds(1)` in anc.py).
pub const PBE_ITERATIONS: u32 = 1;
/// Salt length of every PBE and of the MAC.
pub const SALT_LEN: usize = 8;

const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const OID_ENCRYPTED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06];
const OID_PBE_SHA1_3DES: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03];
const OID_KEY_BAG: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x01,
];
const OID_SHROUDED_KEY_BAG: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x02,
];
const OID_CERT_BAG: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x03,
];
const OID_X509_CERT: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x16, 0x01];
const OID_FRIENDLY_NAME: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x14];
const OID_LOCAL_KEY_ID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x15];
const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];

const T_INT: u8 = 0x02;
const T_OCTET: u8 = 0x04;
const T_NULL: u8 = 0x05;
const T_OID: u8 = 0x06;
const T_BMP: u8 = 0x1e;
const T_SEQ: u8 = 0x30;
const T_SET: u8 = 0x31;
const T_CTX0: u8 = 0xa0;
const T_CTX0_PRIM: u8 = 0x80;

/// An extra certificate (`pkcs12.PKCS12Certificate(cert, friendly_name)`).
#[derive(Debug, Clone, Copy)]
pub struct P12Cert<'a> {
    /// Certificate DER.
    pub der: &'a [u8],
    /// `friendly_name` (`None` — no attributes).
    pub friendly_name: Option<&'a str>,
}

/// Arguments of `serialize_key_and_certificates(name, key, cert, cas, …)`.
#[derive(Debug, Clone, Copy)]
pub struct P12Input<'a> {
    /// `name`: friendlyName of the certificate and key bags.
    pub name: Option<&'a str>,
    /// `key` as PKCS#8 `PrivateKeyInfo` DER (`None` — certificate-only p12, e.g. `server.p12`).
    pub key_pkcs8: Option<&'a [u8]>,
    /// `cert` DER.
    pub cert: &'a [u8],
    /// `cas`, in order.
    pub cas: &'a [P12Cert<'a>],
}

/// The three random salts of a p12 (fixed only for byte-exact tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Salts {
    /// Salt of the certificates' `EncryptedData`.
    pub certs: [u8; SALT_LEN],
    /// Salt of the `pkcs8ShroudedKeyBag`.
    pub key: [u8; SALT_LEN],
    /// MAC salt.
    pub mac: [u8; SALT_LEN],
}

impl Salts {
    /// Fresh random salts (OS RNG).
    pub fn random() -> Salts {
        Salts {
            certs: rand::random(),
            key: rand::random(),
            mac: rand::random(),
        }
    }
}

/// `serialize_key_and_certificates` with anc.py's encryption (3DES PBE ×1, HMAC-SHA1 ×2048).
pub fn serialize(input: &P12Input<'_>, password: &str) -> Result<Vec<u8>, PkiError> {
    serialize_with_salts(input, password, &Salts::random())
}

/// [`serialize`] with given salts (deterministic; tests).
pub fn serialize_with_salts(
    input: &P12Input<'_>,
    password: &str,
    salts: &Salts,
) -> Result<Vec<u8>, PkiError> {
    let pw = bmp_password(password)?;
    let local_key_id = input.key_pkcs8.map(|_| Sha1::digest(input.cert).to_vec());

    // Certificates: cert bag, then the CA bags, all in one EncryptedData.
    let mut cert_bags = vec![cert_bag(input.cert, input.name, local_key_id.as_deref())];
    for ca in input.cas {
        cert_bags.push(cert_bag(ca.der, ca.friendly_name, None));
    }
    let certs_plain = tlv(T_SEQ, &cert_bags.concat());
    let certs_ct = pbe_encrypt(&pw, &salts.certs, PBE_ITERATIONS, &certs_plain)?;
    let encrypted_data = tlv(
        T_SEQ,
        &[
            int(0),
            tlv(
                T_SEQ,
                &[
                    tlv(T_OID, OID_DATA),
                    pbe_alg(&salts.certs, PBE_ITERATIONS),
                    tlv(T_CTX0_PRIM, &certs_ct),
                ]
                .concat(),
            ),
        ]
        .concat(),
    );
    let mut safes = vec![tlv(
        T_SEQ,
        &[tlv(T_OID, OID_ENCRYPTED_DATA), tlv(T_CTX0, &encrypted_data)].concat(),
    )];

    // Key: one pkcs8ShroudedKeyBag in a plain `data` SafeContents.
    if let Some(key) = input.key_pkcs8 {
        let ct = pbe_encrypt(&pw, &salts.key, PBE_ITERATIONS, key)?;
        let epki = tlv(
            T_SEQ,
            &[pbe_alg(&salts.key, PBE_ITERATIONS), tlv(T_OCTET, &ct)].concat(),
        );
        let bag = safe_bag(
            OID_SHROUDED_KEY_BAG,
            &epki,
            &attributes(input.name, local_key_id.as_deref()),
        );
        safes.push(data_content_info(&tlv(T_SEQ, &bag)));
    }

    let auth_safe = tlv(T_SEQ, &safes.concat());
    let mac_key = kdf(&pw, &salts.mac, 3, MAC_ITERATIONS, 20);
    let mut mac = Hmac::<Sha1>::new_from_slice(&mac_key)
        .map_err(|e| PkiError::Invalid(format!("HMAC key: {e}")))?;
    mac.update(&auth_safe);
    let mac = mac.finalize().into_bytes();
    let mac_data = tlv(
        T_SEQ,
        &[
            tlv(
                T_SEQ,
                &[
                    tlv(T_SEQ, &[tlv(T_OID, OID_SHA1), tlv(T_NULL, &[])].concat()),
                    tlv(T_OCTET, &mac),
                ]
                .concat(),
            ),
            tlv(T_OCTET, &salts.mac),
            int(MAC_ITERATIONS),
        ]
        .concat(),
    );
    Ok(tlv(
        T_SEQ,
        &[int(3), data_content_info(&auth_safe), mac_data].concat(),
    ))
}

/// The p12 part of `anc.make_cert`: `name=hostname`, `key` only if `key_in_pem`, `cert`, and the
/// CA certificate with friendlyName `"CA"`.
pub fn make_cert_p12(
    kc: &KeyCert,
    ca: &CertAuthority,
    name: &str,
    key_in_pem: bool,
    password: &str,
) -> Result<Vec<u8>, PkiError> {
    let key = if key_in_pem {
        Some(kc.key_pkcs8_der()?)
    } else {
        None
    };
    let cas = [P12Cert {
        der: ca.cert_der(),
        friendly_name: Some("CA"),
    }];
    serialize(
        &P12Input {
            name: Some(name),
            key_pkcs8: key.as_deref(),
            cert: &kc.cert_der,
            cas: &cas,
        },
        password,
    )
}

/// Writes a p12 file (overwrite). With a private key the file is created / forced to **0600**
/// (D-19; Python leaves it per umask); a certificate-only p12 gets the umask default.
pub fn write_p12(path: &Path, p12: &[u8], has_key: bool) -> Result<(), PkiError> {
    let io = |source| PkiError::Io {
        path: path.to_owned(),
        source,
    };
    let mut o = OpenOptions::new();
    o.write(true).create(true).truncate(true);
    if has_key {
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(io)?;
    if has_key {
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(io)?;
    }
    f.write_all(p12).map_err(io)?;
    Ok(())
}

// --------------------------------------------------------------------------------------------
// Reader

/// PBE parameters of an encrypted part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pbe {
    /// Algorithm OID (DER content bytes).
    pub oid: Vec<u8>,
    /// Salt.
    pub salt: Vec<u8>,
    /// Iterations.
    pub iterations: u32,
}

/// One SafeBag, decrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bag {
    /// Bag type OID (DER content bytes).
    pub bag_oid: Vec<u8>,
    /// Shrouded key bag encryption.
    pub pbe: Option<Pbe>,
    /// Certificate DER (cert bag) or PKCS#8 `PrivateKeyInfo` (key bags, decrypted).
    pub value: Vec<u8>,
    /// Attributes: (OID content bytes, encoded values of the SET).
    pub attributes: Vec<(Vec<u8>, Vec<Vec<u8>>)>,
    /// Whether the attribute SET was present at all.
    pub has_attributes: bool,
}

impl Bag {
    /// Certificate bag?
    pub fn is_cert(&self) -> bool {
        self.bag_oid == OID_CERT_BAG
    }

    /// Key bag (shrouded or plain)?
    pub fn is_key(&self) -> bool {
        self.bag_oid == OID_SHROUDED_KEY_BAG || self.bag_oid == OID_KEY_BAG
    }

    /// friendlyName (BMPString decoded; lossy for unpaired surrogates).
    pub fn friendly_name(&self) -> Option<String> {
        let v = self.attr(OID_FRIENDLY_NAME)?;
        let (tag, content, _) = read_tlv(v).ok()?;
        if tag != T_BMP || content.len() % 2 != 0 {
            return None;
        }
        let u: Vec<u16> = content
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&u))
    }

    /// localKeyId.
    pub fn local_key_id(&self) -> Option<Vec<u8>> {
        let v = self.attr(OID_LOCAL_KEY_ID)?;
        let (tag, content, _) = read_tlv(v).ok()?;
        (tag == T_OCTET).then(|| content.to_vec())
    }

    fn attr(&self, oid: &[u8]) -> Option<&[u8]> {
        self.attributes
            .iter()
            .find(|(o, _)| o == oid)
            .and_then(|(_, v)| v.first())
            .map(Vec::as_slice)
    }
}

/// One element of the AuthenticatedSafe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Safe {
    /// `None` — a plain `data` SafeContents; `Some` — `encryptedData`.
    pub pbe: Option<Pbe>,
    /// Bags in order.
    pub bags: Vec<Bag>,
}

/// A parsed, MAC-verified and decrypted PFX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pfx {
    /// MAC salt.
    pub mac_salt: Vec<u8>,
    /// MAC iterations.
    pub mac_iterations: u32,
    /// AuthenticatedSafe contents in order.
    pub safes: Vec<Safe>,
}

impl Pfx {
    /// All bags in file order.
    pub fn bags(&self) -> impl Iterator<Item = &Bag> {
        self.safes.iter().flat_map(|s| s.bags.iter())
    }

    /// The salts, when the layout is the one [`serialize`] writes (certs, then optional key).
    pub fn salts(&self) -> Option<Salts> {
        let arr = |v: &[u8]| <[u8; SALT_LEN]>::try_from(v).ok();
        let certs = arr(&self.safes.first()?.pbe.as_ref()?.salt)?;
        let key = match self.safes.get(1) {
            Some(s) => arr(&s.bags.first()?.pbe.as_ref()?.salt)?,
            None => [0; SALT_LEN],
        };
        Some(Salts {
            certs,
            key,
            mac: arr(&self.mac_salt)?,
        })
    }
}

/// Parses a p12, verifies the HMAC-SHA1 MAC and decrypts every part (3DES PBE only).
pub fn parse(data: &[u8], password: &str) -> Result<Pfx, PkiError> {
    let pw = bmp_password(password)?;
    let mut pfx = Rd::new(Rd::new(data).expect(T_SEQ)?);
    if pfx.integer()? != 3 {
        return Err(bad("PFX version is not 3"));
    }
    let auth_safe = data_content(pfx.expect(T_SEQ)?)?;
    let mut mac_data = Rd::new(pfx.expect(T_SEQ)?);
    let mut digest_info = Rd::new(mac_data.expect(T_SEQ)?);
    let mut alg = Rd::new(digest_info.expect(T_SEQ)?);
    if alg.expect(T_OID)? != OID_SHA1 {
        return Err(bad("MAC digest is not SHA-1"));
    }
    let mac = digest_info.expect(T_OCTET)?;
    let mac_salt = mac_data.expect(T_OCTET)?.to_vec();
    let mac_iterations = if mac_data.is_empty() {
        1
    } else {
        mac_data.integer()?
    };
    let mac_key = kdf(&pw, &mac_salt, 3, mac_iterations, 20);
    let mut h = Hmac::<Sha1>::new_from_slice(&mac_key)
        .map_err(|e| PkiError::Invalid(format!("HMAC key: {e}")))?;
    h.update(auth_safe);
    h.verify_slice(mac)
        .map_err(|_| bad("MAC verification failed (wrong password?)"))?;

    let mut safes = Vec::new();
    let mut rd = Rd::new(Rd::new(auth_safe).expect(T_SEQ)?);
    while !rd.is_empty() {
        let mut ci = Rd::new(rd.expect(T_SEQ)?);
        let ct = ci.expect(T_OID)?;
        let ci_rest = ci.rest();
        if ct == OID_DATA {
            let contents = data_content_inner(ci_rest)?;
            safes.push(Safe {
                pbe: None,
                bags: parse_bags(contents, &pw)?,
            });
        } else if ct == OID_ENCRYPTED_DATA {
            let mut ed = Rd::new(Rd::new(Rd::new(ci_rest).expect(T_CTX0)?).expect(T_SEQ)?);
            ed.integer()?;
            let mut eci = Rd::new(ed.expect(T_SEQ)?);
            if eci.expect(T_OID)? != OID_DATA {
                return Err(bad("EncryptedContentInfo type is not data"));
            }
            let pbe = read_pbe(eci.expect(T_SEQ)?)?;
            let ct = eci.expect(T_CTX0_PRIM)?;
            let plain = pbe_decrypt(&pw, &pbe, ct)?;
            safes.push(Safe {
                pbe: Some(pbe),
                bags: parse_bags(&plain, &pw)?,
            });
        } else {
            return Err(bad("unsupported AuthenticatedSafe content type"));
        }
    }
    Ok(Pfx {
        mac_salt,
        mac_iterations,
        safes,
    })
}

fn parse_bags(safe_contents: &[u8], pw: &[u8]) -> Result<Vec<Bag>, PkiError> {
    let mut out = Vec::new();
    let mut rd = Rd::new(Rd::new(safe_contents).expect(T_SEQ)?);
    while !rd.is_empty() {
        let mut b = Rd::new(rd.expect(T_SEQ)?);
        let bag_oid = b.expect(T_OID)?.to_vec();
        let mut val = Rd::new(b.expect(T_CTX0)?);
        let (pbe, value) = if bag_oid == OID_SHROUDED_KEY_BAG {
            let mut epki = Rd::new(val.expect(T_SEQ)?);
            let pbe = read_pbe(epki.expect(T_SEQ)?)?;
            let plain = pbe_decrypt(pw, &pbe, epki.expect(T_OCTET)?)?;
            (Some(pbe), plain)
        } else if bag_oid == OID_CERT_BAG {
            let mut cb = Rd::new(val.expect(T_SEQ)?);
            if cb.expect(T_OID)? != OID_X509_CERT {
                return Err(bad("certBag is not an x509Certificate"));
            }
            let der = Rd::new(cb.expect(T_CTX0)?).expect(T_OCTET)?.to_vec();
            (None, der)
        } else if bag_oid == OID_KEY_BAG {
            (None, val.rest().to_vec())
        } else {
            return Err(bad("unsupported SafeBag type"));
        };
        let mut attributes = Vec::new();
        let has_attributes = !b.is_empty();
        if has_attributes {
            let mut set = Rd::new(b.expect(T_SET)?);
            while !set.is_empty() {
                let mut a = Rd::new(set.expect(T_SEQ)?);
                let oid = a.expect(T_OID)?.to_vec();
                let mut vals = Rd::new(a.expect(T_SET)?);
                let mut vs = Vec::new();
                while !vals.is_empty() {
                    vs.push(vals.raw()?.to_vec());
                }
                attributes.push((oid, vs));
            }
        }
        out.push(Bag {
            bag_oid,
            pbe,
            value,
            attributes,
            has_attributes,
        });
    }
    Ok(out)
}

fn read_pbe(alg_id: &[u8]) -> Result<Pbe, PkiError> {
    let mut a = Rd::new(alg_id);
    let oid = a.expect(T_OID)?.to_vec();
    if oid != OID_PBE_SHA1_3DES {
        return Err(bad(
            "unsupported PBE algorithm (only pbeWithSHA1And3-KeyTripleDES-CBC)",
        ));
    }
    let mut p = Rd::new(a.expect(T_SEQ)?);
    let salt = p.expect(T_OCTET)?.to_vec();
    let iterations = p.integer()?;
    Ok(Pbe {
        oid,
        salt,
        iterations,
    })
}

fn data_content(content_info: &[u8]) -> Result<&[u8], PkiError> {
    let mut ci = Rd::new(content_info);
    if ci.expect(T_OID)? != OID_DATA {
        return Err(bad("ContentInfo type is not data"));
    }
    data_content_inner(ci.rest())
}

fn data_content_inner(rest: &[u8]) -> Result<&[u8], PkiError> {
    Rd::new(Rd::new(rest).expect(T_CTX0)?).expect(T_OCTET)
}

// --------------------------------------------------------------------------------------------
// Crypto (RFC 7292 Appendix B KDF, PBE with SHA-1 and 3-key 3DES-CBC)

fn bmp_password(password: &str) -> Result<Vec<u8>, PkiError> {
    if password.is_empty() {
        return Err(PkiError::Invalid(
            "Password must be 1 or more bytes.".into(),
        ));
    }
    let mut out: Vec<u8> = password.encode_utf16().flat_map(u16::to_be_bytes).collect();
    out.extend_from_slice(&[0, 0]);
    Ok(out)
}

/// RFC 7292 B.2 with SHA-1 (u = 20, v = 64). `id`: 1 key, 2 IV, 3 MAC key.
fn kdf(pw: &[u8], salt: &[u8], id: u8, iterations: u32, n: usize) -> Vec<u8> {
    const V: usize = 64;
    let fill = |x: &[u8]| -> Vec<u8> {
        let len = V * x.len().div_ceil(V);
        (0..len).map(|i| x[i % x.len()]).collect()
    };
    let mut ibuf = fill(salt);
    ibuf.extend(fill(pw));
    let mut out = Vec::with_capacity(n + 20);
    loop {
        let mut h = Sha1::new();
        h.update([id; V]);
        h.update(&ibuf);
        let mut a = h.finalize();
        for _ in 1..iterations.max(1) {
            a = Sha1::digest(a);
        }
        out.extend_from_slice(&a);
        if out.len() >= n {
            out.truncate(n);
            return out;
        }
        let b: Vec<u8> = (0..V).map(|k| a[k % a.len()]).collect();
        for block in ibuf.chunks_mut(V) {
            let mut carry = 1u16;
            for k in (0..V).rev() {
                let s = u16::from(block[k]) + u16::from(b[k]) + carry;
                block[k] = s as u8;
                carry = s >> 8;
            }
        }
    }
}

fn pbe_encrypt(pw: &[u8], salt: &[u8], iterations: u32, plain: &[u8]) -> Result<Vec<u8>, PkiError> {
    let key = kdf(pw, salt, 1, iterations, 24);
    let iv = kdf(pw, salt, 2, iterations, 8);
    let enc = cbc::Encryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
        .map_err(|_| bad("3DES key/IV length"))?;
    let mut buf = plain.to_vec();
    buf.resize(plain.len() + 8, 0);
    let n = enc
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plain.len())
        .map_err(|_| bad("3DES padding"))?
        .len();
    buf.truncate(n);
    Ok(buf)
}

fn pbe_decrypt(pw: &[u8], pbe: &Pbe, ct: &[u8]) -> Result<Vec<u8>, PkiError> {
    let key = kdf(pw, &pbe.salt, 1, pbe.iterations, 24);
    let iv = kdf(pw, &pbe.salt, 2, pbe.iterations, 8);
    let dec = cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
        .map_err(|_| bad("3DES key/IV length"))?;
    let mut buf = ct.to_vec();
    let n = dec
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| bad("decryption failed (wrong password or corrupt data)"))?
        .len();
    buf.truncate(n);
    Ok(buf)
}

// --------------------------------------------------------------------------------------------
// DER writing

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes = n.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

fn int(v: u32) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count().min(3);
    let mut c = Vec::new();
    if bytes[skip] & 0x80 != 0 {
        c.push(0);
    }
    c.extend_from_slice(&bytes[skip..]);
    tlv(T_INT, &c)
}

fn pbe_alg(salt: &[u8], iterations: u32) -> Vec<u8> {
    tlv(
        T_SEQ,
        &[
            tlv(T_OID, OID_PBE_SHA1_3DES),
            tlv(T_SEQ, &[tlv(T_OCTET, salt), int(iterations)].concat()),
        ]
        .concat(),
    )
}

fn data_content_info(content: &[u8]) -> Vec<u8> {
    tlv(
        T_SEQ,
        &[tlv(T_OID, OID_DATA), tlv(T_CTX0, &tlv(T_OCTET, content))].concat(),
    )
}

fn cert_bag(der: &[u8], name: Option<&str>, local_key_id: Option<&[u8]>) -> Vec<u8> {
    let cb = tlv(
        T_SEQ,
        &[tlv(T_OID, OID_X509_CERT), tlv(T_CTX0, &tlv(T_OCTET, der))].concat(),
    );
    safe_bag(OID_CERT_BAG, &cb, &attributes(name, local_key_id))
}

fn safe_bag(oid: &[u8], value: &[u8], attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut c = [tlv(T_OID, oid), tlv(T_CTX0, value)].concat();
    if !attrs.is_empty() {
        let mut sorted = attrs.to_vec();
        sorted.sort(); // DER SET OF: ascending encodings
        c.extend(tlv(T_SET, &sorted.concat()));
    }
    tlv(T_SEQ, &c)
}

fn attributes(name: Option<&str>, local_key_id: Option<&[u8]>) -> Vec<Vec<u8>> {
    let attr =
        |oid: &[u8], value: Vec<u8>| tlv(T_SEQ, &[tlv(T_OID, oid), tlv(T_SET, &value)].concat());
    let mut out = Vec::new();
    if let Some(n) = name {
        let bmp: Vec<u8> = n.encode_utf16().flat_map(u16::to_be_bytes).collect();
        out.push(attr(OID_FRIENDLY_NAME, tlv(T_BMP, &bmp)));
    }
    if let Some(k) = local_key_id {
        out.push(attr(OID_LOCAL_KEY_ID, tlv(T_OCTET, k)));
    }
    out
}

// --------------------------------------------------------------------------------------------
// DER reading (definite lengths, single-byte tags — what DER p12 writers produce)

fn bad(msg: &str) -> PkiError {
    PkiError::Invalid(format!("PKCS#12: {msg}"))
}

/// One TLV: (tag, content, whole encoding).
fn read_tlv(buf: &[u8]) -> Result<(u8, &[u8], &[u8]), PkiError> {
    let trunc = || bad("truncated DER");
    let tag = *buf.first().ok_or_else(trunc)?;
    if tag & 0x1f == 0x1f {
        return Err(bad("multi-byte DER tag"));
    }
    let l0 = *buf.get(1).ok_or_else(trunc)?;
    let (len, hdr) = if l0 < 0x80 {
        (usize::from(l0), 2)
    } else {
        let k = usize::from(l0 & 0x7f);
        if k == 0 || k > 4 {
            return Err(bad("unsupported DER length (indefinite or too long)"));
        }
        let bytes = buf.get(2..2 + k).ok_or_else(trunc)?;
        (
            bytes.iter().fold(0usize, |a, b| (a << 8) | usize::from(*b)),
            2 + k,
        )
    };
    let end = hdr.checked_add(len).ok_or_else(trunc)?;
    let content = buf.get(hdr..end).ok_or_else(trunc)?;
    Ok((tag, content, &buf[..end]))
}

struct Rd<'a> {
    buf: &'a [u8],
}

impl<'a> Rd<'a> {
    fn new(buf: &'a [u8]) -> Rd<'a> {
        Rd { buf }
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn rest(&self) -> &'a [u8] {
        self.buf
    }

    fn raw(&mut self) -> Result<&'a [u8], PkiError> {
        let (_, _, whole) = read_tlv(self.buf)?;
        self.buf = &self.buf[whole.len()..];
        Ok(whole)
    }

    fn expect(&mut self, tag: u8) -> Result<&'a [u8], PkiError> {
        let (t, content, whole) = read_tlv(self.buf)?;
        if t != tag {
            return Err(PkiError::Invalid(format!(
                "PKCS#12: expected DER tag {tag:#04x}, got {t:#04x}"
            )));
        }
        self.buf = &self.buf[whole.len()..];
        Ok(content)
    }

    fn integer(&mut self) -> Result<u32, PkiError> {
        let c = self.expect(T_INT)?;
        if c.is_empty() || c[0] & 0x80 != 0 || c.len() > 5 || (c.len() == 5 && c[0] != 0) {
            return Err(bad("INTEGER out of range"));
        }
        Ok(c.iter().fold(0u32, |a, b| (a << 8) | u32::from(*b)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        crate::pem::hex_decode(s).expect("hex")
    }

    #[test]
    fn kdf_known_vectors() {
        // Vectors used by OpenSSL / BouncyCastle (password "smeg", salt 0A58CF64530D823F).
        let pw = bmp_password("smeg").expect("pw");
        let salt = hex("0A58CF64530D823F");
        assert_eq!(
            kdf(&pw, &salt, 1, 1, 24),
            hex("8AAAE6297B6CB04642AB5B077851284EB7128F1A2A7FBCA3")
        );
        assert_eq!(kdf(&pw, &salt, 2, 1, 8), hex("79993DFE048D3B76"));
        // "queeg", salt 05DEC959ACFF72F7, 1000 iterations.
        let pw = bmp_password("queeg").expect("pw");
        let salt = hex("05DEC959ACFF72F7");
        assert_eq!(
            kdf(&pw, &salt, 1, 1000, 24),
            hex("ED2034E36328830FF09DF1E1A07DD357185DAC0D4F9EB3D4")
        );
        assert_eq!(kdf(&pw, &salt, 2, 1000, 8), hex("11DEDAD7758D4860"));
    }

    #[test]
    fn password_encoding() {
        assert_eq!(bmp_password("a").expect("pw"), vec![0, 0x61, 0, 0]);
        // Non-BMP → surrogate pair, as cryptography does.
        assert_eq!(
            bmp_password("\u{1F600}").expect("pw"),
            vec![0xd8, 0x3d, 0xde, 0x00, 0, 0]
        );
        let e = bmp_password("").expect_err("empty");
        assert!(e.to_string().contains("Password must be 1 or more bytes."));
    }

    #[test]
    fn der_helpers() {
        assert_eq!(int(0), vec![2, 1, 0]);
        assert_eq!(int(1), vec![2, 1, 1]);
        assert_eq!(int(128), vec![2, 2, 0, 128]);
        assert_eq!(int(2048), vec![2, 2, 8, 0]);
        assert_eq!(tlv(4, &[0; 200])[..3], [4, 0x81, 200]);
        assert_eq!(tlv(4, &[0; 300])[..4], [4, 0x82, 1, 44]);
        let mut r = Rd::new(&[2, 2, 8, 0]);
        assert_eq!(r.integer().expect("int"), 2048);
        assert!(read_tlv(&[0x30, 0x80, 0, 0]).is_err());
        assert!(read_tlv(&[0x30, 5, 0]).is_err());
    }

    #[test]
    fn roundtrip_and_salts() {
        let cert = b"\x30\x03\x02\x01\x01".to_vec(); // opaque to the encoder
        let ca = b"\x30\x03\x02\x01\x02".to_vec();
        let key = b"\x30\x03\x02\x01\x00".to_vec();
        let cas = [P12Cert {
            der: &ca,
            friendly_name: Some("CA"),
        }];
        let salts = Salts {
            certs: [1; 8],
            key: [2; 8],
            mac: [3; 8],
        };
        let input = P12Input {
            name: Some("JENNY"),
            key_pkcs8: Some(&key),
            cert: &cert,
            cas: &cas,
        };
        let a = serialize_with_salts(&input, "atakatak", &salts).expect("p12");
        assert_eq!(
            a,
            serialize_with_salts(&input, "atakatak", &salts).expect("p12")
        );
        let p = parse(&a, "atakatak").expect("parse");
        assert_eq!(p.salts(), Some(salts));
        assert_eq!(p.mac_iterations, MAC_ITERATIONS);
        let bags: Vec<&Bag> = p.bags().collect();
        assert_eq!(bags.len(), 3);
        assert!(bags[0].is_cert() && bags[1].is_cert() && bags[2].is_key());
        assert_eq!(bags[0].value, cert);
        assert_eq!(bags[1].value, ca);
        assert_eq!(bags[2].value, key);
        assert_eq!(bags[0].friendly_name().as_deref(), Some("JENNY"));
        assert_eq!(bags[1].friendly_name().as_deref(), Some("CA"));
        assert_eq!(bags[2].friendly_name().as_deref(), Some("JENNY"));
        let lkid = Sha1::digest(&cert).to_vec();
        assert_eq!(bags[0].local_key_id(), Some(lkid.clone()));
        assert_eq!(bags[1].local_key_id(), None);
        assert_eq!(bags[2].local_key_id(), Some(lkid));
        assert!(parse(&a, "wrong").is_err());

        // Certificate-only: one safe, no localKeyId; CA without a name has no attributes.
        let cas = [P12Cert {
            der: &ca,
            friendly_name: None,
        }];
        let b = serialize(
            &P12Input {
                name: None,
                key_pkcs8: None,
                cert: &cert,
                cas: &cas,
            },
            "x",
        )
        .expect("p12");
        let p = parse(&b, "x").expect("parse");
        assert_eq!(p.safes.len(), 1);
        assert!(p.bags().all(|b| !b.has_attributes));
    }

    #[test]
    fn write_p12_modes() {
        let d = tempfile::tempdir().expect("tmp");
        let k = d.path().join("k.p12");
        std::fs::write(&k, b"old").expect("w");
        std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        write_p12(&k, b"new", true).expect("write");
        let m = std::fs::metadata(&k).expect("meta");
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&k).expect("r"), b"new");
    }
}
