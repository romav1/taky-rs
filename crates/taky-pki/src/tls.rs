//! rustls server configurations (ARCHITECTURE §11, ADR-003).

use std::path::Path;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::crypto::CryptoProvider;
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use taky_config::SslSect;

use crate::PkiError;
use crate::pem::{load_certs, load_private_key};

/// Which listener the configuration is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// CoT server: client cert mandatory iff `ssl.client_cert_required`, otherwise optional.
    Cot,
    /// DPS: client cert always optional (gunicorn `CERT_OPTIONAL`).
    Dps,
}

/// The `ring` crypto provider used by every taky-rs TLS config.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Build the server config: CAs from `ssl.ca` (or system roots), chain `ssl.cert`, key `ssl.key`
/// (PKCS#1/#8/SEC1, encrypted with `ssl.key_pw`), TLS 1.2 + 1.3, `ring` provider.
///
/// `ssl.key` unset ⇒ the key is read from the `ssl.cert` file (Python `load_cert_chain(keyfile=None)`);
/// an empty `ssl.key` is a path like any other and fails to load (`keyfile=""`, S-A06 Q1).
/// With an empty trust store (no `ssl.ca`, no usable system roots) a mandatory-cert config is an
/// error; an optional-cert config then does not request client certificates at all (Python would
/// request one but fail any presented certificate — the no-cert path is the same).
pub fn server_config(ssl: &SslSect, mode: TlsMode) -> Result<Arc<rustls::ServerConfig>, PkiError> {
    let cert_path = ssl
        .cert
        .as_deref()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| PkiError::Invalid("ssl.cert is not set".into()))?;
    let key_path = ssl.key.as_deref().unwrap_or(cert_path);
    let chain = load_certs(cert_path)?;
    let key = load_private_key(key_path, ssl.key_pw.as_deref())?;

    let required = mode == TlsMode::Cot && ssl.client_cert_required;
    let roots = load_roots(ssl.ca.as_deref())?;
    let provider = provider();
    let verifier: Arc<dyn ClientCertVerifier> = if roots.is_empty() {
        if required {
            return Err(PkiError::Invalid(
                "client_cert_required: no trusted CA certificates (ssl.ca / system)".into(),
            ));
        }
        WebPkiClientVerifier::no_client_auth()
    } else {
        let b = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone());
        let b = if required {
            b
        } else {
            b.allow_unauthenticated()
        };
        b.build()
            .map_err(|e| PkiError::Invalid(format!("client verifier: {e}")))?
    };

    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?;
    Ok(Arc::new(cfg))
}

/// Trust store: every certificate in `ca` (PEM) or, if unset/empty, the system roots
/// (`load_default_certs()`; unparsable system certificates are skipped).
pub fn load_roots(ca: Option<&Path>) -> Result<RootCertStore, PkiError> {
    let mut roots = RootCertStore::empty();
    match ca.filter(|p| !p.as_os_str().is_empty()) {
        Some(path) => {
            for c in load_certs(path)? {
                roots
                    .add(c)
                    .map_err(|e| PkiError::Invalid(format!("{}: CA: {e}", path.display())))?;
            }
        }
        None => {
            let native = rustls_native_certs::load_native_certs();
            roots.add_parsable_certificates(native.certs);
        }
    }
    Ok(roots)
}
