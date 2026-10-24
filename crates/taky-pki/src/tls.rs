//! rustls server configurations (ARCHITECTURE §11, ADR-003).

use std::sync::Arc;

use taky_config::SslSect;

use crate::PkiError;

/// Which listener the configuration is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// CoT server: client cert mandatory iff `ssl.client_cert_required`, otherwise optional.
    Cot,
    /// DPS: client cert always optional (gunicorn `CERT_OPTIONAL`).
    Dps,
}

/// Build the server config: CAs from `ssl.ca` (or system roots), chain `ssl.cert`, key `ssl.key`
/// (PKCS#1/#8/SEC1, encrypted with `ssl.key_pw`), TLS 1.2 + 1.3, `ring` provider.
pub fn server_config(ssl: &SslSect, mode: TlsMode) -> Result<Arc<rustls::ServerConfig>, PkiError> {
    let _ = (ssl, mode);
    todo!("dev02: S-311")
}
