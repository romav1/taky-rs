//! PKI errors.

/// Errors of cert-db, key/certificate loading and TLS configuration.
#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    /// File I/O.
    #[error("{path}: {source}")]
    Io {
        /// File involved.
        path: std::path::PathBuf,
        /// Cause.
        #[source]
        source: std::io::Error,
    },
    /// Malformed PEM/DER, wrong password, unsupported key type.
    #[error("invalid key or certificate: {0}")]
    Invalid(String),
    /// `revoke`: serial not in the database (`IndexError("Unable to find certificate")`).
    #[error("Unable to find certificate")]
    NotFound,
    /// rustls configuration error.
    #[error("TLS configuration: {0}")]
    Tls(#[from] rustls::Error),
}
