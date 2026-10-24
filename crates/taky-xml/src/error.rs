//! XML errors.

/// XML parse error. For a CoT stream any of them ⇒ disconnect `"XML Syntax Error"`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XmlError {
    /// Syntax error (position in bytes from the start of the input).
    #[error("XML syntax error at byte {pos}: {msg}")]
    Syntax {
        /// Offset in bytes.
        pos: u64,
        /// Description.
        msg: String,
    },
    /// `<!DOCTYPE …>` encountered (DTDs are forbidden, ADR-002, D-1).
    #[error("DTD is not allowed")]
    DtdForbidden,
    /// Unknown/external entity.
    #[error("undefined entity: {0}")]
    UnknownEntity(String),
    /// One of the [`crate::Limits`] was exceeded.
    #[error("limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// Invalid UTF-8.
    #[error("invalid UTF-8")]
    InvalidUtf8,
    /// Unexpected end of document.
    #[error("unexpected end of document")]
    UnexpectedEof,
}
