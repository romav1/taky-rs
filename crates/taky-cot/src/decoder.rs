//! Streaming CoT decoder: bytes from a socket → top-level `<event>` elements (D-2).
//!
//! Used by the read half of a connection task (dev02) as
//! `FramedRead::new(read_half, CotDecoder::new())`.

use bytes::BytesMut;
use taky_xml::{Element, Limits, TreeBuilder, XmlError};

use crate::limits::STREAM_LIMITS;

/// Fatal stream error: the connection is closed with `"XML Syntax Error"`.
#[derive(Debug, thiserror::Error)]
pub enum CotStreamError {
    /// Malformed XML, DTD/entity, or a [`Limits`] violation.
    #[error("XML Syntax Error: {0}")]
    Xml(#[from] XmlError),
    /// Socket I/O error (required by `tokio_util::codec::Decoder`).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Incremental decoder over [`TreeBuilder`].
///
/// Yields every complete top-level element (cleaned `<event/>` and non-event elements, as the
/// original accumulates them, see the an01 spec); deciding what to do with non-events is the
/// caller's job (`Event::from_element` returns [`crate::UnmarshalError`]).
#[derive(Debug)]
pub struct CotDecoder {
    builder: TreeBuilder,
}

impl CotDecoder {
    /// Decoder with [`STREAM_LIMITS`].
    pub fn new() -> CotDecoder {
        CotDecoder::with_limits(STREAM_LIMITS)
    }

    /// Decoder with custom limits (tests).
    pub fn with_limits(limits: Limits) -> CotDecoder {
        CotDecoder {
            builder: TreeBuilder::new(limits),
        }
    }
}

impl Default for CotDecoder {
    fn default() -> Self {
        CotDecoder::new()
    }
}

impl tokio_util::codec::Decoder for CotDecoder {
    type Item = Element;
    type Error = CotStreamError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Element>, CotStreamError> {
        let _ = (&mut self.builder, src);
        todo!("S-305")
    }
}
