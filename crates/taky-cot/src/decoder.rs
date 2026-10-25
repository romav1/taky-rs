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

/// Incremental decoder over [`TreeBuilder`] (spec §5.1, ADR-002).
///
/// Yields every `<event>` element (local name `event`) completed in the stream, **at any depth**
/// (`<wrap><event/></wrap>` too; a nested event first, then its outer event with an `<event/>`
/// placeholder — V016/V020). Top-level text and non-event elements are checked for
/// well-formedness and dropped; nothing is retained after an event is taken (no lxml leak).
/// Validating the element is the caller's job (`Event::from_element` returns
/// [`crate::UnmarshalError`]). Each `decode` call feeds all buffered bytes as one chunk.
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
        if !src.is_empty() {
            let chunk = src.split();
            self.builder.feed(&chunk)?;
        }
        Ok(self.builder.next_element()?)
    }
}
