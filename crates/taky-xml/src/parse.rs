//! XML parsing without DTD/entities.

use crate::{Element, Limits, XmlError};

/// Parse a single document (root element; the `<?xml …?>` prolog is allowed, DTD is not).
///
/// **T-10 scaffold:** implementation — T-21.
pub fn parse_element(xml: &[u8], lim: &Limits) -> Result<Element, XmlError> {
    let _ = (xml, lim);
    todo!("T-21: quick-xml based parser")
}

/// Incremental tree builder: accepts stream fragments and yields completed
/// depth-1 elements (children of the root `<event>` stream — see `taky-cot::CotDecoder`).
#[derive(Debug)]
pub struct TreeBuilder {
    limits: Limits,
}

impl TreeBuilder {
    /// New builder with limits `limits`.
    pub fn new(limits: Limits) -> TreeBuilder {
        TreeBuilder { limits }
    }

    /// Builder limits.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Feed the next input fragment.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), XmlError> {
        let _ = chunk;
        todo!("T-21")
    }

    /// Take the next completed top-level element, if any.
    pub fn next_element(&mut self) -> Result<Option<Element>, XmlError> {
        todo!("T-21")
    }
}
