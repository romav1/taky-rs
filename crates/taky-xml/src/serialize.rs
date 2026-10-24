//! Serialization byte-compatible with `lxml.etree.tostring`.

use crate::Element;

/// `etree.tostring` parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerOpts {
    /// `pretty_print=True`.
    pub pretty_print: bool,
    /// `xml_declaration=True` (lxml's `<?xml version='1.0' encoding='ASCII'?>` form).
    pub xml_declaration: bool,
    /// `standalone=` (only together with `xml_declaration`).
    pub standalone: Option<bool>,
    /// `with_tail=` (default `true`, as in lxml).
    pub with_tail: bool,
}

impl Default for SerOpts {
    /// Like `etree.tostring(e)` with no arguments: ASCII + `&#NNN;`, no declaration, with tail.
    fn default() -> Self {
        SerOpts {
            pretty_print: false,
            xml_declaration: false,
            standalone: None,
            with_tail: true,
        }
    }
}

/// `etree.tostring(e, **o)` — byte-exact (ASCII, `&#NNN;`, `<x/>`, attribute escaping as in libxml2).
///
/// **T-10 scaffold:** implementation — T-21.
pub fn serialize(e: &Element, o: &SerOpts) -> Vec<u8> {
    let _ = (e, o);
    todo!("T-21")
}
