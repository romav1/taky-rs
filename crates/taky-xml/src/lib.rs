//! Safe XML for taky-rs (ADR-002). Owner: dev01.
//!
//! * [`Element`]/[`Node`] — mini-DOM modeled on lxml (`text`/`tail`, attributes in document order,
//!   tags in Clark notation `{ns}local`);
//! * [`parse_element`] — parses a single document **without DTD and entities** with [`Limits`];
//! * [`TreeBuilder`] — incremental CoT stream decoder: `<?xml` stripping ([`XmlDeclStrip`]),
//!   emission of `<event>` elements at any depth, limits (for `taky-cot::CotDecoder`);
//! * [`serialize`] — byte-compatible with `lxml.etree.tostring(e, **opts)` (S-304).

mod chars;
pub mod decl_strip;
pub mod element;
pub mod error;
pub mod limits;
pub mod parse;
pub mod serialize;

pub use decl_strip::XmlDeclStrip;
pub use element::{Element, Node};
pub use error::XmlError;
pub use limits::Limits;
pub use parse::{TreeBuilder, parse_element};
pub use serialize::{SerOpts, serialize};
