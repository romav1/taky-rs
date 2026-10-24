//! Shared helpers for taky-xml integration tests.
#![allow(dead_code, clippy::unwrap_used)]

use serde_json::{Value, json};
use taky_xml::{Element, Node, TreeBuilder, XmlError};

/// Minimal standard base64 decoder (fixtures and vectors carry binary chunks as base64).
pub fn b64(s: &str) -> Vec<u8> {
    fn val(c: u8) -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("bad base64 byte {c}"),
        }
    }
    let bytes: Vec<u8> = s
        .bytes()
        .filter(|&c| c != b'=' && !c.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for ch in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in ch.iter().enumerate() {
            n |= val(c) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if ch.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if ch.len() > 3 {
            out.push(n as u8);
        }
    }
    out
}

fn node(n: &Node) -> Value {
    match n {
        Node::Element(e) => dump(e),
        Node::Comment { text, tail } => json!({"comment": text, "tail": tail}),
        Node::Pi { target, data, tail } => json!({"pi": target, "data": data, "tail": tail}),
    }
}

/// Same structure as `dump()` in `fixtures/gen_lxml_stream.py`.
pub fn dump(e: &Element) -> Value {
    json!({
        "tag": e.tag,
        "attrs": e.attrs.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        "text": e.text,
        "tail": e.tail,
        "children": e.children.iter().map(node).collect::<Vec<_>>(),
    })
}

/// Outcome of feeding `chunks` one by one: events after each successful chunk and the index of
/// the failing chunk.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub events: Vec<Vec<Value>>,
    pub error_at: Option<usize>,
    pub error: Option<XmlError>,
}

pub fn run(chunks: &[Vec<u8>]) -> Outcome {
    let mut tb = TreeBuilder::new(taky_xml::Limits::DEFAULT);
    let mut events = Vec::new();
    for (i, c) in chunks.iter().enumerate() {
        if let Err(e) = tb.feed(c) {
            return Outcome {
                events,
                error_at: Some(i),
                error: Some(e),
            };
        }
        let mut evs = Vec::new();
        while let Some(e) = tb.next_element().unwrap() {
            evs.push(dump(&e));
        }
        events.push(evs);
    }
    Outcome {
        events,
        error_at: None,
        error: None,
    }
}

/// All events emitted, flattened, plus whether the stream failed.
pub fn run_flat(chunks: &[&[u8]]) -> (Vec<Element>, Option<XmlError>) {
    let mut tb = TreeBuilder::new(taky_xml::Limits::DEFAULT);
    let mut out = Vec::new();
    for c in chunks {
        if let Err(e) = tb.feed(c) {
            return (out, Some(e));
        }
        while let Some(e) = tb.next_element().unwrap() {
            out.push(e);
        }
    }
    (out, None)
}
