//! Shared helpers of the taky-rs fuzz targets (qa01, S-407, test-strategy §1.6).
//!
//! * [`split_chunks`] — the input framing of the stream target `cot_decoder_stream`; mirrored
//!   byte-for-byte in `tools/difftest/harness/fuzzdiff.py` (`split_chunks`), so a libFuzzer corpus
//!   file means the same chunk sequence for Rust and for the lxml oracle.
//! * [`run_stream`] — feeds the chunks to a fresh [`CotDecoder`] exactly like
//!   `taky-server` `conn::read_half` (one `decode` loop per received chunk) and records what the
//!   server would see: every emitted element (`tostring(elm, with_tail=False)`), the outcome of
//!   `Event::from_element` ⇒ `to_frame`, and whether the stream failed.
//! * [`check_stream_invariants`] — the in-target invariants of §1.6.

use bytes::BytesMut;
use taky_cot::{CotDecoder, Event};
use taky_xml::{Element, Node, SerOpts, serialize};
use tokio_util::codec::Decoder;

/// Split a fuzz input into socket chunks. `mode = data[0] & 3`:
///
/// * `0` — `data[1..]` is one chunk;
/// * `1` — `n = data[1] % 8 + 1` size bytes `data[2..2+n]` follow; the body (rest) is cut into
///   chunks of `size[i % n] + 1` bytes (1..=256) cycling through the sizes;
/// * `2` — records: `[len_hi, len_lo, bytes…]`; a record shorter than its length takes what is
///   left; a trailing single byte is a chunk of its own (used for seeds with exact boundaries);
/// * `3` — fixed chunk size `data[1] % 16 + 1`, body `data[2..]` (byte-by-byte splits).
///
/// Empty chunks are skipped (the server never sees a zero-length read as data).
pub fn split_chunks(data: &[u8]) -> Vec<&[u8]> {
    let mut out: Vec<&[u8]> = Vec::new();
    let Some((&h, rest)) = data.split_first() else {
        return out;
    };
    match h & 3 {
        0 => out.push(rest),
        1 => {
            let n = rest.first().map_or(1, |b| usize::from(*b % 8) + 1);
            if rest.len() < 1 + n {
                out.push(rest);
            } else {
                let sizes = &rest[1..1 + n];
                let mut body = &rest[1 + n..];
                let mut i = 0;
                while !body.is_empty() {
                    let sz = (usize::from(sizes[i % n]) + 1).min(body.len());
                    out.push(&body[..sz]);
                    body = &body[sz..];
                    i += 1;
                }
            }
        }
        2 => {
            let mut body = rest;
            while !body.is_empty() {
                if body.len() < 2 {
                    out.push(body);
                    break;
                }
                let len = usize::from(u16::from_be_bytes([body[0], body[1]]));
                let take = len.min(body.len() - 2);
                out.push(&body[2..2 + take]);
                body = &body[2 + take..];
            }
        }
        _ => {
            let sz = rest.first().map_or(1, |b| usize::from(*b % 16) + 1);
            let body = rest.get(1..).unwrap_or(&[]);
            out.extend(body.chunks(sz));
        }
    }
    out.retain(|c| !c.is_empty());
    out
}

/// Encode chunks in mode 2 (exact boundaries) — used to build seeds from vector `send` steps.
/// Chunks longer than `u16::MAX` are split.
pub fn encode_records(chunks: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![2u8];
    for c in chunks {
        for part in c.chunks(usize::from(u16::MAX)) {
            let len = u16::try_from(part.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(part);
        }
    }
    out
}

/// What `Event::from_element` ⇒ `Event::to_frame` gave for one emitted element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventOutcome {
    /// The wire bytes (`etree.tostring(evt.as_element)`).
    Frame(Vec<u8>),
    /// `UnmarshalError` (message).
    Unmarshal(String),
    /// `as_element` failed (D-8: missing version/uid/type/how).
    Serialize(String),
}

/// One emitted element.
#[derive(Debug, Clone)]
pub struct Emitted {
    /// `etree.tostring(elm, with_tail=False)`.
    pub elm: Vec<u8>,
    /// Model outcome.
    pub evt: EventOutcome,
    /// Every element/attribute name in the element is ASCII. lxml (and taky-xml, byte-exact)
    /// serializes a non-ASCII *name* as `&#NNN;` with the default ASCII encoding, which is not
    /// well-formed — parity with the original, so the "frame re-parses" invariant skips such events.
    pub ascii_names: bool,
}

/// The observation of one stream.
#[derive(Debug, Clone, Default)]
pub struct StreamDump {
    /// Emitted elements in order.
    pub events: Vec<Emitted>,
    /// The stream ended with a fatal "XML Syntax Error".
    pub error: bool,
    /// Index of the chunk whose feed failed.
    pub error_chunk: Option<usize>,
    /// Display text of the error.
    pub error_text: Option<String>,
}

fn element_bytes(e: &Element) -> Vec<u8> {
    serialize(
        e,
        &SerOpts {
            with_tail: false,
            ..SerOpts::default()
        },
    )
}

fn ascii_names(e: &Element) -> bool {
    e.tag.is_ascii()
        && e.attrs.iter().all(|(k, _)| k.is_ascii())
        && e.children.iter().all(|n| match n {
            Node::Element(c) => ascii_names(c),
            Node::Pi { target, .. } => target.is_ascii(),
            Node::Comment { .. } => true,
        })
}

/// Feed `chunks` like `conn::read_half` and record the observation.
pub fn run_stream(chunks: &[&[u8]]) -> StreamDump {
    let mut dec = CotDecoder::new();
    let mut buf = BytesMut::new();
    let mut dump = StreamDump::default();
    for (i, c) in chunks.iter().enumerate() {
        buf.extend_from_slice(c);
        loop {
            match dec.decode(&mut buf) {
                Ok(Some(elm)) => {
                    let evt = match Event::from_element(&elm) {
                        Ok(evt) => match evt.to_frame() {
                            Ok(f) => EventOutcome::Frame(f.to_vec()),
                            Err(e) => EventOutcome::Serialize(e.to_string()),
                        },
                        Err(e) => EventOutcome::Unmarshal(e.0),
                    };
                    dump.events.push(Emitted {
                        elm: element_bytes(&elm),
                        evt,
                        ascii_names: ascii_names(&elm),
                    });
                }
                Ok(None) => break,
                Err(e) => {
                    dump.error = true;
                    dump.error_chunk = Some(i);
                    dump.error_text = Some(e.to_string());
                    break;
                }
            }
        }
        if dump.error {
            // Invariant "no events after an error": a poisoned decoder must keep failing even
            // for a perfectly valid event.
            let mut more = BytesMut::from(&b"<event version='2.0' uid='x' type='a' how='h'/>"[..]);
            match dec.decode(&mut more) {
                Err(_) => {}
                Ok(v) => panic!("decoder recovered after a fatal error: {v:?}"),
            }
            break;
        }
    }
    dump
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

/// §1.6 invariants on top of "no panic": the number of emitted events is at most the number of
/// `</event` + `/>` in the input; an emitted element starts with `<event`; a frame is a closed
/// `<event …>` and re-parses when it has only ASCII names and no `:` at all.
pub fn check_stream_invariants(chunks: &[&[u8]], dump: &StreamDump) {
    let all: Vec<u8> = chunks.concat();
    let closers = count(&all, b"</event") + count(&all, b"/>");
    assert!(
        dump.events.len() <= closers,
        "{} events from {} closing tags",
        dump.events.len(),
        closers
    );
    for e in &dump.events {
        // Local name `event`; an undeclared stream prefix (`<p:event>`) is kept verbatim, as lxml does.
        let name_end = e
            .elm
            .iter()
            .position(|b| b" \t\r\n/>".contains(b))
            .unwrap_or(e.elm.len());
        let name = &e.elm[1.min(name_end)..name_end];
        assert!(
            e.elm.starts_with(b"<") && (name == b"event" || name.ends_with(b":event")),
            "emitted non-event element"
        );
        if let EventOutcome::Frame(f) = &e.evt {
            // Structural only. Full re-parse is NOT an invariant: lxml (and taky-xml, byte-exact)
            // writes non-ASCII names as `&#NNN;` and keeps undeclared stream prefixes (`<a:b>`),
            // both not namespace-well-formed — parity with the original (S-407 report §4).
            // Byte equality with lxml is checked by `difftest fuzzdiff`.
            assert!(
                f.starts_with(b"<event "),
                "frame does not start with <event"
            );
            assert!(
                f.ends_with(b"</event>") || f.ends_with(b"/>"),
                "frame is not closed"
            );
            if e.ascii_names && !f.contains(&b':') {
                if let Err(err) = taky_xml::parse_element(f, &taky_xml::Limits::DEFAULT) {
                    panic!(
                        "server frame does not re-parse: {err}: {}",
                        String::from_utf8_lossy(f)
                    );
                }
            }
        }
    }
}
