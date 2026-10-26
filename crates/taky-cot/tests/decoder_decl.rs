//! Port of `taky/tests/test_xmldeclstrip.py` (test-strategy §2 rows 18–22). `XMLDeclStrip` +
//! `XMLPullParser(tag="event")` pre-fed with `<root>` is absorbed by [`CotDecoder`]: the same
//! chunks are fed one `decode` round each, then the completed `<event>`s are counted
//! (`read_events()`).
//!
//! Extra (test-strategy §2): each input is also checked under re-chunking — every 2- and
//! 3-piece split, byte-at-a-time, and 2000 pseudo-random multi-cut splits — and must give the
//! same events as the unsplit stream. (The lower-level `TreeBuilder` port is
//! `taky-xml/tests/xmldeclstrip.rs`.)
#![allow(clippy::unwrap_used)]

use bytes::BytesMut;
use taky_cot::CotDecoder;
use taky_xml::Element;
use tokio_util::codec::Decoder;

const DECL: &[u8] = b"<?xml version='1.0' encoding='utf-8'?>";
const EVENT: &[u8] = b"<event data=\"stuff here\" />";

/// Feed `chunks` like `xdc.feed(...)` and collect every completed `<event>`.
fn read_events(chunks: &[&[u8]]) -> Vec<Element> {
    let mut dec = CotDecoder::new();
    let mut buf = BytesMut::new();
    let mut evts = Vec::new();
    for c in chunks {
        buf.extend_from_slice(c);
        while let Some(e) = dec.decode(&mut buf).unwrap() {
            evts.push(e);
        }
    }
    evts
}

/// Split `data` at the sorted, de-duplicated `cuts`.
fn split<'a>(data: &'a [u8], cuts: &[usize]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut prev = 0;
    for &c in cuts {
        out.push(&data[prev..c]);
        prev = c;
    }
    out.push(&data[prev..]);
    out
}

/// The property: any chunking of the concatenated input yields the same events.
fn assert_all_splits(chunks: &[&[u8]], want: usize) {
    let data: Vec<u8> = chunks.concat();
    let reference = read_events(&[&data]);
    assert_eq!(reference.len(), want, "unsplit stream");
    let n = data.len();
    let check = |cuts: &[usize]| {
        let got = read_events(&split(&data, cuts));
        assert_eq!(got, reference, "cuts {cuts:?}");
    };
    for i in 0..=n {
        check(&[i]);
        for j in i..=n {
            check(&[i, j]);
        }
    }
    check(&(1..n).collect::<Vec<_>>()); // byte at a time
    // xorshift64: deterministic pseudo-random cut sets of 3..=8 cuts.
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15 ^ n as u64;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..2000 {
        let k = 3 + (next() % 6) as usize;
        let mut cuts: Vec<usize> = (0..k).map(|_| (next() % (n as u64 + 1)) as usize).collect();
        cuts.sort_unstable();
        check(&cuts);
    }
}

/// `test_xmldeclstrip.XDCTest.test_valid_xml`.
#[test]
fn valid_xml() {
    let chunks: &[&[u8]] = &[DECL, EVENT];
    assert_eq!(read_events(chunks).len(), 1);
    assert_all_splits(chunks, 1);
}

/// `test_xmldeclstrip.XDCTest.test_split_decl`.
#[test]
fn split_decl() {
    let chunks: &[&[u8]] = &[b"<?xm", b"l version='1.0' encoding='utf-8'?>", EVENT];
    assert_eq!(read_events(chunks).len(), 1);
    assert_all_splits(chunks, 1);
}

/// `test_xmldeclstrip.XDCTest.test_split_decl2`.
#[test]
fn split_decl2() {
    let chunks: &[&[u8]] = &[b"<?xml version='1.0' encoding='utf-8'?", b">", EVENT];
    assert_eq!(read_events(chunks).len(), 1);
    assert_all_splits(chunks, 1);
}

/// `test_xmldeclstrip.XDCTest.test_split_decl3`.
#[test]
fn split_decl3() {
    let chunks: &[&[u8]] = &[
        DECL,
        b"<event data=\"stuff here\" /><",
        b"?xml version='1.0' encoding='utf-8'?>",
        EVENT,
    ];
    let evts = read_events(chunks);
    assert_eq!(evts.len(), 2);
    assert_all_splits(chunks, 2);
}

/// `test_xmldeclstrip.XDCTest.test_split_data`.
#[test]
fn split_data() {
    let chunks: &[&[u8]] = &[DECL, b"<event data=\"stuff", b" here\" />"];
    assert_eq!(read_events(chunks).len(), 1);
    assert_all_splits(chunks, 1);
}

/// Extra: the events are the fixture element itself (`data` attribute, no children).
#[test]
fn events_are_the_fed_elements() {
    let evts = read_events(&[DECL, EVENT, DECL, EVENT]);
    assert_eq!(evts.len(), 2);
    for e in &evts {
        assert_eq!(e.tag, "event");
        assert_eq!(e.get("data"), Some("stuff here"));
        assert!(e.children.is_empty());
    }
}

/// Extra (decoder half of `SocketTAKClientTest.test_invalid_xml`, formerly in `router.rs`):
/// `</invalid>` is a fatal stream error, the reason the connection task closes with.
#[test]
fn invalid_close_tag_is_stream_error() {
    let mut dec = CotDecoder::new();
    let mut buf = BytesMut::from(&b"</invalid>"[..]);
    let err = dec.decode(&mut buf).unwrap_err();
    assert!(err.to_string().starts_with("XML Syntax Error"), "{err}");
}
