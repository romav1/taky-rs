//! TreeBuilder stream semantics (cot-server.md §5, ADR-002) beyond the lxml fixture.
#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

mod common;

use common::{b64, run_flat};
use serde_json::Value;
use taky_xml::{Element, Limits, Node, TreeBuilder, XmlError};

fn uids(evs: &[Element]) -> Vec<&str> {
    evs.iter().map(|e| e.get("a").unwrap_or("-")).collect()
}

#[test]
fn nested_event_is_emitted_first_and_leaves_placeholder() {
    // V020: the inner event comes first; the outer keeps an empty <event/> with its tail.
    let (evs, err) =
        run_flat(&[b"<event a='o'><detail><event a='i'><x/></event>tl</detail></event>"]);
    assert!(err.is_none());
    assert_eq!(uids(&evs), ["i", "o"]);
    let detail = evs[1].find("detail").unwrap();
    let ph = detail.find("event").unwrap();
    assert!(ph.attrs.is_empty() && ph.children.is_empty() && ph.text.is_none());
    assert_eq!(ph.tail.as_deref(), Some("tl"));
}

#[test]
fn event_inside_non_event_and_junk_is_processed() {
    // V016.
    let (evs, err) =
        run_flat(&[b"hello junk <foo a=\"1\"/><wrap><event a='n'/></wrap> more junk "]);
    assert!(err.is_none());
    assert_eq!(uids(&evs), ["n"]);
}

#[test]
fn namespaced_event_is_not_emitted_undeclared_prefix_is() {
    let (evs, _) =
        run_flat(&[b"<event xmlns='urn:x' a='1'/><p:event xmlns:p='u' a='2'/><q:event a='3'/>"]);
    assert_eq!(uids(&evs), ["3"]);
    assert_eq!(evs[0].tag, "q:event");
}

#[test]
fn unknown_entity_drops_only_the_enclosing_event() {
    // V017 / ADR-002: the event with `&foo;` vanishes, the stream lives on (Rust keeps parsing
    // the rest of the chunk; libxml2 would drop it and restart, see lxml_oracle DIVERGENCES).
    let (evs, err) = run_flat(&[
        b"<event a='1'><r>&foo;</r></event><event a='2'/>",
        b"<event a='3' b='&bar;'/><event a='4'/>",
        b"<event a='5'><event a='6'>&x;</event></event>",
    ]);
    assert!(err.is_none());
    assert_eq!(uids(&evs), ["2", "4", "5"]);
    // The dropped inner event leaves a placeholder in the outer one.
    assert!(evs[2].find("event").is_some());
}

#[test]
fn quirk_outcomes_in_rust() {
    // quirk_unknown_entity_restart: every following event is accepted.
    let (evs, err) = run_flat(&[
        b"<event a='1'>&foo;</event><event a='2'/>",
        b"<event a='3'/>",
        b"<event a='4'/>",
    ]);
    assert!(err.is_none());
    assert_eq!(uids(&evs), ["2", "3", "4"]);
    // Malformed references are fatal (libxml2 silently stops parsing instead).
    for bad in [
        &b"<event>&</event>"[..],
        b"<event>&#65</event>",
        b"<event>& x;</event>",
        b"<event a='&'/>",
    ] {
        let (_, err) = run_flat(&[bad, b"<event a='1'/>"]);
        assert!(
            matches!(err, Some(XmlError::Syntax { .. })),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
}

#[test]
fn failing_feed_discards_its_events_and_poisons() {
    let mut tb = TreeBuilder::new(Limits::DEFAULT);
    tb.feed(b"<event a='1'/>").unwrap();
    assert_eq!(tb.queued(), 1);
    // Python raises from feed() before reading events: the event of the failing chunk is lost.
    let e = tb.feed(b"<event a='2'/><event a='x' a='y'/>").unwrap_err();
    assert!(matches!(&e, XmlError::Syntax { msg, .. } if msg.contains("redefined")));
    assert_eq!(tb.queued(), 0);
    assert_eq!(tb.next_element(), Err(e.clone()));
    assert_eq!(tb.feed(b"<event/>"), Err(e));
}

#[test]
fn root_close_then_only_misc() {
    let mut tb = TreeBuilder::new(Limits::DEFAULT);
    tb.feed(b"<event a='1'/></root> <!-- c --><?pi x?>\n")
        .unwrap();
    assert!(tb.next_element().unwrap().is_some());
    assert!(tb.feed(b"<event a='2'/>").is_err());
}

#[test]
fn emitted_event_tail_follows_lxml_chunk_visibility() {
    // Text completed in the same chunk is visible as the emitted element's tail (`<x></x>` is
    // long enough not to be held back by the declaration stripper).
    let (evs, _) = run_flat(&[b"<event a='1'/>tail<x></x>"]);
    assert_eq!(evs[0].tail.as_deref(), Some("tail"));
    let (evs, _) = run_flat(&[b"<event a='1'/>tail", b"<x/>"]);
    assert_eq!(evs[0].tail, None);
    // A reference is flushed as soon as it is complete (libxml2 push parser).
    let (evs, _) = run_flat(&[b"<event a='1'/>&#65;", b"<x/>"]);
    assert_eq!(evs[0].tail.as_deref(), Some("A"));
}

#[test]
fn tree_content_and_namespaces() {
    let (evs, err) = run_flat(&[
        "<event xmlns:p='urn:p' p:a='1' xml:lang='ru' b='Ж'>t<!-- c -->ct<?pi d?>pt<p:d>x</p:d>dt<![CDATA[<&>]]></event>".as_bytes(),
    ]);
    assert!(err.is_none());
    let e = &evs[0];
    assert_eq!(
        e.attrs,
        [
            ("{urn:p}a".to_owned(), "1".to_owned()),
            (
                "{http://www.w3.org/XML/1998/namespace}lang".to_owned(),
                "ru".to_owned()
            ),
            ("b".to_owned(), "Ж".to_owned()),
        ]
    );
    assert_eq!(e.nsmap, [(Some("p".to_owned()), "urn:p".to_owned())]);
    assert_eq!(e.text.as_deref(), Some("t"));
    assert!(
        matches!(&e.children[0], Node::Comment { text, tail } if text == " c " && tail.as_deref() == Some("ct"))
    );
    assert!(
        matches!(&e.children[1], Node::Pi { target, data, tail } if target == "pi" && data.as_deref() == Some("d") && tail.as_deref() == Some("pt"))
    );
    let Node::Element(d) = &e.children[2] else {
        panic!()
    };
    assert_eq!(d.tag, "{urn:p}d");
    assert_eq!(d.tail.as_deref(), Some("dt<&>"));
}

fn strip_tails(mut evs: Vec<Element>) -> Vec<Element> {
    for e in &mut evs {
        e.tail = None;
    }
    evs
}

/// Every fixture input (all vector connections + edge cases) fed one byte at a time gives the
/// same events (modulo the emitted element's own tail, which depends on chunking in lxml too)
/// and the same error as feeding it at once.
#[test]
fn byte_at_a_time_equals_one_shot() {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/lxml_stream.json"
    );
    let fx: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    for item in fx["items"].as_array().unwrap() {
        let data: Vec<u8> = item["chunks_b64"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|c| b64(c.as_str().unwrap()))
            .collect();
        let (whole, e1) = run_flat(&[&data]);
        let bytes: Vec<&[u8]> = data.chunks(1).collect();
        let (split, e2) = run_flat(&bytes);
        let id = item["id"].as_str().unwrap();
        assert_eq!(e1, e2, "{id}");
        if e1.is_none() {
            assert_eq!(strip_tails(whole), strip_tails(split), "{id}");
        }
    }
}
