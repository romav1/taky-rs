//! Fuzzing regressions (S-407a; qa01/reports/fuzzing.md §4 F-1, F-2): the repro files in
//! `fuzz/corpus/regressions/fuzzdiff/` and variants, byte-exact against lxml 6.1.3 / libxml2 2.14.6
//! (`tostring(elm)` and the frame `Event.as_element` builds by moving `<detail>` into a new event).
#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

use taky_xml::{Element, Limits, SerOpts, TreeBuilder, XmlError, parse_element, serialize};

/// Mode-0 fuzzdiff stream: the leading `\0` means "one chunk".
fn repro(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../fuzz/corpus/regressions/fuzzdiff/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let data = std::fs::read(&path).unwrap();
    assert_eq!(data.first(), Some(&0), "{path}: not a mode-0 stream");
    data[1..].to_vec()
}

fn run(input: &[u8]) -> (Vec<Element>, Option<XmlError>) {
    let mut tb = TreeBuilder::new(Limits::DEFAULT);
    if let Err(e) = tb.feed(input) {
        return (Vec::new(), Some(e));
    }
    let mut out = Vec::new();
    while let Some(e) = tb.next_element().unwrap() {
        out.push(e);
    }
    (out, None)
}

fn s(e: &Element) -> String {
    String::from_utf8(serialize(e, &SerOpts::default())).unwrap()
}

/// `new = Element("event"); new.append(elm.find("detail")); tostring(new)`.
fn frame(e: &Element) -> String {
    let mut detail = e.find("detail").unwrap().clone();
    detail.reconcile_moved_ns();
    let mut n = Element::new("event");
    n.append(detail);
    s(&n)
}

fn one_event(input: &[u8]) -> Element {
    let (mut evs, err) = run(input);
    assert!(err.is_none(), "{err:?}");
    assert_eq!(evs.len(), 1);
    evs.remove(0)
}

const DETAIL_BRACE: &str =
    r#"<detail><x xmlns="urn:a}b" k="v"/><p:y xmlns:p="urn:c}d" p:z="1"/></detail>"#;

#[test]
fn f1_ns_uri_brace_repro_is_byte_exact() {
    let input = repro("ns-uri-brace");
    let e = one_event(&input);
    // lxml writes the input bytes back for both the event and the routed frame.
    assert_eq!(s(&e).as_bytes(), &input[..]);
    assert_eq!(frame(&e), format!("<event>{DETAIL_BRACE}</event>"));
    // The Clark keys keep the whole URI (split at the last `}`).
    let d = e.find("detail").unwrap();
    assert!(d.find("{urn:a}b}x").is_some());
    let y = d.find("{urn:c}d}y").unwrap();
    assert_eq!(y.get("{urn:c}d}z"), Some("1"));
}

#[test]
fn f1_brace_uri_on_event_and_inherited() {
    // Default and prefixed namespace with `}` on the event itself, prefix declared on an ancestor.
    let e = one_event(br#"<w xmlns:p="urn:c}d"><event p:k="1"><p:y/></event></w>"#);
    assert_eq!(s(&e), r#"<event xmlns:p="urn:c}d" p:k="1"><p:y/></event>"#);
    let e = one_event(format!("<event>{DETAIL_BRACE}</event>").as_bytes());
    assert_eq!(s(&e), format!("<event>{DETAIL_BRACE}</event>"));
    assert_eq!(frame(&e), format!("<event>{DETAIL_BRACE}</event>"));
    // A namespace declared outside the moved `<detail>` is re-declared on it (reconcile_moved_ns).
    let e = one_event(br#"<event xmlns:p="urn:c}d"><detail><p:y p:z="1"/></detail></event>"#);
    assert_eq!(
        frame(&e),
        r#"<event><detail xmlns:p="urn:c}d"><p:y p:z="1"/></detail></event>"#
    );
}

#[test]
fn f2_invalid_ncname_prefix_on_ancestor_is_not_inherited() {
    let input = repro("qname-inherited-invalid-prefix");
    let e = one_event(&input);
    let text = std::str::from_utf8(&input).unwrap();
    let start = text.find("<event").unwrap();
    let end = text.find("</wrap>").unwrap();
    assert_eq!(s(&e), &text[start..end]);
    assert!(e.nsmap.is_empty());
}

#[test]
fn f2_invalid_ncname_prefix_in_detail_is_a_plain_attribute() {
    let detail =
        r#"<detail><c a="1" xmlns:00="u" b="2"/><d xmlns:p="v" xmlns:9x="w" p:k="1"/></detail>"#;
    let e = one_event(format!("<event>{detail}</event>").as_bytes());
    // Input order kept (not moved before the other attributes), in the event and in the frame.
    assert_eq!(s(&e), format!("<event>{detail}</event>"));
    assert_eq!(frame(&e), format!("<event>{detail}</event>"));
    let c = e.find("detail").unwrap().find("c").unwrap();
    assert!(c.nsmap.is_empty());
    assert_eq!(c.get("xmlns:00"), Some("u"));
}

#[test]
fn f2_duplicate_malformed_qname_attribute_is_fatal() {
    let (evs, err) = run(&repro("qname-dup-malformed-attr"));
    assert!(evs.is_empty());
    assert!(matches!(err, Some(XmlError::Syntax { .. })), "{err:?}");
    // Also for an invalid `xmlns:` prefix, which is a plain attribute as well.
    let (_, err) = run(br#"<event xmlns:9x="a" xmlns:9x="b"/>"#);
    assert!(matches!(err, Some(XmlError::Syntax { .. })), "{err:?}");
    // A valid QName with an undeclared prefix stays tolerated (libxml2 too).
    let (evs, err) = run(br#"<x u:s="1" u:s="2"/><event/>"#);
    assert!(err.is_none());
    assert_eq!(evs.len(), 1);
}

#[test]
fn f2_malformed_local_part_is_a_raw_name() {
    let input = r#"<event xmlns:a="u"><a:0b a:0c="1"/><w xmlns="d"><a:-b/></w></event>"#;
    let e = one_event(input.as_bytes());
    assert_eq!(s(&e), input);
    let b = e.find("a:0b").unwrap();
    assert_eq!(b.get("a:0c"), Some("1"));
    // An element still gets the default namespace (libxml2 prefix NULL).
    assert!(e.find("{d}w").unwrap().find("{d}a:-b").is_some());
    // etree.fromstring: "Failed to parse QName".
    for doc in [&br#"<event xmlns:9x="u"/>"#[..], br#"<event a:0s="1"/>"#] {
        assert!(parse_element(doc, &Limits::DEFAULT).is_err());
    }
}
