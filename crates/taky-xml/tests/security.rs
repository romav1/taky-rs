//! ADR-002 security properties, re-verified on quick-xml 0.42 (review-T-10 N-6) and on
//! taky-xml's decoder: DTD rejected, no entity expansion (billion laughs / XXE impossible),
//! unknown entity drops the event (V017), limits (D-2) with bounded memory.
#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

mod common;

use common::run_flat;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use taky_xml::{Limits, TreeBuilder, XmlError, parse_element};

const BILLION_LAUGHS: &str = r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol9 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<event uid="&lol9;">&lol9;</event>"#;

const XXE: &str = r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><event uid="x"><remarks>&xxe;</remarks></event>"#;
const XXE_PARAM: &str =
    r#"<!DOCTYPE foo [<!ENTITY % ext SYSTEM "http://127.0.0.1:1/evil.dtd"> %ext;]><event/>"#;
const XXE_EXTERNAL_DTD: &str = r#"<!DOCTYPE event SYSTEM "http://127.0.0.1:1/evil.dtd"><event/>"#;

// ---- quick-xml 0.42 itself (the properties ADR-002 relies on) ----

fn raw_events(doc: &str) -> Vec<String> {
    let mut r = Reader::from_str(doc);
    let mut out = Vec::new();
    loop {
        match r.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::DocType(_)) => out.push("DOCTYPE".to_owned()),
            Ok(Event::GeneralRef(g)) => out.push(format!("REF {}", &*g)),
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                for a in e.attributes() {
                    let a = a.unwrap();
                    out.push(format!(
                        "ATTR {:?}",
                        a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                            .map(|v| v.into_owned())
                    ));
                }
            }
            Ok(Event::Text(t)) => out.push(format!("TEXT {:?}", t.xml10_content())),
            Ok(_) => {}
            Err(e) => {
                out.push(format!("ERR {e}"));
                break;
            }
        }
    }
    out
}

#[test]
fn quick_xml_042_delivers_doctype_as_an_event() {
    let ev = raw_events(BILLION_LAUGHS);
    assert!(ev.iter().any(|e| e == "DOCTYPE"), "{ev:?}");
    assert!(raw_events(XXE).iter().any(|e| e == "DOCTYPE"));
}

#[test]
fn quick_xml_042_never_expands_custom_entities() {
    let ev = raw_events(BILLION_LAUGHS);
    // Text reference: delivered as a GeneralRef, not expanded.
    assert!(ev.iter().any(|e| e == "REF lol9"), "{ev:?}");
    // Attribute: unescaping an undeclared entity fails instead of expanding it.
    assert!(ev.iter().any(|e| e.starts_with("ATTR Err(")), "{ev:?}");
    assert!(!ev.iter().any(|e| e.contains("lollol")), "{ev:?}");
    // Predefined entities and char refs still work.
    let ev = raw_events(r#"<e a="x&amp;y&#65;">a &lt; b</e>"#);
    assert!(ev.contains(&r#"ATTR Ok("x&yA")"#.to_owned()), "{ev:?}");
    assert!(ev.contains(&"REF lt".to_owned()), "{ev:?}");
}

// ---- taky-xml stream decoder ----

#[test]
fn doctype_is_fatal_in_stream_and_document() {
    for doc in [
        BILLION_LAUGHS,
        XXE,
        XXE_PARAM,
        XXE_EXTERNAL_DTD,
        "<event><!DOCTYPE x></event>",
    ] {
        let (evs, err) = run_flat(&[doc.as_bytes()]);
        assert!(evs.is_empty(), "{doc}");
        assert_eq!(err, Some(XmlError::DtdForbidden), "{doc}");
        assert_eq!(
            parse_element(doc.as_bytes(), &Limits::DEFAULT),
            Err(XmlError::DtdForbidden),
            "{doc}"
        );
    }
    // V018: DOCTYPE inside the stream, split anywhere.
    let v018 = b"<!DOCTYPE x [<!ENTITY e \"boom\">]><event a='1'/>";
    for i in 1..v018.len() {
        let (evs, err) = run_flat(&[&v018[..i], &v018[i..]]);
        assert!(
            evs.is_empty() && err == Some(XmlError::DtdForbidden),
            "split {i}"
        );
    }
}

#[test]
fn entity_references_without_dtd_are_never_expanded() {
    // Billion-laughs-style references with no DTD: the event is dropped (V017), nothing grows.
    let refs = "&lol9;".repeat(10_000);
    let doc = format!("<event a='1'>{refs}</event><event a='2' b='&xxe;'/><event a='3'/>");
    let mut tb = TreeBuilder::new(Limits::DEFAULT);
    tb.feed(doc.as_bytes()).unwrap();
    let a = tb.next_element().unwrap().unwrap();
    assert_eq!(a.get("a"), Some("3"));
    assert!(tb.next_element().unwrap().is_none());
    assert_eq!(
        parse_element(b"<event>&xxe;</event>", &Limits::DEFAULT),
        Err(XmlError::UnknownEntity("xxe".into()))
    );
}

#[test]
fn v017_unknown_entity_drops_event_and_connection_lives() {
    let mut tb = TreeBuilder::new(Limits::DEFAULT);
    tb.feed(b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><event uid=\"M-1\"><detail><remarks>&foo;</remarks></detail></event>").unwrap();
    assert!(tb.next_element().unwrap().is_none());
    tb.feed(b"<?xml version=\"1.0\"?><event uid=\"M-2\"/>")
        .unwrap();
    assert_eq!(tb.next_element().unwrap().unwrap().get("uid"), Some("M-2"));
}

#[test]
fn size_limit_4_mib_with_bounded_buffer() {
    // 3 MiB event: accepted.
    let big = format!(
        "<event a='1'><remarks>{}</remarks></event>",
        "x".repeat(3 << 20)
    );
    let mut tb = TreeBuilder::new(Limits::DEFAULT);
    for c in big.as_bytes().chunks(64 * 1024) {
        tb.feed(c).unwrap();
    }
    assert!(tb.next_element().unwrap().is_some());
    // > 4 MiB: fatal, detected while streaming (the end tag never needs to arrive).
    let mut tb = TreeBuilder::new(Limits::DEFAULT);
    tb.feed(b"<event a='1'><remarks>").unwrap();
    let chunk = vec![b'x'; 64 * 1024];
    let mut fed = 0usize;
    let err = loop {
        match tb.feed(&chunk) {
            Ok(()) => {
                fed += chunk.len();
                assert!(tb.buffered_bytes() <= Limits::DEFAULT.max_bytes + chunk.len());
            }
            Err(e) => break e,
        }
    };
    assert_eq!(err, XmlError::LimitExceeded("max_bytes"));
    assert!(fed <= Limits::DEFAULT.max_bytes, "{fed}");
    assert_eq!(tb.buffered_bytes(), 0, "buffers released after the error");
    // Same for one huge start tag / attribute value and for junk at depth 0.
    for head in [&b"<event a='"[..], b"<!-- ", b"junk "] {
        let mut tb = TreeBuilder::new(Limits::DEFAULT);
        tb.feed(head).unwrap();
        let err = (0..100).find_map(|_| tb.feed(&chunk).err());
        assert_eq!(err, Some(XmlError::LimitExceeded("max_bytes")), "{head:?}");
    }
}

#[test]
fn depth_10000_is_rejected_early() {
    let doc = "<a>".repeat(10_000);
    let (evs, err) = run_flat(&[doc.as_bytes()]);
    assert!(evs.is_empty());
    assert_eq!(err, Some(XmlError::LimitExceeded("max_depth")));
    // libxml2 counts the virtual <root>: 255 nested elements are fine, 256 are not.
    let ok = format!("{}{}<event a='1'/>", "<a>".repeat(255), "</a>".repeat(255));
    assert_eq!(run_flat(&[ok.as_bytes()]).0.len(), 1);
    let bad = format!("{}{}", "<a>".repeat(256), "</a>".repeat(256));
    assert_eq!(
        run_flat(&[bad.as_bytes()]).1,
        Some(XmlError::LimitExceeded("max_depth"))
    );
    assert!(parse_element(doc.as_bytes(), &Limits::DEFAULT).is_err());
}

#[test]
fn attribute_name_and_node_limits() {
    let many: String = (0..257).map(|i| format!(" a{i}='1'")).collect();
    let (_, err) = run_flat(&[format!("<event{many}/>").as_bytes()]);
    assert_eq!(err, Some(XmlError::LimitExceeded("max_attrs")));
    let ok: String = (0..256).map(|i| format!(" a{i}='1'")).collect();
    assert_eq!(run_flat(&[format!("<event{ok}/>").as_bytes()]).0.len(), 1);

    let long = "n".repeat(1025);
    assert_eq!(
        run_flat(&[format!("<{long}/>").as_bytes()]).1,
        Some(XmlError::LimitExceeded("max_name"))
    );
    assert_eq!(
        run_flat(&[format!("<event {long}='1'/>").as_bytes()]).1,
        Some(XmlError::LimitExceeded("max_name"))
    );

    let nodes = format!("<event>{}</event>", "<p/>".repeat(100_000));
    assert_eq!(
        run_flat(&[nodes.as_bytes()]).1,
        Some(XmlError::LimitExceeded("max_nodes"))
    );
    let nodes = format!("<event>{}</event>", "<p/>".repeat(99_999));
    assert_eq!(run_flat(&[nodes.as_bytes()]).0.len(), 1);
}

#[test]
fn no_leak_for_many_top_level_elements_and_events() {
    // 10^5 junk top-level elements and 10^5 events: nothing is retained (the original keeps one
    // child of <root> per element — known leak, D-2).
    let mut tb = TreeBuilder::new(Limits::DEFAULT);
    let junk = b"<foo a='1'><bar/></foo> text ".repeat(1000);
    let ev = b"<event uid='u'><detail/></event>".repeat(1000);
    let mut n = 0;
    for _ in 0..100 {
        tb.feed(&junk).unwrap();
        tb.feed(&ev).unwrap();
        while tb.next_element().unwrap().is_some() {
            n += 1;
        }
        assert!(tb.buffered_bytes() < 64, "{}", tb.buffered_bytes());
        assert_eq!(tb.depth(), 0);
    }
    assert_eq!(n, 100_000);
}

#[test]
fn endless_declaration_does_not_buffer() {
    let mut tb = TreeBuilder::new(Limits::DEFAULT);
    tb.feed(b"<?xml ").unwrap();
    for _ in 0..200 {
        tb.feed(&[b'v'; 64 * 1024]).unwrap();
        assert_eq!(tb.buffered_bytes(), 0);
    }
    tb.feed(b"?><event a='1'/>").unwrap();
    assert!(tb.next_element().unwrap().is_some());
}

#[test]
fn tiny_chunks_are_linear() {
    // A 1 MiB attribute value fed one byte at a time: the scanner resumes where it stopped and
    // the buffer is compacted amortized, so this is O(n) (a quadratic rescan would not finish).
    let doc = format!("<event a='{}'/>", "v".repeat(1 << 20));
    let mut tb = TreeBuilder::new(Limits::DEFAULT);
    for b in doc.as_bytes().chunks(1) {
        tb.feed(b).unwrap();
    }
    assert_eq!(
        tb.next_element().unwrap().unwrap().get("a").map(str::len),
        Some(1 << 20)
    );
}

#[test]
fn invalid_utf8_and_chars_are_fatal() {
    assert_eq!(
        run_flat(&[b"<event a='\xff'/>"]).1,
        Some(XmlError::InvalidUtf8)
    );
    assert_eq!(
        run_flat(&[b"<event>\xc3\x28</event>"]).1,
        Some(XmlError::InvalidUtf8)
    );
    assert!(matches!(
        run_flat(&[b"<event>&#1;</event>"]).1,
        Some(XmlError::Syntax { .. })
    ));
    assert!(matches!(
        run_flat(&[b"<event a='&#xFFFE;'/>"]).1,
        Some(XmlError::Syntax { .. })
    ));
    // A multibyte character split across chunks is fine (V003).
    let (evs, err) = run_flat(&[b"<event a='\xc3", b"\x84'/>"]);
    assert!(err.is_none());
    assert_eq!(evs[0].get("a"), Some("Ä"));
}
