//! `serialize_roundtrip` (S-407, §1.6): parse ⇒ serialize ⇒ parse: the trees are equal (tag,
//! attributes, text, tail, children; namespace bookkeeping ignored) and serialization is
//! idempotent (`serialize(parse(serialize(e))) == serialize(e)`), for the plain and the pretty form.
#![no_main]
use libfuzzer_sys::fuzz_target;
use taky_xml::{Element, Limits, Node, SerOpts, parse_element, serialize};

/// lxml (and taky-xml, byte-exact) writes non-ASCII in a *name*, a PI or a comment as `&#NNN;` (ASCII
/// output encoding): not well-formed / not reversible, parity with the original — such documents are
/// outside the roundtrip invariant.
fn ascii_names(e: &Element) -> bool {
    e.tag.is_ascii()
        && e.attrs.iter().all(|(k, _)| k.is_ascii())
        && e.children.iter().all(|n| match n {
            Node::Element(c) => ascii_names(c),
            Node::Pi { target, data, .. } => {
                target.is_ascii() && data.as_deref().is_none_or(str::is_ascii)
            }
            Node::Comment { text, .. } => text.is_ascii(),
        })
}

fn txt(t: &Option<String>) -> &str {
    t.as_deref().unwrap_or("")
}

fn same(a: &Element, b: &Element, root: bool) -> bool {
    a.tag == b.tag
        && a.attrs == b.attrs
        && txt(&a.text) == txt(&b.text)
        && (root || txt(&a.tail) == txt(&b.tail))
        && a.children.len() == b.children.len()
        && a.children
            .iter()
            .zip(&b.children)
            .all(|(x, y)| match (x, y) {
                (Node::Element(x), Node::Element(y)) => same(x, y, false),
                (Node::Comment { text: t1, tail: l1 }, Node::Comment { text: t2, tail: l2 }) => {
                    t1 == t2 && txt(l1) == txt(l2)
                }
                (
                    Node::Pi {
                        target: g1,
                        data: d1,
                        tail: l1,
                    },
                    Node::Pi {
                        target: g2,
                        data: d2,
                        tail: l2,
                    },
                ) => g1 == g2 && txt(d1) == txt(d2) && txt(l1) == txt(l2),
                _ => false,
            })
}

fuzz_target!(|data: &[u8]| {
    let lim = Limits::DEFAULT;
    let Ok(e1) = parse_element(data, &lim) else {
        return;
    };
    if !ascii_names(&e1) {
        return;
    }
    let plain = SerOpts {
        with_tail: false,
        ..SerOpts::default()
    };
    let s1 = serialize(&e1, &plain);
    let e2 = match parse_element(&s1, &lim) {
        Ok(e) => e,
        Err(err) => panic!(
            "serialized output does not re-parse: {err}: {}",
            String::from_utf8_lossy(&s1)
        ),
    };
    assert!(
        same(&e1, &e2, true),
        "tree changed by a roundtrip:\n{e1:?}\n{e2:?}"
    );
    let s2 = serialize(&e2, &plain);
    assert_eq!(s1, s2, "serialization is not idempotent");
});
