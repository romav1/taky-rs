//! `serialize_roundtrip` (S-407, §1.6): parse ⇒ serialize ⇒ parse: the trees are equal (tag,
//! attributes, text, tail, children; empty text and no text are the same; namespace bookkeeping
//! ignored) and serialization reaches a fixpoint after one roundtrip: with `e2 = parse(s1)`,
//! `s2 = serialize(e2)`, `e3 = parse(s2)` the tree `e3` equals `e2` and `serialize(e3) == s2`.
//! Plain form (`with_tail = false`) only; the pretty form is not exercised.
//!
//! `s1 == s2` is NOT an invariant (S-509): an empty CDATA section gives text `Some("")`, which is
//! written as `<event></event>`; re-parsed, that has text `None` and is written as `<event/>`.
//! lxml does the same (`<event><![CDATA[]]></event>` ⇒ `<event></event>` ⇒ `<event/>`) — parity
//! with the original. From the first re-parse on, the text is canonical and the output is stable.
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
    // Fixpoint from the second serialization (s1 may differ: '' vs None text, see the header).
    let s2 = serialize(&e2, &plain);
    let e3 = match parse_element(&s2, &lim) {
        Ok(e) => e,
        Err(err) => panic!(
            "second serialization does not re-parse: {err}: {}",
            String::from_utf8_lossy(&s2)
        ),
    };
    assert!(
        same(&e2, &e3, true),
        "tree changed by the second roundtrip:\n{e2:?}\n{e3:?}"
    );
    let s3 = serialize(&e3, &plain);
    assert_eq!(s2, s3, "serialization does not reach a fixpoint");
});
