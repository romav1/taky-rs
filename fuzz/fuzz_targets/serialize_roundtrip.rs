//! `serialize_roundtrip` (S-407, §1.6): parse ⇒ serialize ⇒ parse: the trees are equal (tag,
//! attributes, text, tail, children; empty text and no text are the same; namespace bookkeeping
//! ignored) and serialization is stable: with `e2 = parse(s1)`, `s2 = serialize(e2)`,
//! `e3 = parse(s2)`: `s1 == s2` (unless the exception below applies), `e3` equals `e2` and
//! `serialize(e3) == s2` (fixpoint). Plain form (`with_tail = false`) only; the pretty form is not
//! exercised.
//!
//! The one exception to `s1 == s2` (S-509, narrowed in S-823 after S-822 M-2): a parsed element
//! with an empty-string text or tail (`Some("")`, e.g. from an empty CDATA section) is written as
//! `<event></event>`; re-parsed, that has text `None` and is written as `<event/>`. lxml does the
//! same (`<event><![CDATA[]]></event>` ⇒ `<event></event>` ⇒ `<event/>`, fixture `cdata_only` in
//! `crates/taky-xml/tests/fixtures/lxml_serialize.json`) — parity with the original. Only for such
//! trees `s1 == s2` is skipped; the `s2 == s3` fixpoint always holds. `same()` ignores `nsmap` /
//! `prefix` / `attr_prefixes`, so `s1 == s2` is what catches a first-pass-only drift in them.
//!
//! Tests (stable toolchain, no cargo-fuzz): `cargo test --release --bin serialize_roundtrip` in
//! `fuzz/` — the committed corpus and regressions pass, a synthetic first-pass-only drift fails.
#![cfg_attr(not(test), no_main)]
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

/// `Some("")` text or tail anywhere in the tree (the root's tail is not written: ignored). Such a
/// tree is written differently once (`<x></x>`, then `<x/>`): the only allowed `s1 != s2`.
fn has_empty_text(e: &Element) -> bool {
    e.text.as_deref() == Some("")
        || e.children.iter().any(|n| match n {
            Node::Element(c) => c.tail.as_deref() == Some("") || has_empty_text(c),
            Node::Comment { tail, .. } | Node::Pi { tail, .. } => tail.as_deref() == Some(""),
        })
}

fn reparse(s: &[u8], what: &str) -> Result<Element, String> {
    parse_element(s, &Limits::DEFAULT).map_err(|err| {
        format!(
            "{what} does not re-parse: {err}: {}",
            String::from_utf8_lossy(s)
        )
    })
}

/// The invariant, with the serializer as a parameter so the tests can inject a drift.
fn check(data: &[u8], ser: &mut dyn FnMut(&Element) -> Vec<u8>) -> Result<(), String> {
    let Ok(e1) = parse_element(data, &Limits::DEFAULT) else {
        return Ok(());
    };
    if !ascii_names(&e1) {
        return Ok(());
    }
    let s1 = ser(&e1);
    let e2 = reparse(&s1, "serialized output")?;
    if !same(&e1, &e2, true) {
        return Err(format!("tree changed by a roundtrip:\n{e1:?}\n{e2:?}"));
    }
    let s2 = ser(&e2);
    if s1 != s2 && !has_empty_text(&e1) {
        return Err(format!(
            "serialization changed by the first roundtrip:\n{}\n{}",
            String::from_utf8_lossy(&s1),
            String::from_utf8_lossy(&s2)
        ));
    }
    let e3 = reparse(&s2, "second serialization")?;
    if !same(&e2, &e3, true) {
        return Err(format!(
            "tree changed by the second roundtrip:\n{e2:?}\n{e3:?}"
        ));
    }
    let s3 = ser(&e3);
    if s2 != s3 {
        return Err(format!(
            "serialization does not reach a fixpoint:\n{}\n{}",
            String::from_utf8_lossy(&s2),
            String::from_utf8_lossy(&s3)
        ));
    }
    Ok(())
}

fn plain(e: &Element) -> Vec<u8> {
    let opts = SerOpts {
        with_tail: false,
        ..SerOpts::default()
    };
    serialize(e, &opts)
}

#[cfg(not(test))]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Err(msg) = check(data, &mut plain) {
        panic!("{msg}");
    }
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn files(dir: &str) -> Vec<(PathBuf, Vec<u8>)> {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(dir);
        let mut v: Vec<_> = std::fs::read_dir(&d)
            .unwrap_or_else(|e| panic!("{}: {e}", d.display()))
            .map(|f| {
                let p = f.unwrap_or_else(|e| panic!("{e}")).path();
                let b = std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
                (p, b)
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn corpus_and_regressions_pass() {
        let mut n = 0;
        for dir in [
            "corpus/serialize_roundtrip",
            "corpus/regressions/serialize_roundtrip",
        ] {
            for (p, b) in files(dir) {
                if let Err(m) = check(&b, &mut plain) {
                    panic!("{}: {m}", p.display());
                }
                n += 1;
            }
        }
        assert!(n > 3, "corpus not found ({n} files)");
    }

    /// The S-509 repro still passes, and it does need the exception (s1 != s2 for it).
    #[test]
    fn empty_cdata_regression_is_the_allowed_exception() {
        let data = include_bytes!("../corpus/regressions/serialize_roundtrip/empty-cdata");
        assert_eq!(check(data, &mut plain), Ok(()));
        let e1 = parse_element(data, &Limits::DEFAULT).unwrap_or_else(|e| panic!("{e}"));
        assert!(has_empty_text(&e1));
        let s1 = plain(&e1);
        let s2 = plain(&reparse(&s1, "s1").unwrap_or_else(|e| panic!("{e}")));
        assert_eq!(
            (&s1[..], &s2[..]),
            (&b"<event></event>"[..], &b"<event/>"[..])
        );
    }

    /// A serializer that writes the first pass in another (re-parseable, tree-equal) form and is
    /// stable from then on: the S-509 check (trees + `s2 == s3`) let it through; `s1 == s2` does not.
    #[test]
    fn first_pass_only_drift_is_rejected() {
        let data = br#"<event xmlns:a="u" a:k="1"><a:x/>t</event>"#;
        let mut calls = 0;
        let mut drift = |e: &Element| {
            calls += 1;
            let s = plain(e);
            if calls == 1 {
                String::from_utf8_lossy(&s)
                    .replacen("/>", " />", 1)
                    .into_bytes()
            } else {
                s
            }
        };
        let err = check(data, &mut drift).expect_err("drift must be rejected");
        assert!(
            err.starts_with("serialization changed by the first roundtrip"),
            "{err}"
        );
        assert_eq!(check(data, &mut plain), Ok(()), "the input itself is fine");
    }

    #[test]
    fn has_empty_text_sees_nested_text_and_tails() {
        let t = |s: &[u8]| {
            has_empty_text(&parse_element(s, &Limits::DEFAULT).unwrap_or_else(|e| panic!("{e}")))
        };
        assert!(t(b"<a><b><![CDATA[]]></b></a>"));
        assert!(t(b"<a><b/><![CDATA[]]></a>"));
        assert!(t(b"<a><!--c--><![CDATA[]]></a>"));
        assert!(!t(b"<a><b>x</b>y</a>"));
        assert!(!t(b"<a/>"));
    }
}
