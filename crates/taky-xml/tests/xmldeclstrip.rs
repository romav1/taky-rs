//! Port of `taky/tests/test_xmldeclstrip.py` (XDCTest). The original feeds an
//! `XMLPullParser(tag="event")` pre-fed with `<root>` through `XMLDeclStrip` and counts events;
//! here the same chunks go to [`TreeBuilder`], which includes the stripper.
#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

mod common;

use taky_xml::{Limits, TreeBuilder};

fn count_events(chunks: &[&[u8]]) -> usize {
    let mut xdc = TreeBuilder::new(Limits::DEFAULT);
    for c in chunks {
        xdc.feed(c).unwrap();
    }
    let mut n = 0;
    while xdc.next_element().unwrap().is_some() {
        n += 1;
    }
    n
}

#[test]
fn test_valid_xml() {
    let n = count_events(&[
        b"<?xml version='1.0' encoding='utf-8'?>",
        b"<event data=\"stuff here\" />",
    ]);
    assert_eq!(n, 1);
}

#[test]
fn test_split_decl() {
    let n = count_events(&[
        b"<?xm",
        b"l version='1.0' encoding='utf-8'?>",
        b"<event data=\"stuff here\" />",
    ]);
    assert_eq!(n, 1);
}

#[test]
fn test_split_decl2() {
    let n = count_events(&[
        b"<?xml version='1.0' encoding='utf-8'?",
        b">",
        b"<event data=\"stuff here\" />",
    ]);
    assert_eq!(n, 1);
}

#[test]
fn test_split_decl3() {
    let n = count_events(&[
        b"<?xml version='1.0' encoding='utf-8'?>",
        b"<event data=\"stuff here\" /><",
        b"?xml version='1.0' encoding='utf-8'?>",
        b"<event data=\"stuff here\" />",
    ]);
    assert_eq!(n, 2);
}

#[test]
fn test_split_data() {
    let n = count_events(&[
        b"<?xml version='1.0' encoding='utf-8'?>",
        b"<event data=\"stuff",
        b" here\" />",
    ]);
    assert_eq!(n, 1);
}

/// Extra (not in the original): every split point of the `test_split_decl3` stream, in two and
/// three pieces, still yields exactly 2 events (ADR-002 "all splits of test_xmldeclstrip.py").
#[test]
fn all_splits_of_two_documents() {
    let doc: &[u8] = b"<?xml version='1.0' encoding='utf-8'?><event data=\"stuff here\" /><?xml version='1.0' encoding='utf-8'?><event data=\"stuff here\" />";
    for i in 0..=doc.len() {
        assert_eq!(count_events(&[&doc[..i], &doc[i..]]), 2, "split at {i}");
        for j in i..=doc.len() {
            assert_eq!(
                count_events(&[&doc[..i], &doc[i..j], &doc[j..]]),
                2,
                "split at {i},{j}"
            );
        }
    }
}
