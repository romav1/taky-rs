//! Property: chunk boundaries do not change what the stream decoder produces (S-303).
//!
//! For random documents (and the real vector streams) split at random points, the emitted
//! events — ignoring the emitted element's own `tail`, whose visibility depends on chunking in
//! lxml as well — and the fatal error are the same as when the input is fed at once.
#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

mod common;

use common::{b64, run_flat};
use proptest::prelude::*;
use serde_json::Value;
use taky_xml::Element;

fn strip_tails(mut evs: Vec<Element>) -> Vec<Element> {
    for e in &mut evs {
        e.tail = None;
    }
    evs
}

fn split(data: &[u8], cuts: &[usize]) -> Vec<Vec<u8>> {
    let mut cs: Vec<usize> = cuts.iter().map(|c| c % (data.len() + 1)).collect();
    cs.sort_unstable();
    let mut out = Vec::new();
    let mut prev = 0;
    for c in cs {
        out.push(data[prev..c].to_vec());
        prev = c;
    }
    out.push(data[prev..].to_vec());
    out
}

fn check(data: &[u8], cuts: &[usize]) -> Result<(), TestCaseError> {
    let (whole, e1) = run_flat(&[data]);
    let chunks = split(data, cuts);
    let refs: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
    let (parts, e2) = run_flat(&refs);
    prop_assert_eq!(&e1, &e2);
    if e1.is_none() {
        prop_assert_eq!(strip_tails(whole), strip_tails(parts));
    }
    Ok(())
}

fn text() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select(vec![
            "", " ", "hi", "Ä", "Ж", "😀", "\r\n", "\r", "\t", "&amp;", "&lt;", "&#65;",
            "&#x20AC;", "&#13;", "]]", "x>y", "'", "\"", "&foo;",
        ]),
        0..4,
    )
    .prop_map(|v| v.concat())
}

fn attrs() -> impl Strategy<Value = String> {
    prop::collection::vec(
        (
            prop::sample::select(vec!["a", "uid", "xml:lang", "p:q", "xmlns:p", "how"]),
            prop::sample::select(vec![
                "",
                "v",
                " \t\n",
                "&amp;&#10;",
                "Ä",
                ">",
                "urn:x",
                "/",
                "&bar;",
            ]),
        ),
        0..3,
    )
    .prop_map(|v| {
        let mut seen = Vec::new();
        let mut s = String::new();
        for (k, val) in v {
            if !seen.contains(&k) {
                seen.push(k);
                s.push_str(&format!(" {k}='{val}'"));
            }
        }
        s
    })
}

fn node() -> impl Strategy<Value = String> {
    let leaf = prop_oneof![
        (
            prop::sample::select(vec!["event", "point", "detail", "a:event", "x"]),
            attrs()
        )
            .prop_map(|(n, a)| format!("<{n}{a}/>")),
        Just("<!-- c -->".to_owned()),
        Just("<?pinst data?>".to_owned()),
        Just("<![CDATA[a<b]]>".to_owned()),
    ];
    leaf.prop_recursive(5, 64, 4, |inner| {
        (
            prop::sample::select(vec!["event", "detail", "contact", "p:event", "b"]),
            attrs(),
            text(),
            prop::collection::vec((inner, text()), 0..4),
            any::<bool>(),
        )
            .prop_map(|(n, a, t, kids, sp)| {
                let body: String = kids.into_iter().map(|(k, t)| k + &t).collect();
                format!("<{n}{a}>{t}{body}</{n}{}>", if sp { " " } else { "" })
            })
    })
}

fn stream() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        (
            prop::sample::select(vec![
                "",
                "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>",
                "junk ",
            ]),
            node(),
        ),
        1..4,
    )
    .prop_map(|v| {
        v.into_iter()
            .map(|(d, n)| d.to_owned() + &n)
            .collect::<String>()
            .into_bytes()
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, .. ProptestConfig::default() })]

    #[test]
    fn random_documents_are_split_invariant(data in stream(), cuts in prop::collection::vec(any::<usize>(), 0..12)) {
        check(&data, &cuts)?;
    }

    #[test]
    fn random_garbage_never_panics(data in prop::collection::vec(any::<u8>(), 0..256), cuts in prop::collection::vec(any::<usize>(), 0..8)) {
        let mut d = b"<event a='1'>".to_vec();
        d.extend(data);
        check(&d, &cuts)?;
    }
}

fn vector_streams() -> &'static [Vec<u8>] {
    static CACHE: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
    CACHE.get_or_init(load_vector_streams)
}

fn load_vector_streams() -> Vec<Vec<u8>> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/lxml_stream.json"
    );
    let fx: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    fx["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            i["chunks_b64"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|c| b64(c.as_str().unwrap()))
                .collect()
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    /// The real streams of every vector connection and fixture case, re-split at random.
    #[test]
    fn vector_streams_are_split_invariant(idx in any::<prop::sample::Index>(), cuts in prop::collection::vec(any::<usize>(), 0..16)) {
        let streams = vector_streams();
        let data = &streams[idx.index(streams.len())];
        check(data, &cuts)?;
    }
}
