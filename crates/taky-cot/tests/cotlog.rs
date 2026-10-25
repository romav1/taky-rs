//! S-313: `CotLogger` (spec §15, review-3B N-1, D-12) without sockets.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

use taky_common::SharedClock;
use taky_common::clock::FakeClock;
use taky_cot::cotlog::sanitize_file_name;
use taky_cot::{ClientKind, CotLogger, Event};
use taky_xml::{Element, Limits};

fn clock() -> SharedClock {
    FakeClock::new(taky_cot::isoparse::isoparse("2030-01-01T00:00:00Z").unwrap()).shared()
}

fn elm(xml: &str) -> Element {
    taky_xml::parse_element(xml.as_bytes(), &Limits::default()).unwrap()
}

fn sa(uid: &str, cs: &str) -> String {
    format!(
        r#"<event version="2.0" uid="{uid}" type="a-f-G-U-C" time="2030-01-01T00:00:00.000Z" start="2030-01-01T00:00:00.000Z" stale="2030-01-01T00:10:00.000Z" how="m-g"><point lat="1.0" lon="2.0" hae="0.0" ce="1.0" le="1.0"/><detail><takv os="29" version="4.10.0" device="PIXEL 7" platform="ATAK-CIV"/><contact endpoint="*:-1:stcp" callsign="{cs}"/><__group role="Team Member" name="Cyan"/></detail></event>"#
    )
}

const MARKER: &str = r#"<event version="2.0" uid="M-1" type="b-m-p" time="2030-01-01T00:00:00.000Z" start="2030-01-01T00:00:00.000Z" stale="2030-01-01T00:10:00.000Z" how="h-g-i-g-o"><point lat="1.0" lon="2.0" hae="0.0" ce="1.0" le="1.0"/></event>"#;

fn feed(lg: &mut CotLogger, xml: &str) {
    let e = elm(xml);
    lg.on_event(&e, &Event::from_element(&e).unwrap());
}

fn files(dir: &Path) -> BTreeMap<String, String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().into_string().unwrap(),
                std::fs::read_to_string(e.path()).unwrap(),
            )
        })
        .collect()
}

fn ip() -> Option<IpAddr> {
    Some("10.1.2.3".parse().unwrap())
}

/// First identification closes the anonymous file; a later SA with another callsign keeps the
/// already open `<uid>-<callsign>.cot` (client.py:336); max_ttl applies to the logged copy.
#[test]
fn identification_and_file_names() {
    let d = tempfile::tempdir().unwrap();
    let mut lg = CotLogger::new(Some(d.path()), ClientKind::Cot, ip(), 60, clock());
    feed(&mut lg, MARKER);
    feed(&mut lg, &sa("U-1", "ONE"));
    feed(&mut lg, &sa("U-1", "TWO"));
    feed(&mut lg, MARKER);
    let f = files(d.path());
    assert_eq!(
        f.keys().collect::<Vec<_>>(),
        ["U-1-ONE.cot", "anonymous-10.1.2.3.cot"]
    );
    assert_eq!(f["anonymous-10.1.2.3.cot"].matches("<event ").count(), 1);
    let main = &f["U-1-ONE.cot"];
    assert_eq!(main.matches("<event ").count(), 3);
    assert!(main.contains(r#"callsign="TWO""#));
    // max_persist_ttl = 60: stale corrected in the log.
    assert_eq!(
        main.matches(r#"stale="2030-01-01T00:01:00.000Z""#).count(),
        3
    );
    assert!(!main.contains("00:10:00"));
}

/// Pings, empty types and `*-ping` uids are not logged; a monitor never identifies.
#[test]
fn skips_and_monitor() {
    let d = tempfile::tempdir().unwrap();
    let mut lg = CotLogger::new(Some(d.path()), ClientKind::Monitor, ip(), -1, clock());
    feed(&mut lg, &MARKER.replace("b-m-p", "t-x-c-t"));
    feed(&mut lg, &MARKER.replace(r#"type="b-m-p""#, r#"type="""#));
    feed(&mut lg, &MARKER.replace("M-1", "M-1-ping"));
    assert!(files(d.path()).is_empty());
    feed(&mut lg, &sa("U-1", "ONE"));
    let f = files(d.path());
    assert_eq!(f.keys().collect::<Vec<_>>(), ["monitor-10.1.2.3.cot"]);
}

/// Error records: original element + `<__taky_err>`; an error text that is not a valid XML
/// comment skips the record (lxml ValueError); D-12 names; no address ⇒ no file.
#[test]
fn errors_traversal_and_no_addr() {
    let d = tempfile::tempdir().unwrap();
    let mut lg = CotLogger::new(Some(d.path()), ClientKind::Cot, ip(), -1, clock());
    let bad = elm(r#"<event uid="x" b="1"><point/></event>"#);
    lg.on_error(&bad, "boom\n");
    lg.on_error(&bad, "a -- b");
    lg.on_error(&bad, "ends-");
    let f = files(d.path());
    assert_eq!(
        f["anonymous-10.1.2.3.cot"],
        "<event uid=\"x\" b=\"1\">\n  <point/>\n  <__taky_err>\n    <!--boom\n-->\n  </__taky_err>\n</event>\n"
    );

    let d2 = tempfile::tempdir().unwrap();
    let mut lg = CotLogger::new(Some(d2.path()), ClientKind::Cot, None, -1, clock());
    feed(&mut lg, MARKER);
    assert!(
        files(d2.path()).is_empty(),
        "anonymous without an address: no file"
    );
    feed(&mut lg, &sa("../../x", "a/b"));
    assert_eq!(
        files(d2.path()).keys().collect::<Vec<_>>(),
        [".._.._x-a_b.cot"]
    );
    assert_eq!(sanitize_file_name(".."), "_");
}
