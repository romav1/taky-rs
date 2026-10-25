//! Port of `taky/tests/test_cot_event.py` (+ S-306 model checks: wire bytes, D-8, persist_ttl,
//! marti, detail dispatch, decoder).
#![allow(clippy::unwrap_used, clippy::approx_constant)] // test helpers outside #[test] fns; XML_S lon

use bytes::BytesMut;
use chrono::{NaiveDate, NaiveDateTime, TimeDelta};
use taky_common::clock::FakeClock;
use taky_cot::{CotDecoder, Event, EventDetail, UnmarshalError};
use taky_xml::{Element, Node, SerOpts, parse_element, serialize};
use tokio_util::codec::Decoder;

/// `taky/tests/__init__.py:XML_S`.
const XML_S: &str = r#"<event version="2.0" uid="ANDROID-deadbeef" type="a-f-G-U-C" how="m-g" time="2021-02-27T20:32:24.771Z" start="2021-02-27T20:32:24.771Z" stale="2021-02-27T20:38:39.771Z"><point lat="1.234567" lon="-3.141592" hae="-25.7" ce="9.9" le="9999999.0"/><detail><takv os="29" version="4.0.0.0 (deadbeef).1234567890-CIV" device="Some Android Device" platform="ATAK-CIV"/><contact xmppUsername="xmpp@host.com" endpoint="*:-1:stcp" callsign="JENNY"/><uid Droid="JENNY"/><precisionlocation altsrc="GPS" geopointsrc="GPS"/><__group role="Team Member" name="Cyan"/><status battery="78"/><track course="80.24833892285461" speed="0.0"/></detail></event>"#;

fn parse(s: &str) -> Element {
    parse_element(s.as_bytes(), &taky_cot::limits::STREAM_LIMITS).unwrap()
}

/// `taky/tests/__init__.py:elements_equal` (tag, text, tail, attrib, children).
fn elements_equal(a: &Element, b: &Element) {
    assert_eq!(a.tag, b.tag);
    assert_eq!(a.text, b.text, "text of {}", a.tag);
    assert_eq!(a.tail, b.tail, "tail of {}", a.tag);
    let (mut x, mut y) = (a.attrs.clone(), b.attrs.clone());
    x.sort();
    y.sort();
    assert_eq!(x, y, "attrib of {}", a.tag);
    assert_eq!(a.children.len(), b.children.len(), "len of {}", a.tag);
    for (c, d) in a.children.iter().zip(&b.children) {
        match (c, d) {
            (Node::Element(c), Node::Element(d)) => elements_equal(c, d),
            (c, d) => assert_eq!(c, d),
        }
    }
}

fn unmarshal_err(e: &Element) -> UnmarshalError {
    Event::from_element(e).unwrap_err()
}

#[test]
fn test_unmarshall() {
    let event = Event::from_element(&parse(XML_S)).unwrap();
    assert_eq!(event.version.as_deref(), Some("2.0"));
    assert_eq!(event.uid.as_deref(), Some("ANDROID-deadbeef"));
    assert_eq!(event.etype.as_deref(), Some("a-f-G-U-C"));
    assert_eq!(event.how.as_deref(), Some("m-g"));
    assert_eq!(event.time, event.start);
    let p = event.point;
    assert!((p.lat - 1.234567).abs() < 5e-7);
    assert!((p.lon + 3.141592).abs() < 5e-7);
    assert!((p.hae + 25.7).abs() < 0.05);
    assert!((p.ce - 9.9).abs() < 0.05);
    assert!((p.le - 9_999_999.0).abs() < 0.05);
    let d = event.detail.as_ref().unwrap();
    assert!(!d.has_marti());
    assert!(d.marti_cs().is_empty());
    // XML_S is a TAKUser detail (takv + contact + __group).
    let EventDetail::TakUser(u) = d else {
        panic!("expected TakUser, got {d:?}")
    };
    assert_eq!(u.callsign.as_deref(), Some("JENNY"));
    assert_eq!(u.uid.as_deref(), Some("ANDROID-deadbeef"));
    assert_eq!(u.xmpp, None); // the original never reads xmppUsername
    assert_eq!(u.course, Some(80.24833892285461));
}

#[test]
fn test_marshall() {
    let event = Event::from_element(&parse(XML_S)).unwrap();
    elements_equal(&parse(XML_S), &event.to_element().unwrap());
    // Stronger than the original: byte-exact wire form.
    assert_eq!(&*event.to_frame().unwrap(), XML_S.as_bytes());
}

#[test]
fn test_marshall_err_tagname() {
    let mut e = parse(XML_S);
    e.tag = "xxx".into();
    assert_eq!(unmarshal_err(&e).0, "Cannot create Event from xxx");
}

#[test]
fn test_marshall_err_ts_failure() {
    let mut e = parse(XML_S);
    e.set("start", "xxx");
    assert_eq!(unmarshal_err(&e).0, "Date parsing error");
}

fn first_child_mut(e: &mut Element, idx: usize) -> &mut Element {
    match &mut e.children[idx] {
        Node::Element(c) => c,
        n => panic!("{n:?}"),
    }
}

#[test]
fn test_marshall_err_invalid_point() {
    let mut e = parse(XML_S);
    first_child_mut(&mut e, 0).set("lat", "xxx");
    assert_eq!(unmarshal_err(&e).0, "Issue parsing point");
}

#[test]
fn test_marshall_err_no_uid() {
    let mut e = parse(XML_S);
    e.attrs.retain(|(k, _)| k != "uid");
    assert_eq!(unmarshal_err(&e).0, "Event must have 'uid' attribute");
}

#[test]
fn test_marshall_err_no_type() {
    let mut e = parse(XML_S);
    e.attrs.retain(|(k, _)| k != "type");
    assert_eq!(unmarshal_err(&e).0, "Event must have 'type' attribute");
}

#[test]
fn test_marti_exceptions() {
    let mut e = parse(XML_S);
    e.children.remove(1);
    let evt = Event::from_element(&e).unwrap();
    assert!(evt.detail.is_none());
}

// ---- S-306 additions ----

#[test]
fn marti_rules() {
    let ev = |d: &str| {
        let x = format!(
            r#"<event version="2.0" uid="M" type="a-u-G" how="h" time="2030-01-01" start="2030-01-01" stale="2030-01-02">{d}</event>"#
        );
        Event::from_element(&parse(&x)).unwrap().detail.unwrap()
    };
    assert!(!ev("<detail><marti/></detail>").has_marti());
    assert!(!ev("<detail><marti><x/></marti></detail>").has_marti());
    let d = ev(
        r#"<detail><marti><dest callsign="A"/><dest/><x callsign="Z"/></marti><marti><dest callsign="B"/></marti></detail>"#,
    );
    assert!(d.has_marti());
    assert_eq!(d.marti_cs(), vec![Some("A".to_string()), None]);
}

#[test]
fn rewrite_drops_extras_and_keeps_detail_tail() {
    // V011-like input plus whitespace/tails and a namespaced detail.
    let x = "<event version=\"2.0\" uid=\"RW-1\" type=\"a-u-G\" how=\"h-e\" access=\"x\" time=\"2030-01-01T03:00:00+03:00\" start=\"2030-01-01T00:00:00.123456Z\" stale=\"2030-01-01T00:10:00Z\">\n <point lat=\"1.23456789\" lon=\"2\" hae=\"3.06\" ce=\"4\" le=\"5\"/>\n <foo/>\n <detail xmlns:a=\"urn:a\"><a:x>\u{e9}</a:x></detail>\n</event>";
    let evt = Event::from_element(&parse(x)).unwrap();
    let out = String::from_utf8(evt.to_frame().unwrap().to_vec()).unwrap();
    assert_eq!(
        out,
        "<event version=\"2.0\" uid=\"RW-1\" type=\"a-u-G\" how=\"h-e\" time=\"2030-01-01T03:00:00.000Z\" start=\"2030-01-01T00:00:00.123Z\" stale=\"2030-01-01T00:10:00.000Z\"><point lat=\"1.234568\" lon=\"2.000000\" hae=\"3.1\" ce=\"4.0\" le=\"5.0\"/><detail xmlns:a=\"urn:a\"><a:x>&#233;</a:x></detail>\n</event>"
    );
}

#[test]
fn missing_version_or_how_d8() {
    let mut e = parse(XML_S);
    e.attrs.retain(|(k, _)| k != "version" && k != "how");
    let evt = Event::from_element(&e).unwrap();
    assert_eq!((evt.version.as_deref(), evt.how.as_deref()), (None, None));
    assert!(evt.to_frame().is_err());
    // to_element omits the absent attributes.
    let out = serialize(&evt.to_element().unwrap(), &SerOpts::default());
    assert!(out.starts_with(b"<event uid=\"ANDROID-deadbeef\" type=\"a-f-G-U-C\" time="));
}

#[test]
fn default_point_and_last_child_wins() {
    let x = r#"<event version="2.0" uid="P" type="a" how="h" time="2030-01-01" start="2030-01-01" stale="2030-01-01"><detail><a/></detail><detail><b/></detail></event>"#;
    let evt = Event::from_element(&parse(x)).unwrap();
    assert_eq!(evt.point, taky_cot::Point::default());
    let EventDetail::Plain(d) = evt.detail.unwrap() else {
        panic!()
    };
    assert_eq!(d.elm.child_elements().next().unwrap().tag, "b");
    let x = r#"<event version="2.0" uid="P" type="" how="h" time="2030-01-01" start="2030-01-01" stale="2030-01-01"><point lat="1" lon="1" hae="1" ce="1"/></event>"#;
    assert_eq!(unmarshal_err(&parse(x)).0, "Issue parsing point");
}

#[test]
fn detail_dispatch_errors() {
    let ev = |d: &str| {
        let x = format!(
            r#"<event version="2.0" uid="C" type="b-t-f" how="h" time="2030-01-01" start="2030-01-01" stale="2030-01-02">{d}</event>"#
        );
        Event::from_element(&parse(&x))
    };
    let chat = |parent: &str, room: &str, time: &str| {
        format!(
            r#"<detail><__chat parent="{parent}" chatroom="{room}" id="X" senderCallsign="S"><chatgrp/></__chat><link uid="L" type="a"/><remarks {time}>hi</remarks></detail>"#
        )
    };
    let ok = ev(&chat(
        "RootContactGroup",
        "Bob",
        r#"time="2030-01-01T00:00:00Z""#,
    ))
    .unwrap();
    let Some(EventDetail::GeoChat(g)) = ok.detail else {
        panic!()
    };
    assert_eq!(
        (g.dst_uid.as_deref(), g.message.as_deref()),
        (Some("X"), Some("hi"))
    );
    let e = ev(&chat("TeamGroups", "Nope", r#"time="2030-01-01""#)).unwrap_err();
    assert_eq!(e.0, "Issue parsing detail");
    let e = ev(&chat("RootContactGroup", "Bob", "")).unwrap_err();
    assert_eq!(e.0, "Issue parsing detail");
    let e = ev("<detail><__chat/><link/><remarks/></detail>").unwrap_err();
    assert_eq!(e.0, "Detail does not contain GeoChat");
    let e = ev(r#"<detail><takv/><contact/><__group/><track course="x" speed="1"/></detail>"#)
        .unwrap_err();
    assert_eq!(e.0, "Issue parsing detail");
    // TAKUser wins over GeoChat; an unknown team name is Teams.UNKNOWN (= Cyan).
    let both =
        ev(r#"<detail><takv/><contact/><__group name="??"/><__chat/><link/><remarks/></detail>"#)
            .unwrap();
    let Some(EventDetail::TakUser(u)) = both.detail else {
        panic!()
    };
    assert_eq!(u.group, Some(taky_cot::Teams::Cyan));
}

fn at(s: &str) -> NaiveDateTime {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f").unwrap()
}

#[test]
fn persist_ttl_uses_clock_and_half_even() {
    let mut evt = Event::from_element(&parse(XML_S)).unwrap();
    let clock = FakeClock::new(at("2021-02-27T20:32:24.771"));
    assert_eq!(evt.persist_ttl(&*clock.shared()), 375);
    evt.stale = at("2030-01-01T00:00:02.5");
    clock.set(at("2030-01-01T00:00:00"));
    assert_eq!(evt.persist_ttl(&*clock.shared()), 2);
    evt.stale = at("2030-01-01T00:00:03.5");
    assert_eq!(evt.persist_ttl(&*clock.shared()), 4);
    clock.set(at("2030-01-01T00:00:10"));
    assert_eq!(evt.persist_ttl(&*clock.shared()), -6);
    // utcnow() has microsecond resolution: nanoseconds of the clock are truncated.
    evt.stale = at("2030-01-01T00:00:00.5");
    let t = NaiveDate::from_ymd_opt(2030, 1, 1)
        .unwrap()
        .and_hms_nano_opt(0, 0, 0, 999)
        .unwrap();
    clock.set(t);
    assert_eq!(evt.persist_ttl(&*clock.shared()), 0);
    clock.advance(TimeDelta::days(-3650));
    assert_eq!(evt.persist_ttl(&*clock.shared()), 315_360_000);
}

#[test]
fn decoder_yields_events_across_chunks() {
    let mut dec = CotDecoder::new();
    let mut buf = BytesMut::new();
    let (a, b) = XML_S.split_at(100);
    buf.extend_from_slice(format!("<?xml version=\"1.0\"?>junk<x/>{a}").as_bytes());
    assert!(dec.decode(&mut buf).unwrap().is_none());
    assert!(buf.is_empty());
    buf.extend_from_slice(format!("{b}<wrap>{XML_S}</wrap>").as_bytes());
    let e1 = dec.decode(&mut buf).unwrap().unwrap();
    let e2 = dec.decode(&mut buf).unwrap().unwrap();
    assert!(dec.decode(&mut buf).unwrap().is_none());
    for e in [e1, e2] {
        let evt = Event::from_element(&e).unwrap();
        assert_eq!(&*evt.to_frame().unwrap(), XML_S.as_bytes());
    }
    buf.extend_from_slice(b"<!DOCTYPE x>");
    let err = dec.decode(&mut buf).unwrap_err();
    assert!(err.to_string().starts_with("XML Syntax Error"), "{err}");
    assert!(dec.decode_eof(&mut buf).is_err());
}
