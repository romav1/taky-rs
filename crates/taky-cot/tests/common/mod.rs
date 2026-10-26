//! Shared fixtures of the original `taky/tests/__init__.py` (test-strategy §2):
//! `XML_S`, `XML_EMPTY_MARTI_BC` (bytes 1:1), `elements_equal` → [`assert_elements_equal`],
//! `UnittestTAKClient` + `COTRouter` → [`Bench`] (feature `testkit`: Router clients with a
//! `TestOutbox` as their `queue`).
//!
//! `UnittestTAKClient.__init__` calls the `connect` callback (`router.send_persist`) on creation;
//! in every original test that happens in `setUp` with empty persistence, so it is a no-op and
//! [`Bench::connect`] does not repeat it.
#![allow(dead_code, clippy::unwrap_used)] // each test binary uses a subset; test helpers

use taky_xml::{Element, Node, parse_element};

/// `taky/tests/__init__.py:XML_S` (also `test_cot_event.py`, `test_takclient.py`).
pub const XML_S: &str = r#"<event version="2.0" uid="ANDROID-deadbeef" type="a-f-G-U-C" how="m-g" time="2021-02-27T20:32:24.771Z" start="2021-02-27T20:32:24.771Z" stale="2021-02-27T20:38:39.771Z"><point lat="1.234567" lon="-3.141592" hae="-25.7" ce="9.9" le="9999999.0"/><detail><takv os="29" version="4.0.0.0 (deadbeef).1234567890-CIV" device="Some Android Device" platform="ATAK-CIV"/><contact xmppUsername="xmpp@host.com" endpoint="*:-1:stcp" callsign="JENNY"/><uid Droid="JENNY"/><precisionlocation altsrc="GPS" geopointsrc="GPS"/><__group role="Team Member" name="Cyan"/><status battery="78"/><track course="80.24833892285461" speed="0.0"/></detail></event>"#;

/// `taky/tests/__init__.py:XML_EMPTY_MARTI_BC`.
pub const XML_EMPTY_MARTI_BC: &str = r#"
<event version="2.0" uid="EB77220E-6299-4CA3-95FC-0200BD9FE78A" type="a-u-G" how="h-g-i-g-o" time="2023-01-12T09:53:31.000Z" start="2023-01-12T09:53:31.000Z" stale="2023-01-12T09:55:31.000Z">
    <point lat="54.338986" lon="9.755263" hae="0.0" ce="0.0" le="0.0"/>
    <detail>
        <contact callsign="poop"/>
        <precisionlocation geopointsrc="???" altsrc="???"/>
        <status readiness="true"/>
        <archive/>
        <link uid="1874F828-5CF1-4289-B6C0-D4F6ABFB0B4D" production_time="2023-01-12T09:53:31Z" type="a-f-G-U-C" parent_callsign="FM05-iOS" relation="p-p"/>
        <usericon iconsetpath="COT_MAPPING_2525B/a-u/a-u-G"/>
        <color argb="-1"/>
        <marti/>
        <remarks/>
    </detail>
</event>
"#;

/// `etree.fromstring` (leading/trailing whitespace of the fixtures is not part of the tree).
pub fn parse(s: &str) -> Element {
    parse_element(s.trim().as_bytes(), &taky_cot::limits::STREAM_LIMITS).unwrap()
}

/// `taky/tests/__init__.py:elements_equal`: tag, text, tail, attrib (as a dict), length, then
/// children pairwise; panics with the original's `ValueError` texts.
pub fn assert_elements_equal(e1: &Element, e2: &Element) {
    assert!(e1.tag == e2.tag, "Tags differ: {} != {}", e1.tag, e2.tag);
    assert!(
        e1.text == e2.text,
        "Text differs: '{:?}' != '{:?}'",
        e1.text,
        e2.text
    );
    assert!(
        e1.tail == e2.tail,
        "Tail differs: '{:?}' != '{:?}'",
        e1.tail,
        e2.tail
    );
    let (mut a, mut b) = (e1.attrs.clone(), e2.attrs.clone());
    a.sort();
    b.sort();
    assert!(
        a == b,
        "Attrib differs {}.attrib != {}.attrib ({a:?} != {b:?})",
        e1.tag,
        e2.tag
    );
    // lxml `len(e)` and iteration include comments and PIs (compared by value here).
    assert!(
        e1.children.len() == e2.children.len(),
        "Length differs: len({})({}) != len({})({})",
        e1.tag,
        e1.children.len(),
        e2.tag,
        e2.children.len()
    );
    for (x, y) in e1.children.iter().zip(&e2.children) {
        match (x, y) {
            (Node::Element(x), Node::Element(y)) => assert_elements_equal(x, y),
            (x, y) => assert_eq!(x, y),
        }
    }
}

/// Python `datetime.isoformat()` of a naive datetime: no fraction when microseconds are 0.
pub fn py_isoformat(d: chrono::NaiveDateTime) -> String {
    use chrono::Timelike;
    if d.nanosecond() / 1000 == 0 {
        d.format("%Y-%m-%dT%H:%M:%S").to_string()
    } else {
        d.format("%Y-%m-%dT%H:%M:%S%.6f").to_string()
    }
}

#[cfg(feature = "testkit")]
#[allow(unused_imports)] // not every test binary uses the Bench
pub use bench::Bench;

#[cfg(feature = "testkit")]
mod bench {
    use std::sync::Arc;

    use bytes::BytesMut;
    use chrono::{NaiveDate, NaiveDateTime, TimeDelta};
    use taky_cot::testkit::{FakeClock, TestOutbox};
    use taky_cot::{
        ClientHandle, ClientId, ClientKind, ClientStats, CotDecoder, Event, Persistence, Router,
    };
    use taky_xml::parse_element;
    use tokio_util::codec::Decoder;

    /// `COTRouter` (memory persistence, `FakeClock`) + `UnittestTAKClient`s.
    pub struct Bench {
        pub clock: Arc<FakeClock>,
        pub router: Router,
        pub outs: Vec<(ClientId, Arc<TestOutbox>)>,
    }

    impl Bench {
        pub fn new(max_ttl: i64, now: NaiveDateTime) -> Bench {
            let clock = FakeClock::new(now);
            let router = Router::new(max_ttl, Persistence::memory(clock.shared()), clock.shared());
            Bench {
                clock,
                router,
                outs: Vec::new(),
            }
        }

        /// `datetime.utcnow()` stand-in used by the original tests.
        pub fn real_now() -> Bench {
            Bench::new(
                -1,
                NaiveDate::from_ymd_opt(2026, 10, 25)
                    .unwrap()
                    .and_hms_micro_opt(12, 0, 0, 123_456)
                    .unwrap(),
            )
        }

        pub fn connect_with(
            &mut self,
            id: u64,
            kind: ClientKind,
            out: Arc<TestOutbox>,
        ) -> ClientId {
            let id = ClientId(id);
            self.router.client_connect(ClientHandle {
                id,
                kind,
                outbox: out.clone(),
                stats: Arc::new(ClientStats::new(0.0)),
                addr: None,
                peer_serial: None,
            });
            self.outs.push((id, out));
            id
        }

        /// `router.client_connect(tk)`.
        pub fn connect(&mut self, id: u64, kind: ClientKind) -> ClientId {
            self.connect_with(id, kind, TestOutbox::new())
        }

        pub fn out(&self, id: ClientId) -> &Arc<TestOutbox> {
            &self.outs.iter().find(|(i, _)| *i == id).unwrap().1
        }

        /// Frames received by `id`, re-parsed (`UnittestTAKClient.queue`).
        pub fn recv(&self, id: ClientId) -> Vec<Event> {
            self.out(id)
                .drain()
                .iter()
                .map(|f| {
                    Event::from_element(
                        &parse_element(f, &taky_cot::limits::STREAM_LIMITS).unwrap(),
                    )
                    .unwrap()
                })
                .collect()
        }

        pub fn uids(&self, id: ClientId) -> Vec<String> {
            self.recv(id).into_iter().map(|e| e.uid.unwrap()).collect()
        }

        /// `TAKClient.feed`: decoder → `Event::from_element` → `Router::on_event`.
        pub async fn feed(&mut self, src: ClientId, data: &str) {
            let mut dec = CotDecoder::new();
            let mut buf = BytesMut::from(data.as_bytes());
            while let Some(elm) = dec.decode(&mut buf).unwrap() {
                let Ok(evt) = Event::from_element(&elm) else {
                    continue;
                };
                self.router.on_event(src, evt).await;
            }
        }

        /// The fixture with time/start = now and stale = now + `ttl` (the tests'
        /// `elm.set(..., now.isoformat())` + `etree.tostring(elm)`).
        pub fn ident_msg(&self, xml: &str, ttl: TimeDelta) -> String {
            let now = self.clock_now();
            let mut e = super::parse(xml);
            e.set("time", super::py_isoformat(now));
            e.set("start", super::py_isoformat(now));
            e.set("stale", super::py_isoformat(now + ttl));
            String::from_utf8(taky_xml::serialize(&e, &taky_xml::SerOpts::default())).unwrap()
        }

        pub fn clock_now(&self) -> NaiveDateTime {
            use taky_common::Clock;
            self.clock.utc_now()
        }
    }
}
