//! Port of `taky/tests/test_geo_chat.py` (test-strategy §2 row 9).
#![allow(clippy::unwrap_used)]

mod common;

use common::parse;
use taky_cot::{Event, EventDetail};

/// `test_geo_chat.py:XML_S` (byte-for-byte, including the indentation).
const XML_S: &str = r#"<event version="2.0" uid="GeoChat.ANDROID-deadbeef.JOKER MAN.563040b9-2ac9-4af3-9e01-4cb2b05d98ea" type="b-t-f" how="h-g-i-g-o" time="2021-02-23T22:28:22.191Z" start="2021-02-23T22:28:22.191Z" stale="2021-02-24T22:28:22.191Z">
  <point lat="1.234567" lon="-3.141592" hae="-25.8" ce="9.9" le="9999999.0"/>
  <detail>
    <__chat parent="RootContactGroup" groupOwner="false" chatroom="JOKER MAN" id="ANDROID-cafebabe" senderCallsign="JENNY">
      <chatgrp uid0="ANDROID-deadbeef" uid1="ANDROID-cafebabe" id="ANDROID-cafebabe"/>
    </__chat>
    <link uid="ANDROID-deadbeef" type="a-f-G-U-C" relation="p-p"/>
    <remarks source="BAO.F.ATAK.ANDROID-deadbeef" to="ANDROID-cafebabe" time="2021-02-23T22:28:22.191Z">test</remarks>
    <__serverdestination destinations="123.45.67.89:4242:tcp:ANDROID-deadbeef"/>
    <marti>
      <dest callsign="JOKER MAN"/>
    </marti>
  </detail>
</event>
"#;

/// `test_geo_chat.GeoChatTestcase.test_unmarshall`.
#[test]
fn unmarshall() {
    let elm = parse(XML_S);
    let event = Event::from_element(&elm).unwrap();
    let Some(EventDetail::GeoChat(chat)) = &event.detail else {
        panic!("expected GeoChat, got {:?}", event.detail)
    };
    assert_eq!(chat.chatroom.as_deref(), Some("JOKER MAN"));
    assert_eq!(chat.chat_parent.as_deref(), Some("RootContactGroup"));
    assert!(!chat.group_owner);
    assert!(!chat.broadcast());
    assert_eq!(chat.src_uid.as_deref(), Some("ANDROID-deadbeef"));
    assert_eq!(chat.src_cs.as_deref(), Some("JENNY"));
    assert_eq!(chat.src_marker.as_deref(), Some("a-f-G-U-C"));
    assert_eq!(chat.message.as_deref(), Some("test"));
    assert_eq!(chat.dst_uid.as_deref(), Some("ANDROID-cafebabe"));

    // Beyond the original (S-307): no team destination, the parsed detail goes on the wire as
    // the original element (spec §7.5), marti destinations are read.
    assert_eq!(chat.dst_team, None);
    assert_eq!(&chat.to_element().unwrap(), elm.find("detail").unwrap());
    assert_eq!(chat.marti_cs(), vec![Some("JOKER MAN".to_string())]);
}
