//! Port of `taky/tests/test_router.py` (test-strategy §2 rows 11–14, via `TestOutbox`, no
//! network) + Router rules from spec §6/§8–§12 and the slow-client policy (review-T-10 N-3).
//! `test_max_ttl.py` → `max_ttl.rs`, `test_takclient.py` → `takclient.rs` and
//! `taky-server/tests/socket_client.rs`.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use chrono::{NaiveDateTime, TimeDelta};
use common::{Bench, XML_EMPTY_MARTI_BC, XML_S};
use taky_cot::router::{SLOW_CLIENT, apply_max_ttl, pong_event};
use taky_cot::testkit::{ClientQuery, FakeClock, TestOutbox};
use taky_cot::{ClientId, ClientKind, Event, EventDetail, GeoChat, Persistence, Teams};
use taky_xml::parse_element;

fn t(s: &str) -> NaiveDateTime {
    taky_cot::isoparse::isoparse(s).unwrap()
}

fn plain_event(uid: &str, etype: &str, detail: &str, now: NaiveDateTime, ttl_s: i64) -> String {
    let f = |d: NaiveDateTime| format!("{}Z", d.format("%Y-%m-%dT%H:%M:%S%.3f"));
    format!(
        r#"<event version="2.0" uid="{uid}" type="{etype}" how="m-g" time="{}" start="{}" stale="{}"><point lat="1.0" lon="2.0" hae="0.0" ce="9.9" le="9.9"/>{detail}</event>"#,
        f(now),
        f(now),
        f(now + TimeDelta::seconds(ttl_s))
    )
}

/// A TAKUser detail; the user's uid is the event uid (`_uid` only documents the call sites).
fn sa(_uid: &str, cs: &str, team: &str) -> String {
    format!(
        r#"<detail><takv os="29" version="4" device="d" platform="ATAK-CIV"/><contact endpoint="*:-1:stcp" callsign="{cs}"/><__group role="Team Member" name="{team}"/></detail>"#
    )
}

// ---------------------------------------------------------------- test_router.py

/// `test_router.RouterTestcase.test_route_packet`.
#[tokio::test]
async fn route_packet() {
    let mut b = Bench::real_now();
    let tk1 = b.connect(1, ClientKind::Cot);
    let tk2 = b.connect(2, ClientKind::Cot);
    let msg = b.ident_msg(XML_S, TimeDelta::days(10));
    b.feed(tk1, &msg).await;
    assert_eq!(b.uids(tk2), vec!["ANDROID-deadbeef"]);
    assert!(b.out(tk1).is_empty());
    assert_eq!(
        b.router
            .find_clients(ClientQuery::Uid("ANDROID-deadbeef"))
            .len(),
        1
    );
    assert_eq!(
        b.router.find_clients(ClientQuery::Callsign("JENNY")).len(),
        1
    );
    assert_eq!(
        b.router.find_clients(ClientQuery::Callsign("FOOBAR")).len(),
        0
    );
}

/// `test_router.RouterTestcase.test_persist_announce`.
#[tokio::test]
async fn persist_announce() {
    let mut b = Bench::real_now();
    let tk1 = b.connect(1, ClientKind::Cot);
    let msg = b.ident_msg(XML_S, TimeDelta::days(10));
    b.feed(tk1, &msg).await;
    let tk2 = b.connect(2, ClientKind::Cot);
    b.router.send_persist(tk2).await;
    assert_eq!(b.uids(tk2), vec!["ANDROID-deadbeef"]);
    assert!(b.out(tk1).is_empty());
    // ...even if it re-mock identifies!
    b.router.send_persist(tk1).await;
    assert!(b.out(tk1).is_empty());
}

/// `test_router.RouterTestcase.test_geochat`.
#[tokio::test]
async fn geochat() {
    let mut b = Bench::real_now();
    let tk1 = b.connect(1, ClientKind::Cot);
    let msg = b.ident_msg(XML_S, TimeDelta::days(10));
    b.feed(tk1, &msg).await;
    // `route(None, evt)`: an anonymous registered sender stands in for `src=None`.
    let src = b.connect(99, ClientKind::Cot);
    let now = b.clock_now();
    let gc = GeoChat {
        src_cs: Some("TESTCASE".into()),
        src_uid: Some("ANDROID-cafebabe".into()),
        src_marker: Some("a-f-G-U-C".into()),
        dst_uid: Some("ANDROID-deadbeef".into()),
        chatroom: Some("JENNY".into()),
        chat_parent: Some("RootContactGroup".into()),
        message: Some("Hello world!".into()),
        message_ts: Some(now),
        ..GeoChat::default()
    };
    let evt = Event {
        version: Some("2.0".into()),
        uid: Some("GeoChat.ANDROID-deadbeef.TESTCASE.563040b9-2ac9-4af3-9e01-4cb2b05d98ea".into()),
        etype: Some("b-t-f".into()),
        how: Some("h-g-i-g-o".into()),
        time: now,
        start: now,
        stale: now + TimeDelta::days(1000),
        point: taky_cot::Point::default(),
        detail: Some(EventDetail::GeoChat(gc)),
    };
    b.router.on_event(src, evt).await;
    let got = b.recv(tk1);
    assert_eq!(got.len(), 1, "Message not routed to user");
    let Some(EventDetail::GeoChat(g)) = &got[0].detail else {
        panic!("not a GeoChat: {:?}", got[0].detail)
    };
    assert_eq!(g.message.as_deref(), Some("Hello world!"));
    assert!(b.out(src).is_empty());
}

/// `test_router.RouterTestcase.test_empty_marti`.
#[tokio::test]
async fn empty_marti() {
    let mut b = Bench::real_now();
    let tk1 = b.connect(1, ClientKind::Cot);
    let tk2 = b.connect(2, ClientKind::Cot);
    let msg = b.ident_msg(XML_EMPTY_MARTI_BC, TimeDelta::days(10));
    b.feed(tk1, &msg).await;
    assert_eq!(b.uids(tk2), vec!["EB77220E-6299-4CA3-95FC-0200BD9FE78A"]);
}

// ---------------------------------------------------------------- spec §6/§8–§12

#[tokio::test]
async fn monitor_copy_ping_pong_and_empty_type() {
    let mut b = Bench::real_now();
    let now = b.clock_now();
    let c1 = b.connect(1, ClientKind::Cot);
    let c2 = b.connect(2, ClientKind::Cot);
    let mon = b.connect(3, ClientKind::Monitor);

    // Ping: pong to the sender only (byte-exact), monitor gets a copy, not routed/persisted.
    b.feed(c1, &plain_event("ANDROID-1-ping", "t-x-c-t", "", now, 10))
        .await;
    let pong = b.out(c1).drain();
    assert_eq!(pong.len(), 1);
    let ts = format!("{}Z", now.format("%Y-%m-%dT%H:%M:%S%.3f"));
    let st = format!(
        "{}Z",
        (now + TimeDelta::seconds(20)).format("%Y-%m-%dT%H:%M:%S%.3f")
    );
    assert_eq!(
        std::str::from_utf8(&pong[0]).unwrap(),
        format!(
            r#"<event version="2.0" uid="takPong" type="t-x-c-t-r" how="h-g-i-g-o" time="{ts}" start="{ts}" stale="{st}"><point lat="0.000000" lon="0.000000" hae="0.0" ce="9999999.0" le="9999999.0"/></event>"#
        )
    );
    assert_eq!(
        &*pong_event(b.clock.as_ref()).to_frame().unwrap(),
        &*pong[0]
    );
    assert!(b.out(c2).is_empty());
    assert_eq!(b.uids(mon), vec!["ANDROID-1-ping"]);
    assert!(b.router.persist_snapshot().await.is_empty());

    // Empty type: monitor copy only.
    b.feed(c1, &plain_event("E", "", "", now, 10)).await;
    assert!(b.out(c2).is_empty() && b.out(c1).is_empty());
    assert_eq!(b.uids(mon), vec!["E"]);

    // Broadcast: the monitor receives it twice (copy + broadcast, V047).
    b.feed(c1, &plain_event("M-1", "a-f-G", "", now, 10)).await;
    assert_eq!(b.uids(mon), vec!["M-1", "M-1"]);
    assert_eq!(b.uids(c2), vec!["M-1"]);
    assert!(b.out(c1).is_empty());

    // A monitor's own events: no copy to itself, routed normally, ping gets a pong.
    b.feed(mon, &plain_event("M-2", "a-f-G", "", now, 10)).await;
    assert!(b.out(mon).is_empty());
    assert_eq!(b.uids(c1), vec!["M-2"]);
    b.feed(mon, &plain_event("mon-ping", "t-x-c-t", "", now, 10))
        .await;
    assert_eq!(b.uids(mon), vec!["takPong"]);
    // A monitor never identifies.
    b.feed(
        mon,
        &plain_event("MON", "a-f-G", &sa("MON", "MONCS", "Red"), now, 10),
    )
    .await;
    assert!(b.router.user(mon).is_none());
}

#[tokio::test]
async fn max_ttl_applied_to_monitor_copy_only_after_serialization() {
    let now = t("2022-01-01T00:00:00");
    let mut b = Bench::new(5, now);
    let c1 = b.connect(1, ClientKind::Cot);
    let c2 = b.connect(2, ClientKind::Cot);
    let mon = b.connect(3, ClientKind::Monitor);
    b.feed(c1, &plain_event("X", "a-f-G", "", now, 100)).await;
    let m = b.recv(mon);
    // copy: original stale; broadcast: corrected stale.
    assert_eq!(m[0].stale, now + TimeDelta::seconds(100));
    assert_eq!(m[1].stale, now + TimeDelta::seconds(5));
    assert_eq!(b.recv(c2)[0].stale, now + TimeDelta::seconds(5));
    // persisted with the corrected stale
    assert_eq!(
        b.router.persist_snapshot().await[0].stale,
        now + TimeDelta::seconds(5)
    );
}

#[tokio::test]
async fn max_ttl_variants() {
    let now = t("2022-01-01T00:00:00");
    let clock = FakeClock::new(now);
    let mk = |ttl| {
        Event::from_element(
            &parse_element(
                plain_event("X", "a-f-G", "", now, ttl).as_bytes(),
                &taky_cot::limits::STREAM_LIMITS,
            )
            .unwrap(),
        )
        .unwrap()
    };
    let mut e = mk(100);
    assert!(!apply_max_ttl(-1, &mut e, clock.as_ref()));
    assert!(!apply_max_ttl(100, &mut e, clock.as_ref())); // not > max
    assert!(apply_max_ttl(99, &mut e, clock.as_ref()));
    assert_eq!(e.stale, now + TimeDelta::seconds(99));
    // max_ttl = 0: stale = now ⇒ ttl 0 ⇒ not persisted (V041).
    let mut b = Bench::new(0, now);
    let c1 = b.connect(1, ClientKind::Cot);
    let c2 = b.connect(2, ClientKind::Cot);
    b.feed(c1, &plain_event("X", "a-f-G", "", now, 100)).await;
    assert_eq!(b.recv(c2)[0].stale, now);
    assert!(b.router.persist_snapshot().await.is_empty());
}

#[tokio::test]
async fn ident_replaced_by_later_sa() {
    let now = t("2022-01-01T00:00:00");
    let mut b = Bench::new(-1, now);
    let c1 = b.connect(1, ClientKind::Cot);
    b.feed(
        c1,
        &plain_event("U-1", "a-f-G-U-C", &sa("U-1", "ALPHA", "Red"), now, 60),
    )
    .await;
    assert_eq!(
        b.router.find_clients(ClientQuery::Callsign("ALPHA")),
        vec![c1]
    );
    // `type` starting with "a" (not "a-") still identifies; new uid/callsign/group win (V034).
    b.feed(
        c1,
        &plain_event("U-2", "atom", &sa("U-2", "BRAVO", "Blue"), now, 60),
    )
    .await;
    let u = b.router.user(c1).unwrap();
    assert_eq!(
        (u.uid.as_deref(), u.callsign.as_deref(), u.group),
        (Some("U-2"), Some("BRAVO"), Some(Teams::Blue))
    );
    // a non-"a" type with a TakUser detail does not identify
    b.feed(
        c1,
        &plain_event("U-3", "b-m-p", &sa("U-3", "CHARLIE", "Blue"), now, 60),
    )
    .await;
    assert_eq!(
        b.router.user(c1).unwrap().callsign.as_deref(),
        Some("BRAVO")
    );
}

fn chat(room: &str, parent: &str, dst: &str) -> String {
    format!(
        r#"<detail><__chat parent="{parent}" groupOwner="false" chatroom="{room}" id="{dst}" senderCallsign="ALPHA"><chatgrp uid0="U-1" uid1="{dst}" id="{dst}"/></__chat><link uid="U-1" type="a-f-G-U-C" relation="p-p"/><remarks source="BAO.F.ATAK.U-1" to="{dst}" time="2022-01-01T00:00:00.000Z">hi</remarks><marti><dest callsign="DELTA"/></marti></detail>"#
    )
}

#[tokio::test]
async fn geochat_broadcast_group_direct() {
    let now = t("2022-01-01T00:00:00");
    let mut b = Bench::new(-1, now);
    let a = b.connect(1, ClientKind::Cot);
    let red = b.connect(2, ClientKind::Cot);
    let blue = b.connect(3, ClientKind::Cot);
    let anon = b.connect(4, ClientKind::Cot);
    let mon = b.connect(5, ClientKind::Monitor);
    let delta = b.connect(6, ClientKind::Cot);
    for (id, uid, cs, team) in [
        (a, "U-1", "ALPHA", "Red"),
        (red, "U-2", "RED2", "Red"),
        (blue, "U-3", "BLUE3", "Blue"),
        (delta, "U-6", "DELTA", "Blue"),
    ] {
        b.feed(
            id,
            &plain_event(uid, "a-f-G-U-C", &sa(uid, cs, team), now, 60),
        )
        .await;
    }
    for (id, _) in b.outs.clone() {
        b.out(id).drain();
    }
    // All Chat Rooms → broadcast (not persisted: b-t-f not kept).
    b.feed(
        a,
        &plain_event(
            "GeoChat.1",
            "b-t-f",
            &chat("All Chat Rooms", "RootContactGroup", "All Chat Rooms"),
            now,
            60,
        ),
    )
    .await;
    for id in [red, blue, anon, mon, delta] {
        assert_eq!(b.recv(id).len(), if id == mon { 2 } else { 1 }, "{id:?}");
    }
    assert!(b.out(a).is_empty());
    assert_eq!(b.router.persist_snapshot().await.len(), 4);
    // TeamGroups → group (identified members of the team except the sender; no monitor/anon).
    b.feed(
        a,
        &plain_event(
            "GeoChat.2",
            "b-t-f",
            &chat("Red", "TeamGroups", "Red"),
            now,
            60,
        ),
    )
    .await;
    assert_eq!(b.recv(red).len(), 1);
    for id in [a, blue, anon, delta] {
        assert!(b.out(id).is_empty(), "{id:?}");
    }
    assert_eq!(b.recv(mon).len(), 1); // copy only
    // Direct → by `__chat@id`, GeoChat wins over marti (V033); to self is echoed.
    b.feed(
        a,
        &plain_event(
            "GeoChat.3",
            "b-t-f",
            &chat("BLUE3", "RootContactGroup", "U-3"),
            now,
            60,
        ),
    )
    .await;
    assert_eq!(b.recv(blue).len(), 1);
    assert!(b.out(delta).is_empty());
    b.out(mon).drain();
    b.feed(
        a,
        &plain_event(
            "GeoChat.4",
            "b-t-f",
            &chat("ALPHA", "RootContactGroup", "U-1"),
            now,
            60,
        ),
    )
    .await;
    assert_eq!(b.recv(a).len(), 1);
    // Unknown uid → lost.
    b.feed(
        a,
        &plain_event(
            "GeoChat.5",
            "b-t-f",
            &chat("X", "RootContactGroup", "NOPE"),
            now,
            60,
        ),
    )
    .await;
    for id in [a, red, blue, anon, delta] {
        assert!(b.out(id).is_empty(), "{id:?}");
    }
}

#[tokio::test]
async fn marti_routing_rules() {
    let now = t("2022-01-01T00:00:00");
    let mut b = Bench::new(-1, now);
    let a = b.connect(1, ClientKind::Cot);
    let x1 = b.connect(2, ClientKind::Cot);
    let x2 = b.connect(3, ClientKind::Cot); // same callsign on another socket (V025)
    let y = b.connect(4, ClientKind::Cot);
    for (id, uid, cs) in [
        (a, "U-1", "ALPHA"),
        (x1, "U-2", "XRAY"),
        (x2, "U-3", "XRAY"),
        (y, "U-4", "YANK"),
    ] {
        b.feed(
            id,
            &plain_event(uid, "a-f-G-U-C", &sa(uid, cs, "Cyan"), now, 60),
        )
        .await;
    }
    for (id, _) in b.outs.clone() {
        b.out(id).drain();
    }
    let m = |dests: &str| format!("<detail><marti>{dests}</marti></detail>");
    // Repeated callsign → repeated delivery; to own callsign → echo (V023/V025); not persisted.
    b.feed(
        a,
        &plain_event(
            "P-1",
            "b-m-p-s-p-i",
            &m(r#"<dest callsign="XRAY"/><dest callsign="ALPHA"/><dest callsign="XRAY"/>"#),
            now,
            60,
        ),
    )
    .await;
    assert_eq!(b.recv(x1).len(), 2);
    assert_eq!(b.recv(x2).len(), 2);
    assert_eq!(b.recv(a).len(), 1);
    assert!(b.out(y).is_empty());
    assert_eq!(b.router.persist_snapshot().await.len(), 4);
    // `<dest uid>` ignored (G-9), no callsign / empty callsign → nobody (V024).
    b.feed(
        a,
        &plain_event(
            "P-2",
            "b-m-p",
            &m(r#"<dest uid="U-4"/><dest callsign=""/>"#),
            now,
            60,
        ),
    )
    .await;
    for id in [a, x1, x2, y] {
        assert!(b.out(id).is_empty(), "{id:?}");
    }
    // Empty <marti/> → broadcast (test_empty_marti) and persisted.
    b.feed(a, &plain_event("P-3", "b-m-p", &m(""), now, 60))
        .await;
    assert_eq!(b.recv(y).len(), 1);
    assert_eq!(b.router.persist_snapshot().await.len(), 5);
}

#[tokio::test]
async fn persistence_rules_and_send_persist() {
    let now = t("2022-01-01T00:00:00");
    let mut b = Bench::new(-1, now);
    let c1 = b.connect(1, ClientKind::Cot);
    for (uid, etype, ttl) in [
        ("K-1", "a-f-G", 60),
        ("K-2", "b-m-p-w-GOTO", 60),
        ("K-3", "b-r-f-h-c", 60),
        ("K-4", "u-d-f", 60),
        ("N-1", "b-t-f", 60),
        ("N-2", "a", 60),
        ("N-3", "u-d-x", 60),
        ("N-4", "a-f-G", 0),
        ("N-5", "a-f-G", -5),
        ("K-1", "a-f-G", 30), // replaces, keeps position
    ] {
        b.feed(c1, &plain_event(uid, etype, "", now, ttl)).await;
    }
    let c2 = b.connect(2, ClientKind::Cot);
    b.router.send_persist(c2).await;
    let got = b.recv(c2);
    let uids: Vec<_> = got.iter().map(|e| e.uid.clone().unwrap()).collect();
    assert_eq!(uids, ["K-1", "K-2", "K-3", "K-4"]);
    assert_eq!(got[0].stale, now + TimeDelta::seconds(30));
    // A reconnecting client gets its own SA on connect (user is None, V039).
    b.feed(
        c1,
        &plain_event("U-1", "a-f-G-U-C", &sa("U-1", "ALPHA", "Red"), now, 60),
    )
    .await;
    let c3 = b.connect(3, ClientKind::Cot);
    b.router.send_persist(c3).await;
    assert_eq!(b.recv(c3).len(), 5);
    // Monitors get persist too; unknown id ignored.
    let mon = b.connect(4, ClientKind::Monitor);
    b.router.send_persist(mon).await;
    assert_eq!(b.recv(mon).len(), 5);
    b.router.send_persist(ClientId(77)).await;

    // Prune: stale events go once the clock passes them; maybe_prune runs at most every 10 s.
    b.clock.advance(TimeDelta::seconds(45));
    let t0 = tokio::time::Instant::now();
    b.router.maybe_prune(t0).await;
    let left: Vec<_> = b
        .router
        .persist_snapshot()
        .await
        .iter()
        .map(|e| e.uid.clone().unwrap())
        .collect();
    assert_eq!(left, ["K-2", "K-3", "K-4", "U-1"]);
    b.clock.advance(TimeDelta::seconds(30));
    b.router.maybe_prune(t0 + Duration::from_secs(10)).await; // not due
    if let Persistence::Memory(m) = b.router.persistence() {
        assert_eq!(m.len(), 4);
    }
    b.router.maybe_prune(t0 + Duration::from_secs(11)).await;
    if let Persistence::Memory(m) = b.router.persistence() {
        assert!(m.is_empty());
    }
}

#[tokio::test]
async fn d8_unserializable_event_dropped_not_persisted() {
    let now = t("2022-01-01T00:00:00");
    let mut b = Bench::new(-1, now);
    let c1 = b.connect(1, ClientKind::Cot);
    let c2 = b.connect(2, ClientKind::Cot);
    let mon = b.connect(3, ClientKind::Monitor);
    let no_how = plain_event("X", "a-f-G", "", now, 60).replace(r#" how="m-g""#, "");
    b.feed(c1, &no_how).await;
    assert!(b.out(c2).is_empty() && b.out(mon).is_empty());
    assert!(b.router.persist_snapshot().await.is_empty());
    // the router keeps working
    b.feed(c1, &plain_event("Y", "a-f-G", "", now, 60)).await;
    assert_eq!(b.uids(c2), ["Y"]);
}

#[tokio::test]
async fn slow_client_dropped_and_removed() {
    let now = t("2022-01-01T00:00:00");
    let mut b = Bench::new(-1, now);
    let src = b.connect(1, ClientKind::Cot);
    let slow = b.connect_with(2, ClientKind::Cot, TestOutbox::bounded(2));
    let ok = b.connect(3, ClientKind::Cot);
    for i in 0..2 {
        b.feed(src, &plain_event(&format!("E-{i}"), "a-f-G", "", now, 60))
            .await;
    }
    assert_eq!(b.router.dropped_frames(), 0);
    assert!(b.out(slow).closed().is_none());
    // Past the limit: frame dropped + counted, close("Slow client"), removed from the table.
    b.feed(src, &plain_event("E-2", "a-f-G", "", now, 60)).await;
    assert_eq!(b.out(slow).closed().as_deref(), Some(SLOW_CLIENT));
    assert_eq!(
        (b.router.dropped_frames(), b.router.slow_disconnects()),
        (1, 1)
    );
    assert!(b.router.client(slow).is_none());
    assert_eq!(b.out(slow).len(), 2); // queued frames are kept for the writer
    b.feed(src, &plain_event("E-3", "a-f-G", "", now, 60)).await;
    assert_eq!(b.router.dropped_frames(), 1); // no further fan-out to it
    assert_eq!(b.uids(ok), ["E-0", "E-1", "E-2", "E-3"]);
    // Its later events are dropped (unregistered source); Hub's Disconnected is a no-op.
    b.feed(slow, &plain_event("S-1", "a-f-G", "", now, 60))
        .await;
    assert!(b.out(ok).is_empty());
    b.router.client_disconnect(slow);

    // Repeated marti callsign to a full client: one drop, then no more attempts.
    let tight = b.connect_with(4, ClientKind::Cot, TestOutbox::bounded(0));
    b.router.testkit_set_user(
        tight,
        Some(taky_cot::TakUser {
            callsign: Some("T".into()),
            ..Default::default()
        }),
    );
    b.feed(
        src,
        &plain_event(
            "P",
            "b-m-p",
            r#"<detail><marti><dest callsign="T"/><dest callsign="T"/></marti></detail>"#,
            now,
            60,
        ),
    )
    .await;
    assert_eq!(
        (b.router.dropped_frames(), b.router.slow_disconnects()),
        (2, 2)
    );

    // Closed outbox: dropped, counted, removed, no close call.
    let gone = b.connect(5, ClientKind::Cot);
    {
        use taky_cot::Outbox;
        b.out(gone).close("peer reset");
    }
    b.feed(src, &plain_event("E-4", "a-f-G", "", now, 60)).await;
    assert_eq!(
        (b.router.dropped_frames(), b.router.slow_disconnects()),
        (3, 2)
    );
    assert!(b.router.client(gone).is_none());
    assert_eq!(b.out(gone).closed().as_deref(), Some("peer reset"));

    // send_persist into a full outbox follows the same policy.
    let late = b.connect_with(6, ClientKind::Cot, TestOutbox::bounded(1));
    b.router.send_persist(late).await;
    assert!(b.router.client(late).is_none());
    assert_eq!(b.out(late).closed().as_deref(), Some(SLOW_CLIENT));
}
