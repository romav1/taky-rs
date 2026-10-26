//! Port of `taky/tests/test_max_ttl.py` (test-strategy §2 row 10): `mock.patch(dt.utcnow)` in
//! router/event/persistence ⇒ one `FakeClock` shared by Router and Persistence.
#![cfg(feature = "testkit")]
#![allow(clippy::unwrap_used)]

mod common;

use chrono::{NaiveDate, TimeDelta};
use common::{Bench, XML_S};
use taky_cot::ClientKind;

/// `test_max_ttl.RouterMaxTTLTestcase.test_max_ttl`.
#[tokio::test]
async fn max_ttl() {
    let max_ttl_s = 10;
    let now = NaiveDate::from_ymd_opt(2022, 1, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    let mut b = Bench::new(max_ttl_s, now);
    let tk1_ident_msg = b.ident_msg(XML_S, TimeDelta::days(10));
    // setUp creates tk2 too; its id is used before it connects (as in the original).
    let tk2 = taky_cot::ClientId(2);

    // TK1 connects, and identifies
    let tk1 = b.connect(1, ClientKind::Cot);
    b.router.send_persist(tk2).await; // tk2 not connected yet: nothing to send
    b.feed(tk1, &tk1_ident_msg).await;

    // TK2 connects, and mock identifies. It should receive info about TK1
    let tk2 = b.connect(tk2.0, ClientKind::Cot);
    b.router.send_persist(tk2).await;
    let ret = b.recv(tk2);
    assert_eq!(ret.len(), 1);
    assert_eq!(ret[0].uid.as_deref(), Some("ANDROID-deadbeef"));
    assert_eq!(ret[0].persist_ttl(b.clock.as_ref()), max_ttl_s);
    // Extra: the clamp is `stale = utcnow() + max_ttl`.
    assert_eq!(ret[0].stale, now + TimeDelta::seconds(max_ttl_s));
}
