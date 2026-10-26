//! Port of `taky/tests/test_takclient.py::TAKClientTest` (test-strategy §2 row 15):
//! `TAKClient.feed()` ⇒ `CotDecoder` + `Router::on_event`; `tk.user` ⇒ `Router::user`.
//! `SocketTAKClientTest` (row 16) is `taky-server/tests/socket_client.rs`.
#![cfg(feature = "testkit")]
#![allow(clippy::unwrap_used)]

mod common;

use common::{Bench, XML_S};
use taky_cot::{ClientKind, Teams};

/// `test_takclient.TAKClientTest.test_ident`.
#[tokio::test]
async fn ident() {
    let mut b = Bench::real_now();
    let tk = b.connect(1, ClientKind::Cot);
    b.feed(tk, XML_S).await;

    let u = b.router.user(tk).unwrap();
    assert_eq!(u.callsign.as_deref(), Some("JENNY"));
    assert_eq!(u.uid.as_deref(), Some("ANDROID-deadbeef"));
    assert_eq!(u.device.os.as_deref(), Some("29"));
    assert_eq!(u.device.device.as_deref(), Some("Some Android Device"));
    assert_eq!(u.group, Some(Teams::Cyan));
    assert_eq!(u.battery.as_deref(), Some("78"));
    assert_eq!(u.role.as_deref(), Some("Team Member"));
}
