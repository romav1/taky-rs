//! S-312: the Hub actor driven in-process with real [`ConnOutbox`]es (no sockets): the
//! slow-client contract of ARCHITECTURE §6 / review-3B N-6.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use bytes::BytesMut;
use taky_common::clock::FakeClock;
use taky_cot::{
    ClientHandle, ClientId, ClientKind, ClientStats, CotDecoder, Event, Frame, Outbox, Persistence,
    Router,
};
use taky_server::limits::{OUTBOX_MAX_BYTES, OUTBOX_MAX_FRAMES};
use taky_server::{ConnOutbox, ConnectVerdict, Hub, HubCmd};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::Decoder;

fn event(uid: &str, remarks: usize) -> Event {
    let xml = format!(
        r#"<event version="2.0" uid="{uid}" type="b-t-f" time="2030-01-01T00:00:00Z" start="2030-01-01T00:00:00Z" stale="2030-01-01T00:10:00Z" how="h-g"><point lat="1" lon="2" hae="0" ce="1" le="1"/><detail><remarks>{}</remarks></detail></event>"#,
        "r".repeat(remarks)
    );
    let mut b = BytesMut::from(xml.as_bytes());
    let elm = CotDecoder::new().decode(&mut b).unwrap().unwrap();
    Event::from_element(&elm).unwrap()
}

fn hub() -> Hub {
    let clock =
        FakeClock::new(taky_cot::isoparse::isoparse("2030-01-01T00:00:00Z").unwrap()).shared();
    let router = Router::new(-1, Persistence::memory(clock.clone()), clock.clone());
    Hub::new(router, None, clock).0
}

async fn connect(hub: &mut Hub, id: u64) -> (Arc<ConnOutbox>, mpsc::UnboundedReceiver<Frame>) {
    let (ob, rx) = ConnOutbox::new();
    let (reply, verdict) = oneshot::channel();
    let handle = ClientHandle {
        id: ClientId(id),
        kind: ClientKind::Cot,
        outbox: ob.clone(),
        stats: Arc::new(ClientStats::new(0.0)),
        addr: None,
        peer_serial: Some(vec![1, 2, 3]), // no cert-db (plain) ⇒ no ban check
    };
    hub.handle(HubCmd::Connected { handle, reply }).await;
    assert_eq!(verdict.await.unwrap(), ConnectVerdict::Accepted);
    (ob, rx)
}

async fn send(hub: &mut Hub, from: u64, evt: Event) {
    hub.handle(HubCmd::Event {
        id: ClientId(from),
        event: Box::new(evt),
    })
    .await;
}

/// Frame limit: the 4097th undrained frame closes the client with "Slow client"; it is removed
/// at once, the later `Disconnected` is a no-op and its own events are dropped.
#[tokio::test]
async fn slow_client_by_frames() {
    let mut hub = hub();
    let (slow, _slow_rx) = connect(&mut hub, 1).await;
    let (fast, mut fast_rx) = connect(&mut hub, 2).await;
    for i in 0..OUTBOX_MAX_FRAMES {
        send(&mut hub, 2, event(&format!("u{i}"), 0)).await;
    }
    assert!(!slow.is_closed());
    assert_eq!(slow.pending(), OUTBOX_MAX_FRAMES);
    send(&mut hub, 2, event("over", 0)).await;
    assert_eq!(slow.close_reason(), Some("Slow client"));
    assert_eq!(slow.pending(), 0);

    // Removed: no-op disconnect (twice), and its events are no longer routed.
    hub.handle(HubCmd::Disconnected { id: ClientId(1) }).await;
    hub.handle(HubCmd::Disconnected { id: ClientId(1) }).await;
    send(&mut hub, 1, event("from-removed", 0)).await;
    assert!(fast_rx.try_recv().is_err());
    assert_eq!(fast.pending(), 0);
    // Unknown id: also a no-op.
    hub.handle(HubCmd::Disconnected { id: ClientId(99) }).await;
}

/// Byte limit: big frames hit 8 MiB long before 4096 frames.
#[tokio::test]
async fn slow_client_by_bytes() {
    let mut hub = hub();
    let (slow, _rx) = connect(&mut hub, 1).await;
    let _fast = connect(&mut hub, 2).await;
    let big = 512 * 1024;
    let mut sent = 0;
    while !slow.is_closed() {
        send(&mut hub, 2, event(&format!("b{sent}"), big)).await;
        sent += 1;
        assert!(sent < 100, "byte limit not enforced");
    }
    assert_eq!(slow.close_reason(), Some("Slow client"));
    assert!(sent <= OUTBOX_MAX_BYTES / big + 1, "sent {sent}");
    assert!(sent > OUTBOX_MAX_BYTES / (big + 1024) - 1, "sent {sent}");
}
