//! CoT core for taky-rs (owner: dev01): models, streaming decoder, `Router`,
//! `Persistence` (memory/Redis) and the CoT log (ARCHITECTURE §1, §4, §13, §14).
//!
//! The dev01↔dev02 seams (ARCHITECTURE §14) live here:
//! * [`client`] — [`ClientId`], [`ClientKind`], the [`Outbox`] trait (implemented by dev02),
//!   [`ClientStats`], [`ClientHandle`];
//! * [`router`] — [`Router`], called **only** by the `Hub` actor (taky-server, dev02);
//! * [`persist`] — [`Persistence`] (enum: memory | Redis);
//! * [`decoder`] — [`CotDecoder`] (`tokio_util::codec::Decoder`, stream → `<event>` elements);
//! * [`models`] — [`Event`] and friends, [`Frame`];
//! * [`isoparse`] — `dateutil.parser.isoparse` port (U001);
//! * [`cotlog`] — [`CotLogger`] (`log_cot`);
//! * [`testkit`] (feature `testkit`) — [`testkit::TestOutbox`] and test-only Router hooks.
//!
//! Status: models + decoder (S-306/S-307), Router + memory persistence (S-308) implemented;
//! Redis persistence, `Persistence::from_config`, CoT log — S-309.

pub mod client;
pub mod cotlog;
pub mod decoder;
pub mod isoparse;
pub mod limits;
pub mod models;
pub mod persist;
pub mod router;
#[cfg(feature = "testkit")]
pub mod testkit;

pub use client::{AtomicF64, ClientHandle, ClientId, ClientKind, ClientStats, Outbox, OutboxError};
pub use cotlog::CotLogger;
pub use decoder::{CotDecoder, CotStreamError};
pub use models::{
    Detail, Event, EventDetail, Frame, GeoChat, Point, SerializeError, TakDevice, TakUser, Teams,
    UnmarshalError,
};
pub use persist::{MemoryPersistence, Persistence, RedisPersistence};
pub use router::Router;
