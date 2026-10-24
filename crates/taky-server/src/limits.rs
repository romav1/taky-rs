//! Backpressure and timeout constants (ARCHITECTURE §6). Moving them to `taky.conf` — Q-3.

use std::time::Duration;

/// Capacity of the shared conn→Hub `mpsc` (`send().await` ⇒ natural TCP backpressure).
pub const HUB_QUEUE: usize = 1024;
/// Client outbox limit in bytes; overflow ⇒ disconnect `"Slow client"`.
pub const OUTBOX_MAX_BYTES: usize = 8 * 1024 * 1024;
/// Client outbox limit in frames; overflow ⇒ disconnect `"Slow client"`.
pub const OUTBOX_MAX_FRAMES: usize = 4096;
/// TLS handshake timeout (log `"SSL Handshake timeout"`).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-frame `write_all` timeout ⇒ disconnect.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Hub `Tick` period (drives `Router::maybe_prune`).
pub const TICK_INTERVAL: Duration = Duration::from_secs(1);
