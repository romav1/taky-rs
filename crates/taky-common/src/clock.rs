//! Injectable clock (qa01 test-strategy §4.6, ADR-008).
//!
//! Every place where the original calls `datetime.utcnow()` / `time.time()` gets the time
//! only through [`Clock`]: `Event::persist_ttl`, `Router` (max_ttl, prune, pong), `Persistence`,
//! mgmt (`uptime`, `connected`, `last_rx`), DPS `SubmissionDateTime`, `CertDb::revoke`.
//! Periodic timers (prune 10 s, handshake 10 s) use `tokio::time`, so that in tests
//! `tokio::time::pause()/advance()` work.
//!
//! In tests — [`FakeClock`] (feature `testkit`).

use std::sync::Arc;

use chrono::{NaiveDateTime, Utc};

/// Source of "current time".
///
/// Implementations must be thread-safe: a single instance is shared by the Hub actor,
/// connection tasks and DPS.
pub trait Clock: Send + Sync + 'static {
    /// Current UTC time without a zone — analogue of `datetime.utcnow()`.
    fn utc_now(&self) -> NaiveDateTime;

    /// Seconds since the Unix epoch (fractional) — analogue of `time.time()`.
    ///
    /// Must be consistent with [`Clock::utc_now`] (the same instant).
    fn epoch(&self) -> f64;
}

impl std::fmt::Debug for dyn Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Clock({})", self.utc_now())
    }
}

/// Shared clock; passed to the constructors of `Router`, `Persistence`, the server and DPS.
pub type SharedClock = Arc<dyn Clock>;

/// System clock (production).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl SystemClock {
    /// System clock as a [`SharedClock`].
    pub fn shared() -> SharedClock {
        Arc::new(SystemClock)
    }
}

impl Clock for SystemClock {
    fn utc_now(&self) -> NaiveDateTime {
        Utc::now().naive_utc()
    }

    fn epoch(&self) -> f64 {
        naive_to_epoch(Utc::now().naive_utc())
    }
}

/// Convert naive UTC to seconds since the epoch (fractional, microsecond precision).
pub fn naive_to_epoch(t: NaiveDateTime) -> f64 {
    let utc = t.and_utc();
    utc.timestamp() as f64 + f64::from(utc.timestamp_subsec_micros()) / 1_000_000.0
}

#[cfg(feature = "testkit")]
pub use fake::FakeClock;

#[cfg(feature = "testkit")]
mod fake {
    use std::sync::{Arc, Mutex, PoisonError};

    use chrono::{NaiveDateTime, TimeDelta};

    use super::{Clock, SharedClock, naive_to_epoch};

    /// Controllable clock for tests (feature `testkit`): time stands still until it is moved.
    ///
    /// Replaces `mock.patch("...dt.utcnow")` from `taky/tests/test_max_ttl.py` and the frozen
    /// `now` of the an01 vectors.
    #[derive(Debug)]
    pub struct FakeClock {
        now: Mutex<NaiveDateTime>,
    }

    impl FakeClock {
        /// Clock stopped at `at`.
        pub fn new(at: NaiveDateTime) -> Arc<FakeClock> {
            Arc::new(FakeClock {
                now: Mutex::new(at),
            })
        }

        /// The same clock as a [`SharedClock`] (to pass to constructors).
        pub fn shared(self: &Arc<Self>) -> SharedClock {
            self.clone()
        }

        /// Set the current time.
        pub fn set(&self, at: NaiveDateTime) {
            *self.now.lock().unwrap_or_else(PoisonError::into_inner) = at;
        }

        /// Move time forward (or backward for a negative `by`).
        pub fn advance(&self, by: TimeDelta) {
            let mut g = self.now.lock().unwrap_or_else(PoisonError::into_inner);
            *g += by;
        }
    }

    impl Clock for FakeClock {
        fn utc_now(&self) -> NaiveDateTime {
            *self.now.lock().unwrap_or_else(PoisonError::into_inner)
        }

        fn epoch(&self) -> f64 {
            naive_to_epoch(self.utc_now())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_consistent() {
        let c = SystemClock;
        let a = naive_to_epoch(c.utc_now());
        let b = c.epoch();
        assert!((b - a).abs() < 5.0);
    }

    #[test]
    fn epoch_of_known_instant() {
        let t = chrono::NaiveDate::from_ymd_opt(1970, 1, 1)
            .unwrap()
            .and_hms_micro_opt(0, 0, 1, 500_000)
            .unwrap();
        assert_eq!(naive_to_epoch(t), 1.5);
    }

    #[cfg(feature = "testkit")]
    #[test]
    fn fake_clock_advances() {
        let t0 = chrono::NaiveDate::from_ymd_opt(2021, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        let c = FakeClock::new(t0);
        let shared = c.shared();
        c.advance(chrono::TimeDelta::seconds(10));
        assert_eq!(shared.utc_now(), t0 + chrono::TimeDelta::seconds(10));
        assert_eq!(shared.epoch(), 1_609_459_210.0);
    }
}
