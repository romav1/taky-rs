//! Process shutdown signal (ARCHITECTURE §10): a thin wrapper over `CancellationToken`.

use tokio_util::sync::CancellationToken;

/// Shared "time to shut down" flag. Cloning is cheap; all clones see the same signal.
#[derive(Debug, Clone, Default)]
pub struct Shutdown {
    token: CancellationToken,
}

impl Shutdown {
    /// New signal that has not fired yet.
    pub fn new() -> Shutdown {
        Shutdown::default()
    }

    /// Request shutdown (SIGTERM/SIGINT, fatal Hub error).
    pub fn trigger(&self) {
        self.token.cancel();
    }

    /// `true` if shutdown has already been requested.
    pub fn is_triggered(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Wait for a shutdown request.
    pub async fn wait(&self) {
        self.token.cancelled().await;
    }

    /// Child signal: fires together with the parent, but can also be triggered separately
    /// (e.g. for a single subsystem).
    pub fn child(&self) -> Shutdown {
        Shutdown {
            token: self.token.child_token(),
        }
    }

    /// Access to the token (for `tokio::select!` and APIs that accept `CancellationToken`).
    pub fn token(&self) -> &CancellationToken {
        &self.token
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn trigger_wakes_clones_and_children() {
        let s = Shutdown::new();
        let c = s.clone();
        let ch = s.child();
        assert!(!c.is_triggered());
        s.trigger();
        c.wait().await;
        ch.wait().await;
        assert!(ch.is_triggered());
    }
}
