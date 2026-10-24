//! Limits of the CoT core (ARCHITECTURE §6). Constants for now; moving them to `taky.conf` — Q-3.

use taky_xml::Limits;

/// Limits of one top-level element in the CoT stream (D-2): 4 MiB, depth 256, 256 attributes,
/// names up to 1 KiB. Exceeding them ⇒ disconnect `"XML Syntax Error"`.
pub const STREAM_LIMITS: Limits = Limits::DEFAULT;

/// Interval of `Router::maybe_prune` (the original prunes every 10 s).
pub const PRUNE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_limits_match_architecture() {
        assert_eq!(STREAM_LIMITS.max_bytes, 4 << 20);
        assert_eq!(STREAM_LIMITS.max_depth, 256);
        assert_eq!(PRUNE_INTERVAL.as_secs(), 10);
    }
}
