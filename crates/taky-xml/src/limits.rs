//! Parser limits (ARCHITECTURE §6, ADR-008 G-4 — constants in 1.0).

/// Limits for a single document/top-level element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum size of a single top-level element in bytes (4 MiB).
    pub max_bytes: usize,
    /// Maximum nesting depth (256, as in libxml2).
    pub max_depth: usize,
    /// Maximum number of attributes per element (256).
    pub max_attrs: usize,
    /// Maximum length of a tag/attribute name in bytes (1 KiB).
    pub max_name: usize,
    /// Maximum number of nodes (elements, comments, PIs) in one top-level element (100 000).
    pub max_nodes: usize,
}

impl Limits {
    /// taky-rs 1.0 defaults.
    pub const DEFAULT: Limits = Limits {
        max_bytes: 4 * 1024 * 1024,
        max_depth: 256,
        max_attrs: 256,
        max_name: 1024,
        max_nodes: 100_000,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Limits::DEFAULT
    }
}
