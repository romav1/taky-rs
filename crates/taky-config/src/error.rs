//! `taky-config` errors.

/// INI errors; variants correspond to the Python `configparser` exception classes (ADR-005).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IniError {
    /// `ParsingError`: lines that could not be parsed (`(number, text)`).
    #[error("Source contains parsing errors: {source_name}")]
    Parsing {
        /// Source name (`source` in [`crate::Ini::parse`]).
        source_name: String,
        /// Numbers (1-based) and texts of the unrecognized lines.
        lines: Vec<(usize, String)>,
    },
    /// `MissingSectionHeaderError`.
    #[error("File contains no section headers.\nfile: {source_name}, line: {line}\n{text:?}")]
    MissingSectionHeader {
        /// Source name.
        source_name: String,
        /// Line number (1-based).
        line: usize,
        /// Line text.
        text: String,
    },
    /// `MultilineContinuationError` (indentation after a key without a value).
    #[error(
        "Key without value continued with an indented line.\nfile: {source_name}, line: {line}\n{text:?}"
    )]
    MultilineContinuation {
        /// Source name.
        source_name: String,
        /// Line number (1-based).
        line: usize,
        /// Line text.
        text: String,
    },
    /// `DuplicateSectionError`.
    #[error("While reading from {source_name:?} [line {line}]: section {section:?} already exists")]
    DuplicateSection {
        /// Source name.
        source_name: String,
        /// Line number (1-based).
        line: usize,
        /// Section name.
        section: String,
    },
    /// `DuplicateOptionError`.
    #[error(
        "While reading from {source_name:?} [line {line}]: option {option:?} in section {section:?} already exists"
    )]
    DuplicateOption {
        /// Source name.
        source_name: String,
        /// Line number (1-based).
        line: usize,
        /// Section name.
        section: String,
        /// Key name (lower).
        option: String,
    },
    /// `InterpolationSyntaxError` (a lone `%`, malformed `%(`… form).
    #[error("{message}")]
    InterpolationSyntax {
        /// Text as in Python.
        message: String,
    },
    /// `InterpolationMissingOptionError`.
    #[error(
        "Bad value substitution: option {option:?} in section {section:?} contains an interpolation key {reference:?} which is not a valid option name. Raw value: {raw:?}"
    )]
    InterpolationMissingOption {
        /// Section.
        section: String,
        /// Key.
        option: String,
        /// Reference `%(reference)s`.
        reference: String,
        /// Raw value.
        raw: String,
    },
    /// `InterpolationDepthError` (depth > 10).
    #[error(
        "Recursion limit exceeded in value substitution: option {option:?} in section {section:?} contains an interpolation key which cannot be substituted in 10 steps. Raw value: {raw:?}"
    )]
    InterpolationDepth {
        /// Section.
        section: String,
        /// Key.
        option: String,
        /// Raw value.
        raw: String,
    },
    /// `NoSectionError`.
    #[error("No section: {0:?}")]
    NoSection(String),
    /// `NoOptionError`.
    #[error("No option {option:?} in section: {section:?}")]
    NoOption {
        /// Section.
        section: String,
        /// Key.
        option: String,
    },
    /// `ValueError: Not a boolean: …` from `getboolean`.
    #[error("Not a boolean: {0}")]
    NotABool(String),
    /// `getboolean` on a key without a value (`None.lower()` → `AttributeError` in Python).
    #[error("'NoneType' object has no attribute 'lower'")]
    NoneNotBool,
}

/// Errors of [`crate::load_config`]. Binaries print `Configuration file error: {err}` and exit with 1.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// INI parse/interpolation error.
    #[error(transparent)]
    Ini(#[from] IniError),
    /// `FileNotFoundError("Unable to find default config file")`.
    #[error("Unable to find default config file")]
    DefaultNotFound,
    /// `FileNotFoundError("Config file required, but not present")`.
    #[error("Config file required, but not present")]
    Required,
    /// `ValueError(f"Invalid port: {port}")` (for `port` and `mon_port`).
    #[error("Invalid port: {0}")]
    InvalidPort(String),
    /// `ValueError(f"Invalid max_persist_ttl: {v}")`.
    #[error("Invalid max_persist_ttl: {0}")]
    InvalidMaxPersistTtl(String),
    /// I/O error while reading the file (including non-UTF-8).
    #[error("{0}")]
    Io(#[from] std::io::Error),
}
