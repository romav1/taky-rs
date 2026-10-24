//! `taky-config` errors.

/// INI errors; variants correspond to the Python `configparser` exception classes (ADR-005).
///
/// `Display` reproduces the Python `str(exc)` texts (strings quoted with Python `repr`,
/// line numbers formatted as `%2d` where Python does so).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IniError {
    /// `ParsingError`: lines that could not be parsed (`(number, raw line)`).
    Parsing {
        /// Source name (`source` in [`crate::Ini::parse`]).
        source_name: String,
        /// Numbers (1-based) and raw texts (with the line terminator) of the unrecognized lines.
        lines: Vec<(usize, String)>,
    },
    /// `MissingSectionHeaderError`.
    MissingSectionHeader {
        /// Source name.
        source_name: String,
        /// Line number (1-based).
        line: usize,
        /// Raw line text (with the line terminator, as Python reports it).
        text: String,
    },
    /// `MultilineContinuationError` (indentation after a key without a value).
    MultilineContinuation {
        /// Source name.
        source_name: String,
        /// Line number (1-based).
        line: usize,
        /// Raw line text (with the line terminator).
        text: String,
    },
    /// `DuplicateSectionError`. `source_name`/`line` are `None` for `add_section`.
    DuplicateSection {
        /// Source name (`None` — raised by [`crate::Ini::add_section`]).
        source_name: Option<String>,
        /// Line number (1-based).
        line: Option<usize>,
        /// Section name.
        section: String,
    },
    /// `DuplicateOptionError`.
    DuplicateOption {
        /// Source name.
        source_name: Option<String>,
        /// Line number (1-based).
        line: Option<usize>,
        /// Section name.
        section: String,
        /// Key name (lower).
        option: String,
    },
    /// `InterpolationSyntaxError` (a lone `%`, malformed `%(`… form).
    InterpolationSyntax {
        /// Text as in Python.
        message: String,
    },
    /// `InterpolationMissingOptionError`.
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
    InterpolationDepth {
        /// Section.
        section: String,
        /// Key.
        option: String,
        /// Raw value.
        raw: String,
    },
    /// `NoSectionError`.
    NoSection(String),
    /// `NoOptionError`.
    NoOption {
        /// Section.
        section: String,
        /// Key.
        option: String,
    },
    /// `ValueError: Not a boolean: …` from `getboolean`.
    NotABool(String),
    /// `getboolean` on a key without a value (`None.lower()` → `AttributeError` in Python).
    NoneNotBool,
    /// `ValueError: Invalid section name: …` (`add_section("DEFAULT")`).
    InvalidSectionName(String),
    /// `ValueError: invalid interpolation syntax in … at position …` (`set` with a lone `%`,
    /// `BasicInterpolation.before_set`).
    InvalidInterpolation {
        /// The rejected value.
        value: String,
        /// Character position of the offending `%` (after removing `%%` and `%(..)s`).
        position: usize,
    },
}

impl IniError {
    /// Name of the corresponding Python exception class (used by vector tests and messages).
    pub fn py_class(&self) -> &'static str {
        match self {
            IniError::Parsing { .. } => "ParsingError",
            IniError::MissingSectionHeader { .. } => "MissingSectionHeaderError",
            IniError::MultilineContinuation { .. } => "MultilineContinuationError",
            IniError::DuplicateSection { .. } => "DuplicateSectionError",
            IniError::DuplicateOption { .. } => "DuplicateOptionError",
            IniError::InterpolationSyntax { .. } => "InterpolationSyntaxError",
            IniError::InterpolationMissingOption { .. } => "InterpolationMissingOptionError",
            IniError::InterpolationDepth { .. } => "InterpolationDepthError",
            IniError::NoSection(_) => "NoSectionError",
            IniError::NoOption { .. } => "NoOptionError",
            IniError::NotABool(_)
            | IniError::InvalidSectionName(_)
            | IniError::InvalidInterpolation { .. } => "ValueError",
            IniError::NoneNotBool => "AttributeError",
        }
    }
}

/// `"While reading from 'src' [line  3]: "` prefix of the `Duplicate*Error` messages.
fn while_reading(source_name: &str, line: Option<usize>) -> String {
    let mut s = format!("While reading from {}", py_repr(source_name));
    if let Some(l) = line {
        s.push_str(&format!(" [line {l:2}]"));
    }
    s
}

impl std::fmt::Display for IniError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IniError::Parsing { source_name, lines } => {
                write!(
                    f,
                    "Source contains parsing errors: {}",
                    py_repr(source_name)
                )?;
                for (n, text) in lines {
                    write!(f, "\n\t[line {n:2}]: {}", py_repr(text))?;
                }
                Ok(())
            }
            IniError::MissingSectionHeader {
                source_name,
                line,
                text,
            } => write!(
                f,
                "File contains no section headers.\nfile: {}, line: {line}\n{}",
                py_repr(source_name),
                py_repr(text)
            ),
            IniError::MultilineContinuation {
                source_name,
                line,
                text,
            } => write!(
                f,
                "Key without value continued with an indented line.\nfile: {}, line: {line}\n{}",
                py_repr(source_name),
                py_repr(text)
            ),
            IniError::DuplicateSection {
                source_name,
                line,
                section,
            } => match source_name {
                Some(src) => write!(
                    f,
                    "{}: section {} already exists",
                    while_reading(src, *line),
                    py_repr(section)
                ),
                None => write!(f, "Section {} already exists", py_repr(section)),
            },
            IniError::DuplicateOption {
                source_name,
                line,
                section,
                option,
            } => match source_name {
                Some(src) => write!(
                    f,
                    "{}: option {} in section {} already exists",
                    while_reading(src, *line),
                    py_repr(option),
                    py_repr(section)
                ),
                None => write!(
                    f,
                    "Option {} in section {} already exists",
                    py_repr(option),
                    py_repr(section)
                ),
            },
            IniError::InterpolationSyntax { message } => f.write_str(message),
            IniError::InterpolationMissingOption {
                section,
                option,
                reference,
                raw,
            } => write!(
                f,
                "Bad value substitution: option {} in section {} contains an interpolation key {} \
                 which is not a valid option name. Raw value: {}",
                py_repr(option),
                py_repr(section),
                py_repr(reference),
                py_repr(raw)
            ),
            IniError::InterpolationDepth {
                section,
                option,
                raw,
            } => write!(
                f,
                "Recursion limit exceeded in value substitution: option {} in section {} contains \
                 an interpolation key which cannot be substituted in {} steps. Raw value: {}",
                py_repr(option),
                py_repr(section),
                crate::ini::MAX_INTERPOLATION_DEPTH,
                py_repr(raw)
            ),
            IniError::NoSection(s) => write!(f, "No section: {}", py_repr(s)),
            IniError::NoOption { section, option } => write!(
                f,
                "No option {} in section: {}",
                py_repr(option),
                py_repr(section)
            ),
            IniError::NotABool(v) => write!(f, "Not a boolean: {v}"),
            IniError::NoneNotBool => f.write_str("'NoneType' object has no attribute 'lower'"),
            IniError::InvalidSectionName(s) => write!(f, "Invalid section name: {}", py_repr(s)),
            IniError::InvalidInterpolation { value, position } => write!(
                f,
                "invalid interpolation syntax in {} at position {position}",
                py_repr(value)
            ),
        }
    }
}

impl std::error::Error for IniError {}

/// Python `repr()` of a `str`: quote choice, backslash escapes, `\xNN`/`\uNNNN`/`\UNNNNNNNN`
/// for non-printable characters.
///
/// `str.isprintable` is approximated without Unicode tables: C0/C1 controls, non-ASCII `Zs`, the
/// common `Cf` format characters (incl. U+FEFF BOM), `Zl`/`Zp`, private use and noncharacters are
/// escaped; unassigned code points (`Cn`) are printed as-is.
pub fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if !py_printable(c) => {
                let n = c as u32;
                if n < 0x100 {
                    out.push_str(&format!("\\x{n:02x}"));
                } else if n < 0x10000 {
                    out.push_str(&format!("\\u{n:04x}"));
                } else {
                    out.push_str(&format!("\\U{n:08x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Approximation of Python `str.isprintable` for one character (see [`py_repr`]).
fn py_printable(c: char) -> bool {
    let n = c as u32;
    !matches!(n,
        0x00..=0x1f | 0x7f..=0xa0 | 0xad
        | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x1680 | 0x180e
        | 0x2000..=0x200f | 0x2028..=0x202f | 0x205f..=0x2064 | 0x2066..=0x206f
        | 0x3000 | 0xe000..=0xf8ff | 0xfeff | 0xfff9..=0xfffb | 0xfffe | 0xffff
        | 0xf0000..)
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

impl ConfigError {
    /// Name of the Python exception class the original raises for this error (vector tests).
    pub fn py_class(&self) -> &'static str {
        match self {
            ConfigError::Ini(e) => e.py_class(),
            ConfigError::DefaultNotFound | ConfigError::Required => "FileNotFoundError",
            ConfigError::InvalidPort(_) | ConfigError::InvalidMaxPersistTtl(_) => "ValueError",
            ConfigError::Io(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                "UnicodeDecodeError"
            }
            ConfigError::Io(_) => "OSError",
        }
    }
}
