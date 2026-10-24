//! Own implementation of the semantics of `configparser.ConfigParser(allow_no_value=True)` (ADR-005).

use crate::IniError;

/// Keys of one section in insertion order: `(lower-case key, raw value)`; `None` — key without a value.
type Entries = Vec<(String, Option<String>)>;

/// INI document: sections and keys in insertion order, **raw** values; interpolation
/// (`BasicInterpolation`) is performed in [`Ini::get`].
///
/// Key names are stored in lower case, section names as-is. The `DEFAULT` section
/// is stored separately and inherited by all sections.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ini {
    /// Keys of the `DEFAULT` section.
    defaults: Entries,
    /// Sections in insertion order.
    sections: Vec<(String, Entries)>,
}

impl Ini {
    /// Empty document (no sections).
    pub fn new() -> Ini {
        Ini::default()
    }

    /// Parse text like `read_file(fp, source=source)` (without a preceding `read_dict`).
    pub fn parse(src: &str, source: &str) -> Result<Ini, IniError> {
        let _ = (src, source);
        todo!("T-20")
    }

    /// Read more text on top of existing values, like a repeated `read_file`
    /// (this is how `load_config` overlays the file on `DEFAULT_CFG`).
    pub fn read_str(&mut self, src: &str, source: &str) -> Result<(), IniError> {
        let _ = (src, source);
        todo!("T-20")
    }

    /// `get(section, option)` with `BasicInterpolation`: `Ok(None)` — key without a value.
    pub fn get(&self, s: &str, k: &str) -> Result<Option<String>, IniError> {
        let _ = (s, k);
        todo!("T-20")
    }

    /// Raw value without interpolation (`get(..., raw=True)`).
    pub fn get_raw(&self, s: &str, k: &str) -> Result<Option<&str>, IniError> {
        let _ = (s, k);
        todo!("T-20")
    }

    /// `getboolean`: `1/yes/true/on`, `0/no/false/off`, case-insensitive.
    pub fn getboolean(&self, s: &str, k: &str) -> Result<bool, IniError> {
        let _ = (s, k);
        todo!("T-20")
    }

    /// `set(section, option, value)`; the section must exist (otherwise `NoSection`).
    pub fn set(&mut self, s: &str, k: &str, v: Option<&str>) -> Result<(), IniError> {
        let _ = (s, k, v);
        todo!("T-20")
    }

    /// `add_section`.
    pub fn add_section(&mut self, s: &str) -> Result<(), IniError> {
        let _ = s;
        todo!("T-20")
    }

    /// `has_section` (`false` for `DEFAULT`, as in Python).
    pub fn has_section(&self, s: &str) -> bool {
        self.sections.iter().any(|(n, _)| n == s)
    }

    /// Section names in insertion order (without `DEFAULT`).
    pub fn sections(&self) -> impl Iterator<Item = &str> {
        self.sections.iter().map(|(n, _)| n.as_str())
    }

    /// `config.write(fp)`: Python format (`key = value`, key without a value — `key`,
    /// multi-line values — `\n\t`, blank line after a section).
    pub fn write(&self) -> String {
        let _ = &self.defaults;
        todo!("T-20")
    }
}
