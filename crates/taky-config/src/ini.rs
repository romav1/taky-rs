//! Own implementation of the semantics of `configparser.ConfigParser(allow_no_value=True)` (ADR-005).
//!
//! Reproduced from CPython 3.13 `configparser` with the default options of `ConfigParser`
//! plus `allow_no_value=True`: delimiters `=`/`:`, full-line comments `#`/`;` (no inline
//! comments), `strict=True`, `empty_lines_in_values=True`, `optionxform=str.lower`,
//! `default_section="DEFAULT"`, `BasicInterpolation`.

use std::collections::HashSet;

use crate::IniError;

/// Keys of one section in insertion order: `(lower-case key, raw value)`; `None` — key without a value.
type Entries = Vec<(String, Option<String>)>;

/// Name of the default section (`default_section`).
pub const DEFAULT_SECTION: &str = "DEFAULT";

/// `configparser.MAX_INTERPOLATION_DEPTH`.
pub const MAX_INTERPOLATION_DEPTH: usize = 10;

/// `ConfigParser.BOOLEAN_STATES`.
const BOOLEAN_STATES: &[(&str, bool)] = &[
    ("1", true),
    ("yes", true),
    ("true", true),
    ("on", true),
    ("0", false),
    ("no", false),
    ("false", false),
    ("off", false),
];

/// Python `str.isspace` for one character (Rust `White_Space` plus the `\x1c`..`\x1f` separators).
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// Python `str.strip()`.
fn py_strip(s: &str) -> &str {
    s.trim_matches(py_space)
}

/// Python `str.lower()` (`optionxform`).
fn optionxform(s: &str) -> String {
    s.to_lowercase()
}

/// Where the parser currently writes: the `DEFAULT` section or a section by index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Target {
    Default,
    Sec(usize),
}

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

/// Look up a key in entries.
fn find<'a>(e: &'a Entries, k: &str) -> Option<&'a Option<String>> {
    e.iter().find(|(n, _)| n == k).map(|(_, v)| v)
}

/// Insert or replace (keeping the position, like a Python `dict`).
fn put(e: &mut Entries, k: String, v: Option<String>) {
    match e.iter_mut().find(|(n, _)| *n == k) {
        Some(slot) => slot.1 = v,
        None => e.push((k, v)),
    }
}

/// Parser state of one `read_file` call (`_ReadState` in CPython 3.13).
struct ReadState {
    cursect: Option<Target>,
    sectname: String,
    /// `None` — no current option; `Some("")` — option with an empty name (after a parse error).
    optname: Option<String>,
    indent_level: usize,
    sections_added: HashSet<String>,
    options_added: HashSet<(String, String)>,
    errors: Vec<(usize, String)>,
    /// Options set in this read: their values are `rstrip`ped at the end (`_join_multiline_values`).
    touched: Vec<(Target, String)>,
}

impl Ini {
    /// Empty document (no sections).
    pub fn new() -> Ini {
        Ini::default()
    }

    /// Parse text like `read_file(fp, source=source)` (without a preceding `read_dict`).
    pub fn parse(src: &str, source: &str) -> Result<Ini, IniError> {
        let mut ini = Ini::new();
        ini.read_str(src, source)?;
        Ok(ini)
    }

    fn entries(&self, t: Target) -> &Entries {
        match t {
            Target::Default => &self.defaults,
            Target::Sec(i) => &self.sections[i].1,
        }
    }

    fn entries_mut(&mut self, t: Target) -> &mut Entries {
        match t {
            Target::Default => &mut self.defaults,
            Target::Sec(i) => &mut self.sections[i].1,
        }
    }

    fn section_index(&self, s: &str) -> Option<usize> {
        self.sections.iter().position(|(n, _)| n == s)
    }

    /// Read more text on top of existing values, like a repeated `read_file`
    /// (this is how `load_config` overlays the file on `DEFAULT_CFG`).
    ///
    /// The text is split into lines with universal newlines (`\n`, `\r\n`, `\r`), as Python's
    /// text-mode `open()` does. A leading BOM is **not** stripped. As in Python, on error the
    /// document keeps everything read before the failing line.
    pub fn read_str(&mut self, src: &str, source: &str) -> Result<(), IniError> {
        let text = src.replace("\r\n", "\n").replace('\r', "\n");
        let mut st = ReadState {
            cursect: None,
            sectname: String::new(),
            optname: None,
            indent_level: 0,
            sections_added: HashSet::new(),
            options_added: HashSet::new(),
            errors: Vec::new(),
            touched: Vec::new(),
        };
        let res = self.read_inner(&text, source, &mut st);
        // `finally: self._join_multiline_values()`
        for (t, k) in &st.touched {
            if let Some(slot) = self.entries_mut(*t).iter_mut().find(|(n, _)| n == k)
                && let Some(v) = slot.1.as_mut()
            {
                let trimmed = v.trim_end_matches(py_space).len();
                v.truncate(trimmed);
            }
        }
        res?;
        if !st.errors.is_empty() {
            return Err(IniError::Parsing {
                source_name: source.to_string(),
                lines: st.errors,
            });
        }
        Ok(())
    }

    fn read_inner(&mut self, text: &str, source: &str, st: &mut ReadState) -> Result<(), IniError> {
        for (idx, raw) in text.split_inclusive('\n').enumerate() {
            let lineno = idx + 1;
            let stripped = py_strip(raw);
            let is_comment = stripped.starts_with('#') || stripped.starts_with(';');
            let clean = if is_comment { "" } else { stripped };
            if clean.is_empty() {
                // empty_lines_in_values=True: a blank (not comment) line becomes part of the value.
                if !is_comment
                    && let (Some(t), Some(opt)) = (st.cursect, st.optname.as_deref())
                    && !opt.is_empty()
                    && let Some(slot) = self.entries_mut(t).iter_mut().find(|(n, _)| n == opt)
                    && let Some(v) = slot.1.as_mut()
                {
                    v.push('\n');
                }
                continue;
            }
            let cur_indent = raw.chars().take_while(|c| py_space(*c)).count();

            // Continuation line?
            if let (Some(t), Some(opt)) = (st.cursect, st.optname.as_deref())
                && !opt.is_empty()
                && cur_indent > st.indent_level
            {
                let slot = self.entries_mut(t).iter_mut().find(|(n, _)| n == opt);
                match slot.and_then(|s| s.1.as_mut()) {
                    Some(v) => {
                        v.push('\n');
                        v.push_str(clean);
                    }
                    None => {
                        return Err(IniError::MultilineContinuation {
                            source_name: source.to_string(),
                            line: lineno,
                            text: raw.to_string(),
                        });
                    }
                }
                continue;
            }

            st.indent_level = cur_indent;
            // SECTCRE = r"\[(?P<header>.+)\]" (match at start, greedy).
            let header = clean
                .strip_prefix('[')
                .and_then(|r| r.rfind(']').filter(|&p| p > 0).map(|p| &r[..p]));
            if header.is_none() && st.cursect.is_none() {
                return Err(IniError::MissingSectionHeader {
                    source_name: source.to_string(),
                    line: lineno,
                    text: raw.to_string(),
                });
            }
            if let Some(name) = header {
                st.sectname = name.to_string();
                if let Some(i) = self.section_index(name) {
                    if st.sections_added.contains(name) {
                        return Err(IniError::DuplicateSection {
                            source_name: Some(source.to_string()),
                            line: Some(lineno),
                            section: name.to_string(),
                        });
                    }
                    st.cursect = Some(Target::Sec(i));
                    st.sections_added.insert(name.to_string());
                } else if name == DEFAULT_SECTION {
                    st.cursect = Some(Target::Default);
                } else {
                    self.sections.push((name.to_string(), Vec::new()));
                    st.cursect = Some(Target::Sec(self.sections.len() - 1));
                    st.sections_added.insert(name.to_string());
                }
                st.optname = None;
                continue;
            }

            // Option line: OPTCRE_NV = r"(?P<option>.*?)\s*(?:(?P<vi>[=:])\s*(?P<value>.*))?$"
            let (name, value) = match clean.find(['=', ':']) {
                Some(p) => (&clean[..p], Some(py_strip(&clean[p + 1..]))),
                None => (clean, None),
            };
            let name = name.trim_end_matches(py_space);
            if name.is_empty() {
                st.errors.push((lineno, raw.to_string()));
            }
            let key = optionxform(name);
            let section_key = (st.sectname.clone(), key.clone());
            if st.options_added.contains(&section_key) {
                return Err(IniError::DuplicateOption {
                    source_name: Some(source.to_string()),
                    line: Some(lineno),
                    section: st.sectname.clone(),
                    option: key,
                });
            }
            st.options_added.insert(section_key);
            let Some(t) = st.cursect else {
                // Unreachable: cursect is checked above (MissingSectionHeader).
                continue;
            };
            put(self.entries_mut(t), key.clone(), value.map(str::to_string));
            st.touched.push((t, key.clone()));
            st.optname = Some(key);
        }
        Ok(())
    }

    /// `_unify_values`: own section entries (`None` for `DEFAULT`) or `NoSection`.
    fn unify(&self, s: &str) -> Result<Option<&Entries>, IniError> {
        match self.section_index(s) {
            Some(i) => Ok(Some(&self.sections[i].1)),
            None if s == DEFAULT_SECTION => Ok(None),
            None => Err(IniError::NoSection(s.to_string())),
        }
    }

    /// Lookup in the chain section → `DEFAULT` (key already lowercased).
    fn lookup<'a>(&'a self, sect: Option<&'a Entries>, k: &str) -> Option<&'a Option<String>> {
        sect.and_then(|e| find(e, k))
            .or_else(|| find(&self.defaults, k))
    }

    /// `get(section, option)` with `BasicInterpolation`: `Ok(None)` — key without a value.
    pub fn get(&self, s: &str, k: &str) -> Result<Option<String>, IniError> {
        let sect = self.unify(s)?;
        let opt = optionxform(k);
        let Some(value) = self.lookup(sect, &opt) else {
            return Err(IniError::NoOption {
                section: s.to_string(),
                option: opt,
            });
        };
        let Some(value) = value else {
            return Ok(None);
        };
        let mut acc = String::with_capacity(value.len());
        self.interpolate_some(s, sect, &opt, &mut acc, value, 1)?;
        Ok(Some(acc))
    }

    /// `BasicInterpolation._interpolate_some`.
    fn interpolate_some(
        &self,
        section: &str,
        sect: Option<&Entries>,
        option: &str,
        acc: &mut String,
        rest: &str,
        depth: usize,
    ) -> Result<(), IniError> {
        // rawval = parser.get(section, option, raw=True, fallback=rest)
        let rawval = || match self.lookup(sect, option) {
            Some(Some(v)) => v.clone(),
            Some(None) => "None".to_string(),
            None => rest.to_string(),
        };
        if depth > MAX_INTERPOLATION_DEPTH {
            return Err(IniError::InterpolationDepth {
                section: section.to_string(),
                option: option.to_string(),
                raw: rawval(),
            });
        }
        let mut rest = rest;
        while !rest.is_empty() {
            let Some(p) = rest.find('%') else {
                acc.push_str(rest);
                return Ok(());
            };
            acc.push_str(&rest[..p]);
            rest = &rest[p..];
            let next = rest[1..].chars().next();
            match next {
                Some('%') => {
                    acc.push('%');
                    rest = &rest[2..];
                }
                Some('(') => {
                    // _KEYCRE = r"%\(([^)]+)\)s"
                    let m = rest[2..]
                        .find(')')
                        .filter(|&q| q > 0 && rest[2 + q + 1..].starts_with('s'));
                    let Some(q) = m else {
                        return Err(IniError::InterpolationSyntax {
                            message: format!(
                                "bad interpolation variable reference {}",
                                crate::error::py_repr(rest)
                            ),
                        });
                    };
                    let var = optionxform(&rest[2..2 + q]);
                    rest = &rest[2 + q + 2..];
                    match self.lookup(sect, &var) {
                        Some(Some(v)) => {
                            if v.contains('%') {
                                self.interpolate_some(section, sect, option, acc, v, depth + 1)?;
                            } else {
                                acc.push_str(v);
                            }
                        }
                        // `"%" in None` is a TypeError in Python; reported as a missing option.
                        Some(None) | None => {
                            return Err(IniError::InterpolationMissingOption {
                                section: section.to_string(),
                                option: option.to_string(),
                                reference: var,
                                raw: rawval(),
                            });
                        }
                    }
                }
                _ => {
                    return Err(IniError::InterpolationSyntax {
                        message: format!(
                            "'%' must be followed by '%' or '(', found: {}",
                            crate::error::py_repr(rest)
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// Raw value without interpolation (`get(..., raw=True)`).
    pub fn get_raw(&self, s: &str, k: &str) -> Result<Option<&str>, IniError> {
        let sect = self.unify(s)?;
        let opt = optionxform(k);
        match self.lookup(sect, &opt) {
            Some(v) => Ok(v.as_deref()),
            None => Err(IniError::NoOption {
                section: s.to_string(),
                option: opt,
            }),
        }
    }

    /// `getboolean`: `1/yes/true/on`, `0/no/false/off`, case-insensitive.
    pub fn getboolean(&self, s: &str, k: &str) -> Result<bool, IniError> {
        let v = self.get(s, k)?.ok_or(IniError::NoneNotBool)?;
        let lower = v.to_lowercase();
        BOOLEAN_STATES
            .iter()
            .find(|(n, _)| *n == lower)
            .map(|(_, b)| *b)
            .ok_or(IniError::NotABool(v))
    }

    /// `set(section, option, value)`; the section must exist (otherwise `NoSection`).
    ///
    /// `""`/empty section name or `DEFAULT` sets a default. Like `BasicInterpolation.before_set`,
    /// a value with a `%` that is neither `%%` nor `%(name)s` is rejected (`ValueError`).
    pub fn set(&mut self, s: &str, k: &str, v: Option<&str>) -> Result<(), IniError> {
        if let Some(value) = v
            && !value.is_empty()
        {
            check_before_set(value)?;
        }
        self.set_raw(s, k, v)
    }

    /// `set` without the interpolation syntax check (`RawConfigParser.set`).
    pub(crate) fn set_raw(&mut self, s: &str, k: &str, v: Option<&str>) -> Result<(), IniError> {
        let t = if s.is_empty() || s == DEFAULT_SECTION {
            Target::Default
        } else {
            Target::Sec(
                self.section_index(s)
                    .ok_or_else(|| IniError::NoSection(s.to_string()))?,
            )
        };
        put(self.entries_mut(t), optionxform(k), v.map(str::to_string));
        Ok(())
    }

    /// `add_section`.
    pub fn add_section(&mut self, s: &str) -> Result<(), IniError> {
        if s == DEFAULT_SECTION {
            return Err(IniError::InvalidSectionName(s.to_string()));
        }
        if self.has_section(s) {
            return Err(IniError::DuplicateSection {
                source_name: None,
                line: None,
                section: s.to_string(),
            });
        }
        self.sections.push((s.to_string(), Vec::new()));
        Ok(())
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
    /// multi-line values — `\n\t`, blank line after a section). Values are written raw.
    pub fn write(&self) -> String {
        let mut out = String::new();
        let mut section = |name: &str, entries: &Entries| {
            out.push('[');
            out.push_str(name);
            out.push_str("]\n");
            for (k, v) in entries {
                out.push_str(k);
                if let Some(v) = v {
                    out.push_str(" = ");
                    out.push_str(&v.replace('\n', "\n\t"));
                }
                out.push('\n');
            }
            out.push('\n');
        };
        if !self.defaults.is_empty() {
            section(DEFAULT_SECTION, &self.defaults);
        }
        for (name, entries) in &self.sections {
            section(name, entries);
        }
        out
    }

    /// Own keys of a section (without inherited `DEFAULT` keys), raw; `None` for an unknown section.
    pub fn section_items(&self, s: &str) -> Option<&[(String, Option<String>)]> {
        if s == DEFAULT_SECTION {
            return Some(self.entries(Target::Default));
        }
        self.section_index(s).map(|i| self.sections[i].1.as_slice())
    }
}

/// `BasicInterpolation.before_set`: strip `%%` and `%(name)s`, any `%` left is an error.
fn check_before_set(value: &str) -> Result<(), IniError> {
    let tmp = value.replace("%%", "");
    // _KEYCRE.sub('', tmp)
    let mut stripped = String::with_capacity(tmp.len());
    let mut rest = tmp.as_str();
    while let Some(p) = rest.find("%(") {
        let after = &rest[p + 2..];
        match after
            .find(')')
            .filter(|&q| q > 0 && after[q + 1..].starts_with('s'))
        {
            Some(q) => {
                stripped.push_str(&rest[..p]);
                rest = &after[q + 2..];
            }
            None => {
                stripped.push_str(&rest[..p + 1]);
                rest = &rest[p + 1..];
            }
        }
    }
    stripped.push_str(rest);
    match stripped.find('%') {
        Some(p) => Err(IniError::InvalidInterpolation {
            value: value.to_string(),
            position: stripped[..p].chars().count(),
        }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> Ini {
        Ini::parse(src, "<string>").unwrap()
    }

    fn err(src: &str) -> IniError {
        Ini::parse(src, "<string>").unwrap_err()
    }

    #[test]
    fn basics_and_case() {
        let ini = parse("[Sec]\nKey = V\nb:c\nnv\nempty =\n");
        assert_eq!(ini.get("Sec", "KEY").unwrap().as_deref(), Some("V"));
        assert_eq!(ini.get("Sec", "b").unwrap().as_deref(), Some("c"));
        assert_eq!(ini.get("Sec", "nv").unwrap(), None);
        assert_eq!(ini.get("Sec", "empty").unwrap().as_deref(), Some(""));
        assert_eq!(
            ini.get("sec", "key"),
            Err(IniError::NoSection("sec".into()))
        );
        assert!(matches!(
            ini.get("Sec", "x"),
            Err(IniError::NoOption { .. })
        ));
    }

    #[test]
    fn first_delimiter_wins_and_no_inline_comments() {
        let ini = parse("[s]\na: b = c\nd = e: f ; g # h\n");
        assert_eq!(ini.get_raw("s", "a").unwrap(), Some("b = c"));
        assert_eq!(ini.get_raw("s", "d").unwrap(), Some("e: f ; g # h"));
    }

    #[test]
    fn continuation_blank_lines_and_comments() {
        let ini = parse("[s]\nk = a\n\n  b\n  # not a comment? no: comment\n  c\n\n\nn = 1\n");
        assert_eq!(ini.get_raw("s", "k").unwrap(), Some("a\n\nb\nc"));
        let ini = parse("[s]\nk =\n  x\n");
        assert_eq!(ini.get_raw("s", "k").unwrap(), Some("\nx"));
        let ini = parse("[s]\nk = a\n\n");
        assert_eq!(ini.get_raw("s", "k").unwrap(), Some("a"));
    }

    #[test]
    fn multiline_continuation_error() {
        let e = err("[s]\nk\n  x\n");
        assert_eq!(e.py_class(), "MultilineContinuationError");
        assert_eq!(
            e.to_string(),
            "Key without value continued with an indented line.\nfile: '<string>', line: 3\n'  x\\n'"
        );
    }

    #[test]
    fn default_section() {
        let ini = parse("[DEFAULT]\nd = 1\n[a]\nx = %(d)s+\n");
        assert_eq!(ini.get("a", "d").unwrap().as_deref(), Some("1"));
        assert_eq!(ini.get("a", "x").unwrap().as_deref(), Some("1+"));
        assert_eq!(ini.get("DEFAULT", "d").unwrap().as_deref(), Some("1"));
        assert!(!ini.has_section("DEFAULT"));
        assert_eq!(ini.sections().collect::<Vec<_>>(), vec!["a"]);
    }

    #[test]
    fn error_messages() {
        assert_eq!(
            err("[taky]\nhostname = a\nhostname = b\n").to_string(),
            "While reading from '<string>' [line  3]: option 'hostname' in section 'taky' already exists"
        );
        assert_eq!(
            err("[taky]\nhostname = a\n[taky]\n").to_string(),
            "While reading from '<string>' [line  3]: section 'taky' already exists"
        );
        assert_eq!(
            err("\u{feff}[taky]\n").to_string(),
            "File contains no section headers.\nfile: '<string>', line: 1\n'\\ufeff[taky]\\n'"
        );
        assert_eq!(
            err("[s]\n= x\n[t]\n: y").to_string(),
            "Source contains parsing errors: '<string>'\n\t[line  2]: '= x\\n'\n\t[line  4]: ': y'"
        );
    }

    #[test]
    fn interpolation() {
        let ini = parse(
            "[s]\na = x%%y\nb = %(a)s!\nc = 5%\nd = %(zz)s\ne = %(e)s\nf = %(x\nn\ng = %(n)s\n",
        );
        assert_eq!(ini.get("s", "a").unwrap().as_deref(), Some("x%y"));
        assert_eq!(ini.get("s", "b").unwrap().as_deref(), Some("x%y!"));
        assert_eq!(
            ini.get("s", "c").unwrap_err().to_string(),
            "'%' must be followed by '%' or '(', found: '%'"
        );
        assert_eq!(
            ini.get("s", "d").unwrap_err().to_string(),
            "Bad value substitution: option 'd' in section 's' contains an interpolation key 'zz' \
             which is not a valid option name. Raw value: '%(zz)s'"
        );
        assert_eq!(
            ini.get("s", "e").unwrap_err().py_class(),
            "InterpolationDepthError"
        );
        assert_eq!(
            ini.get("s", "f").unwrap_err().to_string(),
            "bad interpolation variable reference '%(x'"
        );
        assert!(ini.get("s", "g").is_err());
        assert_eq!(ini.get_raw("s", "c").unwrap(), Some("5%"));
    }

    #[test]
    fn booleans() {
        let ini = parse("[s]\na = On\nb = 0\nc = maybe\nd\ne =\n");
        assert!(ini.getboolean("s", "a").unwrap());
        assert!(!ini.getboolean("s", "b").unwrap());
        assert_eq!(
            ini.getboolean("s", "c"),
            Err(IniError::NotABool("maybe".into()))
        );
        assert_eq!(ini.getboolean("s", "d"), Err(IniError::NoneNotBool));
        assert_eq!(
            ini.getboolean("s", "e"),
            Err(IniError::NotABool(String::new()))
        );
    }

    #[test]
    fn overlay_read_and_newlines() {
        let mut ini = parse("[a]\nx = 1\ny = 2\n");
        ini.read_str("[a]\r\nx = 3\rz = 4\n", "f").unwrap();
        assert_eq!(
            ini.section_items("a").unwrap(),
            &[
                ("x".to_string(), Some("3".to_string())),
                ("y".to_string(), Some("2".to_string())),
                ("z".to_string(), Some("4".to_string())),
            ]
        );
    }

    #[test]
    fn section_header_forms() {
        let ini = parse("[a]b] tail\nk = v\n[ sp ]\n");
        assert!(ini.has_section("a]b"));
        assert!(ini.has_section(" sp "));
    }

    #[test]
    fn set_add_section_write() {
        let mut ini = Ini::new();
        assert!(matches!(
            ini.set("x", "k", Some("v")),
            Err(IniError::NoSection(_))
        ));
        ini.add_section("x").unwrap();
        assert_eq!(
            ini.add_section("x").unwrap_err().to_string(),
            "Section 'x' already exists"
        );
        assert_eq!(
            ini.add_section("DEFAULT").unwrap_err().to_string(),
            "Invalid section name: 'DEFAULT'"
        );
        ini.set("x", "Key", Some("a\nb")).unwrap();
        ini.set("x", "nv", None).unwrap();
        ini.set("x", "pct", Some("50%%")).unwrap();
        assert_eq!(
            ini.set("x", "bad", Some("a%(k)s %"))
                .unwrap_err()
                .to_string(),
            "invalid interpolation syntax in 'a%(k)s %' at position 2"
        );
        ini.set("DEFAULT", "d", Some("1")).unwrap();
        assert_eq!(
            ini.write(),
            "[DEFAULT]\nd = 1\n\n[x]\nkey = a\n\tb\nnv\npct = 50%%\n\n"
        );
        let back = Ini::parse(&ini.write(), "w").unwrap();
        assert_eq!(back, ini);
    }
}
