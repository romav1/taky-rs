//! XML parsing without DTD/entities (ADR-002).
//!
//! Both entry points share one resumable core:
//! * a **token scanner** over an internal byte buffer that finds complete markup/text tokens
//!   (`<…>` outside quotes, `<!--…-->`, `<![CDATA[…]]>`, `<?…?>`, character data up to the next
//!   `<`/`&`, a reference `&…;`) and
//!   remembers its scan position, so data arriving in tiny chunks is scanned once (O(n));
//! * a **tree builder** that validates each token (quick-xml attribute tokenizer and value
//!   normalization, plus our own checks: names, legal characters, UTF-8, `<` in values, `]]>`,
//!   duplicate attributes, end-tag names, depth/size/attribute/node limits) and builds the
//!   lxml-like mini-DOM with namespace resolution (Clark notation, undeclared prefix is not an
//!   error, as in lxml).
//!
//! DTDs are rejected (`<!DOCTYPE` ⇒ [`XmlError::DtdForbidden`]); entities are never expanded —
//! only the 5 predefined ones and character references to legal XML characters are resolved.
//! Hence XXE and billion laughs are impossible by construction.

use std::collections::VecDeque;

use quick_xml::XmlVersion;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesRef, BytesStart};

use crate::chars::{first_invalid_char, is_name, is_space, is_xml_char};
use crate::decl_strip::XmlDeclStrip;
use crate::{Element, Limits, Node, XmlError};

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// Parse a single document (root element; the `<?xml …?>` prolog is allowed only at byte 0,
/// comments/PIs/whitespace around the root are allowed, DTD is not).
///
/// An unknown named entity is an error here ([`XmlError::UnknownEntity`]); used for Redis values
/// and DPS `/Marti/vcm` (D-1).
pub fn parse_element(xml: &[u8], lim: &Limits) -> Result<Element, XmlError> {
    let mut core = Core::new(Mode::Document, *lim);
    core.push(xml.strip_prefix(b"\xef\xbb\xbf").unwrap_or(xml))?;
    core.finish()
}

/// Incremental CoT stream decoder (cot-server.md §5, ADR-002).
///
/// Emulates the original `XMLDeclStrip` + `XMLPullParser(tag="event")` pre-fed with `<root>`:
/// * input bytes first pass through [`XmlDeclStrip`] (byte-exact port);
/// * the stream is the content of a virtual `<root>`: text, comments, PIs at depth 0 are
///   validated and dropped; `</root>` closes the document (afterwards only whitespace,
///   comments and PIs are allowed, as in libxml2);
/// * every closed element whose local name is `event` with no namespace is emitted, **at any
///   depth** (V016, V020); in its parent it is replaced by an empty `<event/>` that keeps its
///   tail (emulating `elm.clear(keep_tail=True)`); completed top-level elements are dropped
///   immediately (no leak, D-2). The emitted element has no tail (it is not known yet);
/// * an unknown named entity (`&foo;`) marks the nearest enclosing event as dropped: it is not
///   emitted and the stream continues (ADR-002, V017). Entities are never expanded;
/// * any other well-formedness error or a [`Limits`] violation is fatal: the builder is
///   poisoned, events queued by the failing [`TreeBuilder::feed`] are discarded (the original
///   raises from `feed()` before reading events) and every later call returns the same error.
///
/// Depth counts the virtual root, as libxml2 does: at most `max_depth - 1` nested elements.
#[derive(Debug)]
pub struct TreeBuilder {
    strip: XmlDeclStrip,
    core: Core,
    scratch: Vec<u8>,
    failed: Option<XmlError>,
}

impl TreeBuilder {
    /// New builder with limits `limits`.
    pub fn new(limits: Limits) -> TreeBuilder {
        TreeBuilder {
            strip: XmlDeclStrip::new(),
            core: Core::new(Mode::Stream, limits),
            scratch: Vec::new(),
            failed: None,
        }
    }

    /// Builder limits.
    pub fn limits(&self) -> &Limits {
        &self.core.tree.limits
    }

    /// Feed the next input fragment (one socket read).
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), XmlError> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        self.scratch.clear();
        self.strip.strip(chunk, &mut self.scratch);
        let res = self.core.push(&self.scratch);
        if self.scratch.capacity() > 64 * 1024 {
            self.scratch = Vec::new();
        }
        if let Err(e) = res {
            self.core.tree.out.clear();
            self.core.release();
            self.failed = Some(e.clone());
            return Err(e);
        }
        Ok(())
    }

    /// Take the next emitted `<event>` element, if any. After a fatal error returns that error.
    pub fn next_element(&mut self) -> Result<Option<Element>, XmlError> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        Ok(self.core.tree.out.pop_front())
    }

    /// Number of emitted events waiting in [`TreeBuilder::next_element`].
    pub fn queued(&self) -> usize {
        self.core.tree.out.len()
    }

    /// Bytes currently retained for the incomplete token (memory accounting/tests).
    pub fn buffered_bytes(&self) -> usize {
        self.core.buf.len() - self.core.pos
    }

    /// Current element depth below the virtual root (tests).
    pub fn depth(&self) -> usize {
        self.core.tree.frames.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// CoT stream inside a virtual `<root>`.
    Stream,
    /// One whole document.
    Document,
}

/// State of the document element (the virtual `<root>` in stream mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Top {
    Before,
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Text,
    Start,
    End,
    Comment,
    CData,
    Pi,
}

#[derive(Debug)]
struct Frame {
    elem: Element,
    qname: String,
    is_event: bool,
    dropped: bool,
    ns_len: usize,
}

/// Scanner state + tree.
#[derive(Debug)]
struct Core {
    buf: Vec<u8>,
    /// Start of the current (incomplete) token in `buf`.
    pos: usize,
    /// Scan progress of the current token (index into `buf`).
    scan: usize,
    /// Open quote while scanning a start tag.
    quote: Option<u8>,
    /// Stream offset of `buf[0]`.
    base: u64,
    tree: Tree,
}

#[derive(Debug)]
struct Tree {
    mode: Mode,
    limits: Limits,
    frames: Vec<Frame>,
    /// In-scope namespace declarations: prefix (`None` = default) → URI (`None` = unbound).
    ns: Vec<(Option<String>, Option<String>)>,
    top: Top,
    item_start: u64,
    item_nodes: usize,
    out: VecDeque<Element>,
    /// Index in `out` of the event emitted last in the current `feed()` whose tail is still
    /// being parsed: lxml reads events after the whole chunk, so text completed in the same
    /// chunk is visible as the emitted element's tail (it is the same object).
    tail_to: Option<usize>,
    root: Option<Element>,
}

fn syntax(pos: u64, msg: impl Into<String>) -> XmlError {
    XmlError::Syntax {
        pos,
        msg: msg.into(),
    }
}

fn utf8(b: &[u8]) -> Result<&str, XmlError> {
    std::str::from_utf8(b).map_err(|_| XmlError::InvalidUtf8)
}

/// Index of the first `>` at index `>= min` from `from` whose preceding bytes equal `pre`.
fn find_gt(buf: &[u8], from: usize, min: usize, pre: &[u8]) -> Option<usize> {
    let mut i = from.max(min);
    while i < buf.len() {
        let off = buf[i..].iter().position(|&b| b == b'>')?;
        i += off;
        if buf[..i].ends_with(pre) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// XML 1.0 end-of-line handling: `\r\n` and lone `\r` become `\n`.
fn eol(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.contains('\r') {
        return s.into();
    }
    s.replace("\r\n", "\n").replace('\r', "\n").into()
}

impl Core {
    fn new(mode: Mode, limits: Limits) -> Core {
        Core {
            buf: Vec::new(),
            pos: 0,
            scan: 0,
            quote: None,
            base: 0,
            tree: Tree {
                mode,
                limits,
                frames: Vec::new(),
                ns: Vec::new(),
                top: match mode {
                    Mode::Stream => Top::Open,
                    Mode::Document => Top::Before,
                },
                item_start: 0,
                item_nodes: 0,
                out: VecDeque::new(),
                tail_to: None,
                root: None,
            },
        }
    }

    /// Drop all buffers after a fatal error.
    fn release(&mut self) {
        self.buf = Vec::new();
        self.pos = 0;
        self.scan = 0;
        self.tree.frames = Vec::new();
        self.tree.ns = Vec::new();
    }

    /// Find the end (exclusive) of the token starting at `pos`, or `None` if incomplete.
    fn next_token(&mut self) -> Result<Option<(Tok, usize)>, XmlError> {
        let buf = &self.buf;
        let p = self.pos;
        let len = buf.len();
        if p >= len {
            return Ok(None);
        }
        let from = self.scan.max(p);
        let found = if buf[p] == b'&' {
            // A reference is a token of its own once its `;` is here (libxml2 handles it as
            // soon as it is complete); a `<` first means a malformed reference (error later).
            buf[from.max(p + 1)..]
                .iter()
                .position(|&b| b == b';' || b == b'<')
                .map(|i| from.max(p + 1) + i)
                .map(|i| (Tok::Text, if buf[i] == b';' { i + 1 } else { i }))
        } else if buf[p] != b'<' {
            // Character data up to the next `<` or `&` (libxml2 flushes it at either).
            buf[from..]
                .iter()
                .position(|&b| b == b'<' || b == b'&')
                .map(|i| (Tok::Text, from + i))
        } else if p + 1 >= len {
            None
        } else {
            match buf[p + 1] {
                b'/' => find_gt(buf, from, p + 2, b"").map(|i| (Tok::End, i + 1)),
                b'?' => find_gt(buf, from, p + 3, b"?").map(|i| (Tok::Pi, i + 1)),
                b'!' => {
                    let rest = &buf[p..];
                    if rest.starts_with(b"<!--") {
                        find_gt(buf, from, p + 6, b"--").map(|i| (Tok::Comment, i + 1))
                    } else if rest.starts_with(b"<![CDATA[") {
                        find_gt(buf, from, p + 11, b"]]").map(|i| (Tok::CData, i + 1))
                    } else if b"<!--".starts_with(rest)
                        || b"<![CDATA[".starts_with(rest)
                        || rest.len() < 3
                    {
                        None // not enough bytes to classify yet
                    } else if rest[2] == b'D' {
                        return Err(XmlError::DtdForbidden);
                    } else {
                        return Err(syntax(self.base + p as u64, "invalid markup declaration"));
                    }
                }
                _ => {
                    let mut q = self.quote;
                    let mut end = None;
                    for (i, &b) in buf.iter().enumerate().skip(from.max(p + 1)) {
                        match q {
                            Some(c) if b == c => q = None,
                            Some(_) => {}
                            None if b == b'"' || b == b'\'' => q = Some(b),
                            None if b == b'>' => {
                                end = Some(i + 1);
                                break;
                            }
                            None => {}
                        }
                    }
                    self.quote = q;
                    end.map(|e| (Tok::Start, e))
                }
            }
        };
        if found.is_none() {
            self.scan = len;
        }
        Ok(found)
    }

    /// Byte limit of the current top-level item (D-2), counting up to `end` in `buf`.
    fn check_size(&self, end: usize) -> Result<(), XmlError> {
        let from = if self.tree.frames.is_empty() {
            self.base + self.pos as u64
        } else {
            self.tree.item_start
        };
        let size = self.base + end as u64 - from;
        if size > self.tree.limits.max_bytes as u64 {
            return Err(XmlError::LimitExceeded("max_bytes"));
        }
        Ok(())
    }

    fn push(&mut self, data: &[u8]) -> Result<(), XmlError> {
        self.buf.extend_from_slice(data);
        self.tree.tail_to = None;
        while let Some((kind, end)) = self.next_token()? {
            self.check_size(end)?;
            let off = self.base + self.pos as u64;
            self.tree.token(kind, &self.buf[self.pos..end], off)?;
            self.pos = end;
            self.scan = end;
            self.quote = None;
        }
        self.check_size(self.buf.len())?;
        // Amortized compaction: move the incomplete tail only when it is not larger than what
        // is dropped, so total copying stays O(n).
        if self.pos > 0 && self.pos >= self.buf.len() - self.pos {
            self.buf.drain(..self.pos);
            self.base += self.pos as u64;
            self.scan -= self.pos;
            self.pos = 0;
        }
        Ok(())
    }

    /// Document mode: end of input.
    fn finish(mut self) -> Result<Element, XmlError> {
        if self.pos < self.buf.len() {
            if self.buf[self.pos] == b'<' {
                return Err(XmlError::UnexpectedEof);
            }
            let off = self.base + self.pos as u64;
            self.tree.token(Tok::Text, &self.buf[self.pos..], off)?;
        }
        match (self.tree.top, self.tree.root.take()) {
            (Top::Closed, Some(root)) => Ok(root),
            _ => Err(XmlError::UnexpectedEof),
        }
    }
}

impl Tree {
    fn token(&mut self, kind: Tok, tok: &[u8], off: u64) -> Result<(), XmlError> {
        let n = tok.len();
        if !matches!(kind, Tok::Text | Tok::CData) {
            self.tail_to = None;
        }
        match kind {
            Tok::Text => self.text(utf8(tok)?, off),
            Tok::CData => {
                let s = utf8(&tok[9..n - 3])?;
                if first_invalid_char(s).is_some() {
                    return Err(syntax(off, "PCDATA invalid Char value"));
                }
                if self.frames.is_empty() {
                    self.top_content(off, s.is_empty())?;
                }
                // An empty CDATA section still turns a missing text/tail into "" (as lxml).
                self.append_text(&eol(s), true);
                Ok(())
            }
            Tok::Comment => {
                let s = utf8(&tok[4..n - 3])?;
                if s.contains("--") || s.ends_with('-') {
                    return Err(syntax(off, "Double hyphen within comment"));
                }
                if first_invalid_char(s).is_some() {
                    return Err(syntax(off, "xmlParseComment: invalid xmlChar value"));
                }
                if self.frames.is_empty() {
                    return Ok(());
                }
                self.count_node()?;
                self.push_node(Node::Comment {
                    text: eol(s).into_owned(),
                    tail: None,
                });
                Ok(())
            }
            Tok::Pi => self.pi(utf8(&tok[2..n - 2])?, off),
            Tok::Start => self.start(&tok[1..n - 1], off),
            Tok::End => self.end(utf8(&tok[2..n - 1])?, off),
        }
    }

    /// Character data at depth 0 outside the (virtual) root content.
    fn top_content(&self, off: u64, blank: bool) -> Result<(), XmlError> {
        if self.mode == Mode::Stream && self.top == Top::Open {
            return Ok(());
        }
        if blank {
            return Ok(());
        }
        Err(syntax(
            off,
            match self.top {
                Top::Before => "Start tag expected, '<' not found",
                _ => "Extra content at the end of the document",
            },
        ))
    }

    fn count_node(&mut self) -> Result<(), XmlError> {
        self.item_nodes += 1;
        if self.item_nodes > self.limits.max_nodes {
            return Err(XmlError::LimitExceeded("max_nodes"));
        }
        Ok(())
    }

    fn push_node(&mut self, node: Node) {
        if let Some(f) = self.frames.last_mut() {
            f.elem.children.push(node);
        }
    }

    fn append_text(&mut self, s: &str, keep_empty: bool) {
        if s.is_empty() && !keep_empty {
            return;
        }
        if let Some(e) = self.tail_to.and_then(|i| self.out.get_mut(i)) {
            e.tail.get_or_insert_with(String::new).push_str(s);
        }
        let Some(f) = self.frames.last_mut() else {
            return;
        };
        let slot = match f.elem.children.last_mut() {
            None => &mut f.elem.text,
            Some(Node::Element(e)) => &mut e.tail,
            Some(Node::Comment { tail, .. }) | Some(Node::Pi { tail, .. }) => tail,
        };
        match slot {
            Some(t) => t.push_str(s),
            None => *slot = Some(s.to_owned()),
        }
    }

    /// An unknown named entity: drop the nearest enclosing event (stream) or fail (document).
    fn unknown_entity(&mut self, name: &str) -> Result<(), XmlError> {
        if self.mode == Mode::Document {
            return Err(XmlError::UnknownEntity(name.to_owned()));
        }
        if let Some(f) = self.frames.iter_mut().rev().find(|f| f.is_event) {
            f.dropped = true;
        }
        Ok(())
    }

    fn text(&mut self, s: &str, off: u64) -> Result<(), XmlError> {
        if self.frames.is_empty() && !(self.mode == Mode::Stream && self.top == Top::Open) {
            return self.top_content(off, s.bytes().all(is_space));
        }
        if s.contains("]]>") {
            return Err(syntax(off, "Sequence ']]>' not allowed in content"));
        }
        if first_invalid_char(s).is_some() {
            return Err(syntax(off, "PCDATA invalid Char value"));
        }
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(amp) = rest.find('&') {
            out.push_str(&eol(&rest[..amp]));
            let after = &rest[amp + 1..];
            let Some(semi) = after.find(';') else {
                return Err(syntax(off, "EntityRef: expecting ';'"));
            };
            let name = &after[..semi];
            if name.starts_with('#') {
                match BytesRef::new(name).resolve_char_ref() {
                    Ok(Some(c)) if is_xml_char(c) => out.push(c),
                    _ => return Err(syntax(off, "xmlParseCharRef: invalid xmlChar value")),
                }
            } else if let Some(r) = resolve_predefined_entity(name) {
                out.push_str(r);
            } else if is_name(name) {
                self.unknown_entity(name)?;
            } else {
                return Err(syntax(off, "xmlParseEntityRef: no name"));
            }
            rest = &after[semi + 1..];
        }
        out.push_str(&eol(rest));
        self.append_text(&out, false);
        Ok(())
    }

    fn pi(&mut self, inner: &str, off: u64) -> Result<(), XmlError> {
        if first_invalid_char(inner).is_some() {
            return Err(syntax(off, "PI invalid Char value"));
        }
        let tlen = inner.bytes().position(is_space).unwrap_or(inner.len());
        let target = &inner[..tlen];
        if !is_name(target) {
            return Err(syntax(off, "xmlParsePI : no target name"));
        }
        if target == "xml" {
            if self.mode == Mode::Document && off == 0 {
                return Ok(()); // the XML declaration
            }
            return Err(syntax(
                off,
                "XML declaration allowed only at the start of the document",
            ));
        }
        if target.eq_ignore_ascii_case("xml") {
            return Err(syntax(off, "Invalid PI name"));
        }
        if self.frames.is_empty() {
            return Ok(());
        }
        // libxml2 stores no content for `<?p?>` but an empty one for `<?p ?>`; the serializer
        // writes them back as `<?p?>` and `<?p ?>` (lxml's `.text` is `''` for both).
        let data = (tlen < inner.len())
            .then(|| eol(inner[tlen..].trim_start_matches([' ', '\t', '\r', '\n'])).into_owned());
        self.count_node()?;
        self.push_node(Node::Pi {
            target: target.to_owned(),
            data,
            tail: None,
        });
        Ok(())
    }

    fn lookup(&self, prefix: Option<&str>) -> Option<&str> {
        self.ns
            .iter()
            .rev()
            .find(|(p, _)| p.as_deref() == prefix)
            .and_then(|(_, u)| u.as_deref())
    }

    /// Clark name for `qname`; returns `(clark, namespace, local)`.
    ///
    /// An undeclared prefix keeps the raw `p:local` name (lxml pull parser); in document mode it
    /// is an error, as `etree.fromstring` reports namespace errors. A malformed QName (empty
    /// prefix or local part, a second `:`) is a plain unprefixed name in the stream, as in libxml2
    /// (an element still gets the default namespace), and an error in document mode.
    fn resolve<'q>(
        &self,
        qname: &'q str,
        attr: bool,
        off: u64,
    ) -> Result<(String, Option<String>, &'q str), XmlError> {
        if self.mode == Mode::Document && qname.contains(':') && split_qname(qname).is_none() {
            return Err(syntax(off, format!("Failed to parse QName '{qname}'")));
        }
        Ok(match split_qname(qname) {
            Some(("xml", local)) => (format!("{{{XML_NS}}}{local}"), Some(XML_NS.into()), local),
            Some((p, local)) => match self.lookup(Some(p)) {
                Some(uri) => (format!("{{{uri}}}{local}"), Some(uri.to_owned()), local),
                None if self.mode == Mode::Document => {
                    return Err(syntax(off, format!("Namespace prefix {p} is not defined")));
                }
                None => (qname.to_owned(), None, local),
            },
            None if !attr => match self.lookup(None) {
                Some(uri) => (format!("{{{uri}}}{qname}"), Some(uri.to_owned()), qname),
                None => (qname.to_owned(), None, qname),
            },
            None => (qname.to_owned(), None, qname),
        })
    }

    fn start(&mut self, inner: &[u8], off: u64) -> Result<(), XmlError> {
        if self.frames.is_empty() && self.top == Top::Closed {
            return Err(syntax(off, "Extra content at the end of the document"));
        }
        let (content, empty) = match inner.split_last() {
            Some((b'/', head)) => (head, true),
            _ => (inner, false),
        };
        let content = utf8(content)?;
        if first_invalid_char(content).is_some() {
            return Err(syntax(off, "invalid Char value in start tag"));
        }
        let name_len = content.bytes().position(is_space).unwrap_or(content.len());
        let qname = &content[..name_len];
        if !is_name(qname) {
            return Err(syntax(off, "StartTag: invalid element name"));
        }
        let lim = self.limits;
        if qname.len() > lim.max_name {
            return Err(XmlError::LimitExceeded("max_name"));
        }
        check_attr_spacing(&content[name_len..], off)?;
        let max_frames = match self.mode {
            Mode::Stream => lim.max_depth.saturating_sub(1),
            Mode::Document => lim.max_depth,
        };
        if self.frames.len() >= max_frames {
            return Err(XmlError::LimitExceeded("max_depth"));
        }
        if self.frames.is_empty() {
            self.item_start = off;
            self.item_nodes = 0;
            if self.mode == Mode::Document {
                self.top = Top::Open;
            }
        }
        self.count_node()?;

        let start = BytesStart::from_content(content, name_len);
        let mut raw: Vec<(&str, String)> = Vec::new();
        let mut decls: Vec<(&str, String)> = Vec::new();
        let mut unknown: Option<String> = None;
        let mut bad_ref = false;
        let mut attrs = start.attributes();
        // Duplicates are checked below: libxml2 tolerates a repeated name with an undeclared prefix.
        attrs.with_checks(false);
        for a in attrs {
            let a = a.map_err(|e| syntax(off, format!("attributes construct error: {e}")))?;
            if raw.len() + decls.len() >= lim.max_attrs {
                return Err(XmlError::LimitExceeded("max_attrs"));
            }
            let key: &str = a.key.into_inner();
            if !is_name(key) {
                return Err(syntax(off, "error parsing attribute name"));
            }
            if key.len() > lim.max_name {
                return Err(XmlError::LimitExceeded("max_name"));
            }
            if a.value.contains('<') {
                return Err(syntax(
                    off,
                    "Unescaped '<' not allowed in attributes values",
                ));
            }
            let value = a
                .normalized_value_with(XmlVersion::Implicit1_0, 1, |name| {
                    if let Some(r) = resolve_predefined_entity(name) {
                        Some(r)
                    } else {
                        if is_name(name) {
                            unknown.get_or_insert_with(|| name.to_owned());
                        } else {
                            bad_ref = true;
                        }
                        Some("")
                    }
                })
                .map_err(|e| syntax(off, format!("AttValue: {e}")))?;
            if bad_ref || first_invalid_char(&value).is_some() {
                return Err(syntax(off, "AttValue: invalid reference or char"));
            }
            let value = value.into_owned();
            if key == "xmlns" || matches!(split_qname(key), Some(("xmlns", _))) {
                if key != "xmlns" && value.is_empty() && self.mode == Mode::Stream {
                    // `xmlns:p=""`: libxml2 reports a namespace error and drops it (not even
                    // considered for duplicates).
                    continue;
                }
                if decls.iter().any(|(k, _)| *k == key) {
                    return Err(syntax(off, format!("Attribute {key} redefined")));
                }
                decls.push((key, value));
            } else {
                raw.push((key, value));
            }
        }
        let decls: Vec<(Option<String>, String)> = decls
            .into_iter()
            .map(|(k, v)| (k.strip_prefix("xmlns:").map(str::to_owned), v))
            .collect();

        let ns_len = self.ns.len();
        let mut elem = Element::default();
        for (p, uri) in decls {
            if p.as_deref() == Some("xml") && uri == XML_NS {
                // Redundant `xmlns:xml` declaration: libxml2 accepts it and does not record it.
                continue;
            }
            match (p, uri.is_empty()) {
                // `xmlns:p=""` is a namespace error in libxml2: ignored, the outer binding stays
                // (fatal for `etree.fromstring`).
                (Some(p), true) => {
                    if self.mode == Mode::Document {
                        return Err(syntax(off, format!("xmlns:{p}: Empty XML namespace")));
                    }
                }
                // `xmlns=""` unbinds the default namespace.
                (None, true) => {
                    elem.nsmap.push((None, String::new()));
                    self.ns.push((None, None));
                }
                (p, false) => {
                    elem.nsmap.push((p.clone(), uri.clone()));
                    self.ns.push((p, Some(uri)));
                }
            }
        }
        for (i, (k, _)) in raw.iter().enumerate() {
            if raw[..i].iter().any(|(p, _)| p == k) {
                let undeclared = match split_qname(k) {
                    Some(("xml", _)) | None => false,
                    Some((p, _)) => self.lookup(Some(p)).is_none(),
                };
                if !undeclared {
                    return Err(syntax(off, format!("Attribute {k} redefined")));
                }
            }
        }
        let (tag, ns, local) = self.resolve(qname, false, off)?;
        let is_event = self.mode == Mode::Stream && local == "event" && ns.is_none();
        elem.tag = tag;
        elem.prefix = match ns.as_deref() {
            Some(uri) if uri != XML_NS && split_qname(qname).is_none() => Some(String::new()),
            ns => orig_prefix(qname, ns),
        };
        let mut attrs = Vec::with_capacity(raw.len());
        for (i, (k, v)) in raw.into_iter().enumerate() {
            let (name, ns, _) = self.resolve(k, true, off)?;
            if let Some(p) = orig_prefix(k, ns.as_deref()) {
                elem.attr_prefixes.push((i, p));
            }
            attrs.push((name, v));
        }
        elem.attrs = attrs;
        self.frames.push(Frame {
            elem,
            qname: qname.to_owned(),
            is_event,
            dropped: false,
            ns_len,
        });
        if let Some(name) = unknown {
            self.unknown_entity(&name)?;
        }
        if empty {
            self.close();
        }
        Ok(())
    }

    fn end(&mut self, inner: &str, off: u64) -> Result<(), XmlError> {
        let name = inner.trim_end_matches([' ', '\t', '\r', '\n']);
        if !is_name(name) {
            return Err(syntax(off, "expected '>'"));
        }
        match self.frames.last() {
            None if self.mode == Mode::Stream && self.top == Top::Open && name == "root" => {
                self.top = Top::Closed;
                Ok(())
            }
            None => Err(syntax(
                off,
                format!("Opening and ending tag mismatch: root and {name}"),
            )),
            Some(f) if f.qname != name => Err(syntax(
                off,
                format!("Opening and ending tag mismatch: {} and {name}", f.qname),
            )),
            Some(_) => {
                self.close();
                Ok(())
            }
        }
    }

    /// `etree.tostring` of an element below the document root writes a shallow copy of it
    /// (`xmlCopyNode(node, 2)`): its own declarations, then — while copying the attributes —
    /// a declaration for every prefix an attribute uses that is declared on an ancestor (attribute
    /// order, `xmlCopyProp`), then every other namespace declared on its ancestors, nearest
    /// first, each in declaration order, unless the prefix is already declared on the copy
    /// (`_copyParentNamespaces` + `xmlNewNs`). The emitted event is a detached copy, so the
    /// inherited declarations are added to its `nsmap` here.
    fn inherit_ns(&self, e: &mut Element, own_ns_len: usize) {
        for (i, (k, _)) in e.attrs.iter().enumerate() {
            if let (Some(p), Some((uri, _))) = (e.attr_prefix(i), crate::serialize::split_clark(k))
                && e.nsmap.iter().all(|(q, _)| q.as_deref() != Some(p))
            {
                e.nsmap.push((Some(p.to_owned()), uri.to_owned()));
            }
        }
        let mut end = own_ns_len;
        for f in self.frames.iter().rev() {
            for (p, uri) in &self.ns[f.ns_len..end] {
                if e.nsmap.iter().all(|(q, _)| q != p) {
                    e.nsmap.push((p.clone(), uri.clone().unwrap_or_default()));
                }
            }
            end = f.ns_len;
        }
    }

    /// Close the innermost element.
    fn close(&mut self) {
        let Some(f) = self.frames.pop() else {
            return;
        };
        self.ns.truncate(f.ns_len);
        let mut elem = f.elem;
        if f.is_event {
            // `elm.clear(keep_tail=True)`: same tag, no attributes/text/children; libxml2 keeps
            // the element's own namespace declarations.
            let mut placeholder = Element::new(elem.tag.clone());
            placeholder.nsmap = elem.nsmap.clone();
            placeholder.prefix = elem.prefix.clone();
            let mut done = std::mem::replace(&mut elem, placeholder);
            if !f.dropped {
                self.inherit_ns(&mut done, f.ns_len);
                self.out.push_back(done);
                self.tail_to = Some(self.out.len() - 1);
            }
        }
        match self.frames.last_mut() {
            Some(parent) => parent.elem.children.push(Node::Element(elem)),
            None => {
                if self.mode == Mode::Document {
                    self.root = Some(elem);
                    self.top = Top::Closed;
                }
            }
        }
    }
}

/// `(prefix, local)` of a well-formed prefixed QName; `None` for an unprefixed name and for a
/// malformed one (`:a`, `a:`, `a:b:c`), which libxml2 keeps verbatim as an unprefixed name.
fn split_qname(qname: &str) -> Option<(&str, &str)> {
    match qname.split_once(':') {
        Some((p, l)) if !p.is_empty() && !l.is_empty() && !l.contains(':') => Some((p, l)),
        _ => None,
    }
}

/// Prefix of `qname` worth recording: only for a name resolved to a namespace other than `xml:`.
fn orig_prefix(qname: &str, ns: Option<&str>) -> Option<String> {
    match (split_qname(qname), ns) {
        (Some((p, _)), Some(uri)) if uri != XML_NS => Some(p.to_owned()),
        _ => None,
    }
}

/// libxml2 requires whitespace between attributes (`a='1'b='2'` is an error); quick-xml does not.
fn check_attr_spacing(rest: &str, off: u64) -> Result<(), XmlError> {
    let b = rest.as_bytes();
    let mut q: Option<u8> = None;
    for (i, &c) in b.iter().enumerate() {
        match q {
            Some(open) if c == open => {
                q = None;
                if let Some(&next) = b.get(i + 1)
                    && !is_space(next)
                {
                    return Err(syntax(off, "attributes construct error"));
                }
            }
            Some(_) => {}
            None if c == b'"' || c == b'\'' => q = Some(c),
            None => {}
        }
    }
    Ok(())
}
