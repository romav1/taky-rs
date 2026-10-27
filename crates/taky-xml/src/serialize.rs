//! Serialization byte-compatible with `lxml.etree.tostring` (lxml 6.1 / libxml2 2.14).
//!
//! Output is always US-ASCII (the `tostring` default): every non-ASCII character, wherever it
//! occurs (text, attribute values, comments, PIs, names), becomes a decimal reference `&#N;`,
//! as libxml2's ASCII encoder does.
//!
//! Escaping (libxml2): text `& < >` and `\r` (`&#13;`); attribute values additionally `"`,
//! `\t`, `\n` (`&#9; &#10;`); `'` is never escaped; values are always double-quoted.
//! An element without text and children is written `<x/>`; an empty text (`Some("")`) is a node,
//! so it gives `<x></x>`.
//!
//! Namespaces: declarations in [`Element::nsmap`] are written verbatim before the attributes and
//! names use their recorded original prefixes ([`Element::prefix`], [`Element::attr_prefixes`])
//! verbatim — this is what libxml2 does for a parsed tree. A namespaced name without a recorded
//! prefix (a tree built in code) uses the default namespace if it is bound to the URI (elements
//! only), otherwise it is resolved like lxml at creation time: an in-scope prefix bound to the
//! URI (never the default one for attributes), else a new declaration on that element using the
//! recorded prefix if it is free, else `ns0`, `ns1`, …. For an element moved out of its parsed
//! tree call [`Element::reconcile_moved_ns`] first.

use crate::{Element, Node};

/// The `xml:` namespace (always bound, never declared).
pub(crate) const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// `etree.tostring` parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerOpts {
    /// `pretty_print=True`.
    pub pretty_print: bool,
    /// `xml_declaration=True` (lxml's `<?xml version='1.0' encoding='ASCII'?>` form).
    pub xml_declaration: bool,
    /// `standalone=` (only together with `xml_declaration`).
    pub standalone: Option<bool>,
    /// `with_tail=` (default `true`, as in lxml).
    pub with_tail: bool,
}

impl Default for SerOpts {
    /// Like `etree.tostring(e)` with no arguments: ASCII + `&#NNN;`, no declaration, with tail.
    fn default() -> Self {
        SerOpts {
            pretty_print: false,
            xml_declaration: false,
            standalone: None,
            with_tail: true,
        }
    }
}

/// libxml2 caps indentation at `MAX_INDENT` = 60 spaces, i.e. 30 levels of 2 spaces.
const MAX_INDENT_LEVELS: usize = 30;

/// `etree.tostring(e, **o)` — byte-exact with lxml for an element (see the module docs).
pub fn serialize(e: &Element, o: &SerOpts) -> Vec<u8> {
    let mut w = Writer {
        out: String::new(),
        scope: Vec::new(),
        depth: 0,
        counter: 0,
    };
    if o.xml_declaration {
        w.out.push_str("<?xml version='1.0' encoding='ASCII'");
        match o.standalone {
            Some(true) => w.out.push_str(" standalone='yes'"),
            Some(false) => w.out.push_str(" standalone='no'"),
            None => {}
        }
        w.out.push_str("?>\n");
    }
    w.element(e, 0, o.pretty_print);
    if o.with_tail
        && let Some(t) = &e.tail
    {
        w.text(t);
    }
    if o.pretty_print {
        w.out.push('\n');
    }
    w.out.into_bytes()
}

struct Writer {
    out: String,
    /// Namespace bindings in output scope, innermost element last (`""` = `xmlns=""`).
    scope: Vec<Scoped>,
    /// Depth of the element being written (groups `scope` entries per element).
    depth: usize,
    /// lxml's per-document `ns%d` counter.
    counter: usize,
}

impl Writer {
    fn lookup(&self, prefix: Option<&str>) -> Option<&str> {
        lookup(&self.scope, prefix)
    }

    /// Prefix (as `Some(None)` for the default ns) for a namespaced name, declaring it on the
    /// element being written if needed (pushed to `decls` and `scope`).
    fn qualify(
        &mut self,
        uri: &str,
        recorded: Option<&str>,
        attr: bool,
        decls: &mut Vec<(Option<String>, String)>,
    ) -> Option<String> {
        if uri == XML_NS {
            return Some("xml".to_owned());
        }
        // A recorded prefix is written as is, like libxml2 prints `ns->prefix` without checking
        // the scope (it can differ from the in-scope binding after lxml's own reconciliation);
        // `""` is the default namespace.
        if let Some(p) = recorded {
            return (!p.is_empty()).then(|| p.to_owned());
        }
        if !attr && self.lookup(None) == Some(uri) {
            return None;
        }
        if let Some(p) = by_href(&self.scope, uri, attr) {
            return p;
        }
        let p = loop {
            let p = format!("ns{}", self.counter);
            self.counter += 1;
            if self.lookup(Some(&p)).is_none() {
                break p;
            }
        };
        decls.push((Some(p.clone()), uri.to_owned()));
        self.scope
            .push((self.depth, Some(p.clone()), uri.to_owned()));
        Some(p)
    }

    fn name(
        &mut self,
        name: &str,
        recorded: Option<&str>,
        attr: bool,
        decls: &mut Vec<(Option<String>, String)>,
    ) -> String {
        match split_clark(name) {
            Some((uri, local)) => match self.qualify(uri, recorded, attr, decls) {
                Some(p) => format!("{p}:{local}"),
                None => local.to_owned(),
            },
            None => name.to_owned(),
        }
    }

    fn element(&mut self, e: &Element, level: usize, format: bool) {
        let base = self.scope.len();
        self.depth = level;
        let mut decls = e.nsmap.clone();
        self.scope
            .extend(decls.iter().map(|(p, u)| (level, p.clone(), u.clone())));
        let tag = self.name(&e.tag, e.prefix.as_deref(), false, &mut decls);
        let mut attrs = Vec::with_capacity(e.attrs.len());
        for (i, (k, v)) in e.attrs.iter().enumerate() {
            let k = self.name(k, e.attr_prefix(i), true, &mut decls);
            attrs.push((k, v));
        }
        self.out.push('<');
        self.raw(&tag);
        for (p, uri) in &decls {
            match p {
                Some(p) => {
                    self.out.push_str(" xmlns:");
                    self.raw(p);
                }
                None => self.out.push_str(" xmlns"),
            }
            self.out.push_str("=\"");
            self.attr_value(uri);
            self.out.push('"');
        }
        for (k, v) in attrs {
            self.out.push(' ');
            self.raw(&k);
            self.out.push_str("=\"");
            self.attr_value(v);
            self.out.push('"');
        }
        if e.text.is_none() && e.children.is_empty() {
            self.out.push_str("/>");
            self.scope.truncate(base);
            return;
        }
        // libxml2 stops formatting inside an element that has a text/CDATA child node.
        let format =
            format && e.text.is_none() && e.children.iter().all(|c| node_tail(c).is_none());
        self.out.push('>');
        if format {
            self.out.push('\n');
        }
        if let Some(t) = &e.text {
            self.text(t);
        }
        for c in &e.children {
            if format {
                self.indent(level + 1);
            }
            match c {
                Node::Element(ch) => self.element(ch, level + 1, format),
                Node::Comment { text, .. } => {
                    self.out.push_str("<!--");
                    self.raw(text);
                    self.out.push_str("-->");
                }
                Node::Pi { target, data, .. } => {
                    self.out.push_str("<?");
                    self.raw(target);
                    if let Some(d) = data {
                        self.out.push(' ');
                        self.raw(d);
                    }
                    self.out.push_str("?>");
                }
            }
            if let Some(t) = node_tail(c) {
                self.text(t);
            }
            if format {
                self.out.push('\n');
            }
        }
        if format {
            self.indent(level);
        }
        self.out.push_str("</");
        self.raw(&tag);
        self.out.push('>');
        self.scope.truncate(base);
    }

    fn indent(&mut self, level: usize) {
        for _ in 0..level.min(MAX_INDENT_LEVELS) {
            self.out.push_str("  ");
        }
    }

    /// Markup content (names, comments, PIs): only non-ASCII is converted.
    fn raw(&mut self, s: &str) {
        for c in s.chars() {
            self.ascii(c);
        }
    }

    fn text(&mut self, s: &str) {
        for c in s.chars() {
            match c {
                '&' => self.out.push_str("&amp;"),
                '<' => self.out.push_str("&lt;"),
                '>' => self.out.push_str("&gt;"),
                '\r' => self.out.push_str("&#13;"),
                c => self.ascii(c),
            }
        }
    }

    fn attr_value(&mut self, s: &str) {
        for c in s.chars() {
            match c {
                '&' => self.out.push_str("&amp;"),
                '<' => self.out.push_str("&lt;"),
                '>' => self.out.push_str("&gt;"),
                '"' => self.out.push_str("&quot;"),
                '\t' => self.out.push_str("&#9;"),
                '\n' => self.out.push_str("&#10;"),
                '\r' => self.out.push_str("&#13;"),
                c => self.ascii(c),
            }
        }
    }

    fn ascii(&mut self, c: char) {
        if c.is_ascii() {
            self.out.push(c);
        } else {
            self.out.push_str("&#");
            self.out.push_str(&u32::from(c).to_string());
            self.out.push(';');
        }
    }
}

fn node_tail(n: &Node) -> Option<&String> {
    match n {
        Node::Element(e) => e.tail.as_ref(),
        Node::Comment { tail, .. } | Node::Pi { tail, .. } => tail.as_ref(),
    }
}

/// `{uri}local` → `(uri, local)`.
///
/// Split at the **last** `}`: a namespace URI may contain `}`, a local name (an NCName) cannot
/// (S-407a, fuzzing F-1). Clark names here are internal: libxml2 keeps URI and local name
/// apart, so the serialized bytes match lxml even where lxml's own `get("{a}b}c")` fails.
pub(crate) fn split_clark(name: &str) -> Option<(&str, &str)> {
    name.strip_prefix('{')?.rsplit_once('}')
}

/// A namespace binding with the depth of the element that declares it.
type Scoped = (usize, Option<String>, String);

/// Innermost binding of `prefix` (`None` = default namespace).
fn lookup<'a>(scope: &'a [Scoped], prefix: Option<&str>) -> Option<&'a str> {
    scope
        .iter()
        .rev()
        .find(|(_, p, _)| p.as_deref() == prefix)
        .map(|(_, _, u)| u.as_str())
        .filter(|u| !u.is_empty())
}

/// libxml2/lxml search order for a URI: innermost element first, each element's declarations
/// in document order.
fn search_order(scope: &[Scoped]) -> impl Iterator<Item = &Scoped> {
    let mut runs: Vec<&[Scoped]> = Vec::new();
    let mut rest = scope;
    while let Some(last) = rest.last() {
        let start = rest
            .iter()
            .rposition(|x| x.0 != last.0)
            .map_or(0, |i| i + 1);
        runs.push(&rest[start..]);
        rest = &rest[..start];
    }
    runs.into_iter().flatten()
}

/// Innermost unshadowed prefix bound to `uri` (`Some(None)` = the default namespace, never
/// returned for attributes).
fn by_href(scope: &[Scoped], uri: &str, attr: bool) -> Option<Option<String>> {
    search_order(scope)
        .find(|(_, p, u)| {
            u == uri && !(attr && p.is_none()) && lookup(scope, p.as_deref()) == Some(uri)
        })
        .map(|(_, p, _)| p.clone())
}

impl Element {
    /// Emulates lxml's `moveNodeToDocument` for `new_parent.append(self)` where `self` comes
    /// from a parsed tree and the new parent declares no namespaces (taky's
    /// `Event.as_element` appending the original `<detail>`, the DPS video index appending a
    /// parsed `<feed>`):
    ///
    /// * every element in the subtree (except `self`) drops a declaration whose URI is already
    ///   bound in its new ancestors (`xmlSearchNsByHref`); references are remapped to that binding;
    /// * a namespace used in the subtree but declared outside it is looked up by URI on `self`,
    ///   else declared on `self` with the original prefix (`ns0`… if taken).
    ///
    /// lxml quirks are kept (a remapped name may end up in a shadowed binding). Idempotent; a tree
    /// without namespaces is left untouched. Must be called before the element is serialized
    /// under its new parent.
    pub fn reconcile_moved_ns(&mut self) {
        let mut root = std::mem::take(&mut self.nsmap);
        let mut r = Reconcile {
            orig: root
                .iter()
                .map(|(p, u)| (p.clone(), u.clone(), p.clone()))
                .collect(),
            anc: Vec::new(),
            cache: Vec::new(),
            counter: 0,
        };
        r.refs(self, &mut root);
        r.anc.push(Anc {
            decls: Vec::new(),
            ns: tag_ns(self),
        });
        for c in &mut self.children {
            if let Node::Element(ch) = c {
                r.element(ch, &mut root);
            }
        }
        self.nsmap = root;
    }
}

/// Binding `(prefix, uri)`.
type Binding = (Option<String>, String);

/// An ancestor in the new tree: its kept declarations (empty for the root, whose declarations
/// live in `root`) and its own (already remapped) namespace.
struct Anc {
    decls: Vec<Binding>,
    ns: Option<Binding>,
}

/// The (remapped) namespace binding of an element's tag, if recorded.
fn tag_ns(e: &Element) -> Option<Binding> {
    let (uri, _) = split_clark(&e.tag)?;
    let p = e.prefix.as_ref()?;
    Some(((!p.is_empty()).then(|| p.clone()), uri.to_owned()))
}

struct Reconcile {
    /// Original declarations inside the subtree, innermost last: `(prefix, uri, new prefix)`.
    orig: Vec<(Option<String>, String, Option<String>)>,
    /// Ancestors of the element being processed, `anc[0]` = the moved root.
    anc: Vec<Anc>,
    /// External namespace `(prefix, uri)` → new prefix.
    cache: Vec<(Binding, Option<String>)>,
    counter: usize,
}

impl Reconcile {
    fn element(&mut self, e: &mut Element, root: &mut Vec<Binding>) {
        let orig_len = self.orig.len();
        let decls = std::mem::take(&mut e.nsmap);
        let mut kept = Vec::with_capacity(decls.len());
        // `xmlSearchNsByHref` from the parent: the element's own declarations are not visible.
        let found: Vec<_> = decls
            .iter()
            .map(|(_, u)| self.search_href(root, u))
            .collect();
        for ((p, u), f) in decls.into_iter().zip(found) {
            match f {
                Some(np) => self.orig.push((p, u, np)),
                None => {
                    self.orig.push((p.clone(), u.clone(), p.clone()));
                    kept.push((p, u));
                }
            }
        }
        e.nsmap = kept;
        self.refs(e, root);
        self.anc.push(Anc {
            decls: e.nsmap.clone(),
            ns: tag_ns(e),
        });
        for c in &mut e.children {
            if let Node::Element(ch) = c {
                self.element(ch, root);
            }
        }
        self.anc.pop();
        self.orig.truncate(orig_len);
    }

    /// libxml2 `xmlSearchNsByHref(doc, parent, href)`: for every ancestor from the parent up, its
    /// declarations in order, then (above the parent) its own namespace; the prefix must not be
    /// redeclared between the parent and that ancestor (`xmlNsInScope`).
    fn search_href(&self, root: &[Binding], uri: &str) -> Option<Option<String>> {
        let top = self.anc.len().checked_sub(1)?;
        let decls = |i: usize| -> &[Binding] { if i == 0 { root } else { &self.anc[i].decls } };
        let in_scope = |p: &Option<String>, i: usize| {
            (i + 1..=top).all(|j| decls(j).iter().all(|(q, _)| q != p))
        };
        for i in (0..=top).rev() {
            if let Some((p, _)) = decls(i).iter().find(|(p, u)| u == uri && in_scope(p, i)) {
                return Some(p.clone());
            }
            if i != top
                && let Some((p, u)) = &self.anc[i].ns
                && u == uri
                && in_scope(p, i)
            {
                return Some(p.clone());
            }
        }
        None
    }

    fn refs(&mut self, e: &mut Element, root: &mut Vec<Binding>) {
        if let Some((uri, _)) = split_clark(&e.tag) {
            let uri = uri.to_owned();
            // Only recorded prefixes (`Some("")` = default namespace) are remapped.
            if uri != XML_NS
                && let Some(p) = e.prefix.take()
            {
                let p = (!p.is_empty()).then_some(p);
                e.prefix = Some(self.map(p, &uri, false, root).unwrap_or_default());
            }
        }
        for (i, (k, _)) in e.attrs.iter().enumerate() {
            let Some((uri, _)) = split_clark(k) else {
                continue;
            };
            if uri == XML_NS {
                continue;
            }
            let Some(slot) = e.attr_prefixes.iter_mut().find(|(j, _)| *j == i) else {
                continue;
            };
            if let Some(np) = self.map(Some(slot.1.clone()), uri, true, root) {
                slot.1 = np;
            }
        }
    }

    fn map(
        &mut self,
        p: Option<String>,
        uri: &str,
        attr: bool,
        root: &mut Vec<Binding>,
    ) -> Option<String> {
        let ok = |np: &Option<String>| !(attr && np.is_none());
        if let Some((_, u, np)) = self.orig.iter().rev().find(|(q, _, _)| *q == p)
            && u == uri
            && ok(np)
        {
            return np.clone();
        }
        let key = (p.clone(), uri.to_owned());
        if let Some((_, np)) = self.cache.iter().find(|(k, np)| *k == key && ok(np)) {
            return np.clone();
        }
        // `_findOrBuildNodeNs(start_node, href, prefix, is_attribute)`.
        let np = match root
            .iter()
            .find(|(q, u)| u == uri && !(attr && q.is_none()))
        {
            Some((q, _)) => q.clone(),
            None => {
                let np = match &p {
                    Some(p) if root.iter().all(|(q, _)| q.as_deref() != Some(p)) => p.clone(),
                    _ => loop {
                        let c = format!("ns{}", self.counter);
                        self.counter += 1;
                        if root.iter().all(|(q, _)| q.as_deref() != Some(c.as_str())) {
                            break c;
                        }
                    },
                };
                root.push((Some(np.clone()), uri.to_owned()));
                Some(np)
            }
        };
        self.cache.push((key, np.clone()));
        np
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(e: &Element, o: &SerOpts) -> String {
        String::from_utf8(serialize(e, o)).unwrap_or_default()
    }

    #[test]
    fn escaping_and_ascii() {
        let mut e = Element::new("x");
        e.set("k", "\"'<>&\t\n\r\u{416}");
        e.text = Some("\"'<>&\t\n\r\u{1F600}".into());
        assert_eq!(
            s(&e, &SerOpts::default()),
            "<x k=\"&quot;'&lt;&gt;&amp;&#9;&#10;&#13;&#1046;\">\"'&lt;&gt;&amp;\t\n&#13;&#128512;</x>"
        );
    }

    #[test]
    fn empty_forms_and_declaration() {
        let mut e = Element::new("a");
        assert_eq!(s(&e, &SerOpts::default()), "<a/>");
        e.text = Some(String::new());
        let o = SerOpts {
            pretty_print: true,
            xml_declaration: true,
            standalone: Some(true),
            ..SerOpts::default()
        };
        assert_eq!(
            s(&e, &o),
            "<?xml version='1.0' encoding='ASCII' standalone='yes'?>\n<a></a>\n"
        );
    }

    #[test]
    fn code_built_namespaces_like_lxml() {
        let mut a = Element::new("{u}a");
        let mut b = Element::new("{u}b");
        b.set("{v}k", "1");
        a.append(b);
        assert_eq!(
            s(&a, &SerOpts::default()),
            "<ns0:a xmlns:ns0=\"u\"><ns0:b xmlns:ns1=\"v\" ns1:k=\"1\"/></ns0:a>"
        );
    }
}
