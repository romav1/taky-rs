//! Mini-DOM modeled on lxml.

/// XML element.
///
/// Modeled on `lxml.etree._Element`: text before the first child is `text`, text after the
/// closing tag is `tail` (it belongs to this element, not to the parent).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Element {
    /// Tag in Clark notation: `"{ns}local"` or `"local"`.
    pub tag: String,
    /// Attributes in document order (names in Clark notation).
    ///
    /// Invariant (ADR-002 rev. 3 §2): [`Element::attr_prefixes`] holds indices into this vector.
    /// Code that removes or reorders attributes must re-index `attr_prefixes` (or clear the
    /// affected entries); appending and replacing values in place (as [`Element::set`] does) is safe.
    pub attrs: Vec<(String, String)>,
    /// Text before the first child node.
    pub text: Option<String>,
    /// Text after the closing tag.
    pub tail: Option<String>,
    /// Child nodes (elements, comments, PIs) in document order.
    pub children: Vec<Node>,
    /// Namespace declarations of this element `(prefix, uri)` in document order (`None` — default
    /// ns; `xmlns=""` is kept as `(None, "")`); written verbatim by the serializer (libxml2 `nsDef`).
    /// An event emitted by [`crate::TreeBuilder`] also carries the declarations inherited from its
    /// ancestors, appended nearest ancestor first (what `etree.tostring` copies onto a subtree).
    pub nsmap: Vec<(Option<String>, String)>,
    /// Prefix a namespaced tag was written with (`Some("")` — unprefixed, default namespace),
    /// recorded by the parser: libxml2 prints the original prefix even when several prefixes bind
    /// the same URI. `None` (an element built in code) — the serializer picks one like lxml.
    pub prefix: Option<String>,
    /// Original prefixes of namespaced attributes: `(index into attrs, prefix)`. Filled by the
    /// parser; [`Element::set`] never reorders `attrs`, so the indices stay valid. A namespaced
    /// attribute without an entry gets a prefix chosen like lxml does for `elm.set("{uri}k", v)`.
    pub attr_prefixes: Vec<(usize, String)>,
}

/// Child node of an element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// Nested element.
    Element(Element),
    /// Comment `<!--text-->` and its tail.
    Comment {
        /// Comment text.
        text: String,
        /// Text after the comment.
        tail: Option<String>,
    },
    /// Processing instruction `<?target data?>` and its tail.
    Pi {
        /// PI target.
        target: String,
        /// PI data (`None` — `<?target?>` with no whitespace after the target).
        data: Option<String>,
        /// Text after the PI.
        tail: Option<String>,
    },
}

impl Element {
    /// New element with tag `tag`, without attributes and children.
    pub fn new(tag: impl Into<String>) -> Element {
        Element {
            tag: tag.into(),
            ..Element::default()
        }
    }

    /// `elm.get(name)`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// `elm.set(name, value)`: replaces the value in place or appends it at the end (order as in lxml).
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        match self.attrs.iter_mut().find(|(k, _)| *k == name) {
            Some(slot) => slot.1 = value,
            None => self.attrs.push((name, value)),
        }
    }

    /// Child elements (without comments and PIs) — `elm.iterchildren()` filtered by Element.
    pub fn child_elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }

    /// `elm.find(tag)` — the first direct child with the given tag.
    pub fn find(&self, tag: &str) -> Option<&Element> {
        self.child_elements().find(|e| e.tag == tag)
    }

    /// Prefix recorded for attribute number `idx` (see [`Element::attr_prefixes`]).
    pub fn attr_prefix(&self, idx: usize) -> Option<&str> {
        self.attr_prefixes
            .iter()
            .find(|(i, _)| *i == idx)
            .map(|(_, p)| p.as_str())
    }

    /// `elm.append(child)`.
    pub fn append(&mut self, child: Element) {
        self.children.push(Node::Element(child));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_keeps_order_and_replaces() {
        let mut e = Element::new("event");
        e.set("version", "2.0");
        e.set("uid", "a");
        e.set("version", "2.1");
        assert_eq!(
            e.attrs,
            vec![("version".into(), "2.1".into()), ("uid".into(), "a".into())]
        );
        assert_eq!(e.get("uid"), Some("a"));
        e.append(Element::new("point"));
        assert!(e.find("point").is_some());
        assert!(e.find("detail").is_none());
    }
}
