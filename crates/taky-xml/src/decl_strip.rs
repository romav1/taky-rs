//! Byte-exact port of `taky.util.xmldeclstrip.XMLDeclStrip.strip` (cot-server.md §5.2).
//!
//! ATAK sends every event as a separate document with `<?xml …?>`. The original strips those
//! declarations from the raw byte stream before the pull parser sees them. The semantics are
//! reproduced exactly, including the quirks:
//! * only the bytes `<?xml ` (with a **space**) start a declaration; `<?xml?>`, `<?xml\t…?>` and
//!   `<?XML …?>` are passed through (and then rejected by the parser, V019);
//! * a declaration ends at the first `?>` (even inside a quoted value);
//! * a trailing `<` closer than 6 bytes to the end of the data is held back until the next chunk;
//!   inside a declaration the last byte is held back;
//! * when a chunk ends exactly after `<?xml `, the previously held-back tail is **not** reset
//!   (Python leaves `self.tail` stale in that path) — reproduced for byte identity.
//!
//! The held-back tail is at most 5 bytes, and the contents of a declaration are never buffered,
//! so an endless `<?xml ` cannot grow memory.

const START: &[u8] = b"<?xml ";
const END: &[u8] = b"?>";

/// Streaming `<?xml ` declaration stripper (state between chunks).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XmlDeclStrip {
    tail: Vec<u8>,
    in_decl: bool,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

impl XmlDeclStrip {
    /// New stripper (no pending tail, not inside a declaration).
    pub fn new() -> XmlDeclStrip {
        XmlDeclStrip::default()
    }

    /// Whether the stripper is currently inside a `<?xml ` declaration.
    pub fn in_decl(&self) -> bool {
        self.in_decl
    }

    /// `XMLDeclStrip.strip(data)`: appends the bytes to pass to the parser to `out`.
    pub fn strip(&mut self, data: &[u8], out: &mut Vec<u8>) {
        let mut joined = self.tail.clone();
        joined.extend_from_slice(data);
        let mut d: &[u8] = &joined;
        while !d.is_empty() {
            if !self.in_decl {
                if let Some(pos) = find(d, START) {
                    self.in_decl = true;
                    out.extend_from_slice(&d[..pos]);
                    d = &d[pos + START.len()..];
                } else {
                    match d.iter().rposition(|&b| b == b'<') {
                        Some(pos) if d.len() - pos < START.len() => {
                            self.tail = d[pos..].to_vec();
                            out.extend_from_slice(&d[..pos]);
                        }
                        _ => {
                            self.tail.clear();
                            out.extend_from_slice(d);
                        }
                    }
                    return;
                }
            } else if let Some(pos) = find(d, END) {
                self.in_decl = false;
                d = &d[pos + END.len()..];
                self.tail.clear();
            } else {
                self.tail = d[d.len() - 1..].to_vec();
                return;
            }
        }
        // Consumed everything cleanly (Python leaves `self.tail` untouched here).
    }

    /// Convenience wrapper around [`XmlDeclStrip::strip`].
    pub fn strip_vec(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        self.strip(data, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds `chunks` and then a flush chunk of 6 spaces (pushes out a held-back tail).
    fn run(chunks: &[&[u8]]) -> Vec<u8> {
        let mut s = XmlDeclStrip::new();
        let mut out = Vec::new();
        for c in chunks {
            s.strip(c, &mut out);
        }
        s.strip(b"      ", &mut out);
        out.truncate(out.len() - 6);
        out
    }

    #[test]
    fn strips_whole_and_split_declarations() {
        let ev: &[u8] = b"<event/>";
        assert_eq!(run(&[b"<?xml version='1.0'?>", ev]), ev);
        assert_eq!(run(&[b"<?xm", b"l version='1.0'?>", ev]), ev);
        assert_eq!(run(&[b"<?xml version='1.0'?", b">", ev]), ev);
        assert_eq!(run(&[b"a<", b"?xml v?>b"]), b"ab");
    }

    #[test]
    fn quirks() {
        // Not recognized: no space / tab / uppercase.
        assert_eq!(run(&[b"<?xml?><e/>"]), b"<?xml?><e/>");
        assert_eq!(run(&[b"<?xml\tv?><e/>"]), b"<?xml\tv?><e/>");
        assert_eq!(run(&[b"<?XML v?><e/>"]), b"<?XML v?><e/>");
        // `?>` inside a quoted value ends the declaration early.
        assert_eq!(run(&[b"<?xml a='?>'?><e/>"]), b"'?><e/>");
        // A short trailing `<…` is held back.
        let mut s = XmlDeclStrip::new();
        assert_eq!(s.strip_vec(b"<e/><ab"), b"<e/>");
        assert_eq!(s.strip_vec(b"c/>"), b"<abc/>");
        // An unterminated declaration buffers only one byte.
        let mut s = XmlDeclStrip::new();
        assert_eq!(s.strip_vec(b"<?xml "), b"");
        assert!(s.in_decl());
        assert_eq!(s.strip_vec(&[b'x'; 10_000]), b"");
        assert_eq!(s.tail.len(), 1);
    }

    #[test]
    fn stale_tail_quirk() {
        // Chunk 1 holds back "<?>"; chunk 2 ends right after "<?xml " so the tail stays stale;
        // in chunk 3 the stale "<?>" contains "?>" and ends the declaration early.
        let mut s = XmlDeclStrip::new();
        assert_eq!(s.strip_vec(b"<?>"), b"");
        assert_eq!(s.strip_vec(b"<?xml "), b"<?>");
        assert_eq!(s.strip_vec(b"junk?><e/>"), b"junk?>"); // `<e/>` held back
    }
}
