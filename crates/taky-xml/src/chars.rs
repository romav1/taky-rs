//! XML 1.0 (5th edition) character classes, as enforced by libxml2.

/// `Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]`.
pub(crate) fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

/// `S ::= (#x20 | #x9 | #xD | #xA)+` (one byte).
pub(crate) fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// `NameStartChar`.
pub(crate) fn is_name_start(c: char) -> bool {
    matches!(c,
        ':' | 'A'..='Z' | '_' | 'a'..='z'
        | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}'
        | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}'
        | '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}'
        | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}' | '\u{10000}'..='\u{EFFFF}')
}

fn is_name_char(c: char) -> bool {
    is_name_start(c)
        || matches!(c, '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
}

/// `Name ::= NameStartChar (NameChar)*`.
pub(crate) fn is_name(s: &str) -> bool {
    let mut it = s.chars();
    match it.next() {
        Some(c) if is_name_start(c) => it.all(is_name_char),
        _ => false,
    }
}

/// The first character of `s` that is not an XML `Char`, if any.
pub(crate) fn first_invalid_char(s: &str) -> Option<char> {
    s.chars().find(|&c| !is_xml_char(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert!(is_name("event"));
        assert!(is_name("a:b"));
        assert!(is_name("_x-1.2"));
        assert!(is_name("Ä"));
        assert!(!is_name("1a"));
        assert!(!is_name(""));
        assert!(!is_name("a b"));
        assert!(!is_name("-a"));
        assert_eq!(first_invalid_char("ok\t\n\r"), None);
        assert_eq!(first_invalid_char("a\u{1}"), Some('\u{1}'));
        assert_eq!(first_invalid_char("\u{FFFE}"), Some('\u{FFFE}'));
        assert!(is_xml_char('\u{10FFFF}'));
    }
}
