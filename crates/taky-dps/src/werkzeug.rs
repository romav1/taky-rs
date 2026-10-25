//! Werkzeug 3.1.9 / Python 3.13 helpers the DPS views depend on (ported from the installed
//! sources, probed in S-317): header option parsing, `request.args`, `request.host_url`,
//! `send_file` headers and its conditional / range handling.

use chrono::{DateTime, Utc};

fn is_param_char(c: char) -> bool {
    // `[\w!#$%&'*+\-.^`|~]` with re.ASCII
    c.is_ascii_alphanumeric() || "_!#$%&'*+-.^`|~".contains(c)
}

fn is_charset_char(c: char) -> bool {
    // `[\w!#$%&*+\-.^`|~]` (no single quote)
    c.is_ascii_alphanumeric() || "_!#$%&*+-.^`|~".contains(c)
}

/// `_token_chars` of `quote_header_value`.
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

/// `werkzeug.http.parse_options_header`: `(value, options)`; option keys are lower case, a
/// later key replaces an earlier one (dict semantics, first-insertion position kept).
pub(crate) fn parse_options_header(value: &str) -> (String, Vec<(String, String)>) {
    let (v, rest) = value.split_once(';').unwrap_or((value, ""));
    let v = v.trim_matches([' ', '\t']).to_owned();
    let rest = rest.trim_matches([' ', '\t']);
    if v.is_empty() || rest.is_empty() {
        return (v, Vec::new());
    }
    // Collect key=value parts without processing the value.
    let mut parts: Vec<(String, String)> = Vec::new();
    let r: Vec<char> = rest.chars().collect();
    let len = r.len();
    let mut pos = 0;
    'scan: while pos < len {
        let key_end = (pos..len).find(|&i| !is_param_char(r[i])).unwrap_or(len);
        if key_end > pos && key_end < len && r[key_end] == '=' {
            let pk: String = r[pos..key_end].iter().collect::<String>().to_lowercase();
            pos = key_end + 1;
            let tok_end = (pos..len).find(|&i| !is_param_char(r[i])).unwrap_or(len);
            if tok_end > pos {
                parts.push((pk, r[pos..tok_end].iter().collect()));
                pos = tok_end;
            } else if pos < len && r[pos] == '"' {
                let mut q = pos + 1;
                loop {
                    if q >= len {
                        break 'scan;
                    }
                    if r[q] == '\\' && q + 1 < len && (r[q + 1] == '\\' || r[q + 1] == '"') {
                        q += 2;
                    } else if r[q] == '"' {
                        q += 1;
                        parts.push((pk, r[pos..q].iter().collect()));
                        pos = q;
                        break;
                    } else {
                        q += 1;
                    }
                }
            }
        }
        // `;[ \t]*` searched from pos
        match (pos..len).find(|&i| r[i] == ';') {
            Some(i) => {
                pos = i + 1;
                while pos < len && (r[pos] == ' ' || r[pos] == '\t') {
                    pos += 1;
                }
            }
            None => break,
        }
    }

    let mut options: Vec<(String, String)> = Vec::new();
    let mut continuations: Vec<(String, Vec<String>)> = Vec::new();
    let mut cont_enc: Vec<(String, String)> = Vec::new();
    fn set(v: &mut Vec<(String, String)>, k: &str, val: String) {
        match v.iter_mut().find(|(kk, _)| kk == k) {
            Some(e) => e.1 = val,
            None => v.push((k.to_owned(), val)),
        }
    }
    for (pk, pv) in parts {
        let (pk, has_cont, has_charset) = split_mark(&pk);
        let mut encoding: Option<String> = None;
        let mut pv = pv;
        if has_charset {
            if let Some((enc, val)) = split_charset_value(&pv) {
                encoding = Some(enc.to_lowercase());
                pv = val;
            }
            if encoding.as_deref().is_none_or(str::is_empty) && has_cont {
                encoding = cont_enc
                    .iter()
                    .find(|(k, _)| *k == pk)
                    .map(|(_, e)| e.clone());
            }
            if let Some(e) = encoding.as_deref()
                && matches!(e, "ascii" | "us-ascii" | "utf-8" | "iso-8859-1")
            {
                pv = url_unquote(&pv, e);
            }
        } else {
            pv = unquote_header_value(&pv).replace("%22", "\"");
        }
        if has_cont {
            options.retain(|(k, _)| *k != pk);
            match continuations.iter_mut().find(|(k, _)| *k == pk) {
                Some(c) => c.1.push(pv),
                None => continuations.push((pk.clone(), vec![pv])),
            }
            if let Some(e) = encoding.filter(|e| !e.is_empty()) {
                set(&mut cont_enc, &pk, e);
            }
        } else {
            if continuations.iter().any(|(k, _)| *k == pk) {
                continuations.retain(|(k, _)| *k != pk);
                cont_enc.retain(|(k, _)| *k != pk);
            }
            set(&mut options, &pk, pv);
        }
    }
    for (k, vs) in continuations {
        set(&mut options, &k, vs.concat());
    }
    (v, options)
}

/// `_parameter_mark_re = (?:\*(\d+))?(\*)?$` searched in the key: `(key, continuation, charset)`.
fn split_mark(pk: &str) -> (String, bool, bool) {
    let b = pk.as_bytes();
    for p in 0..=b.len() {
        let s = &b[p..];
        let (cont, rest) = if s.first() == Some(&b'*') {
            let n = s[1..].iter().take_while(|c| c.is_ascii_digit()).count();
            if n > 0 {
                (true, &s[1 + n..])
            } else {
                (false, s)
            }
        } else {
            (false, s)
        };
        let charset = rest == b"*";
        if rest.is_empty() || charset {
            if p == b.len() {
                return (pk.to_owned(), false, false);
            }
            return (pk[..p].to_owned(), cont, charset);
        }
    }
    (pk.to_owned(), false, false)
}

/// `_charset_value_re`: `charset'lang'value` ⇒ `(charset, value)`.
fn split_charset_value(pv: &str) -> Option<(String, String)> {
    let (cs, rest) = pv.split_once('\'')?;
    let (lang, val) = rest.split_once('\'')?;
    (cs.chars().all(is_charset_char)
        && lang.chars().all(is_charset_char)
        && !val.is_empty()
        && val.chars().all(is_param_char))
    .then(|| (cs.to_owned(), val.to_owned()))
}

/// `unquote_header_value`.
pub(crate) fn unquote_header_value(v: &str) -> String {
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        let inner = &v[1..v.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut it = inner.chars().peekable();
        while let Some(c) = it.next() {
            if c == '\\'
                && let Some(&n) = it.peek()
                && n != '\n'
            {
                out.push(n);
                it.next();
                continue;
            }
            out.push(c);
        }
        return out;
    }
    v.to_owned()
}

/// `quote_header_value(value)` (token chars unquoted, otherwise `"…"` with `\` escapes).
pub(crate) fn quote_header_value(v: &str) -> String {
    if v.is_empty() {
        return "\"\"".into();
    }
    if v.chars().all(is_token_char) {
        return v.to_owned();
    }
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}

fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// Percent-decode `%XX` (invalid sequences stay literal), as `urllib.parse.unquote_to_bytes`.
fn pct_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// `urllib.parse.unquote(s, encoding, errors="replace")` for an ASCII-only `s` (the RFC 2231
/// value regex admits only ASCII token characters).
fn url_unquote(s: &str, encoding: &str) -> String {
    let bytes = pct_decode(s);
    match encoding {
        "iso-8859-1" => bytes.iter().map(|&b| b as char).collect(),
        "ascii" | "us-ascii" => bytes
            .iter()
            .map(|&b| if b.is_ascii() { b as char } else { '\u{fffd}' })
            .collect(),
        _ => String::from_utf8_lossy(&bytes).into_owned(),
    }
}

/// `request.args` (Werkzeug 3: `parse_qsl(qs, keep_blank_values=True,
/// errors="werkzeug.url_quote")`, `&` only, `+` = space; undecodable bytes re-quoted `%XX`).
pub(crate) fn parse_args(query: Option<&str>) -> Vec<(String, String)> {
    let Some(q) = query else {
        return Vec::new();
    };
    let unq = |s: &str| -> String {
        let bytes = pct_decode(&s.replace('+', " "));
        let mut out = String::new();
        for chunk in bytes.utf8_chunks() {
            out.push_str(chunk.valid());
            for b in chunk.invalid() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    };
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (unq(k), unq(v))
        })
        .collect()
}

/// First value of `key` (`MultiDict.__getitem__`).
pub(crate) fn arg<'a>(args: &'a [(String, String)], key: &str) -> Option<&'a str> {
    args.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// `request.host_url` = `<scheme>://<host>/` (`get_host`: default port dropped, invalid host ⇒
/// empty; `uri_to_iri`: host name lower-cased). IDNA (`xn--`) labels are not decoded (gap).
pub(crate) fn host_url(scheme: &str, host_header: Option<&str>) -> String {
    let mut host = host_header.unwrap_or("").to_owned();
    if scheme == "http" {
        if let Some(h) = host.strip_suffix(":80") {
            host = h.to_owned();
        }
    } else if let Some(h) = host.strip_suffix(":443") {
        host = h.to_owned();
    }
    if !host_is_valid(&host) {
        host.clear();
    }
    format!("{scheme}://{}/", host.to_ascii_lowercase())
}

/// `_host_re` + port range check of `host_is_trusted`.
fn host_is_valid(h: &str) -> bool {
    if h.is_empty() {
        return false;
    }
    let (name, port) = if let Some(rest) = h.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        let inner = &rest[..end];
        let Some(colon) = inner.find(':') else {
            return false;
        };
        let (a, b) = (&inner[..colon], &inner[colon + 1..]);
        let ok = a.chars().all(|c| c.is_ascii_hexdigit())
            && !b.is_empty()
            && b.chars()
                .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':');
        if !ok {
            return false;
        }
        (true, &rest[end + 1..])
    } else {
        let end = h.find(':').unwrap_or(h.len());
        let name = &h[..end];
        (
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'),
            &h[end..],
        )
    };
    if !name {
        return false;
    }
    if port.is_empty() {
        return true;
    }
    let Some(p) = port.strip_prefix(':') else {
        return false;
    };
    p.len() <= 5
        && p.starts_with(|c: char| ('1'..='9').contains(&c))
        && p.chars().all(|c| c.is_ascii_digit())
        && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n))
}

/// `get_content_type(mimetype, "utf-8")`.
pub(crate) fn content_type_with_charset(mimetype: &str) -> String {
    const CHARSET_TYPES: &[&str] = &[
        "application/ecmascript",
        "application/javascript",
        "application/sql",
        "application/xml",
        "application/xml-dtd",
        "application/xml-external-parsed-entity",
    ];
    if mimetype.starts_with("text/")
        || CHARSET_TYPES.contains(&mimetype)
        || mimetype.ends_with("+xml")
    {
        format!("{mimetype}; charset=utf-8")
    } else {
        mimetype.to_owned()
    }
}

/// `send_file(..., as_attachment=True, download_name=name)` Content-Disposition.
/// `None` ⇒ Werkzeug raises (newline in the value).
pub(crate) fn attachment_disposition(name: &str) -> Option<String> {
    let v = if name.is_ascii() {
        format!("attachment; filename={}", quote_header_value(name))
    } else {
        use unicode_normalization::UnicodeNormalization;
        let simple: String = name.nfkd().filter(char::is_ascii).collect();
        let mut quoted = String::new();
        for b in name.bytes() {
            let c = b as char;
            if c.is_ascii_alphanumeric() || "_.-~!#$&+^`|".contains(c) {
                quoted.push(c);
            } else {
                quoted.push_str(&format!("%{b:02X}"));
            }
        }
        format!(
            "attachment; filename={}; filename*=UTF-8''{quoted}",
            quote_header_value(&simple)
        )
    };
    (!v.contains(['\n', '\r'])).then_some(v)
}

/// `http_date` (`Sun, 25 Oct 2026 08:13:28 GMT`).
pub(crate) fn http_date(t: DateTime<Utc>) -> String {
    t.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// `parse_date` (email.utils.parsedate_to_datetime; `None` on failure).
fn parse_date(v: Option<&str>) -> Option<DateTime<Utc>> {
    let v = v?.trim();
    DateTime::parse_from_rfc2822(v)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// `zlib.adler32`.
pub(crate) fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + u32::from(x)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// `unquote_etag`: strip `W/` and quotes.
fn unquote_etag(v: &str) -> String {
    let v = v.trim();
    let v = v
        .strip_prefix("W/")
        .or_else(|| v.strip_prefix("w/"))
        .unwrap_or(v);
    v.strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .unwrap_or(v)
        .to_owned()
}

/// `parse_etags`: `(star, strong, weak)`.
fn parse_etags(v: Option<&str>) -> Option<(bool, Vec<String>, Vec<String>)> {
    let v = v.filter(|v| !v.is_empty())?;
    let (mut strong, mut weak) = (Vec::new(), Vec::new());
    for item in v.split(',') {
        let item = item.trim();
        if item == "*" {
            return Some((true, Vec::new(), Vec::new()));
        }
        let is_weak = item.starts_with("W/") || item.starts_with("w/");
        let raw = unquote_etag(item);
        if is_weak {
            weak.push(raw)
        } else {
            strong.push(raw)
        }
    }
    Some((false, strong, weak))
}

/// Request headers relevant to `make_conditional`.
#[derive(Debug, Default, Clone)]
pub(crate) struct CondHeaders {
    pub range: Option<String>,
    pub if_range: Option<String>,
    pub if_modified_since: Option<String>,
    pub if_none_match: Option<String>,
    pub if_match: Option<String>,
}

/// `is_resource_modified` (Werkzeug sansio).
fn is_resource_modified(
    h: &CondHeaders,
    etag: &str,
    last_modified: DateTime<Utc>,
    ignore_if_range: bool,
) -> bool {
    let mut unmodified = false;
    // if_range: (date, etag)
    let mut if_range: Option<(Option<DateTime<Utc>>, Option<String>)> = None;
    if !ignore_if_range && h.range.is_some() {
        if let Some(v) = h.if_range.as_deref().filter(|v| !v.is_empty()) {
            if_range = Some(match parse_date(Some(v)) {
                Some(d) => (Some(d), None),
                None => (None, Some(unquote_etag(v))),
            });
        } else {
            if_range = Some((None, None));
        }
    }
    let modified_since = match &if_range {
        Some((Some(d), _)) => Some(*d),
        _ => parse_date(h.if_modified_since.as_deref()),
    };
    if let Some(ms) = modified_since
        && last_modified <= ms
    {
        unmodified = true;
    }
    let etag = unquote_etag(etag);
    if let Some((_, Some(ir))) = &if_range {
        unmodified = *ir == etag;
    } else {
        if let Some((star, strong, weak)) = parse_etags(h.if_none_match.as_deref()) {
            unmodified = star || strong.contains(&etag) || weak.contains(&etag);
        }
        if let Some((_, strong, _)) = parse_etags(h.if_match.as_deref()) {
            unmodified = !strong.contains(&etag);
        }
    }
    !unmodified
}

/// `parse_range_header` + `range_for_length`: `Ok(None)` no usable range request, `Ok(Some((start,
/// stop)))` ⇒ 206, `Err(())` ⇒ 416.
fn range_for(h: &CondHeaders, len: u64) -> Result<(u64, u64), ()> {
    let v = h.range.as_deref().ok_or(())?;
    let (units, rng) = v.split_once('=').ok_or(())?;
    let units = units.trim_matches([' ', '\t']).to_lowercase();
    let plain = |s: &str| -> Result<i128, ()> {
        let s = s.trim_matches([' ', '\t']);
        let d = s.strip_prefix('-').unwrap_or(s);
        if d.is_empty() || !d.bytes().all(|b| b.is_ascii_digit()) || d.len() > 30 {
            return Err(());
        }
        s.parse().map_err(|_| ())
    };
    let mut ranges: Vec<(i128, Option<i128>)> = Vec::new();
    let mut last_end: i128 = 0;
    for item in rng.split(',') {
        let item = item.trim_matches([' ', '\t']);
        if !item.contains('-') {
            return Err(());
        }
        if item.starts_with('-') {
            if last_end < 0 {
                return Err(());
            }
            let begin = plain(item)?;
            if begin == 0 {
                return Err(());
            }
            ranges.push((begin, None));
            last_end = -1;
        } else {
            let (b, e) = item.split_once('-').ok_or(())?;
            let begin = plain(b)?;
            if begin < last_end || last_end < 0 {
                return Err(());
            }
            let e = e.trim_matches([' ', '\t']);
            let end = if e.is_empty() {
                None
            } else {
                let end = plain(e)? + 1;
                if begin >= end {
                    return Err(());
                }
                Some(end)
            };
            last_end = end.unwrap_or(-1);
            ranges.push((begin, end));
        }
    }
    if units != "bytes" || ranges.len() != 1 {
        return Err(());
    }
    let len = i128::from(len);
    let (mut start, end) = ranges[0];
    let end = match end {
        Some(e) => e,
        None => {
            if start < 0 {
                start += len;
            }
            len
        }
    };
    if start < 0 || start >= end || start >= len {
        return Err(());
    }
    let stop = end.min(len);
    Ok((start as u64, stop as u64))
}

/// Outcome of `make_conditional(environ, accept_ranges=True, complete_length=size)`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Conditional {
    /// 200 with the whole file.
    Full,
    /// 206 `[start, stop)`.
    Partial(u64, u64),
    /// 304 Not Modified.
    NotModified,
    /// 412 Precondition Failed (Werkzeug still sends the full body).
    PreconditionFailed,
    /// 416 with `Content-Range: bytes */<len>`.
    RangeNotSatisfiable,
}

/// `Response.make_conditional` for a GET/HEAD file response.
pub(crate) fn conditional(
    h: &CondHeaders,
    etag: &str,
    last_modified: DateTime<Utc>,
    len: u64,
) -> Conditional {
    let processable = h.range.is_some()
        && (h.if_range.is_none() || !is_resource_modified(h, etag, last_modified, false));
    if len > 0 && processable {
        return match range_for(h, len) {
            Ok((a, b)) => Conditional::Partial(a, b),
            Err(()) => Conditional::RangeNotSatisfiable,
        };
    }
    if !is_resource_modified(h, etag, last_modified, true) {
        if parse_etags(h.if_match.as_deref()).is_some() {
            return Conditional::PreconditionFailed;
        }
        return Conditional::NotModified;
    }
    Conditional::Full
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opt(v: &str) -> Vec<(String, String)> {
        parse_options_header(v).1
    }

    fn get<'a>(o: &'a [(String, String)], k: &str) -> Option<&'a str> {
        o.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.as_str())
    }

    #[test]
    fn options_header_like_werkzeug() {
        // Probed with Werkzeug 3.1.9 multipart (S-317).
        let o = opt(r#"form-data; name="assetfile"; filename="a\"b.zip""#);
        assert_eq!(get(&o, "filename"), Some("a\"b.zip"));
        assert_eq!(get(&o, "name"), Some("assetfile"));
        let o = opt(r#"form-data; name="assetfile"; filename="a%22b.zip""#);
        assert_eq!(get(&o, "filename"), Some("a\"b.zip"));
        let o = opt("form-data; name=\"assetfile\"; filename*=UTF-8''%C3%BC.zip");
        assert_eq!(get(&o, "filename"), Some("\u{fc}.zip"));
        let o = opt(r#"form-data; name="assetfile"; filename="C:\\x\\y.zip""#);
        assert_eq!(get(&o, "filename"), Some("C:\\x\\y.zip"));
        let o = opt(r#"form-data; name="assetfile"; filename="""#);
        assert_eq!(get(&o, "filename"), Some(""));
        let o = opt(r#"form-data; name="assetfile""#);
        assert_eq!(get(&o, "filename"), None);
        let o = opt("form-data; NAME=assetfile; filename=tok.zip");
        assert_eq!(get(&o, "name"), Some("assetfile"));
        let o = opt(r#"form-data; filename="a.zip"; filename="b.zip""#);
        assert_eq!(get(&o, "filename"), Some("b.zip"));
        let o = opt("x; a*0=ab; a*1=cd");
        assert_eq!(get(&o, "a"), Some("abcd"));
        assert_eq!(
            parse_options_header("Application/ZIP; x=1").0,
            "Application/ZIP"
        );
        assert_eq!(parse_options_header("").0, "");
    }

    #[test]
    fn args_like_werkzeug() {
        let a = parse_args(Some("hash=a+b&x&hash=2&k=%zz&f=%ff&s=a;b&=v&&"));
        assert_eq!(arg(&a, "hash"), Some("a b"));
        assert_eq!(arg(&a, "x"), Some(""));
        assert_eq!(arg(&a, "k"), Some("%zz"));
        assert_eq!(arg(&a, "f"), Some("%FF"));
        assert_eq!(arg(&a, "s"), Some("a;b"));
        assert_eq!(arg(&a, ""), Some("v"));
        assert_eq!(arg(&parse_args(Some("x=1;hash=2")), "hash"), None);
        assert_eq!(arg(&parse_args(Some("n=%C3%BC")), "n"), Some("\u{fc}"));
    }

    #[test]
    fn host_url_like_werkzeug() {
        assert_eq!(
            host_url("https", Some("taky.example:8443")),
            "https://taky.example:8443/"
        );
        assert_eq!(
            host_url("https", Some("Taky.Example:443")),
            "https://taky.example/"
        );
        assert_eq!(host_url("http", Some("h:80")), "http://h/");
        assert_eq!(host_url("http", Some("[::1]:8080")), "http://[::1]:8080/");
        assert_eq!(host_url("http", Some("a b")), "http:///");
        assert_eq!(host_url("http", Some("h:0")), "http:///");
        assert_eq!(host_url("http", None), "http:///");
    }

    #[test]
    fn disposition_like_send_file() {
        let d = |n: &str| attachment_disposition(n).unwrap();
        assert_eq!(d("pkg.zip"), "attachment; filename=pkg.zip");
        assert_eq!(d("a\"b.zip"), "attachment; filename=\"a\\\"b.zip\"");
        assert_eq!(d("a b.zip"), "attachment; filename=\"a b.zip\"");
        assert_eq!(d("a\\b.zip"), "attachment; filename=\"a\\\\b.zip\"");
        assert_eq!(d(""), "attachment; filename=\"\"");
        assert_eq!(
            d("\u{fc}.zip"),
            "attachment; filename=u.zip; filename*=UTF-8''%C3%BC.zip"
        );
        assert_eq!(
            d("\u{e9} b\u{20ac}.txt"),
            "attachment; filename=\"e b.txt\"; filename*=UTF-8''%C3%A9%20b%E2%82%AC.txt"
        );
        assert!(attachment_disposition("a\nb").is_none());
        assert_eq!(
            content_type_with_charset("text/plain"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            content_type_with_charset("image/svg+xml"),
            "image/svg+xml; charset=utf-8"
        );
        assert_eq!(
            content_type_with_charset("application/zip"),
            "application/zip"
        );
    }

    #[test]
    fn conditional_like_werkzeug() {
        let lm = DateTime::parse_from_rfc2822("Sun, 25 Oct 2026 08:13:28 GMT")
            .unwrap()
            .with_timezone(&Utc);
        let et = "\"1.5-10-7\"";
        let c = |h: CondHeaders| conditional(&h, et, lm, 10);
        let r = |v: &str| CondHeaders {
            range: Some(v.into()),
            ..Default::default()
        };
        assert_eq!(c(r("bytes=0-3")), Conditional::Partial(0, 4));
        assert_eq!(c(r("bytes=5-")), Conditional::Partial(5, 10));
        assert_eq!(c(r("bytes=-3")), Conditional::Partial(7, 10));
        assert_eq!(c(r("bytes=0-100")), Conditional::Partial(0, 10));
        for bad in [
            "bytes=0-1,4-5",
            "bytes=20-",
            "bytes=x",
            "items=0-1",
            "bytes=3-2",
        ] {
            assert_eq!(c(r(bad)), Conditional::RangeNotSatisfiable, "{bad}");
        }
        let inm = CondHeaders {
            if_none_match: Some(et.into()),
            ..Default::default()
        };
        assert_eq!(c(inm), Conditional::NotModified);
        let ims = CondHeaders {
            if_modified_since: Some("Sun, 25 Oct 2026 08:13:28 GMT".into()),
            ..Default::default()
        };
        assert_eq!(c(ims), Conditional::NotModified);
        let im = |v: &str| CondHeaders {
            if_match: Some(v.into()),
            ..Default::default()
        };
        assert_eq!(c(im("\"zz\"")), Conditional::PreconditionFailed);
        assert_eq!(c(im(et)), Conditional::Full);
        let ir = |v: &str| CondHeaders {
            range: Some("bytes=0-1".into()),
            if_range: Some(v.into()),
            ..Default::default()
        };
        assert_eq!(c(ir("\"zz\"")), Conditional::Full);
        assert_eq!(c(ir(et)), Conditional::Partial(0, 2));
        assert_eq!(conditional(&r("bytes=0-1"), et, lm, 0), Conditional::Full);
    }

    #[test]
    fn adler32_like_zlib() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(adler32(b""), 1);
    }
}
