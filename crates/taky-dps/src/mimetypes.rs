//! Python 3.13 `mimetypes.guess_type` with the built-in tables (Flask `send_file` Content-Type,
//! spec dps-cli-config §2.4 "Download"; the Werkzeug test client's default part type).
//!
//! Python also merges the host's `/etc/mime.types` etc. at first use; that is deployment
//! dependent and deliberately not reproduced (only the built-in strict table is used).

/// Python raises `ValueError("Invalid IPv6 URL")` (`urlsplit`: unbalanced `[`/`]` in a netloc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidUrl;

/// `mimetypes.guess_type(url)` = `(type, encoding)`.
pub fn guess_type(url: &str) -> Result<(Option<String>, Option<&'static str>), InvalidUrl> {
    let Some((scheme, path)) = url_scheme_and_path(url)? else {
        return Ok(guess_file_type(url));
    };
    if scheme == "data" {
        let Some(comma) = path.find(',') else {
            return Ok((None, None));
        };
        let head = &path[..comma];
        let ty = match head.find(';') {
            Some(semi) => &head[..semi],
            None => head,
        };
        let ty = if ty.contains('=') || !ty.contains('/') {
            "text/plain"
        } else {
            ty
        };
        return Ok((Some(ty.to_owned()), None));
    }
    Ok(guess_file_type(&path))
}

/// `urllib.parse.urlparse(url)`: `Some((scheme, path))` when the scheme has more than one
/// character (the only case `guess_type` uses the parse), `None` otherwise.
fn url_scheme_and_path(url: &str) -> Result<Option<(String, String)>, InvalidUrl> {
    let mut u: String = url
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut scheme = String::new();
    if let Some(i) = u.find(':') {
        let first = u.chars().next().unwrap_or(' ');
        if i > 0
            && first.is_ascii_alphabetic()
            && u[..i]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            scheme = u[..i].to_ascii_lowercase();
            u = u[i + 1..].to_owned();
        }
    }
    if scheme.chars().count() <= 1 {
        return Ok(None);
    }
    if let Some(rest) = u.strip_prefix("//") {
        let delim = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let netloc = &rest[..delim];
        if netloc.contains('[') != netloc.contains(']') {
            return Err(InvalidUrl);
        }
        u = rest[delim..].to_owned();
    }
    if let Some(i) = u.find('#') {
        u.truncate(i);
    }
    if let Some(i) = u.find('?') {
        u.truncate(i);
    }
    const USES_PARAMS: &[&str] = &[
        "", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp", "rtsp", "rtsps", "rtspu",
        "sip", "sips", "mms", "sftp", "tel",
    ];
    if USES_PARAMS.contains(&scheme.as_str()) && u.contains(';') {
        let from = u.rfind('/').unwrap_or(0);
        if let Some(i) = u[from..].find(';') {
            u.truncate(from + i);
        }
    }
    Ok(Some((scheme, u)))
}

/// `posixpath.splitext`.
fn splitext(p: &str) -> (&str, &str) {
    let sep = p.rfind('/').map_or(0, |i| i + 1);
    if let Some(dot) = p.rfind('.')
        && dot >= sep
        && p[sep..dot].bytes().any(|b| b != b'.')
    {
        return (&p[..dot], &p[dot..]);
    }
    (p, "")
}

fn lookup(table: &'static [(&'static str, &'static str)], k: &str) -> Option<&'static str> {
    table
        .binary_search_by(|(e, _)| e.as_bytes().cmp(k.as_bytes()))
        .ok()
        .map(|i| table[i].1)
}

/// `MimeTypes._guess_file_type(path, strict=True, posixpath.splitext)`.
fn guess_file_type(path: &str) -> (Option<String>, Option<&'static str>) {
    let mut cur = path.to_owned();
    loop {
        let (base, ext) = splitext(&cur);
        match SUFFIX_MAP.iter().find(|(k, _)| *k == ext.to_lowercase()) {
            Some((_, rep)) => cur = format!("{base}{rep}"),
            None => break,
        }
    }
    let (mut base, mut ext) = splitext(&cur);
    let mut encoding = None;
    if let Some((_, enc)) = ENCODINGS_MAP.iter().find(|(k, _)| *k == ext) {
        encoding = Some(*enc);
        (base, ext) = splitext(base);
    }
    let _ = base;
    (
        lookup(TYPES_MAP, &ext.to_lowercase()).map(str::to_owned),
        encoding,
    )
}

// @generated from Python 3.13 `mimetypes._types_map_default` (strict table, no system mime.types):
// python3 -c "import mimetypes as m; print(sorted(m._types_map_default.items()))"
// Sorted by key (binary search).
const TYPES_MAP: &[(&str, &str)] = &[
    (".3g2", "audio/3gpp2"),
    (".3gp", "audio/3gpp"),
    (".3gpp", "audio/3gpp"),
    (".3gpp2", "audio/3gpp2"),
    (".a", "application/octet-stream"),
    (".aac", "audio/aac"),
    (".adts", "audio/aac"),
    (".ai", "application/postscript"),
    (".aif", "audio/x-aiff"),
    (".aifc", "audio/x-aiff"),
    (".aiff", "audio/x-aiff"),
    (".ass", "audio/aac"),
    (".au", "audio/basic"),
    (".avi", "video/x-msvideo"),
    (".avif", "image/avif"),
    (".bat", "text/plain"),
    (".bcpio", "application/x-bcpio"),
    (".bin", "application/octet-stream"),
    (".bmp", "image/bmp"),
    (".c", "text/plain"),
    (".cdf", "application/x-netcdf"),
    (".cpio", "application/x-cpio"),
    (".csh", "application/x-csh"),
    (".css", "text/css"),
    (".csv", "text/csv"),
    (".dll", "application/octet-stream"),
    (".doc", "application/msword"),
    (".dot", "application/msword"),
    (".dvi", "application/x-dvi"),
    (".eml", "message/rfc822"),
    (".eps", "application/postscript"),
    (".etx", "text/x-setext"),
    (".exe", "application/octet-stream"),
    (".gif", "image/gif"),
    (".gtar", "application/x-gtar"),
    (".h", "text/plain"),
    (".h5", "application/x-hdf5"),
    (".hdf", "application/x-hdf"),
    (".heic", "image/heic"),
    (".heif", "image/heif"),
    (".htm", "text/html"),
    (".html", "text/html"),
    (".ico", "image/vnd.microsoft.icon"),
    (".ief", "image/ief"),
    (".jpe", "image/jpeg"),
    (".jpeg", "image/jpeg"),
    (".jpg", "image/jpeg"),
    (".js", "text/javascript"),
    (".json", "application/json"),
    (".ksh", "text/plain"),
    (".latex", "application/x-latex"),
    (".loas", "audio/aac"),
    (".m1v", "video/mpeg"),
    (".m3u", "application/vnd.apple.mpegurl"),
    (".m3u8", "application/vnd.apple.mpegurl"),
    (".man", "application/x-troff-man"),
    (".markdown", "text/markdown"),
    (".md", "text/markdown"),
    (".me", "application/x-troff-me"),
    (".mht", "message/rfc822"),
    (".mhtml", "message/rfc822"),
    (".mif", "application/x-mif"),
    (".mjs", "text/javascript"),
    (".mov", "video/quicktime"),
    (".movie", "video/x-sgi-movie"),
    (".mp2", "audio/mpeg"),
    (".mp3", "audio/mpeg"),
    (".mp4", "video/mp4"),
    (".mpa", "video/mpeg"),
    (".mpe", "video/mpeg"),
    (".mpeg", "video/mpeg"),
    (".mpg", "video/mpeg"),
    (".ms", "application/x-troff-ms"),
    (".n3", "text/n3"),
    (".nc", "application/x-netcdf"),
    (".nq", "application/n-quads"),
    (".nt", "application/n-triples"),
    (".nws", "message/rfc822"),
    (".o", "application/octet-stream"),
    (".obj", "application/octet-stream"),
    (".oda", "application/oda"),
    (".opus", "audio/opus"),
    (".p12", "application/x-pkcs12"),
    (".p7c", "application/pkcs7-mime"),
    (".pbm", "image/x-portable-bitmap"),
    (".pdf", "application/pdf"),
    (".pfx", "application/x-pkcs12"),
    (".pgm", "image/x-portable-graymap"),
    (".pl", "text/plain"),
    (".png", "image/png"),
    (".pnm", "image/x-portable-anymap"),
    (".pot", "application/vnd.ms-powerpoint"),
    (".ppa", "application/vnd.ms-powerpoint"),
    (".ppm", "image/x-portable-pixmap"),
    (".pps", "application/vnd.ms-powerpoint"),
    (".ppt", "application/vnd.ms-powerpoint"),
    (".ps", "application/postscript"),
    (".pwz", "application/vnd.ms-powerpoint"),
    (".py", "text/x-python"),
    (".pyc", "application/x-python-code"),
    (".pyo", "application/x-python-code"),
    (".qt", "video/quicktime"),
    (".ra", "audio/x-pn-realaudio"),
    (".ram", "application/x-pn-realaudio"),
    (".ras", "image/x-cmu-raster"),
    (".rdf", "application/xml"),
    (".rgb", "image/x-rgb"),
    (".roff", "application/x-troff"),
    (".rst", "text/x-rst"),
    (".rtf", "text/rtf"),
    (".rtx", "text/richtext"),
    (".sgm", "text/x-sgml"),
    (".sgml", "text/x-sgml"),
    (".sh", "application/x-sh"),
    (".shar", "application/x-shar"),
    (".snd", "audio/basic"),
    (".so", "application/octet-stream"),
    (".src", "application/x-wais-source"),
    (".srt", "text/plain"),
    (".sv4cpio", "application/x-sv4cpio"),
    (".sv4crc", "application/x-sv4crc"),
    (".svg", "image/svg+xml"),
    (".swf", "application/x-shockwave-flash"),
    (".t", "application/x-troff"),
    (".tar", "application/x-tar"),
    (".tcl", "application/x-tcl"),
    (".tex", "application/x-tex"),
    (".texi", "application/x-texinfo"),
    (".texinfo", "application/x-texinfo"),
    (".tif", "image/tiff"),
    (".tiff", "image/tiff"),
    (".tr", "application/x-troff"),
    (".trig", "application/trig"),
    (".tsv", "text/tab-separated-values"),
    (".txt", "text/plain"),
    (".ustar", "application/x-ustar"),
    (".vcf", "text/x-vcard"),
    (".vtt", "text/vtt"),
    (".wasm", "application/wasm"),
    (".wav", "audio/x-wav"),
    (".webm", "video/webm"),
    (".webmanifest", "application/manifest+json"),
    (".webp", "image/webp"),
    (".wiz", "application/msword"),
    (".wsdl", "application/xml"),
    (".xbm", "image/x-xbitmap"),
    (".xlb", "application/vnd.ms-excel"),
    (".xls", "application/vnd.ms-excel"),
    (".xml", "text/xml"),
    (".xpdl", "application/xml"),
    (".xpm", "image/x-xpixmap"),
    (".xsl", "application/xml"),
    (".xwd", "image/x-xwindowdump"),
    (".zip", "application/zip"),
];
const SUFFIX_MAP: &[(&str, &str)] = &[
    (".svgz", ".svg.gz"),
    (".tgz", ".tar.gz"),
    (".taz", ".tar.gz"),
    (".tz", ".tar.gz"),
    (".tbz2", ".tar.bz2"),
    (".txz", ".tar.xz"),
];
const ENCODINGS_MAP: &[(&str, &str)] = &[
    (".gz", "gzip"),
    (".Z", "compress"),
    (".bz2", "bzip2"),
    (".xz", "xz"),
    (".br", "br"),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn t(n: &str) -> Option<String> {
        guess_type(n).unwrap().0
    }

    #[test]
    fn table_sorted() {
        assert!(TYPES_MAP.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn like_python_313() {
        // Observed with Flask 2.3.3 send_file on Python 3.13 (an01 venv, S-317 probe).
        assert_eq!(t("pkg.zip").as_deref(), Some("application/zip"));
        assert_eq!(t("X.ZIP").as_deref(), Some("application/zip"));
        assert_eq!(t("loot.txt").as_deref(), Some("text/plain"));
        assert_eq!(t("x.js").as_deref(), Some("text/javascript"));
        assert_eq!(t("a.svg").as_deref(), Some("image/svg+xml"));
        assert_eq!(
            guess_type("x.tar.gz").unwrap(),
            (Some("application/x-tar".into()), Some("gzip"))
        );
        assert_eq!(
            guess_type("x.tgz").unwrap(),
            (Some("application/x-tar".into()), Some("gzip"))
        );
        assert_eq!(t("noext"), None);
        assert_eq!(t(".zip"), None);
        assert_eq!(t(""), None);
        assert_eq!(t("ab:c.txt").as_deref(), Some("text/plain"));
        assert_eq!(t("data:image/png,x").as_deref(), Some("image/png"));
        assert_eq!(t("a;b.json").as_deref(), Some("application/json"));
        assert_eq!(t("http://h/a.zip;x").as_deref(), Some("application/zip"));
        assert!(guess_type("ab://[x/y.zip").is_err());
    }
}
