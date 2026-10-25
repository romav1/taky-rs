//! Client data package of `takyctl build_client` (`taky/util/datapackage.py`,
//! `cli/build_client_cmd.py`; spec dps-cli-config §6). Library part only: the `.pref` and
//! `manifest.xml` documents (byte-exact with lxml), the ATAK / iTAK preference sets and file
//! names, and the ZIP writer. The `build_client` command itself (certificate, cert-db, config)
//! is S-322.
//!
//! Layout (ATAK; iTAK has the three `certs/` files at the root and no manifest):
//!
//! ```text
//! MANIFEST/manifest.xml
//! certs/preference.pref
//! certs/server-<uuid4>.p12          copy of ssl.server_p12
//! certs/<name>-<uuid4>.p12          client key + certificate + CA
//! ```
//!
//! Entry order: Python writes what `os.walk` returns (filesystem order, not normative); we
//! write the manifest first, then the files in manifest `Contents` order. ZIP_DEFLATED, no
//! directory entries, Unix mode bits and local-time mtime as `zipfile.ZipFile.write` stores them.

use std::io::Write;
use std::path::Path;

use taky_xml::{Element, SerOpts};
use zip::write::SimpleFileOptions;

/// Name of the preference file in the package (`pref_name`).
pub const PREF_NAME: &str = "preference.pref";
/// Path of the manifest in an ATAK package.
pub const MANIFEST_PATH: &str = "MANIFEST/manifest.xml";
/// ATAK's certificate directory on the device (`caLocation` / `certificateLocation`).
pub const ATAK_CERT_DIR: &str = "/storage/emulated/0/atak/cert/";

/// Errors (messages as Python's `ValueError`s where there is one).
#[derive(Debug, thiserror::Error)]
pub enum DataPackageError {
    /// lxml refuses a string with a non-XML character (NUL, C0 controls, U+FFFE/U+FFFF).
    #[error(
        "All strings must be XML compatible: Unicode or ASCII, no NULL bytes or control characters"
    )]
    NotXmlCompatible,
    /// `build_pref`: a value that is not bool / int / str (Python: `None` from the config).
    #[error("Unknown preference type: <class 'NoneType'>")]
    UnknownPrefType,
    /// File I/O.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// ZIP writer.
    #[error("{0}")]
    Zip(#[from] zip::result::ZipError),
}

/// A preference value (`build_pref` types).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrefValue {
    /// `class java.lang.Boolean`, written `true` / `false`.
    Bool(bool),
    /// `class java.lang.Integer`, `str(int)`.
    Int(i64),
    /// `class java.lang.String`.
    Str(String),
    /// Python `None` (an option without a value): `build_pref` raises
    /// [`DataPackageError::UnknownPrefType`].
    None,
}

impl PrefValue {
    /// `Str` from an optional config value (`None` stays [`PrefValue::None`]).
    pub fn opt_str(v: Option<&str>) -> PrefValue {
        v.map_or(PrefValue::None, |s| PrefValue::Str(s.to_owned()))
    }
}

/// One `<preference name=…>` with its entries, in order (a Python dict).
pub type Preference = (String, Vec<(String, PrefValue)>);

fn checked(s: &str) -> Result<&str, DataPackageError> {
    if taky_xml::is_xml_compatible(s) {
        Ok(s)
    } else {
        Err(DataPackageError::NotXmlCompatible)
    }
}

/// `build_pref(pref_fp, prefs)`: `tostring(pretty_print=True, xml_declaration=True,
/// standalone=True)` — `<?xml version='1.0' encoding='ASCII' standalone='yes'?>`.
pub fn build_pref(prefs: &[Preference]) -> Result<Vec<u8>, DataPackageError> {
    let mut root = Element::new("preferences");
    for (name, entries) in prefs {
        let mut p = Element::new("preference");
        p.set("version", "1");
        p.set("name", checked(name)?);
        for (key, val) in entries {
            let (ty, text) = match val {
                PrefValue::Bool(b) => ("Boolean", b.to_string()),
                PrefValue::Int(i) => ("Integer", i.to_string()),
                PrefValue::Str(s) => ("String", s.clone()),
                PrefValue::None => return Err(DataPackageError::UnknownPrefType),
            };
            let mut e = Element::new("entry");
            e.set("key", checked(key)?);
            e.set("class", format!("class java.lang.{ty}"));
            e.text = Some(checked(&text)?.to_owned());
            p.append(e);
        }
        root.append(p);
    }
    Ok(taky_xml::serialize(
        &root,
        &SerOpts {
            pretty_print: true,
            xml_declaration: true,
            standalone: Some(true),
            ..SerOpts::default()
        },
    ))
}

/// `os.path.join("certs", name)`.
fn certs_join(name: &str) -> String {
    if name.starts_with('/') {
        name.to_owned()
    } else {
        format!("certs/{name}")
    }
}

/// `build_manifest(man_fp, cfg_params, contents)`: `tostring(pretty_print=True)`, no XML
/// declaration; every content is `zipEntry="certs/<name>"`, `ignore="false"`.
pub fn build_manifest(
    cfg_params: &[(String, String)],
    contents: &[String],
) -> Result<Vec<u8>, DataPackageError> {
    let mut mpm = Element::new("MissionPackageManifest");
    mpm.set("version", "2");
    let mut cfg = Element::new("Configuration");
    for (name, value) in cfg_params {
        let mut p = Element::new("Parameter");
        p.set("name", checked(name)?);
        p.set("value", checked(value)?);
        cfg.append(p);
    }
    mpm.append(cfg);
    let mut cts = Element::new("Contents");
    for name in contents {
        let mut c = Element::new("Content");
        c.set("ignore", "false");
        c.set("zipEntry", checked(&certs_join(name))?);
        cts.append(c);
    }
    mpm.append(cts);
    Ok(taky_xml::serialize(
        &mpm,
        &SerOpts {
            pretty_print: true,
            ..SerOpts::default()
        },
    ))
}

/// `server-<uuid4>.p12` (`server_p12_pkg_name`).
pub fn server_p12_pkg_name(uuid: &uuid::Uuid) -> String {
    format!("server-{}.p12", uuid.hyphenated())
}

/// `<name>-<uuid4>` (`client_pkg_name`, without `.p12`).
pub fn client_pkg_name(name: &str, uuid: &uuid::Uuid) -> String {
    format!("{name}-{}", uuid.hyphenated())
}

/// Inputs of the client package (config values as Python reads them: `None` = option without a
/// value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPackage {
    /// `--is_itak`.
    pub is_itak: bool,
    /// `taky.hostname` (`description0`, manifest `name` = `<hostname>_DP`).
    pub hostname: Option<String>,
    /// `taky.public_ip` (`None` ⇒ `None:<port>:<method>`, QUIRK).
    pub public_ip: Option<String>,
    /// `cot_server.port`.
    pub port: i64,
    /// `ssl.enabled` ⇒ `ssl`, else `tcp`.
    pub ssl_enabled: bool,
    /// `ssl.server_p12_pw` (`caPassword`).
    pub server_p12_pw: Option<String>,
    /// `--p12_pw` (`clientPassword`).
    pub p12_pw: String,
    /// [`server_p12_pkg_name`].
    pub server_p12_name: String,
    /// [`client_pkg_name`] (the p12 is `<client_pkg_name>.p12`).
    pub client_pkg_name: String,
    /// Manifest `uid` (`str(uuid.uuid4())`; ATAK only).
    pub manifest_uid: uuid::Uuid,
}

impl ClientPackage {
    /// The `prefs` dict of `build_client` (ATAK or iTAK variant).
    pub fn prefs(&self) -> Vec<Preference> {
        let s = |v: &str| PrefValue::Str(v.to_owned());
        let method = if self.ssl_enabled { "ssl" } else { "tcp" };
        let public_ip = self.public_ip.as_deref().unwrap_or("None");
        let streams = (
            "cot_streams".to_owned(),
            vec![
                ("count".to_owned(), PrefValue::Int(1)),
                (
                    "description0".to_owned(),
                    PrefValue::opt_str(self.hostname.as_deref()),
                ),
                ("enabled0".to_owned(), PrefValue::Bool(false)),
                (
                    "connectString0".to_owned(),
                    s(&format!("{public_ip}:{}:{method}", self.port)),
                ),
            ],
        );
        let client_p12 = format!("{}.p12", self.client_pkg_name);
        let mut app = Vec::new();
        let (ca_loc, cert_loc) = if self.is_itak {
            (
                format!("cert/{}", basename(&self.server_p12_name)),
                format!("cert/{client_p12}"),
            )
        } else {
            app.push((
                "displayServerConnectionWidget".to_owned(),
                PrefValue::Bool(true),
            ));
            (
                format!("{ATAK_CERT_DIR}{}", self.server_p12_name),
                format!("{ATAK_CERT_DIR}{client_p12}"),
            )
        };
        app.push(("caLocation".to_owned(), s(&ca_loc)));
        app.push((
            "caPassword".to_owned(),
            PrefValue::opt_str(self.server_p12_pw.as_deref()),
        ));
        app.push(("clientPassword".to_owned(), s(&self.p12_pw)));
        app.push(("certificateLocation".to_owned(), s(&cert_loc)));
        vec![streams, ("com.atakmap.app_preferences".to_owned(), app)]
    }

    /// The manifest (`cfg_params` + `man_cts`).
    pub fn manifest(&self) -> Result<Vec<u8>, DataPackageError> {
        let hostname = self.hostname.as_deref().unwrap_or("None");
        build_manifest(
            &[
                ("uid".to_owned(), self.manifest_uid.hyphenated().to_string()),
                ("name".to_owned(), format!("{hostname}_DP")),
                ("onReceiveDelete".to_owned(), "true".to_owned()),
            ],
            &[
                PREF_NAME.to_owned(),
                basename(&self.server_p12_name).to_owned(),
                format!("{}.p12", self.client_pkg_name),
            ],
        )
    }

    /// The ZIP entries, in the order they are written: (manifest,) pref, server p12, client p12.
    /// `server_p12` is the content of `ssl.server_p12`, `client_p12` the new client p12.
    pub fn entries(
        &self,
        server_p12: Vec<u8>,
        client_p12: Vec<u8>,
    ) -> Result<Vec<ZipEntry>, DataPackageError> {
        let dir = if self.is_itak { "" } else { "certs/" };
        let mut out = Vec::new();
        if !self.is_itak {
            out.push(ZipEntry::new(MANIFEST_PATH, self.manifest()?, 0o644));
        }
        out.push(ZipEntry::new(
            format!("{dir}{PREF_NAME}"),
            build_pref(&self.prefs())?,
            0o644,
        ));
        out.push(ZipEntry::new(
            format!("{dir}{}", self.server_p12_name),
            server_p12,
            0o644,
        ));
        // Holds the client private key: 0600 like the p12 file itself (D-19).
        out.push(ZipEntry::new(
            format!("{dir}{}.p12", self.client_pkg_name),
            client_p12,
            0o600,
        ));
        Ok(out)
    }
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// One file of the ZIP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry {
    /// Archive name (`/`-separated, relative).
    pub name: String,
    /// Content.
    pub data: Vec<u8>,
    /// Unix permission bits (stored as a regular file, like `zipfile` does from `st_mode`).
    pub mode: u32,
}

impl ZipEntry {
    /// New entry.
    pub fn new(name: impl Into<String>, data: Vec<u8>, mode: u32) -> ZipEntry {
        ZipEntry {
            name: name.into(),
            data,
            mode,
        }
    }
}

/// Writes `entries` to `path` (overwrite), ZIP_DEFLATED, mtime = local now.
pub fn write_zip(path: &Path, entries: &[ZipEntry]) -> Result<(), DataPackageError> {
    let f = std::fs::File::create(path)?;
    let mut z = zip::ZipWriter::new(f);
    let now = chrono::Local::now().naive_local();
    let mtime = zip_time(now);
    for e in entries {
        let mut opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(e.mode);
        if let Some(t) = mtime {
            opts = opts.last_modified_time(t);
        }
        z.start_file(e.name.as_str(), opts)?;
        z.write_all(&e.data)?;
    }
    z.finish()?.sync_all()?;
    Ok(())
}

/// DOS date/time; `zipfile` clamps nothing here (now is after 1980), so out of range ⇒ default.
fn zip_time(t: chrono::NaiveDateTime) -> Option<zip::DateTime> {
    use chrono::{Datelike, Timelike};
    let y = u16::try_from(t.year()).ok()?;
    zip::DateTime::from_date_and_time(
        y,
        t.month() as u8,
        t.day() as u8,
        t.hour() as u8,
        t.minute() as u8,
        t.second() as u8,
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(is_itak: bool) -> ClientPackage {
        ClientPackage {
            is_itak,
            hostname: Some("taky.local".into()),
            public_ip: Some("192.0.2.1".into()),
            port: 8089,
            ssl_enabled: true,
            server_p12_pw: Some("atakatak".into()),
            p12_pw: "atakatak".into(),
            server_p12_name: server_p12_pkg_name(&uuid::Uuid::nil()),
            client_pkg_name: client_pkg_name("JENNY", &uuid::Uuid::nil()),
            manifest_uid: uuid::Uuid::nil(),
        }
    }

    #[test]
    fn pref_atak_exact() {
        let got = String::from_utf8(build_pref(&pkg(false).prefs()).expect("pref")).expect("u8");
        let want = "<?xml version='1.0' encoding='ASCII' standalone='yes'?>
<preferences>
  <preference version=\"1\" name=\"cot_streams\">
    <entry key=\"count\" class=\"class java.lang.Integer\">1</entry>
    <entry key=\"description0\" class=\"class java.lang.String\">taky.local</entry>
    <entry key=\"enabled0\" class=\"class java.lang.Boolean\">false</entry>
    <entry key=\"connectString0\" class=\"class java.lang.String\">192.0.2.1:8089:ssl</entry>
  </preference>
  <preference version=\"1\" name=\"com.atakmap.app_preferences\">
    <entry key=\"displayServerConnectionWidget\" class=\"class java.lang.Boolean\">true</entry>
    <entry key=\"caLocation\" class=\"class java.lang.String\">/storage/emulated/0/atak/cert/server-00000000-0000-0000-0000-000000000000.p12</entry>
    <entry key=\"caPassword\" class=\"class java.lang.String\">atakatak</entry>
    <entry key=\"clientPassword\" class=\"class java.lang.String\">atakatak</entry>
    <entry key=\"certificateLocation\" class=\"class java.lang.String\">/storage/emulated/0/atak/cert/JENNY-00000000-0000-0000-0000-000000000000.p12</entry>
  </preference>
</preferences>
";
        assert_eq!(got, want);
    }

    #[test]
    fn manifest_exact_and_escaping() {
        let got = String::from_utf8(pkg(false).manifest().expect("m")).expect("u8");
        let n = "00000000-0000-0000-0000-000000000000";
        let want = format!(
            "<MissionPackageManifest version=\"2\">
  <Configuration>
    <Parameter name=\"uid\" value=\"{n}\"/>
    <Parameter name=\"name\" value=\"taky.local_DP\"/>
    <Parameter name=\"onReceiveDelete\" value=\"true\"/>
  </Configuration>
  <Contents>
    <Content ignore=\"false\" zipEntry=\"certs/preference.pref\"/>
    <Content ignore=\"false\" zipEntry=\"certs/server-{n}.p12\"/>
    <Content ignore=\"false\" zipEntry=\"certs/JENNY-{n}.p12\"/>
  </Contents>
</MissionPackageManifest>
"
        );
        assert_eq!(got, want);
        let m = build_manifest(&[("u".into(), "a&\"<é\t".into())], &["/abs".into()]).expect("m");
        let m = String::from_utf8(m).expect("u8");
        assert!(m.contains("value=\"a&amp;&quot;&lt;&#233;&#9;\""), "{m}");
        assert!(m.contains("zipEntry=\"/abs\""), "{m}");
        assert_eq!(
            String::from_utf8(build_manifest(&[], &[]).expect("m")).expect("u8"),
            "<MissionPackageManifest version=\"2\">\n  <Configuration/>\n  <Contents/>\n</MissionPackageManifest>\n"
        );
    }

    #[test]
    fn pref_errors_and_quirks() {
        let mut p = pkg(false);
        p.public_ip = None;
        p.ssl_enabled = false;
        let s = String::from_utf8(build_pref(&p.prefs()).expect("pref")).expect("u8");
        assert!(s.contains(">None:8089:tcp<"), "{s}");
        p.hostname = None;
        assert_eq!(
            build_pref(&p.prefs()).expect_err("None").to_string(),
            "Unknown preference type: <class 'NoneType'>"
        );
        assert!(p.manifest().expect("m").windows(7).any(|w| w == b"None_DP"));
        let bad = vec![(
            "a".to_owned(),
            vec![("k".to_owned(), PrefValue::Str("\u{1}".into()))],
        )];
        assert!(matches!(
            build_pref(&bad),
            Err(DataPackageError::NotXmlCompatible)
        ));
        let empty: Vec<Preference> = vec![("a".into(), vec![])];
        assert_eq!(
            build_pref(&empty).expect("p"),
            b"<?xml version='1.0' encoding='ASCII' standalone='yes'?>\n<preferences>\n  <preference version=\"1\" name=\"a\"/>\n</preferences>\n"
        );
    }

    #[test]
    fn itak_layout() {
        let p = pkg(true);
        let e = p.entries(b"S".to_vec(), b"C".to_vec()).expect("entries");
        let names: Vec<&str> = e.iter().map(|e| e.name.as_str()).collect();
        let n = "00000000-0000-0000-0000-000000000000";
        assert_eq!(
            names,
            [
                "preference.pref".to_owned(),
                format!("server-{n}.p12"),
                format!("JENNY-{n}.p12")
            ]
        );
        let pref = String::from_utf8(e[0].data.clone()).expect("u8");
        assert!(!pref.contains("displayServerConnectionWidget"));
        assert!(pref.contains(&format!(">cert/server-{n}.p12<")));
        assert!(pref.contains(&format!(">cert/JENNY-{n}.p12<")));
        let a = pkg(false).entries(vec![], vec![]).expect("entries");
        assert_eq!(a[0].name, MANIFEST_PATH);
        assert!(a[1..].iter().all(|e| e.name.starts_with("certs/")));
        assert_eq!(a[3].mode, 0o600);
    }

    #[test]
    fn zip_roundtrip() {
        let d = tempfile::tempdir().expect("tmp");
        let path = d.path().join("JENNY.zip");
        let entries = pkg(false).entries(b"S".to_vec(), b"C".to_vec()).expect("e");
        write_zip(&path, &entries).expect("zip");
        let mut z = zip::ZipArchive::new(std::fs::File::open(&path).expect("open")).expect("zip");
        assert_eq!(z.len(), 4);
        for (i, e) in entries.iter().enumerate() {
            let mut f = z.by_index(i).expect("entry");
            assert_eq!(f.name().expect("name"), e.name.as_str());
            assert_eq!(f.compression(), zip::CompressionMethod::Deflated);
            assert_eq!(f.unix_mode().map(|m| m & 0o777), Some(e.mode));
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut f, &mut buf).expect("read");
            assert_eq!(buf, e.data);
        }
    }
}
