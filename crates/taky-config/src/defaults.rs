//! `DEFAULT_CFG` from `taky/config.py`.

use crate::Ini;

/// One `DEFAULT_CFG` section: `(section, [(key, value)])`.
pub type DefaultSection = (
    &'static str,
    &'static [(&'static str, Option<&'static str>)],
);

/// Sections and keys of `DEFAULT_CFG` in the original order: `(section, [(key, value)])`.
///
/// Values as `ConfigParser.read_dict` sees them (strings; `None` — key without a value).
pub const DEFAULT_CFG: &[DefaultSection] = &[
    (
        "taky",
        &[
            ("hostname", Some("taky.local")),
            ("node_id", Some("TAKY")),
            ("bind_ip", None),
            ("public_ip", None),
            ("redis", None),
            ("root_dir", Some("/var/taky")),
        ],
    ),
    (
        "cot_server",
        &[
            ("port", None),
            ("mon_ip", None),
            ("mon_port", None),
            ("log_cot", None),
            ("max_persist_ttl", Some("-1")),
        ],
    ),
    ("dp_server", &[("upload_path", Some("/var/taky/dp-user"))]),
    (
        "ssl",
        &[
            ("enabled", Some("False")),
            ("client_cert_required", Some("True")),
            ("ca", Some("/etc/taky/ssl/ca.crt")),
            ("ca_key", Some("/etc/taky/ssl/ca.key")),
            ("server_p12", Some("/etc/taky/ssl/server.p12")),
            ("server_p12_pw", Some("atakatak")),
            ("cert", Some("/etc/taky/ssl/server.crt")),
            ("key", Some("/etc/taky/ssl/server.key")),
            ("key_pw", None),
            ("cert_db", Some("/etc/taky/ssl/cert-db.txt")),
        ],
    ),
];

/// `ConfigParser(allow_no_value=True)` after `read_dict(DEFAULT_CFG)` — for `takyctl-rs setup`.
///
/// **T-10 scaffold:** implementation — T-20.
pub fn default_ini() -> Ini {
    todo!("T-20: build Ini from DEFAULT_CFG")
}
