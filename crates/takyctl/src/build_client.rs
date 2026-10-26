//! `takyctl-rs build_client` (`cli/build_client_cmd.py`; spec dps-cli-config §6, §7.6).
//!
//! Same inputs, side effects and order as the original: `load_config(-c)` (not explicit),
//! server p12 copied as `server-<uuid4>.p12`, cert-db loaded, client certificate
//! `CN=<name>` signed by `ssl.ca`/`ssl.ca_key`, client p12 (key + cert + CA), one `V` line in
//! cert-db, `preference.pref` (+ `MANIFEST/manifest.xml` for ATAK), `--dump_pem` copies
//! `<name>-<uuid>.p12/.crt/.key` into the cwd, `<cwd>/<name>.zip`. No stdout output.
//!
//! The package is assembled in memory (no `taky-cert-*` temp directory, so nothing is left
//! behind on failure). A `name` containing `/` is refused before anything is written (Python
//! fails later with `FileNotFoundError`, after copying the server p12 into its temp dir).

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use chrono::NaiveDateTime;
use taky_config::{ConfigError, load_config_in};
use taky_pki::CertDb;
use taky_pki::certgen::{self, CertAuthority, CertKind};
use taky_pki::pkcs12;

use crate::cli::BuildClientArgs;
use crate::datapackage::{ClientPackage, MANIFEST_PATH, client_pkg_name, server_p12_pkg_name};
use crate::fsutil::current_umask;
use crate::pyerr::{none_path, os_error, pki};

/// `except (OSError, configparser.ParsingError)` in `build_client` (also `status`, `kickban`,
/// `systemd`): these are printed and exit 1; every other config error takes the `"build_client failed: …"` path.
pub(crate) fn printed_config_error(e: &ConfigError) -> bool {
    matches!(
        e.py_class(),
        "OSError"
            | "FileNotFoundError"
            | "ParsingError"
            | "MissingSectionHeaderError"
            | "MultilineContinuationError"
    )
}

/// Runs `build_client` in `cwd`; returns the exit code. `Err` ⇒ the failed path (exit 1).
pub fn build_client(
    args: &BuildClientArgs,
    cfg_file: Option<&Path>,
    cwd: &Path,
    now: NaiveDateTime,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    let cfg = match load_config_in(cfg_file, false, cwd) {
        Ok(c) => c,
        Err(e) if printed_config_error(&e) => {
            writeln!(err, "{e}")?;
            return Ok(1);
        }
        Err(e) => return Err(e.into()),
    };
    if args.name.contains('/') {
        anyhow::bail!(
            "invalid client name {}: must not contain '/'",
            taky_config::error::py_repr(&args.name)
        );
    }
    let ini = cfg.raw();
    let path =
        |s: &str, k: &str| -> anyhow::Result<String> { ini.get(s, k)?.ok_or_else(none_path) };
    let fs = |p: &str| cwd.join(p);

    // Server p12 (`shutil.copy`: content and mode bits).
    let server_p12_s = path("ssl", "server_p12")?;
    let server_p12 = std::fs::read(fs(&server_p12_s)).map_err(|e| os_error(&e, &server_p12_s))?;
    let server_mode = std::fs::metadata(fs(&server_p12_s))
        .map(|m| m.permissions().mode() & 0o7777)
        .map_err(|e| os_error(&e, &server_p12_s))?;
    let server_p12_name = server_p12_pkg_name(&uuid::Uuid::new_v4());

    let cert_db_s = path("ssl", "cert_db")?;
    let mut cert_db = CertDb::open(&fs(&cert_db_s)).map_err(pki)?;

    // Client certificate (`make_cert(..., key_in_pem=True, is_server_cert=False)`).
    let pkg_name = client_pkg_name(&args.name, &uuid::Uuid::new_v4());
    let (ca_s, ca_key_s) = (path("ssl", "ca")?, path("ssl", "ca_key")?);
    let ca = CertAuthority::load(&fs(&ca_s), &fs(&ca_key_s)).map_err(pki)?;
    let client = certgen::make_cert(&ca, &args.name, now, certgen::CERT_YEARS, CertKind::Client)
        .map_err(pki)?;
    let client_p12 =
        pkcs12::make_cert_p12(&client, &ca, &args.name, true, &args.p12_pw).map_err(pki)?;
    cert_db.add(&client.cert_der).map_err(pki)?;

    let pkg = ClientPackage {
        is_itak: args.is_itak,
        hostname: ini.get("taky", "hostname")?,
        public_ip: ini.get("taky", "public_ip")?,
        port: i64::from(cfg.cot_server.port),
        ssl_enabled: cfg.ssl.enabled,
        server_p12_pw: ini.get("ssl", "server_p12_pw")?,
        p12_pw: args.p12_pw.clone(),
        server_p12_name: server_p12_name.clone(),
        client_pkg_name: pkg_name.clone(),
        manifest_uid: uuid::Uuid::new_v4(),
    };
    let mut entries = pkg.entries(server_p12, client_p12.clone())?;
    // Files Python writes into its temp dir get the umask mode; the server p12 copy keeps the
    // source mode (shutil.copy); the client p12 stays 0600 (D-19).
    let file_mode = 0o666 & !current_umask();
    for e in &mut entries {
        if e.name.ends_with(&server_p12_name) {
            e.mode = server_mode;
        } else if e.name == MANIFEST_PATH || e.name.ends_with(crate::datapackage::PREF_NAME) {
            e.mode = file_mode;
        }
    }

    if args.dump_pem {
        pkcs12::write_p12(&cwd.join(format!("{pkg_name}.p12")), &client_p12, true).map_err(pki)?;
        certgen::write_certificate(
            &cwd.join(format!("{pkg_name}.crt")),
            &cwd.join(format!("{pkg_name}.key")),
            &client,
        )
        .map_err(pki)?;
    }

    let zip_path = cwd.join(format!("{}.zip", args.name));
    crate::datapackage::write_zip(&zip_path, &entries)
        .map_err(|e| anyhow::anyhow!("{}: {e}", zip_path.display()))?;
    Ok(0)
}
