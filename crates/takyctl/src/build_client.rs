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
use std::path::{Path, PathBuf};

use chrono::NaiveDateTime;
use taky_config::{ConfigError, TakyConfig, load_config_in};
use taky_pki::CertDb;
use taky_pki::certgen::{self, CertAuthority, CertKind, KeyCert};
use taky_pki::pkcs12;

use crate::cli::BuildClientArgs;
use crate::datapackage::{
    ClientPackage, MANIFEST_PATH, PREF_NAME, ZipEntry, client_pkg_name, server_p12_pkg_name,
};
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
///
/// Steps in the original's order (spec §7.6), each its own function: [`load`] the config,
/// [`BuildPlan::new`] (validate the name, read the config values once), copy the server p12,
/// open the cert-db, [`issue`] the client certificate, record it in the cert-db, build the
/// [`package`], `--dump_pem`, write the ZIP.
pub fn build_client(
    args: &BuildClientArgs,
    cfg_file: Option<&Path>,
    cwd: &Path,
    now: NaiveDateTime,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    let Some(cfg) = load(cfg_file, cwd, err)? else {
        return Ok(1);
    };
    run(&BuildPlan::new(args, &cfg, cwd)?, now)?;
    Ok(0)
}

/// The side effects, in order: server p12 read, cert-db opened, client issued and recorded,
/// package built, `--dump_pem` files, `<cwd>/<name>.zip`.
fn run(plan: &BuildPlan, now: NaiveDateTime) -> anyhow::Result<()> {
    let server_p12 = ServerP12::read(plan)?;
    let mut cert_db = open_cert_db(plan)?;
    let client = issue(plan, now)?;
    cert_db.add(&client.cert.cert_der).map_err(pki)?;
    let entries = package(plan, server_p12, client.p12.clone(), &client.pkg_name)?;
    if plan.dump_pem {
        dump_pem(plan, &client)?;
    }
    write_zip(plan, &entries)
}

fn open_cert_db(plan: &BuildPlan) -> anyhow::Result<CertDb> {
    CertDb::open(&plan.file(&plan.cert_db)?).map_err(pki)
}

/// `<cwd>/<name>.zip` (overwritten).
fn write_zip(plan: &BuildPlan, entries: &[ZipEntry]) -> anyhow::Result<()> {
    let zip_path = plan.cwd.join(format!("{}.zip", plan.name));
    crate::datapackage::write_zip(&zip_path, entries)
        .map_err(|e| anyhow::anyhow!("{}: {e}", zip_path.display()))
}

/// `load_config(-c)` (not explicit). `Ok(None)`: a config error was printed (exit 1).
fn load(
    cfg_file: Option<&Path>,
    cwd: &Path,
    err: &mut dyn Write,
) -> anyhow::Result<Option<TakyConfig>> {
    match load_config_in(cfg_file, false, cwd) {
        Ok(c) => Ok(Some(c)),
        Err(e) if printed_config_error(&e) => {
            writeln!(err, "{e}")?;
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

/// Everything `build_client` uses, read once from the arguments and the config.
///
/// Values are the raw INI strings the original reads (`None` = option without a value), not
/// the typed `TakyConfig` fields: those normalise `""`/`None` differently (e.g. `hostname`
/// defaults to `""`, empty paths become `None`), which would change the package and the
/// error texts. A `None` path fails ([`none_path`]) only where the original uses it.
struct BuildPlan {
    name: String,
    is_itak: bool,
    p12_pw: String,
    dump_pem: bool,
    cwd: PathBuf,
    server_p12: Option<String>,
    cert_db: Option<String>,
    ca: Option<String>,
    ca_key: Option<String>,
    hostname: Option<String>,
    public_ip: Option<String>,
    server_p12_pw: Option<String>,
    port: i64,
    ssl_enabled: bool,
}

impl BuildPlan {
    /// Refuses a `name` containing `/` (D-25) before anything is read or written.
    fn new(args: &BuildClientArgs, cfg: &TakyConfig, cwd: &Path) -> anyhow::Result<BuildPlan> {
        if args.name.contains('/') {
            anyhow::bail!(
                "invalid client name {}: must not contain '/'",
                taky_config::error::py_repr(&args.name)
            );
        }
        let ini = cfg.raw();
        Ok(BuildPlan {
            name: args.name.clone(),
            is_itak: args.is_itak,
            p12_pw: args.p12_pw.clone(),
            dump_pem: args.dump_pem,
            cwd: cwd.to_owned(),
            server_p12: ini.get("ssl", "server_p12")?,
            cert_db: ini.get("ssl", "cert_db")?,
            ca: ini.get("ssl", "ca")?,
            ca_key: ini.get("ssl", "ca_key")?,
            hostname: ini.get("taky", "hostname")?,
            public_ip: ini.get("taky", "public_ip")?,
            server_p12_pw: ini.get("ssl", "server_p12_pw")?,
            port: i64::from(cfg.cot_server.port),
            ssl_enabled: cfg.ssl.enabled,
        })
    }

    /// A config path as the original opens it (relative to the cwd); `None` ⇒ [`none_path`].
    fn file(&self, p: &Option<String>) -> anyhow::Result<PathBuf> {
        Ok(self.cwd.join(required(p)?))
    }
}

fn required(p: &Option<String>) -> anyhow::Result<&str> {
    p.as_deref().ok_or_else(none_path)
}

/// `shutil.copy(ssl.server_p12, …)`: content and mode bits.
struct ServerP12 {
    data: Vec<u8>,
    mode: u32,
}

impl ServerP12 {
    fn read(plan: &BuildPlan) -> anyhow::Result<ServerP12> {
        let name = required(&plan.server_p12)?;
        let path = plan.file(&plan.server_p12)?;
        let data = std::fs::read(&path).map_err(|e| os_error(&e, name))?;
        let mode = std::fs::metadata(&path)
            .map(|m| m.permissions().mode() & 0o7777)
            .map_err(|e| os_error(&e, name))?;
        Ok(ServerP12 { data, mode })
    }
}

/// The new client certificate and its p12 (key + cert + CA).
struct Client {
    cert: KeyCert,
    p12: Vec<u8>,
    /// `<name>-<uuid4>`.
    pkg_name: String,
}

/// `make_cert(..., key_in_pem=True, is_server_cert=False)`: `CN=<name>` signed by
/// `ssl.ca`/`ssl.ca_key`, p12 protected by `--p12_pw`.
fn issue(plan: &BuildPlan, now: NaiveDateTime) -> anyhow::Result<Client> {
    let pkg_name = client_pkg_name(&plan.name, &uuid::Uuid::new_v4());
    let (ca, ca_key) = (plan.file(&plan.ca)?, plan.file(&plan.ca_key)?);
    let ca = CertAuthority::load(&ca, &ca_key).map_err(pki)?;
    let cert = certgen::make_cert(&ca, &plan.name, now, certgen::CERT_YEARS, CertKind::Client)
        .map_err(pki)?;
    let p12 = pkcs12::make_cert_p12(&cert, &ca, &plan.name, true, &plan.p12_pw).map_err(pki)?;
    Ok(Client {
        cert,
        p12,
        pkg_name,
    })
}

/// The ZIP entries (§6) with the modes the original's temp-dir files have: the server p12 copy
/// keeps the source mode (`shutil.copy`), pref/manifest get the umask mode, the client p12
/// stays 0600 (D-19).
fn package(
    plan: &BuildPlan,
    server_p12: ServerP12,
    client_p12: Vec<u8>,
    pkg_name: &str,
) -> anyhow::Result<Vec<ZipEntry>> {
    let server_p12_name = server_p12_pkg_name(&uuid::Uuid::new_v4());
    let pkg = ClientPackage {
        is_itak: plan.is_itak,
        hostname: plan.hostname.clone(),
        public_ip: plan.public_ip.clone(),
        port: plan.port,
        ssl_enabled: plan.ssl_enabled,
        server_p12_pw: plan.server_p12_pw.clone(),
        p12_pw: plan.p12_pw.clone(),
        server_p12_name: server_p12_name.clone(),
        client_pkg_name: pkg_name.to_owned(),
        manifest_uid: uuid::Uuid::new_v4(),
    };
    let mut entries = pkg.entries(server_p12.data, client_p12)?;
    let file_mode = 0o666 & !current_umask();
    for e in &mut entries {
        if e.name.ends_with(&server_p12_name) {
            e.mode = server_p12.mode;
        } else if e.name == MANIFEST_PATH || e.name.ends_with(PREF_NAME) {
            e.mode = file_mode;
        }
    }
    Ok(entries)
}

/// `--dump_pem`: `<name>-<uuid>.p12/.crt/.key` into the cwd.
fn dump_pem(plan: &BuildPlan, client: &Client) -> anyhow::Result<()> {
    let out = |ext: &str| plan.cwd.join(format!("{}.{ext}", client.pkg_name));
    pkcs12::write_p12(&out("p12"), &client.p12, true).map_err(pki)?;
    certgen::write_certificate(&out("crt"), &out("key"), &client.cert).map_err(pki)?;
    Ok(())
}
