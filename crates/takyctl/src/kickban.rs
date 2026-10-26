//! `takyctl-rs kickban` (`cli/kickban_cmd.py`; spec dps-cli-config §7.5, compat 1.4.11).
//!
//! Like the original, the CLI only sends `{"cmd": "kickban", "user": <name>}` over the mgmt
//! socket; the **server** revokes the certificates in cert-db (`taky_pki::CertDb` refresh +
//! revoke under flock, D-11; `taky-server` hub) and disconnects the matching clients, then
//! replies `{"revoked_sns": [...]}` (integers of any size).

use std::io::Write;
use std::path::Path;

use serde_json::{Value, json};
use taky_common::pyjson::{DumpOpts, dumps};

use crate::cli::KickbanArgs;
use crate::mgmt::{self, hex040, py_type};

/// Prints the kickban reply (`-j` off); returns the exit code.
pub fn print_kickban(name: &str, resp: &Value, out: &mut dyn Write) -> anyhow::Result<u8> {
    let resp = match resp {
        Value::Object(m) => m,
        other => anyhow::bail!("'{}' object has no attribute 'get'", py_type(other)),
    };
    let empty = Vec::new();
    let sns = match resp.get("revoked_sns") {
        None => &empty,
        Some(Value::Array(a)) => a,
        Some(other) if other.as_str() == Some("") => &empty,
        Some(other) => anyhow::bail!("object of type '{}' has no len()", py_type(other)),
    };
    if sns.is_empty() {
        writeln!(out, "Unable to find certificates for user {name}")?;
        return Ok(0);
    }
    writeln!(out, "Revoked certificate SNs for {name}:")?;
    for sn in sns {
        writeln!(out, " - {}", hex040(sn)?)?;
    }
    Ok(0)
}

/// Runs `kickban`; returns the exit code. `Err` ⇒ the "failed" path.
pub fn kickban(
    args: &KickbanArgs,
    cfg_file: Option<&Path>,
    cwd: &Path,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<u8> {
    let socket = match mgmt::resolve_socket(args.socket.as_deref(), cfg_file, cwd, err)? {
        Ok(s) => s,
        Err(code) => return Ok(code),
    };
    let req = json!({"cmd": "kickban", "user": args.name});
    let resp = match mgmt::request(&socket, &req) {
        Ok(v) => v,
        Err(e) => return Ok(mgmt::report(&e, &socket, out, err)?),
    };
    if args.json {
        writeln!(out, "{}", dumps(&resp, &DumpOpts::default()))?;
        Ok(0)
    } else {
        print_kickban(&args.name, &resp, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(resp: &str) -> String {
        let mut o = Vec::new();
        let v: Value = serde_json::from_str(resp).unwrap();
        assert_eq!(print_kickban("alice", &v, &mut o).unwrap(), 0);
        String::from_utf8(o).unwrap()
    }

    #[test]
    fn output_golden() {
        assert_eq!(
            render(r#"{"revoked_sns": []}"#),
            "Unable to find certificates for user alice\n"
        );
        assert_eq!(
            render(r#"{"revoked_sns": [1148112432542345069093428530316431016766373781528, 10]}"#),
            "Revoked certificate SNs for alice:\n - c91b245c67e94578f256a66fbd3190c75ea26018\n - 000000000000000000000000000000000000000a\n"
        );
        assert_eq!(
            render(r#"{"error": "Invalid cmd: None"}"#),
            "Unable to find certificates for user alice\n"
        );
    }
}
