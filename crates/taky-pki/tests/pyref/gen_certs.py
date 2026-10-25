"""Reference certificates from the ORIGINAL taky/taky/util/anc.py (imported read-only).

Run with `python -I -B` (no __pycache__ is written next to anc.py). Usage:
  gen_certs.py <anc.py> full <out_dir>
      ca.{crt,key}; server/srvip/srvlong (server profile, dump_pem); JENNY (client);
      cert-db.txt with server + JENNY (CertificateDatabase.add_certificate)
  gen_certs.py <anc.py> issue <ca_crt> <ca_key> <out_dir> <name> <server|client>
      one certificate signed by the given CA (e.g. a CA written by taky-rs)
Used by taky-pki/tests/pyref_x509.rs (S-320).
"""
import configparser
import importlib.util
import os
import sys
import types


def load_anc(anc_path, cert_db):
    cfg = configparser.ConfigParser(allow_no_value=True)
    cfg.read_dict({"ssl": {"cert_db": cert_db}})
    taky = types.ModuleType("taky")
    taky.__path__ = []
    taky_config = types.ModuleType("taky.config")
    taky_config.app_config = cfg
    sys.modules["taky"] = taky
    sys.modules["taky.config"] = taky_config
    spec = importlib.util.spec_from_file_location("anc", anc_path)
    anc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(anc)
    return anc


def main(argv):
    anc_path, mode = argv[1], argv[2]
    if mode == "full":
        out = argv[3]
        anc = load_anc(anc_path, os.path.join(out, "cert-db.txt"))
        ca = (os.path.join(out, "ca.crt"), os.path.join(out, "ca.key"))
        anc.make_ca(*ca)
        db = anc.CertificateDatabase()
        cert = anc.make_cert(out, "server", "taky.local", "atakatak", ca,
                             dump_pem=True, key_in_pem=False, is_server_cert=True)
        db.add_certificate(cert)
        anc.make_cert(out, "srvip", "192.168.1.10", "atakatak", ca,
                      dump_pem=True, key_in_pem=False, is_server_cert=True)
        anc.make_cert(out, "srvlong", "h" * 64, "atakatak", ca,
                      dump_pem=True, key_in_pem=False, is_server_cert=True)
        cert = anc.make_cert(out, "JENNY", "JENNY", "atakatak", ca,
                             dump_pem=True, key_in_pem=True, is_server_cert=False)
        db.add_certificate(cert)
    elif mode == "issue":
        ca_crt, ca_key, out, name, kind = argv[3:8]
        anc = load_anc(anc_path, os.path.join(out, "cert-db.txt"))
        anc.make_cert(out, name, name, "atakatak", (ca_crt, ca_key), dump_pem=True,
                      key_in_pem=True, is_server_cert=(kind == "server"))
    else:
        raise SystemExit(f"unknown mode {mode}")
    print("ok")


if __name__ == "__main__":
    main(sys.argv)
