"""Loads a p12 with Python `cryptography` (pkcs12.load_pkcs12) and prints a JSON summary.

Usage: load_p12.py <file.p12> <password>   (run with `python -I -B`)
Used by taky-pki/tests/pyref_p12.rs (S-321).
"""
import json
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


def name(n):
    return None if n is None else n.decode("utf-8", "replace")


def main(path, pw):
    with open(path, "rb") as fp:
        data = fp.read()
    # The tuple API anc.py users (and takyctl tests) rely on …
    key, cert, cas = pkcs12.load_key_and_certificates(data, pw.encode())
    # … and the full one, which also exposes friendly names.
    p = pkcs12.load_pkcs12(data, pw.encode())
    der = lambda c: None if c is None else c.public_bytes(serialization.Encoding.DER).hex()
    out = {
        "has_key": key is not None,
        "key_matches_cert": key is not None and key.public_key().public_numbers()
        == cert.public_key().public_numbers(),
        "key_pkcs8": None if key is None else key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).hex(),
        "cert": der(cert),
        # Without a key there is no "main" certificate: every cert is in `cas`.
        "cert_name": None if p.cert is None else name(p.cert.friendly_name),
        "cas": [der(c) for c in cas],
        "ca_names": [name(c.friendly_name) for c in p.additional_certs],
    }
    print(json.dumps(out, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
