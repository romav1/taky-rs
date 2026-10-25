"""Runs the ORIGINAL `takyctl build_client` (taky/taky/cli/build_client_cmd.py) without
installing taky: taky.config, taky.util.anc and taky.util.datapackage are loaded from the
read-only source tree by file path (run with `python -I -B`, nothing is written into taky/).

Usage: build_client.py <taky_pkg_dir> <taky.conf> <out_dir> <name> <0|1 is_itak> <p12_pw>
Writes <out_dir>/<name>.zip (build_client writes into the cwd). Used by
takyctl/tests/pyref_datapackage.rs (S-321).
"""
import argparse
import importlib.util
import os
import sys
import types


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def main(argv):
    pkg, conf, out, name, itak, pw = argv[1:7]
    for p in ("taky", "taky.util", "taky.cli"):
        m = types.ModuleType(p)
        m.__path__ = []
        sys.modules[p] = m
    sys.modules["taky"].config = load("taky.config", os.path.join(pkg, "config.py"))
    util = sys.modules["taky.util"]
    util.anc = load("taky.util.anc", os.path.join(pkg, "util", "anc.py"))
    util.datapackage = load("taky.util.datapackage", os.path.join(pkg, "util", "datapackage.py"))
    bc = load("taky.cli.build_client_cmd", os.path.join(pkg, "cli", "build_client_cmd.py"))
    os.chdir(out)
    args = argparse.Namespace(cfg_file=conf, name=name, is_itak=(itak == "1"),
                              p12_pw=pw, dump_pem=False)
    sys.exit(bc.build_client(args))


if __name__ == "__main__":
    main(sys.argv)
