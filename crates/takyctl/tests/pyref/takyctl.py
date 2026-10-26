"""Runs the ORIGINAL `takyctl` (taky/taky/cli/__main__.py:main) from the read-only source tree,
without installing taky: the repository root is put first on sys.path (run with
`python -I -B -W ignore`, so nothing is written into taky/).

Usage: takyctl.py <taky_repo_root> <takyctl args...>   (cwd = where the command runs).
Used by takyctl/tests/pyref_cli.rs (S-322).
"""
import sys


def main():
    root = sys.argv[1]
    sys.path.insert(0, root)
    sys.argv = ["takyctl"] + sys.argv[2:]
    from taky.cli.__main__ import main as takyctl_main  # pylint: disable=import-outside-toplevel

    takyctl_main()


if __name__ == "__main__":
    main()
