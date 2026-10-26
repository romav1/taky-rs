"""Runs the ORIGINAL CoT server `taky` (taky/taky/cot/__main__.py:main) from the read-only
source tree, without installing taky (repository root first on sys.path; run with
`python -I -B -W ignore`).

Usage: taky_cot.py <taky_repo_root> <taky args...>   (cwd = the site directory).
Used by takyctl/tests/pyref_mgmt.rs (S-323).
"""
import sys


def main():
    root = sys.argv[1]
    sys.path.insert(0, root)
    sys.argv = ["taky"] + sys.argv[2:]
    from taky.cot.__main__ import main as taky_main  # pylint: disable=import-outside-toplevel

    sys.exit(taky_main())


if __name__ == "__main__":
    main()
