#!/usr/bin/env python3
"""ub-mode ratchet (S-805): compare crapper / dryer results with tools/quality/baseline.toml.

  ratchet.py check  --baseline B --crap CRAP.edn --dry DRY.edn --root R  -> exit 1 if a count rises
  ratchet.py check  ... --write-baseline                                -> rewrite B (keeps [exceptions])

Counts are the gate; the `known_*` lists only name the offenders, so a failure can print the
new ones. Keys: crapper `namespace::name`; dryer `file::fn <-> file::fn` (fn enclosing the
reported start line), so line shifts do not create "new" offenders.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

CRAP_THRESHOLD = 10.0
_CRAP_ENTRY = re.compile(r'\{:name "((?:[^"\\]|\\.)*)", :namespace "((?:[^"\\]|\\.)*)".*?:crap ([0-9.]+|nil)\}')
_DRY_SIDE = re.compile(r':(left|right) \{:file "((?:[^"\\]|\\.)*)", :start-line (\d+)')
_FN = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")


@dataclass
class Baseline:
    crap_ge_10: int
    dryer_pairs: int
    known_crap: list[str]
    known_dryer: list[str]
    exceptions: list[str]


def crap_offenders(text: str, threshold: float, exceptions: list[str]) -> list[str]:
    """Sorted `namespace::name` of functions with CRAP >= threshold, exceptions removed."""
    out = []
    for name, ns, crap in _CRAP_ENTRY.findall(text):
        key = f"{ns}::{name}"
        if crap != "nil" and float(crap) >= threshold and key not in exceptions:
            out.append(key)
    return sorted(out)


def _fn_at(root: Path, rel: str, line: int) -> str:
    try:
        lines = (root / rel).read_text(encoding="utf-8").splitlines()
    except OSError:
        return f"L{line}"
    for text in lines[line - 1 : line + 3]:  # signature may follow attributes/doc lines
        m = _FN.search(text)
        if m:
            return m.group(1)
    return f"L{line}"


def _rel(file: str, root: Path) -> str:
    p = Path(file)
    return p.relative_to(root).as_posix() if p.is_absolute() and p.is_relative_to(root) else file


def dryer_pairs(text: str, root: Path) -> list[str]:
    """Sorted pair keys from a dryer EDN report."""
    sides = _DRY_SIDE.findall(text)
    out = []
    for (_, lf, ll), (_, rf, rl) in zip(sides[0::2], sides[1::2]):
        lf, rf = _rel(lf, root), _rel(rf, root)
        out.append(f"{lf}::{_fn_at(root, lf, int(ll))} <-> {rf}::{_fn_at(root, rf, int(rl))}")
    return sorted(out)


def _one(name: str, base: int, known: list[str], now: list[str]) -> tuple[bool, list[str]]:
    new = sorted((Counter(now) - Counter(known)).elements())
    gone = sorted((Counter(known) - Counter(now)).elements())
    n = len(now)
    if n > base:
        return False, [f"FAIL {name} {n} > baseline {base}; new offenders:", *[f"  + {k}" for k in new]]
    lines = [f"ok   {name} {n} (baseline {base})"]
    if n < base:
        lines.append(f"note {name} {n} < baseline {base}: lower it (ratchet.py ... --write-baseline)")
        lines += [f"  - {k}" for k in gone]
    if new:
        lines.append(f"warn {name}: offenders not in the baseline list (count did not rise):")
        lines += [f"  + {k}" for k in new]
    return True, lines


def compare(b: Baseline, crap: list[str], dry: list[str]) -> tuple[bool, list[str]]:
    ok1, l1 = _one("crap_ge_10", b.crap_ge_10, b.known_crap, crap)
    ok2, l2 = _one("dryer_pairs", b.dryer_pairs, b.known_dryer, dry)
    return ok1 and ok2, l1 + l2


def read_baseline(path: Path) -> Baseline:
    d = tomllib.loads(path.read_text(encoding="utf-8"))
    return Baseline(
        d["crap_ge_10"],
        d["dryer_pairs"],
        list(d.get("known", {}).get("crap", [])),
        list(d.get("known", {}).get("dryer", [])),
        list(d.get("exceptions", {}).get("crap", [])),
    )


def _toml_list(items: list[str]) -> str:
    esc = [i.replace("\\", "\\\\").replace('"', '\\"') for i in items]
    return "[\n" + "".join(f'  "{i}",\n' for i in esc) + "]"


HEADER = """\
# ub-mode quality baseline (S-805). Gate: scripts/check.sh --ub fails when a count RISES.
# Lower the counts when offenders are fixed: tools/quality/ub.sh --write-baseline (see README.md).
# crap_ge_10: functions with CRAP >= 10 (crapper, tarpaulin LCOV), [exceptions] not counted.
# dryer_pairs: dryer --threshold 0.8 pairs (defaults --min-lines 4 --min-nodes 20).
"""


def write_baseline(path: Path, b: Baseline) -> None:
    path.write_text(
        HEADER
        + f"crap_ge_10 = {b.crap_ge_10}\ndryer_pairs = {b.dryer_pairs}\n\n"
        + "# Accepted exceptions (ub01 §6): Python lookup tables written as `match`; by\n"
        + "# crapper key `namespace::name`. Control-flow functions get no exemption.\n"
        + f"[exceptions]\ncrap = {_toml_list(b.exceptions)}\n\n"
        + "# Offenders at baseline time (names only; the counts above are the gate).\n"
        + f"[known]\ncrap = {_toml_list(b.known_crap)}\ndryer = {_toml_list(b.known_dryer)}\n",
        encoding="utf-8",
    )


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", type=Path, required=True)
    ap.add_argument("--crap", type=Path, required=True)
    ap.add_argument("--dry", type=Path, required=True)
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--write-baseline", action="store_true")
    a = ap.parse_args(argv)
    b = read_baseline(a.baseline)
    crap = crap_offenders(a.crap.read_text(encoding="utf-8"), CRAP_THRESHOLD, b.exceptions)
    dry = dryer_pairs(a.dry.read_text(encoding="utf-8"), a.root.resolve())
    if a.write_baseline:
        write_baseline(a.baseline, Baseline(len(crap), len(dry), crap, dry, b.exceptions))
        print(f"baseline written: crap_ge_10 = {len(crap)}, dryer_pairs = {len(dry)}")
        return 0
    ok, lines = compare(b, crap, dry)
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
