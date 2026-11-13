#!/usr/bin/env python3
"""ub-mode ratchet (S-805): compare crapper / dryer results with tools/quality/baseline.toml.

  ratchet.py check  --baseline B --crap CRAP.edn --dry DRY.edn --root R  -> exit 1 if a count rises
  ratchet.py check  ... --write-baseline                                -> rewrite B (keeps [exceptions])

Fails (exit 1) when: a count rises; an offender appears that is not in `[known]` (even if the
count stays the same, S-807 M-2); a known CRAP offender's score rises by more than
`score_tolerance`. Exit 2 when a report is missing, empty or unparsable (M-3). Decreases pass
with a hint. Keys: crapper `namespace::name`; dryer `file::fn <-> file::fn` (fn enclosing the
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


class ReportError(Exception):
    """A crapper/dryer report is missing, empty or not in the expected shape."""


@dataclass
class Baseline:
    crap_ge_10: int
    dryer_pairs: int
    known_crap: dict[str, float]
    known_dryer: list[str]
    exceptions: list[str]
    score_tolerance: float = 0.5


def crap_offenders(text: str, threshold: float, exceptions: list[str]) -> dict[str, float]:
    """`namespace::name` -> CRAP of functions with CRAP >= threshold, exceptions removed.
    A report with no parsable entry is an error, never "0 offenders"."""
    entries = _CRAP_ENTRY.findall(text)
    if not entries:
        raise ReportError("crapper report has no parsable entries")
    out: dict[str, float] = {}
    for name, ns, crap in entries:
        key = f"{ns}::{name}"
        if crap != "nil" and float(crap) >= threshold and key not in exceptions:
            out[key] = max(float(crap), out.get(key, 0.0))
    return dict(sorted(out.items()))


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
    if not text.lstrip().startswith("{:candidates ["):
        raise ReportError("dryer report: no ':candidates [' header")
    sides = _DRY_SIDE.findall(text)
    if len(sides) % 2 or text.count(":score ") != len(sides) // 2:
        raise ReportError(f"dryer report: {text.count(':score ')} candidates, {len(sides)} sides")
    out = []
    for (_, lf, ll), (_, rf, rl) in zip(sides[0::2], sides[1::2]):
        lf, rf = _rel(lf, root), _rel(rf, root)
        out.append(f"{lf}::{_fn_at(root, lf, int(ll))} <-> {rf}::{_fn_at(root, rf, int(rl))}")
    return sorted(out)


def _counted(name: str, base: int, n: int, gone: list[str]) -> tuple[bool, list[str]]:
    if n > base:
        return False, [f"FAIL {name} {n} > baseline {base}"]
    lines = [f"ok   {name} {n} (baseline {base})"]
    if n < base:
        lines.append(f"note {name} {n} < baseline {base}: lower it (check.sh --ub --write-baseline)")
        lines += [f"  - {k}" for k in gone]
    return True, lines


def _new(name: str, new: list[str]) -> list[str]:
    return [f"FAIL {name}: new offender(s) not in [known]:", *[f"  + {k}" for k in new]] if new else []


def compare(b: Baseline, crap: dict[str, float], dry: list[str]) -> tuple[bool, list[str]]:
    lines: list[str] = []
    new_c = [f"{k} ({v})" for k, v in crap.items() if k not in b.known_crap]
    rose = [f"  ^ {k} {b.known_crap[k]} -> {v}" for k, v in crap.items()
            if k in b.known_crap and v > b.known_crap[k] + b.score_tolerance]
    ok1, l1 = _counted("crap_ge_10", b.crap_ge_10, len(crap), sorted(set(b.known_crap) - set(crap)))
    lines += l1 + _new("crap_ge_10", new_c)
    if rose:
        lines += [f"FAIL crap_ge_10: known offender(s) scored higher (> +{b.score_tolerance}):", *rose]
    new_d = sorted((Counter(dry) - Counter(b.known_dryer)).elements())
    gone_d = sorted((Counter(b.known_dryer) - Counter(dry)).elements())
    ok2, l2 = _counted("dryer_pairs", b.dryer_pairs, len(dry), gone_d)
    lines += l2 + _new("dryer_pairs", new_d)
    return ok1 and ok2 and not new_c and not rose and not new_d, lines


def read_baseline(path: Path) -> Baseline:
    d = tomllib.loads(path.read_text(encoding="utf-8"))
    known = d.get("known", {})
    return Baseline(
        d["crap_ge_10"],
        d["dryer_pairs"],
        {k: float(v) for k, v in known.get("crap", {}).items()},
        list(known.get("dryer", [])),
        list(d.get("exceptions", {}).get("crap", [])),
        float(d.get("score_tolerance", 0.5)),
    )


def _q(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _toml_list(items: list[str]) -> str:
    return "[\n" + "".join(f"  {_q(i)},\n" for i in items) + "]"


HEADER = """\
# ub-mode quality baseline (S-805). Gate: scripts/check.sh --ub fails when a count RISES.
# Lower the counts when offenders are fixed: tools/quality/ub.sh --write-baseline (see README.md).
# crap_ge_10: functions with CRAP >= 10 (crapper, tarpaulin LCOV), [exceptions] not counted.
# dryer_pairs: dryer --threshold 0.8 pairs (defaults --min-lines 4 --min-nodes 20).
# Also failing: an offender not in [known]; a [known.crap] score rising by > score_tolerance
# (absorbs ptrace coverage noise).
"""


def write_baseline(path: Path, b: Baseline) -> None:
    path.write_text(
        HEADER
        + f"crap_ge_10 = {b.crap_ge_10}\ndryer_pairs = {b.dryer_pairs}\n"
        + f"score_tolerance = {b.score_tolerance}\n\n"
        + "# Accepted exceptions (ub01 §6): Python lookup tables written as `match`; by\n"
        + "# crapper key `namespace::name`. Control-flow functions get no exemption.\n"
        + f"[exceptions]\ncrap = {_toml_list(b.exceptions)}\n\n"
        + "# Offenders at baseline time: CRAP key = score; dryer pair keys.\n"
        + f"[known]\ndryer = {_toml_list(b.known_dryer)}\n\n[known.crap]\n"
        + "".join(f"{_q(k)} = {v}\n" for k, v in b.known_crap.items()),
        encoding="utf-8",
    )


def _report(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as e:
        raise ReportError(f"{path}: {e.strerror}") from e


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", type=Path, required=True)
    ap.add_argument("--crap", type=Path, required=True)
    ap.add_argument("--dry", type=Path, required=True)
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--write-baseline", action="store_true")
    a = ap.parse_args(argv)
    b = read_baseline(a.baseline)
    try:
        crap = crap_offenders(_report(a.crap), CRAP_THRESHOLD, b.exceptions)
        dry = dryer_pairs(_report(a.dry), a.root.resolve())
    except ReportError as e:
        print(f"FAIL report: {e}")
        return 2
    if a.write_baseline:
        nb = Baseline(len(crap), len(dry), crap, dry, b.exceptions, b.score_tolerance)
        write_baseline(a.baseline, nb)
        print(f"baseline written: crap_ge_10 = {len(crap)}, dryer_pairs = {len(dry)}")
        return 0
    ok, lines = compare(b, crap, dry)
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
