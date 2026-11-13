"""Tests for ratchet.py (run: python3 -I -m unittest discover -s tools/quality)."""

import tempfile
import unittest
from pathlib import Path

import ratchet

CRAP_EDN = """{:entries [
  {:name "start", :namespace "taky_xml::parse::Tree", :complexity 57, :coverage 97.0, :crap 57.1}
  {:name "as_str", :namespace "taky_cot::models::Teams", :complexity 15, :coverage 100.0, :crap 15.0}
  {:name "small", :namespace "taky_cot::x", :complexity 3, :coverage 100.0, :crap 3.0}
  {:name "edge", :namespace "taky_cot::x", :complexity 10, :coverage 100.0, :crap 10.0}
  {:name "na", :namespace "taky_cot::x", :complexity 12, :coverage nil, :crap nil}
]}
"""

DRY_EDN = """{:candidates [
 {:score 1.0
  :language "rust"
  :left {:file "crates/a/src/x.rs", :start-line 2, :end-line 4}
  :right {:file "crates/b/src/y.rs", :start-line 1, :end-line 3}
  :left-nodes 71
  :right-nodes 71}
]}
"""


def baseline(crap, dry, known_crap=(), known_dry=(), exceptions=()):
    return ratchet.Baseline(crap, dry, list(known_crap), list(known_dry), list(exceptions))


class Parse(unittest.TestCase):
    def test_crap_offenders_at_or_above_threshold_minus_exceptions(self):
        got = ratchet.crap_offenders(CRAP_EDN, 10.0, ["taky_cot::models::Teams::as_str"])
        self.assertEqual(got, ["taky_cot::x::edge", "taky_xml::parse::Tree::start"])

    def test_dryer_pairs_named_by_enclosing_fn(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for rel, body in [
                ("crates/a/src/x.rs", "// c\npub fn alpha(v: u8) -> u8 {\n    v\n}\n"),
                ("crates/b/src/y.rs", "fn beta(v: u8) -> u8 {\n    v\n}\n"),
            ]:
                (root / rel).parent.mkdir(parents=True)
                (root / rel).write_text(body)
            got = ratchet.dryer_pairs(DRY_EDN, root)
        self.assertEqual(got, ["crates/a/src/x.rs::alpha <-> crates/b/src/y.rs::beta"])


class Compare(unittest.TestCase):
    def test_equal_passes(self):
        ok, lines = ratchet.compare(baseline(1, 1, ["f"], ["p"]), ["f"], ["p"])
        self.assertTrue(ok, lines)

    def test_rise_fails_and_names_the_new_offender(self):
        ok, lines = ratchet.compare(baseline(1, 1, ["f"], ["p"]), ["f"], ["p", "q"])
        self.assertFalse(ok)
        text = "\n".join(lines)
        self.assertIn("FAIL dryer_pairs 2 > baseline 1", text)
        self.assertIn("+ q", text)

    def test_crap_rise_fails(self):
        ok, lines = ratchet.compare(baseline(1, 0, ["f"]), ["f", "g"], [])
        self.assertFalse(ok)
        self.assertIn("+ g", "\n".join(lines))

    def test_decrease_passes_with_hint(self):
        ok, lines = ratchet.compare(baseline(2, 0, ["f", "g"]), ["f"], [])
        self.assertTrue(ok)
        text = "\n".join(lines)
        self.assertIn("crap_ge_10 1 < baseline 2", text)
        self.assertIn("--write-baseline", text)

    def test_duplicate_keys_count_as_multiset(self):
        ok, lines = ratchet.compare(baseline(1, 0, ["f"]), ["f", "f"], [])
        self.assertFalse(ok)


class BaselineFile(unittest.TestCase):
    def test_round_trip_keeps_exceptions(self):
        b = baseline(2, 1, ["a", "b"], ['x "q" <-> y'], ["m::T::as_str"])
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "baseline.toml"
            ratchet.write_baseline(p, b)
            self.assertEqual(ratchet.read_baseline(p), b)


if __name__ == "__main__":
    unittest.main()
