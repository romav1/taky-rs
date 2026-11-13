"""Tests for ratchet.py (run: python3 -I -B -m unittest discover -s tools/quality)."""

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


def baseline(crap, dry, known_crap=None, known_dry=(), exceptions=(), tol=0.5):
    return ratchet.Baseline(crap, dry, dict(known_crap or {}), list(known_dry), list(exceptions), tol)


class Parse(unittest.TestCase):
    def test_crap_offenders_at_or_above_threshold_minus_exceptions(self):
        got = ratchet.crap_offenders(CRAP_EDN, 10.0, ["taky_cot::models::Teams::as_str"])
        self.assertEqual(got, {"taky_cot::x::edge": 10.0, "taky_xml::parse::Tree::start": 57.1})

    def test_crap_report_without_entries_is_an_error(self):  # M-3
        for text in ["", "{:entries [\n]}\n", '{:entries [ {:namespace "a", :name "b"} ]}']:
            with self.assertRaises(ratchet.ReportError, msg=repr(text)):
                ratchet.crap_offenders(text, 10.0, [])

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

    def test_dryer_empty_report_is_zero_pairs(self):
        self.assertEqual(ratchet.dryer_pairs("{:candidates [\n]}\n", Path(".")), [])

    def test_dryer_unparsable_report_is_an_error(self):  # M-3
        for text in ["", "garbage", '{:candidates [ {:left {:file "a", :start-line 1} } ]}']:
            with self.assertRaises(ratchet.ReportError, msg=repr(text)):
                ratchet.dryer_pairs(text, Path("."))

    def test_missing_report_file_fails_the_gate(self):  # M-3
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            ratchet.write_baseline(p / "b.toml", baseline(0, 0))
            (p / "crap.edn").write_text(CRAP_EDN)
            args = ["--baseline", str(p / "b.toml"), "--crap", str(p / "crap.edn"),
                    "--dry", str(p / "missing.edn"), "--root", d]
            self.assertEqual(ratchet.main(args), 2)


class Compare(unittest.TestCase):
    def test_equal_passes(self):
        ok, lines = ratchet.compare(baseline(1, 1, {"f": 12.0}, ["p"]), {"f": 12.0}, ["p"])
        self.assertTrue(ok, lines)

    def test_rise_fails_and_names_the_new_offender(self):
        ok, lines = ratchet.compare(baseline(1, 1, {"f": 12.0}, ["p"]), {"f": 12.0}, ["p", "q"])
        self.assertFalse(ok)
        text = "\n".join(lines)
        self.assertIn("FAIL dryer_pairs 2 > baseline 1", text)
        self.assertIn("+ q", text)

    def test_crap_rise_fails(self):
        ok, lines = ratchet.compare(baseline(1, 0, {"f": 12.0}), {"f": 12.0, "g": 11.0}, [])
        self.assertFalse(ok)
        self.assertIn("+ g", "\n".join(lines))

    def test_swap_with_same_count_fails(self):  # M-2
        ok, lines = ratchet.compare(baseline(1, 1, {"f": 12.0}, ["p"]), {"g": 11.0}, ["q"])
        self.assertFalse(ok)
        text = "\n".join(lines)
        self.assertIn("FAIL crap_ge_10: new offender", text)
        self.assertIn("+ g (11.0)", text)
        self.assertIn("FAIL dryer_pairs: new offender", text)
        self.assertIn("+ q", text)

    def test_known_offender_whose_score_rose_fails(self):  # M-2
        ok, lines = ratchet.compare(baseline(1, 0, {"f": 12.0}), {"f": 12.6}, [])
        self.assertFalse(ok)
        self.assertIn("^ f 12.0 -> 12.6", "\n".join(lines))

    def test_score_noise_within_tolerance_passes(self):
        ok, lines = ratchet.compare(baseline(1, 0, {"f": 12.0}), {"f": 12.4}, [])
        self.assertTrue(ok, lines)

    def test_decrease_passes_with_hint(self):
        ok, lines = ratchet.compare(baseline(2, 0, {"f": 12.0, "g": 11.0}), {"f": 12.0}, [])
        self.assertTrue(ok)
        text = "\n".join(lines)
        self.assertIn("crap_ge_10 1 < baseline 2", text)
        self.assertIn("--write-baseline", text)

    def test_duplicate_dryer_pairs_count_as_multiset(self):
        ok, lines = ratchet.compare(baseline(0, 1, {}, ["p"]), {}, ["p", "p"])
        self.assertFalse(ok)


class BaselineFile(unittest.TestCase):
    def test_round_trip_keeps_exceptions_and_scores(self):
        b = baseline(2, 1, {"a::b": 12.5, 'x"q': 10.0}, ['x "q" <-> y'], ["m::T::as_str"], 0.25)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "baseline.toml"
            ratchet.write_baseline(p, b)
            self.assertEqual(ratchet.read_baseline(p), b)


if __name__ == "__main__":
    unittest.main()
