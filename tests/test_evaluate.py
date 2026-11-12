import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("evaluator", ROOT / "scripts" / "evaluate.py")
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)
BASE, AMP, MAPPING = ev.load_policy(ROOT / "policy")


class PolicyTests(unittest.TestCase):
    def test_all_16_base_combinations(self):
        self.assertEqual(len(MAPPING), 16)
        # Independent expected rows, not derived from the policy file being tested.
        expected = {
            ("N", "N", "N", "P"): "FSU", ("N", "N", "N", "T"): "FSU",
            ("N", "Y", "N", "P"): "60D", ("N", "N", "Y", "P"): "60D",
            ("N", "N", "Y", "T"): "60D", ("N", "Y", "Y", "P"): "14D",
            ("N", "Y", "N", "T"): "14D", ("N", "Y", "Y", "T"): "3D",
            ("Y", "N", "N", "P"): "14D", ("Y", "Y", "N", "P"): "14D",
            ("Y", "N", "Y", "P"): "14D", ("Y", "N", "N", "T"): "14D",
            ("Y", "Y", "Y", "P"): "3D", ("Y", "Y", "N", "T"): "3DF",
            ("Y", "N", "Y", "T"): "3DF", ("Y", "Y", "Y", "T"): "3DF",
        }
        self.assertEqual(MAPPING, expected)

    def test_all_20_amplifier_cells(self):
        expected = {
            "FSU": ["FSU", "FSU", "60D", "14D"],
            "60D": ["FSU", "60D", "14D", "3D"],
            "14D": ["60D", "14D", "3D", "3D"],
            "3D": ["3D", "3D", "3D", "3D"],
            "3DF": ["3DF", "3DF", "3DF", "3DF"],
        }
        for base, finals in expected.items():
            self.assertEqual([AMP["table"][base][q] for q in ("Q1", "Q2", "Q3", "Q4")], finals)

    def test_quartile_boundaries(self):
        for percentile, bin_name in [(0, "Q1"), (.2499, "Q1"), (.25, "Q2"),
                                     (.499, "Q2"), (.5, "Q3"), (.749, "Q3"),
                                     (.75, "Q4"), (1.0, "Q4"), (None, "Q2")]:
            self.assertEqual(ev.epss_bin(percentile), bin_name)
        with self.assertRaises(ValueError):
            ev.epss_bin(1.5)

    def test_kev_and_urgent_guards(self):
        for base in BASE["outcome_order"]:
            for percentile in [0.1, 0.3, 0.6, 0.95, None]:
                self.assertEqual(ev.apply_amp(base, "Y", percentile, AMP)[0], base)
        for base in ("3D", "3DF"):
            for percentile in [0.01, 0.99, None]:
                self.assertEqual(ev.apply_amp(base, "N", percentile, AMP)[0], base)

    def test_fixture_and_vex_exclusion(self):
        data = json.loads((ROOT / "tests/fixtures/grype-sample.json").read_text())
        report = ev.evaluate(data, "public", "demo:sha", BASE, AMP, MAPPING)
        self.assertEqual(report["admission"], "BLOCK")
        self.assertEqual(report["vex_ignored_count"], 1)
        self.assertEqual(len(report["findings"]), 2)
        self.assertEqual(report["findings"][0]["base_outcome"], "14D")
        self.assertEqual(report["findings"][0]["final_outcome"], "3D")
        self.assertEqual(report["findings"][1]["final_outcome"], "3DF")

    def test_internal_and_missing_epss(self):
        data = {"matches": [{"vulnerability": {"id": "CVE-2025-99999", "cvss": []},
                             "artifact": {"name": "pkg", "version": "v"}}]}
        report = ev.evaluate(data, "internal", "demo", BASE, AMP, MAPPING)
        self.assertEqual(report["admission"], "ALLOW")
        self.assertEqual(report["findings"][0]["base_outcome"], "60D")
        self.assertEqual(report["findings"][0]["epss_bin"], "Q2")
        self.assertEqual(report["findings"][0]["rule"], "EPSS_UNAVAILABLE_NEUTRAL")

    def test_unmapped_ghsa_requires_review(self):
        data = {"matches": [{"vulnerability": {"id": "GHSA-aaaa-bbbb-cccc"},
                             "artifact": {"name": "pkg"}}]}
        result = ev.evaluate(data, "public", "test", BASE, AMP, MAPPING)
        self.assertEqual(result["admission"], "REVIEW_REQUIRED")
        self.assertEqual(result["findings"][0]["status"], "INCOMPLETE")

    def test_bad_report_fails_closed(self):
        with self.assertRaises(ValueError):
            ev.evaluate({}, "unknown", "test", BASE, AMP, MAPPING)


if __name__ == "__main__":
    unittest.main()
