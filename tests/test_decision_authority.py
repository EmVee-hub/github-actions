"""Regression tests: BOD 26-04 must remain the decision authority.

EPSS percentiles influence only the configured post-BOD amplifier.
The removed 5%/10% probability shortcut must never silently override BOD.
"""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from test_evaluate import ev, BASE, AMP, MAPPING, ROOT


def synthetic_match(percentile=.01, probability=.001, *, exploited=False,
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
    cve = "CVE-2026-99993"
    return {
        "vulnerability": {
            "id": cve,
            "cvss": [{"vector": vector}],
            "epss": [{"cve": cve, "date": "2026-11-12",
                      "percentile": percentile, "epss": probability}],
            "knownExploited": [{"cve": cve}] if exploited else [],
        },
        "artifact": {"name": "demo-package", "version": "1.0"},
    }


class DecisionTableAuthorityTests(unittest.TestCase):
    def test_old_probability_policy_removed_and_quartile_policy_primary(self):
        self.assertNotIn("probability_policy", AMP)
        report = ev.evaluate({"matches": [synthetic_match()]}, "public",
                             "demo:sha", BASE, AMP, MAPPING)
        self.assertEqual(report["model"], "cisa:DT_BOD2604:1.0.0")
        self.assertEqual(report["amplifier"], AMP["id"])
        self.assertEqual(report["amplifier_table"], AMP["table"])
        self.assertEqual(report["admission_policy"], "LOCAL:BOD2604_EPSS_QUARTILE_CI:1.0.0")

    def test_non_kev_bod_3d_stays_blocked_even_below_five_percent(self):
        report = ev.evaluate({"matches": [synthetic_match()]},
                             "public", "demo:sha", BASE, AMP, MAPPING)
        item = report["findings"][0]
        self.assertEqual(item["kev"], "N")
        self.assertEqual(item["base_outcome"], "3D")
        self.assertEqual(item["final_outcome"], "3D")
        self.assertEqual(item["rule"], "URGENT_BASE_GUARD")
        self.assertEqual(report["admission"], "BLOCK")

    def test_kev_bod_14d_is_not_overridden_with_3d(self):
        report = ev.evaluate({"matches": [synthetic_match(.99, .9, exploited=True,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L")]},
            "internal", "demo:sha", BASE, AMP, MAPPING)
        item = report["findings"][0]
        self.assertEqual(item["base_outcome"], "14D")
        self.assertEqual(item["final_outcome"], "14D")
        self.assertEqual(item["rule"], "KEV_GUARD")
        self.assertEqual(report["admission"], "ALLOW")  # only 3D/3DF block

    def test_amplifier_is_driven_by_json_not_a_hardcoded_threshold(self):
        policy = copy.deepcopy(AMP)
        self.assertEqual(ev.apply_amp("60D", "N", .90, AMP)[0], "3D")
        policy["table"]["60D"]["Q4"] = "14D"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "bod-26-04.json").write_text(json.dumps(BASE))
            (root / "epss-amplifier.json").write_text(json.dumps(policy))
            loaded_base, loaded_amp, loaded_mapping = ev.load_policy(root)
            self.assertEqual(loaded_mapping, MAPPING)
            self.assertEqual(loaded_base["id"], BASE["id"])
            self.assertEqual(ev.apply_amp("60D", "N", .90, loaded_amp)[0], "14D")

    def test_cannot_create_new_3df_via_amplifier(self):
        policy = copy.deepcopy(AMP)
        policy["table"]["FSU"]["Q4"] = "3DF"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "bod-26-04.json").write_text(json.dumps(BASE))
            (root / "epss-amplifier.json").write_text(json.dumps(policy))
            with self.assertRaisesRegex(ValueError, "cannot create a forensic 3DF"):
                ev.load_policy(root)

    def test_report_shows_active_quartile_table(self):
        report = ev.evaluate({"matches": [synthetic_match()]},
                             "public", "demo:sha", BASE, AMP, MAPPING)
        md = ev.markdown_report(report)
        self.assertIn("Active BOD + EPSS quartile policy", md)
        self.assertIn("| 60D | FSU | 60D | 14D | 3D |", md)
        self.assertNotIn("POC_KEV_URGENT", md)
        self.assertNotIn("POC_EPSS_PROBABILITY", md)


if __name__ == "__main__":
    unittest.main()
