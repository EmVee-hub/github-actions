"""Offline tests for CISA-ADP SSVC parsing and policy integration."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import evaluate as ev
import fetch_vulnrichment as fv

BASE, AMP, MAPPING = ev.load_policy(ROOT / "policy")
CVE = "CVE-2026-51669"


def record(auto="no", impact="total"):
    return {
        "cveMetadata": {"cveId": CVE, "state": "PUBLISHED"},
        "containers": {"adp": [
            {"providerMetadata": {"shortName": "CISA-ADP", "orgId": fv.CISA_ORG},
             "metrics": [{"other": {"type": "ssvc", "content": {
                 "id": CVE, "version": "2.0.3", "role": "CISA Coordinator",
                 "timestamp": "2026-09-01T12:43:52Z",
                 "options": [{"Exploitation": "none"},
                             {"Automatable": auto}, {"Technical Impact": impact}]
             }}}]}
        ]}
    }


def grype():
    return {"matches": [{"vulnerability": {"id": CVE, "cvss": []},
                         "artifact": {"name": "test-pkg"}}]}


class VulnrichmentTests(unittest.TestCase):
    def test_official_values_preferred_over_defaults(self):
        result = fv.parse_cisa_ssvc(record(), CVE)
        finding = ev.evaluate(grype(), "public", "test", BASE, AMP, MAPPING,
                              {"cves": {CVE: result}})["findings"][0]
        self.assertEqual(result["status"], "FOUND")
        self.assertEqual(finding["automatable"], "N")
        self.assertEqual(finding["technical_impact"], "T")
        self.assertEqual(finding["base_outcome"], "14D")
        self.assertEqual(finding["automatable_source"], "CISA_VULNRICHMENT_ADP")

    def test_no_assessment_uses_default(self):
        empty = record()
        empty["containers"]["adp"] = []
        self.assertEqual(fv.parse_cisa_ssvc(empty, CVE)["status"], "NO_SSVC")
        finding = ev.evaluate(grype(), "public", "test", BASE, AMP, MAPPING,
                              {"cves": {CVE: {"status": "NO_SSVC"}}})["findings"][0]
        self.assertEqual(finding["automatable"], "Y")
        self.assertEqual(finding["technical_impact_source"], "LOCAL_CONSERVATIVE_DEFAULT")

    def test_bad_provider_is_not_trusted(self):
        altered = record()
        altered["containers"]["adp"][0]["providerMetadata"]["orgId"] = "wrong"
        self.assertEqual(fv.parse_cisa_ssvc(altered, CVE)["status"], "NO_SSVC")

    def test_invalid_official_record_is_not_silent_default(self):
        with self.assertRaises(fv.InvalidSSVC):
            fv.parse_cisa_ssvc(record(auto="unknown"), CVE)

    def test_lookup_error_requires_review(self):
        decision = ev.evaluate(grype(), "public", "test", BASE, AMP, MAPPING,
                               {"cves": {CVE: {"status": "FETCH_ERROR"}}})
        self.assertEqual(decision["admission"], "REVIEW_REQUIRED")

    def test_deduplicated_cves(self):
        data = grype()
        data["matches"].append(data["matches"][0])
        seen = []
        result = fv.collect(data, getter=lambda cve: (seen.append(cve) or {"status": "NO_SSVC"}))
        self.assertEqual(seen, [CVE])
        self.assertEqual(result["counts"], {"NO_SSVC": 1})

    def test_404_vs_503(self):
        with patch.object(fv.urllib.request, "urlopen",
                          side_effect=HTTPError("url", 404, "missing", None, None)):
            self.assertEqual(fv.fetch_one(CVE, retries=0)["status"], "NO_RECORD")
        with patch.object(fv.urllib.request, "urlopen",
                          side_effect=HTTPError("url", 503, "unavailable", None, None)):
            self.assertEqual(fv.fetch_one(CVE, retries=0)["status"], "FETCH_ERROR")


    def test_markdown_decision_rule_column_and_vex_evidence(self):
        """Per-scan reports retain rule fields and VEX evidence without repeating the legend."""
        sample = json.loads((ROOT / "tests/fixtures/grype-sample.json").read_text())
        result = ev.evaluate(sample, "public", "demo", BASE, AMP, MAPPING)
        report = ev.markdown_report(result)
        self.assertNotIn("Decision rule legend", report)
        self.assertIn("## Scan results", report)
        self.assertIn("VEX-suppressed findings", report)
        self.assertIn("CVE-2024-00003", report)
        self.assertIn("Decision rule |", report)

    def test_report_without_vex_has_explicit_empty_message(self):
        report = ev.evaluate({"matches": []}, "internal", "demo", BASE, AMP, MAPPING)
        self.assertIn("No findings suppressed", ev.markdown_report(report))


if __name__ == "__main__":
    unittest.main()
