"""Regression coverage for obsolete policy columns in GitHub summaries."""
import unittest
from test_evaluate import ev, BASE, AMP, MAPPING


class ReportLayoutTests(unittest.TestCase):
    def test_current_policy_table_has_no_empty_legacy_columns(self):
        match = {"vulnerability": {"id": "CVE-2026-99993"},
                 "artifact": {"name": "demo", "version": "1"}}
        for matches in ([], [match]):
            with self.subTest(matches=bool(matches)):
                report = ev.evaluate({"matches": matches}, "unknown", "demo", BASE, AMP, MAPPING)
                markdown = ev.markdown_report(report)
                table = markdown.split("| CVE/advisory", 1)[1].split("## How to read", 1)[0]
                rows = [line for line in ("| CVE/advisory" + table).splitlines() if line.startswith("|")]
                self.assertTrue(all(len(row.split("|")) - 2 == 12 for row in rows))
                self.assertNotIn("Admission reason", markdown)
                self.assertNotIn("Defaulted inputs", markdown)
                self.assertNotIn("Provisional urgent findings", markdown)
                self.assertNotIn("POC_", markdown)
                self.assertIn("- Admission: **" + report["admission"], markdown)


if __name__ == "__main__":
    unittest.main()
