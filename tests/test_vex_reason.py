import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ev", ROOT / "scripts/evaluate.py")
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)

class ReasonTests(unittest.TestCase):
    def setUp(self):
        self.match = {"vulnerability": {"id": "CVE-2021-44228"},
                      "relatedVulnerabilities": [{"id": "GHSA-example"}],
                      "artifact": {"name": "log4j-core", "purl": "pkg:maven/log4j-core@2.14.1"},
                      "appliedIgnoreRules": [{"namespace": "vex"}]}
        self.statement = {"vulnerability": {"name": "GHSA-example"},
                          "status": "not_affected",
                          "products": [{"@id": "demo:123", "subcomponents": [{"@id": "pkg:maven/log4j-core@2.14.1"}]}],
                          "impact_statement": "Not in use by application - Showcase"}
        self.vex = {"statements": [self.statement]}

    def test_reason_in_json_and_markdown_without_gate_change(self):
        base, amp, mapping = ev.load_policy(ROOT / "policy")
        data = {"matches": [], "ignoredMatches": [self.match]}
        before = ev.evaluate(data, "public", "demo:123", base, amp, mapping)
        after = ev.evaluate(data, "public", "demo:123", base, amp, mapping, vex=self.vex)
        self.assertEqual(before["admission"], after["admission"])
        self.assertEqual(after["ignored_matches"][0]["reason"], self.statement["impact_statement"])
        self.assertIn("| Ignore evidence | Reason |", ev.markdown_report(after))
        self.assertIn("| vex | Not in use by application - Showcase |", ev.markdown_report(after))

    def test_wrong_image_or_component_does_not_borrow_reason(self):
        self.assertEqual(ev.suppression_reason(self.match, self.vex, "other:123"), "Not provided")
        self.match["artifact"]["purl"] += "-different"
        self.assertEqual(ev.suppression_reason(self.match, self.vex, "demo:123"), "Not provided")

    def test_missing_reason_and_non_vex_ignore(self):
        self.assertEqual(ev.suppression_reason(self.match, None, "demo:123"), "Not provided")
        self.match["appliedIgnoreRules"] = [{"namespace": "manual"}]
        self.assertEqual(ev.suppression_reason(self.match, self.vex, "demo:123"), "Not provided")

    def test_ambiguous_reason_is_explicit(self):
        other = copy.deepcopy(self.statement)
        other["impact_statement"] = "Different assessment"
        self.vex["statements"].append(other)
        self.assertIn("Multiple", ev.suppression_reason(self.match, self.vex, "demo:123"))

    def test_package_scoped_cae_live_reason_displays_both_fields(self):
        purl = "pkg:apk/alpine/libxslt@1.1.43-r3?arch=x86_64&distro=alpine-3.24.4"
        self.match["artifact"]["purl"] = purl
        self.statement["products"] = [{"@id": purl}]
        self.statement["justification"] = "vulnerable_code_not_in_execute_path"
        base, amp, mapping = ev.load_policy(ROOT / "policy")
        data = {"matches": [], "ignoredMatches": [self.match]}
        before = ev.evaluate(data, "public", "cae-live:ci-123", base, amp, mapping)
        after = ev.evaluate(data, "public", "cae-live:ci-123", base, amp, mapping, vex=self.vex)
        self.assertEqual(before["admission"], after["admission"])
        self.assertEqual(before["vex_ignored_count"], after["vex_ignored_count"])
        for text in (self.statement["justification"], self.statement["impact_statement"]):
            self.assertIn(text, after["ignored_matches"][0]["reason"])
            self.assertIn(text, ev.markdown_report(after))
        self.match["artifact"]["purl"] = purl.replace("1.1.43-r3", "1.1.43-r4")
        self.assertEqual(ev.suppression_reason(self.match, self.vex, "cae-live:ci-123"), "Not provided")

    def test_package_reason_requires_matching_vulnerability_and_vex_ignore(self):
        self.statement["products"] = [{"@id": self.match["artifact"]["purl"]}]
        self.match["appliedIgnoreRules"] = [{"namespace": "manual"}]
        self.assertEqual(ev.suppression_reason(self.match, self.vex, "cae-live:ci-123"), "Not provided")
        self.match["appliedIgnoreRules"] = [{"namespace": "vex"}]
        self.statement["vulnerability"] = {"name": "CVE-2099-9999"}
        self.assertEqual(ev.suppression_reason(self.match, self.vex, "cae-live:ci-123"), "Not provided")

    def test_markdown_escapes_reason(self):
        self.statement["impact_statement"] = "example | reason\nnext line"
        base, amp, mapping = ev.load_policy(ROOT / "policy")
        report = ev.evaluate({"matches": [], "ignoredMatches": [self.match]}, "public", "demo:123", base, amp, mapping, vex=self.vex)
        self.assertIn("example \\| reason next line", ev.markdown_report(report))

if __name__ == "__main__":
    unittest.main()

