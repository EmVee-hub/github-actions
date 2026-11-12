"""Intelligence completeness and EPSS percentile interpretation."""
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import fetch_runtime_intel as intel


def kev():
    return {"catalogVersion": "test-version", "count": 1,
            "vulnerabilities": [{"cveID": "CVE-2021-44228"}]}

class IntelligenceTests(unittest.TestCase):
    def test_fetch_with_authoritative_kev_and_percentile(self):
        def getter(url):
            if url == intel.KEV_URL:
                return kev()
            return {"status": "OK", "total": 1,
                    "data": [{"cve": "CVE-2021-44228", "epss": "0.90",
                              "percentile": "0.99", "date": "2026-11-12"}]}
        data = intel.fetch_snapshot(["CVE-2021-44228"], getter,
                                    ssvc_getter=lambda _: {"status": "NO_SSVC"})
        self.assertTrue(data["kev"]["complete"])
        self.assertEqual(data["epss"]["CVE-2021-44228"]["percentile"], .99)
        self.assertEqual(data["epss"]["CVE-2021-44228"]["probability"], .9)

    def test_kev_count_mismatch_fails_closed(self):
        bad = kev()
        bad["count"] = 2
        with self.assertRaises(ValueError):
            intel.parse_kev(bad)

    def test_epss_failure_is_not_a_missing_score(self):
        def getter(url):
            if url == intel.KEV_URL:
                return kev()
            raise TimeoutError("no network")
        result = intel.fetch_snapshot(["CVE-2021-44228"], getter,
                                      ssvc_getter=lambda _: {"status": "NO_SSVC"})
        self.assertEqual(result["epss"]["CVE-2021-44228"]["status"], "FETCH_ERROR")

    def test_epss_no_record_uses_documented_missing_state(self):
        def getter(url):
            if url == intel.KEV_URL:
                return kev()
            return {"status": "OK", "total": 0, "data": []}
        data = intel.fetch_snapshot(["CVE-2021-44228"], getter,
                                    ssvc_getter=lambda _: {"status": "NO_SSVC"})
        self.assertEqual(data["epss"]["CVE-2021-44228"], {"status": "NOT_FOUND"})

    def test_invalid_epss_rejected(self):
        with self.assertRaises(ValueError):
            intel.parse_epss({"status": "OK", "total": 1,
                              "data": [{"cve": "CVE-2021-44228",
                                        "epss": "0.1", "percentile": "2"}]},
                             ["CVE-2021-44228"])

if __name__ == "__main__":
    unittest.main()
