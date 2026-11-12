"""End-to-end synthetic replay using the same CLI as authenticated production reads."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts"
FIX = ROOT / "tests" / "fixtures" / "runtime"


def cli(*args):
    return subprocess.run([sys.executable, *map(str, args)], cwd=ROOT,
                          check=True, text=True, capture_output=True).stdout


class RuntimePipelineTests(unittest.TestCase):
    def test_aks_and_eks_pods_exact_runtime_join_and_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp)
            sources = [
                ("EKS", "eks", ["--account-id", "123456789012", "--region", "eu-north-1"]),
                ("AKS", "aks", ["--subscription-id", "11111111-1111-1111-1111-111111111111"]),
            ]
            for platform, name, options in sources:
                cli(SCRIPT / "runtime_workloads.py", "--platform", platform,
                    "--cluster", name + "-demo", *options,
                    "--input", FIX / (name + "-pods.json"),
                    "--output", dest / (name + ".json"))
            args = [SCRIPT / "runtime_assess.py", "--inspector", FIX / "inspector-normalized.json",
                    "--defender", FIX / "defender-observations.json"]
            cli(*args, "--cves-only", dest / "cves.json")
            self.assertEqual(json.loads((dest / "cves.json").read_text()),
                             ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"])
            cli(*args, "--inventory", *[dest / (name + ".json") for name in ("eks", "aks")],
                "--intel", FIX / "intelligence.json", "--vex-map", FIX / "vex-map.json",
                "--output", dest / "results.json", "--markdown", dest / "report.md")
            results = json.loads((dest / "results.json").read_text())
            self.assertEqual(results["inventory_modes"], ["OFFLINE"])
            self.assertEqual(results["runtime_workloads_observed"], 3)  # two EKS Pods and one AKS Pod
            self.assertEqual(results["counts"], {"EVALUATED": 2, "SUPPRESSED_BY_VEX": 1})
            self.assertEqual(results["excluded_uncorrelated_observations"], 2)
            self.assertEqual(results["excluded_by_reason"],
                             {"NO_EXACT_RUNTIME_MATCH": 1, "IMAGE_IDENTITY_INCOMPLETE": 1})
            rows = {r["observation_id"]: r for r in results["observations"]}
            self.assertEqual(rows["synthetic-inspector-1"]["final_outcome"], "3D")
            self.assertEqual(rows["synthetic-inspector-2"]["platform"], "EKS")
            self.assertEqual(rows["synthetic-inspector-2"]["decision_rule"], "KEV_GUARD")
            self.assertEqual(rows["synthetic-defender-container-1"]["decision_status"],
                             "SUPPRESSED_BY_VEX")
            self.assertNotIn("synthetic-inspector-stale", rows)
            self.assertNotIn("synthetic-defender-unknown-identity", rows)
            self.assertIn("Running container vulnerability assessment", (dest / "report.md").read_text())


if __name__ == "__main__":
    unittest.main()
