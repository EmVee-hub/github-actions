"""End-to-end, fail-closed runtime correlation and BOD/EPSS policy tests."""
import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import runtime_workloads as inv
import runtime_assess as policy

D = "sha256:" + "a" * 64
D2 = "sha256:" + "b" * 64
ACCT = "123456789012"
REGION = "eu-north-1"
REG = ACCT + ".dkr.ecr." + REGION + ".amazonaws.com"
PROJECT = "payments"
CVE = "CVE-2026-10001"


def workload(platform="EKS", digest=D, repo="payments/api", project=PROJECT):
    return {
        "platform": platform, "cluster": "demo-cluster", "account_id": ACCT if platform != "AKS" else None,
        "subscription_id": "sub-a" if platform == "AKS" else None,
        "region": REGION if platform != "AKS" else None,
        "namespace": "prod", "workload": "payments-api", "container": "app",
        "workload_uid": "p1", "image_digest": digest, "registry": REG if platform != "AKS" else "demo.azurecr.io",
        "repository": repo, "project": project, "prod_critical": True, "exposure": "public",
        "state": "RUNNING",
    }


def inspector(cve=CVE, digest=D, repo="payments/api", status="ACTIVE", purl="pkg:maven/com.example/payments@1.0"):
    return {"findings": [{
        "observation_id": "f1", "finding_arn": "arn:test",
        "asset": {"type": "AWS_ECR_CONTAINER_IMAGE", "image_digest": digest,
                  "repository": repo, "registry": ACCT},
        "account_id": ACCT, "region": REGION, "vulnerability_id": cve,
        "provider_status": status, "severity": "HIGH",
        "runtime": {"in_use_count": 0}, # important: count=0 must not override a real digest join
        "package": {"name": "payments", "version": "1.0", "purl": purl},
        "cvss": [{"scoringVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"}],
    }]}


def defender(digest=D):
    return [{
        "assessment_id": "azure-assessment-1", "vulnerability_id": CVE,
        "provider_status": "Unhealthy", "severity": "High", "subscription_id": "sub-a",
        "resource_details": {"imageDigest": digest, "registry": "demo.azurecr.io",
                             "repository": "payments/api", "ResourceType": "container-image"},
        "image_digest": None, "package_purl": "pkg:maven/com.example/payments@1.0",
        "package_name": "payments", "package_version": "1.0",
    }]


def intelligence(kev=None, pct=.99, cisa_status="FOUND"):
    return {
        "complete": True, "fetched_at": "2026-11-12T00:00:00Z",
        "kev": {"complete": True, "cves": kev if kev is not None else []},
        "epss": {CVE: {"status": "FOUND", "percentile": pct,
                      "probability": .20}},
        "cisa": {CVE: {"status": cisa_status, "automatable": "N",
                      "technical_impact": "P"}},
    }


def vex_doc(digest=D, purl="pkg:maven/com.example/payments@1.0", status="not_affected"):
    return {"statements": [{
        "vulnerability": {"name": CVE},
        "products": [{"@id": "urn:container:" + digest,
                      "subcomponents": [{"@id": purl}]}],
        "status": status, "justification": "vulnerable_code_not_in_execute_path",
        "impact_statement": "Verified by project owner for this exact image/component",
    }]}


def inventory(*workloads):
    return {"collection_complete": True, "mode": "OFFLINE", "workloads": list(workloads),
            "unresolved": []}


def run(inspector_data=None, defender_data=None, inventories=None, intelligence_data=None, vex=None):
    return policy.assess(
        inspector_data, defender_data,
        inventories if inventories is not None else [inventory(workload())],
        intelligence_data if intelligence_data is not None else intelligence(),
        vex if vex is not None else {PROJECT: {"statements": []}}, ROOT / "policy")


class RuntimePolicyTests(unittest.TestCase):
    def test_eks_inspector_exact_running_image_bod_epss_amplifier(self):
        r = run(inspector())
        row = r["observations"][0]
        self.assertEqual(row["correlation_status"], "CONFIRMED_RUNNING")
        self.assertEqual(row["platform"], "EKS")
        self.assertEqual(row["base_outcome"], "60D")
        self.assertEqual(row["final_outcome"], "3D")
        self.assertEqual(row["decision_rule"], "AMPLIFIED")
        self.assertEqual(row["decision_status"], "EVALUATED")
        self.assertEqual(row["epss_percentile"], .99)
        self.assertEqual(row["publicly_exposed"], "Y")
        # Inspector zero 'in use' is not a confirmed runtime negative.
        self.assertEqual(r["runtime_workloads_observed"], 1)

    def test_reject_non_pod_inventory_platform(self):
        invalid = workload("UNSUPPORTED")
        with self.assertRaisesRegex(ValueError, "AKS/EKS Pod"):
            run(inspector(), inventories=[inventory(invalid)])

    def test_defender_aks_with_verified_digest_identity(self):
        row = run(defender_data=defender(), inventories=[inventory(workload("AKS"))])["observations"][0]
        self.assertEqual(row["source"], "AZURE_DEFENDER")
        self.assertEqual(row["correlation_status"], "CONFIRMED_RUNNING")
        self.assertEqual(row["final_outcome"], "3D")

    def test_defender_vm_finding_never_attaches_to_image(self):
        azure = defender()
        azure[0]["resource_details"]["ResourceType"] = "microsoft.compute/virtualmachines"
        result = run(defender_data=azure, inventories=[inventory(workload("AKS"))])
        self.assertEqual(result["observations"], [])
        self.assertEqual(result["excluded_uncorrelated_observations"], 0)

    def test_defender_aws_origin_cannot_attach_to_aks(self):
        azure = defender()
        azure[0]["resource_details"]["ResourceType"] = "K8s-container"
        azure[0]["resource_details"]["Source"] = "AWS"
        result = run(defender_data=azure, inventories=[inventory(workload("AKS"))])
        self.assertEqual(result["excluded_by_reason"]["PROVIDER_SCOPE_MISMATCH"], 1)
    def test_defender_missing_digest_remains_unresolved(self):
        x = defender()
        x[0]["resource_details"].pop("imageDigest")
        result = run(defender_data=x, inventories=[inventory(workload("AKS"))])
        self.assertEqual(result["observations"], [])
        self.assertEqual(result["excluded_by_reason"]["IMAGE_IDENTITY_INCOMPLETE"], 1)

    def test_other_digest_not_running(self):
        result = run(inspector(digest=D2))
        self.assertEqual(result["observations"], [])
        self.assertEqual(result["excluded_by_reason"]["NO_EXACT_RUNTIME_MATCH"], 1)

    def test_other_repo_not_running(self):
        result = run(inspector(repo="other/api"))
        self.assertEqual(result["observations"], [])
        self.assertEqual(result["excluded_by_reason"]["NO_EXACT_RUNTIME_MATCH"], 1)

    def test_account_region_mismatch(self):
        wrong = workload()
        wrong["account_id"] = "999999999999"
        result = run(inspector(), inventories=[inventory(wrong)])
        self.assertEqual(result["observations"], [])
        self.assertEqual(result["excluded_by_reason"]["NO_EXACT_RUNTIME_MATCH"], 1)
        wrong["account_id"] = ACCT
        wrong["region"] = "us-east-1"
        self.assertEqual(run(inspector(), inventories=[inventory(wrong)])["excluded_by_reason"]
                         ["NO_EXACT_RUNTIME_MATCH"], 1)

    def test_two_running_workloads_receive_separate_observations(self):
        second = workload()
        second["workload"] = "payments-replica"
        second["workload_uid"] = "p2"
        result = run(inspector(), inventories=[inventory(workload(), second)])
        self.assertEqual(len(result["observations"]), 2)
        self.assertEqual(result["counts"], {"EVALUATED": 2})

    def test_kev_guard_same_as_ci_evaluator(self):
        result = run(inspector(), intelligence_data=intelligence(kev=[CVE]))
        row = result["observations"][0]
        self.assertEqual(row["decision_rule"], "KEV_GUARD")
        self.assertEqual(row["base_outcome"], "14D")
        self.assertEqual(row["final_outcome"], "14D")

    def test_epss_absence_uses_neutral_q2(self):
        intel = intelligence()
        intel["epss"][CVE] = {"status": "NOT_FOUND"}
        row = run(inspector(), intelligence_data=intel)["observations"][0]
        self.assertEqual(row["epss_bin"], "Q2")
        self.assertEqual(row["final_outcome"], "60D")
        self.assertEqual(row["decision_rule"], "EPSS_UNAVAILABLE_NEUTRAL")

    def test_network_failure_requires_review(self):
        intel = intelligence()
        intel["epss"][CVE] = {"status": "FETCH_ERROR"}
        row = run(inspector(), intelligence_data=intel)["observations"][0]
        self.assertEqual(row["decision_status"], "REVIEW_REQUIRED")
        self.assertIn("INTELLIGENCE_LOOKUP_FAILED", row["reasons"])

    def test_missing_kev_catalog_requires_review(self):
        intel = intelligence()
        intel["kev"]["complete"] = False
        row = run(inspector(), intelligence_data=intel)["observations"][0]
        self.assertIn("AUTHORITATIVE_KEV_UNAVAILABLE", row["reasons"])

    def test_vex_exact_match_suppressed(self):
        row = run(inspector(), vex={PROJECT: vex_doc()})["observations"][0]
        self.assertEqual(row["vex_status"], "SUPPRESSED")
        self.assertEqual(row["decision_status"], "SUPPRESSED_BY_VEX")

    def test_wrong_vex_digest_stays_active(self):
        row = run(inspector(), vex={PROJECT: vex_doc(digest=D2)})["observations"][0]
        self.assertEqual(row["vex_status"], "ACTIVE")
        self.assertEqual(row["decision_status"], "EVALUATED")

    def test_no_purl_cannot_suppress_or_finalize(self):
        row = run(inspector(purl=None), vex={PROJECT: vex_doc()})["observations"][0]
        self.assertEqual(row["decision_status"], "REVIEW_REQUIRED")
        self.assertIn("PACKAGE_PURL_UNKNOWN", row["reasons"])
        self.assertEqual(row["final_outcome"], "3D")  # preliminary priority retained

    def test_unknown_project_needs_review(self):
        row = run(inspector(), inventories=[inventory(workload(project=None))])["observations"][0]
        self.assertIn("PROJECT_IDENTITY_UNKNOWN", row["reasons"])

    def test_unknown_criticality_needs_review(self):
        w = workload()
        w["prod_critical"] = None
        row = run(inspector(), inventories=[inventory(w)])["observations"][0]
        self.assertIn("PROD_CRITICAL_CLASSIFICATION_UNKNOWN", row["reasons"])

    def test_unknown_exposure_conservatively_public(self):
        w = workload()
        w["exposure"] = "unknown"
        row = run(inspector(), inventories=[inventory(w)])["observations"][0]
        self.assertEqual(row["publicly_exposed"], "Y")
        self.assertEqual(row["exposure_source"], "UNKNOWN_DEFAULT_PUBLIC")

    def test_provider_suppressed_is_not_project_vex(self):
        row = run(inspector(status="SUPPRESSED"))["observations"][0]
        self.assertIn("PROVIDER_STATUS_NOT_ACTIVE", row["reasons"])
        self.assertNotEqual(row["decision_status"], "SUPPRESSED_BY_VEX")

    def test_inventory_incomplete_not_accepted(self):
        with self.assertRaises(ValueError):
            run(inspector(), inventories=[{"collection_complete": False, "workloads": []}])

    def test_host_finding_never_joins_ecr_image(self):
        data = inspector()
        data["findings"][0]["asset"]["type"] = "AWS_EC2_INSTANCE"
        result = run(data)
        self.assertEqual(result["observations"], [])
        self.assertEqual(result["excluded_uncorrelated_observations"], 0)

    def test_missing_vex_mapping_needs_review(self):
        row = run(inspector(), vex={})["observations"][0]
        self.assertIn("PROJECT_VEX_NOT_AVAILABLE", row["reasons"])

    def test_intelligence_selection_uses_running_digest_not_all_registry_findings(self):
        source = policy.observations(inspector(), None)
        source.append(policy.observations(inspector(cve="CVE-2028-99999", digest=D2), None)[0])
        selected = policy.cves_for_intelligence(source, [inventory(workload())])
        self.assertEqual(selected, [CVE])
        self.assertEqual(len(policy.cves_for_intelligence(source)), 2)

    def test_missing_inventory_rejected_during_cve_selection(self):
        with self.assertRaises(ValueError):
            policy.cves_for_intelligence(policy.observations(inspector(), None), [])
    def test_no_provider_finding_not_clean_coverage(self):
        result = run({"findings": []})
        self.assertEqual(result["observations"], [])
        self.assertEqual(result["runtime_workloads_observed"], 1)
        self.assertIn("coverage", policy.markdown_report(result).lower())

if __name__ == "__main__":
    unittest.main()

