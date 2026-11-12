"""Runtime inventory parsing and manifest-digest safety tests."""
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import runtime_workloads as inv

D = "sha256:" + "a" * 64
ACCOUNT = "123456789012"
REG = ACCOUNT + ".dkr.ecr.eu-north-1.amazonaws.com"
IMG = REG + "/payments/api:v1"
POD = {"items": [
    {"metadata": {"name": "p1", "namespace": "prod", "uid": "pod1",
                  "labels": {inv.LABEL_PROJECT: "payments", inv.LABEL_EXPOSURE: "public",
                             inv.LABEL_CRITICAL: "true"}},
     "spec": {"containers": [{"name": "app", "image": IMG}]},
     "status": {"phase": "Running", "containerStatuses": [
         {"name": "app", "image": IMG, "imageID": "docker-pullable://" + REG + "/payments/api@" + D,
          "state": {"running": {"startedAt": "2026-11-12T00:00:00Z"}}}
     ]}}
]}

class InventoryTests(unittest.TestCase):
    def test_exact_eks_digest(self):
        data = inv.parse_pods(POD, "EKS", "eks-demo", ACCOUNT, "eu-north-1")
        self.assertEqual(len(data["workloads"]), 1)
        w = data["workloads"][0]
        self.assertEqual(w["repository"], "payments/api")
        self.assertEqual(w["image_digest"], D)
        self.assertEqual(w["project"], "payments")
        self.assertEqual(w["prod_critical"], True)

    def test_containerd_hash_not_assumed_manifest(self):
        payload = __import__("copy").deepcopy(POD)
        payload["items"][0]["status"]["containerStatuses"][0]["imageID"] = "containerd://" + D
        x = inv.parse_pods(payload, "EKS", "eks-demo", ACCOUNT, "eu-north-1")
        self.assertEqual(len(x["workloads"]), 0)
        self.assertEqual(x["unresolved"][0]["reason"], "IMAGE_MANIFEST_DIGEST_OR_REGISTRY_UNKNOWN")

    def test_not_running_excluded(self):
        payload = __import__("copy").deepcopy(POD)
        payload["items"][0]["status"]["phase"] = "Pending"
        payload["items"][0]["status"]["containerStatuses"][0]["state"] = {"waiting": {"reason": "ContainerCreating"}}
        self.assertEqual(inv.parse_pods(payload, "AKS", "aks", "subscription")["workloads"], [])

    def test_running_init_container_during_pending_pod(self):
        payload = __import__("copy").deepcopy(POD)
        pod = payload["items"][0]
        pod["status"]["phase"] = "Pending"
        pod["spec"]["containers"] = []
        pod["status"]["containerStatuses"] = []
        pod["spec"]["initContainers"] = [{"name": "init", "image": IMG}]
        pod["status"]["initContainerStatuses"] = [{"name": "init", "image": IMG,
            "imageID": "docker-pullable://" + REG + "/payments/api@" + D,
            "state": {"running": {"startedAt": "2026-11-12T00:00:00Z"}}}]
        records = inv.parse_pods(payload, "EKS", "demo", ACCOUNT, "eu-north-1")
        self.assertEqual(len(records["workloads"]), 1)
        self.assertEqual(records["workloads"][0]["container_role"], "init")

    def test_ephemeral_container_and_terminating_pod_still_running(self):
        payload = __import__("copy").deepcopy(POD)
        pod = payload["items"][0]
        pod["metadata"]["deletionTimestamp"] = "2026-11-12T00:01:00Z"
        pod["spec"]["ephemeralContainers"] = [{"name": "debug", "image": IMG}]
        pod["status"]["ephemeralContainerStatuses"] = [{"name": "debug", "image": IMG,
            "imageID": "docker-pullable://" + REG + "/payments/api@" + D,
            "state": {"running": {"startedAt": "2026-11-12T00:00:00Z"}}}]
        records = inv.parse_pods(payload, "EKS", "demo", ACCOUNT, "eu-north-1")
        self.assertEqual({w["container_role"] for w in records["workloads"]}, {"app", "ephemeral"})
        self.assertTrue(all(w["pod_terminating"] for w in records["workloads"]))

    def test_reject_non_kubernetes_platform(self):
        with self.assertRaisesRegex(ValueError, "AKS or EKS"):
            inv.parse_pods(POD, "unsupported", "cluster", ACCOUNT)

    def test_missing_registry_unresolved(self):
        payload = __import__("copy").deepcopy(POD)
        payload["items"][0]["spec"]["containers"][0]["image"] = "nginx:latest"
        payload["items"][0]["status"]["containerStatuses"][0]["image"] = "nginx:latest"
        x = inv.parse_pods(payload, "EKS", "eks-demo", ACCOUNT, "eu-north-1")
        self.assertFalse(x["workloads"])
        self.assertEqual(len(x["unresolved"]), 1)

if __name__ == "__main__":
    unittest.main()
