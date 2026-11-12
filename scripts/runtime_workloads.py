#!/usr/bin/env python3
"""Read-only runtime inventory of running AKS/EKS Pod containers.

This is a *point-in-time workload observation*, not complete scan coverage.
Only registry MANIFEST digests are eligible for vulnerability joins.
"""
from __future__ import annotations
import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
LABEL_PROJECT = "security.example.com/project"
LABEL_EXPOSURE = "security.example.com/exposure"
LABEL_CRITICAL = "security.example.com/prod-critical"


def locator(image: str) -> tuple[str | None, str | None]:
    """Require explicit registry/repository; never invent an implicit Docker Hub host."""
    ref = image.split("@", 1)[0]
    fields = ref.split("/")
    if len(fields) < 2 or not any(s in fields[0] for s in (".", ":", "localhost")):
        return None, None
    repository = "/".join(fields[1:]).rsplit(":", 1)[0] if ":" in fields[-1] else "/".join(fields[1:])
    return fields[0].lower(), repository.lower()


def manifest_digest(image_id: str, image: str) -> str | None:
    """containerd://sha256 may be a config digest: it is NOT a safe registry digest."""
    if "@sha256:" in image_id and not image_id.startswith("containerd://"):
        digest = "sha256:" + image_id.rsplit("@sha256:", 1)[-1]
    elif "@sha256:" in image:
        digest = "sha256:" + image.rsplit("@sha256:", 1)[-1]
    else:
        return None
    return digest if DIGEST.fullmatch(digest) else None


def labels(metadata: dict) -> dict:
    values = metadata.get("labels") or {}
    exposure = values.get(LABEL_EXPOSURE, "unknown")
    if exposure not in ("public", "internal", "unknown"):
        exposure = "unknown"
    critical = values.get(LABEL_CRITICAL)
    return {
        "project": values.get(LABEL_PROJECT),
        "exposure": exposure,
        "prod_critical": True if critical == "true" else (False if critical == "false" else None),
    }


def parse_pods(payload: dict, platform: str, cluster: str, scope: str,
               region: str | None = None) -> dict:
    if platform not in ("AKS", "EKS"):
        raise ValueError("Kubernetes platform must be AKS or EKS")
    if not isinstance(payload.get("items"), list):
        raise ValueError("Expected kubectl get pods -A -o json object with items array")
    workloads, unresolved = [], []
    for pod in payload["items"]:
        if not isinstance(pod, dict):
            raise ValueError("Invalid Pod item")
        md, status, spec = pod.get("metadata") or {}, pod.get("status") or {}, pod.get("spec") or {}
        namespace, name = md.get("namespace"), md.get("name")
        if not namespace or not name:
            raise ValueError("Pod missing namespace/name")
        # A Pod in Pending may still have an actively running init container.
        # A terminating Pod may still contain running containers until it stops.
        # Never infer runtime presence from Pod phase alone.
        if status.get("phase") not in ("Running", "Pending"):
            continue
        groups = (
            ("app", "containers", "containerStatuses"),
            ("init", "initContainers", "initContainerStatuses"),
            ("ephemeral", "ephemeralContainers", "ephemeralContainerStatuses"),
        )
        for role, declared_key, statuses_key in groups:
            declared = {c.get("name"): c.get("image")
                        for c in (spec.get(declared_key) or [])}
            for c in status.get(statuses_key) or []:
                if not (c.get("state") or {}).get("running"):
                    continue
                image = c.get("image") or declared.get(c.get("name")) or ""
                image_id = c.get("imageID") or ""
                digest = manifest_digest(image_id, image)
                registry, repository = locator(image)
                entry = {
                    "platform": platform, "cluster": cluster,
                    "account_id": scope if platform == "EKS" else None,
                    "subscription_id": scope if platform == "AKS" else None,
                    "region": region, "namespace": namespace, "workload": name,
                    "container": c.get("name"), "container_role": role,
                    "workload_uid": md.get("uid"), "image": image, "image_id": image_id,
                    "image_digest": digest, "registry": registry, "repository": repository,
                    "architecture": None, "state": "RUNNING",
                    "pod_terminating": bool(md.get("deletionTimestamp")), **labels(md),
                }
                if digest and registry and repository:
                    workloads.append(entry)
                else:
                    unresolved.append({**entry, "reason": "IMAGE_MANIFEST_DIGEST_OR_REGISTRY_UNKNOWN"})
    return {"workloads": workloads, "unresolved": unresolved}



def command(*argv: str) -> dict:
    result = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=180)
    return json.loads(result.stdout)



def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--platform", required=True, choices=["AKS", "EKS"])
    p.add_argument("--cluster", required=True)
    p.add_argument("--account-id", help="Required for EKS")
    p.add_argument("--subscription-id", help="Required for AKS")
    p.add_argument("--region", help="Required for AWS")
    p.add_argument("--input", type=Path, help="Offline kubectl pods JSON")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if a.platform == "AKS" and not a.subscription_id:
        p.error("--subscription-id required for AKS")
    if a.platform == "EKS" and (not a.account_id or not a.region):
        p.error("--account-id and --region required for EKS")
    scope = a.subscription_id if a.platform == "AKS" else a.account_id
    payload = (json.loads(a.input.read_text()) if a.input
               else command("kubectl", "get", "pods", "--all-namespaces", "-o", "json"))
    observation = parse_pods(payload, a.platform, a.cluster, scope, a.region)
    result = {
        "schema_version": "runtime-inventory/1.0", "mode": "OFFLINE" if a.input else "LIVE",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "collection_complete": True, **observation,
    }
    a.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Runtime inventory: {len(observation['workloads'])} eligible, "
          f"{len(observation['unresolved'])} unresolved (not safe to join)")


if __name__ == "__main__":
    main()
