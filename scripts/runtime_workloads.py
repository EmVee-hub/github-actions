#!/usr/bin/env python3
"""Read-only runtime inventory for AKS/EKS pods and ECS running tasks.

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
        # Terminal or pending workloads cannot be marked as running.
        if status.get("phase") != "Running" or md.get("deletionTimestamp"):
            continue
        declared = {c.get("name"): c.get("image") for c in (spec.get("containers") or [])}
        for c in status.get("containerStatuses") or []:
            if not (c.get("state") or {}).get("running"):
                continue
            image = c.get("image") or declared.get(c.get("name")) or ""
            image_id = c.get("imageID") or ""
            digest = manifest_digest(image_id, image)
            registry, repository = locator(image)
            entry = {
                "platform": platform, "cluster": cluster, "account_id": scope if platform == "EKS" else None,
                "subscription_id": scope if platform == "AKS" else None, "region": region,
                "namespace": namespace, "workload": name, "container": c.get("name"),
                "workload_uid": md.get("uid"), "image": image, "image_id": image_id,
                "image_digest": digest, "registry": registry, "repository": repository,
                "architecture": None, "state": "RUNNING", **labels(md),
            }
            if digest and registry and repository:
                workloads.append(entry)
            else:
                unresolved.append({**entry, "reason": "IMAGE_MANIFEST_DIGEST_OR_REGISTRY_UNKNOWN"})
    return {"workloads": workloads, "unresolved": unresolved}


def parse_ecs(payload: dict, cluster: str, account: str, region: str) -> dict:
    tasks = payload.get("tasks")
    if not isinstance(tasks, list):
        raise ValueError("Expected AWS ECS DescribeTasks response with tasks array")
    workloads, unresolved = [], []
    for task in tasks:
        if task.get("lastStatus") != "RUNNING" or task.get("desiredStatus") != "RUNNING":
            continue
        task_labels = {"labels": {k: v for t in (task.get("tags") or [])
                                  if (k := t.get("key")) and (v := t.get("value"))}}
        # Direct ECS task tags use the same explicit names as Kubernetes Pod labels.
        tags = labels(task_labels)
        for c in task.get("containers") or []:
            if c.get("lastStatus") != "RUNNING":
                continue
            image = c.get("image") or ""
            registry, repository = locator(image)
            digest = c.get("imageDigest")
            digest = digest if isinstance(digest, str) and DIGEST.fullmatch(digest) else None
            entry = {
                "platform": "ECS", "cluster": cluster, "account_id": account,
                "subscription_id": None, "region": region, "namespace": None,
                "workload": task.get("group") or task.get("taskDefinitionArn"),
                "container": c.get("name"), "workload_uid": task.get("taskArn"),
                "image": image, "image_id": None, "image_digest": digest,
                "registry": registry, "repository": repository,
                "architecture": None, "state": "RUNNING", **tags,
            }
            if digest and registry and repository:
                workloads.append(entry)
            else:
                unresolved.append({**entry, "reason": "IMAGE_MANIFEST_DIGEST_OR_REGISTRY_UNKNOWN"})
    return {"workloads": workloads, "unresolved": unresolved}


def command(*argv: str) -> dict:
    result = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=180)
    return json.loads(result.stdout)


def collect_ecs(cluster: str, region: str, account: str) -> dict:
    caller = command("aws", "sts", "get-caller-identity", "--region", region, "--output", "json")
    if caller.get("Account") != account:
        raise ValueError("AWS identity does not match configured account")
    token, seen, arns, tasks = None, set(), [], []
    while True:
        cmd = ["aws", "ecs", "list-tasks", "--region", region, "--cluster", cluster,
               "--desired-status", "RUNNING", "--no-paginate", "--output", "json"]
        if token:
            cmd += ["--starting-token", token]
        page = command(*cmd)
        if not isinstance(page.get("taskArns"), list):
            raise ValueError("Missing ECS taskArns")
        arns.extend(page["taskArns"])
        token = page.get("nextToken")
        if not token:
            break
        if token in seen:
            raise ValueError("Repeated ECS continuation token")
        seen.add(token)
    for i in range(0, len(arns), 100):
        page = command("aws", "ecs", "describe-tasks", "--region", region, "--cluster", cluster,
                       "--tasks", *arns[i:i+100], "--include", "TAGS", "--output", "json")
        if page.get("failures"):
            raise ValueError("ECS describe-tasks returned failures")
        tasks.extend(page.get("tasks") or [])
    if len(tasks) != len(arns):
        raise ValueError("ECS tasks missing from description; inventory incomplete")
    return {"tasks": tasks}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--platform", required=True, choices=["AKS", "EKS", "ECS"])
    p.add_argument("--cluster", required=True)
    p.add_argument("--account-id", help="Required for EKS/ECS")
    p.add_argument("--subscription-id", help="Required for AKS")
    p.add_argument("--region", help="Required for AWS")
    p.add_argument("--input", type=Path, help="Offline kubectl pods JSON / ECS describe-tasks JSON")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if a.platform == "AKS" and not a.subscription_id:
        p.error("--subscription-id required for AKS")
    if a.platform in ("EKS", "ECS") and (not a.account_id or not a.region):
        p.error("--account-id and --region required for EKS/ECS")
    scope = a.subscription_id if a.platform == "AKS" else a.account_id
    payload = json.loads(a.input.read_text()) if a.input else (
        collect_ecs(a.cluster, a.region, a.account_id) if a.platform == "ECS"
        else command("kubectl", "get", "pods", "--all-namespaces", "-o", "json"))
    observation = (parse_ecs(payload, a.cluster, a.account_id, a.region)
                   if a.platform == "ECS"
                   else parse_pods(payload, a.platform, a.cluster, scope, a.region))
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
