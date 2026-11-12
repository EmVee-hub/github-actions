#!/usr/bin/env python3
"""Correlate AWS Inspector/Azure Defender CVEs with RUNNING image digests and BOD+EPSS.

No cloud credentials required to replay collected evidence. Runtime is verified
only by explicit image registry/repository/manifest digest and account scope.
Never conflate absence of matches with absence of vulnerabilities/coverage.
"""
from __future__ import annotations
import argparse
import json
import re
from collections import Counter
from pathlib import Path

from evaluate import apply_amp, load_policy, technical_impact
from validate_vex import validate as validate_vex

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def observations(inspector: dict | None, defender: list | None) -> list[dict]:
    out = []
    if inspector is not None:
        rows = inspector.get("findings")
        if not isinstance(rows, list):
            raise ValueError("Inspector input missing normalized findings array")
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("Invalid Inspector row")
            a = row.get("asset") or {}
            package = row.get("package") or {}
            out.append({
                "source": "AWS_INSPECTOR", "observation_id": row.get("observation_id"),
                "resource_id": row.get("finding_arn"), "provider_status": row.get("provider_status"),
                "cve": row.get("vulnerability_id"), "severity": row.get("severity"),
                "account_id": row.get("account_id"), "subscription_id": None,
                "region": row.get("region"), "image_digest": a.get("image_digest"),
                "repository": a.get("repository"), "registry": a.get("registry"),
                "asset_type": a.get("type"), "package": package.get("name"),
                "package_version": package.get("version"), "package_purl": package.get("purl"),
                "cvss": row.get("cvss") or [],
                "in_use_count": (row.get("runtime") or {}).get("in_use_count"),
            })
    if defender is not None:
        if not isinstance(defender, list):
            raise ValueError("Defender input must be normalized observations array")
        for row in defender:
            if not isinstance(row, dict):
                raise ValueError("Invalid Defender observation")
            details = row.get("resource_details") or {}
            # Only explicitly structured registry identities are accepted. Existing
            # Defender observations mostly have no digest: they remain unresolved.
            out.append({
                "source": "AZURE_DEFENDER", "observation_id": row.get("assessment_id"),
                "resource_id": row.get("assessment_id"), "provider_status": row.get("provider_status"),
                "cve": row.get("vulnerability_id"), "severity": row.get("severity"),
                "account_id": None, "subscription_id": row.get("subscription_id"),
                "region": None, "image_digest": row.get("image_digest") or details.get("imageDigest"),
                "repository": details.get("repository"), "registry": details.get("registry"),
                "asset_type": (details.get("ResourceType") or "UNKNOWN"),
                "package": row.get("package_name"), "package_version": row.get("package_version"),
                "package_purl": row.get("package_purl"), "cvss": row.get("cvss") or [],
                "in_use_count": None,
            })
    return out


def join(observation: dict, workloads: list[dict]) -> tuple[list[dict], str]:
    if observation["source"] == "AWS_INSPECTOR" and observation["asset_type"] != "AWS_ECR_CONTAINER_IMAGE":
        return [], "NON_CONTAINER_ASSET"
    digest, repo = observation.get("image_digest"), observation.get("repository")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or not repo:
        return [], "IMAGE_IDENTITY_INCOMPLETE"
    matches = []
    for w in workloads:
        if w.get("state") != "RUNNING" or w.get("image_digest") != digest or w.get("repository") != repo:
            continue
        if observation["source"] == "AWS_INSPECTOR":
            if w.get("platform") not in ("EKS", "ECS"):
                continue
            account, region = observation.get("account_id"), observation.get("region")
            if not account or not region or w.get("account_id") != account or w.get("region") != region:
                continue
            if w.get("registry") != f"{account}.dkr.ecr.{region}.amazonaws.com":
                continue
            if observation.get("registry") not in (account, w["registry"]):
                continue
        else:
            if w.get("platform") != "AKS" or w.get("subscription_id") != observation.get("subscription_id"):
                continue
            if not observation.get("registry") or w.get("registry") != observation["registry"]:
                continue
        matches.append(w)
    return matches, "CONFIRMED_RUNNING" if matches else "NO_EXACT_RUNTIME_MATCH"


def vex_status(cve: str, workload: dict, obs: dict, vex_map: dict) -> tuple[str, str]:
    project = workload.get("project")
    if not project:
        return "REVIEW_REQUIRED", "PROJECT_IDENTITY_UNKNOWN"
    doc = vex_map.get(project)
    if doc is None:
        return "REVIEW_REQUIRED", "PROJECT_VEX_NOT_AVAILABLE"
    purl = obs.get("package_purl")
    if not purl:
        return "REVIEW_REQUIRED", "PACKAGE_PURL_UNKNOWN"
    candidates = []
    for statement in doc.get("statements", []):
        if (statement.get("vulnerability") or {}).get("name") != cve:
            continue
        for product in statement.get("products") or []:
            # Exact immutable image digest and exact versioned component are required.
            if product.get("@id") != "urn:container:" + workload["image_digest"]:
                continue
            if any(part.get("@id") == purl for part in (product.get("subcomponents") or [])):
                candidates.append(statement)
    if len(candidates) > 1:
        return "REVIEW_REQUIRED", "CONFLICTING_VEX_STATEMENTS"
    if not candidates:
        return "ACTIVE", "NO_EXACT_VEX_MATCH"
    stmt = candidates[0]
    if stmt.get("status") == "not_affected":
        if not stmt.get("justification") or not stmt.get("impact_statement"):
            return "REVIEW_REQUIRED", "VEX_EVIDENCE_INCOMPLETE"
        return "SUPPRESSED", "SCOPED_NOT_AFFECTED"
    return "ACTIVE", "VEX_" + str(stmt.get("status")).upper()


def evaluate_row(obs: dict, workload: dict, intel: dict, vex_docs: dict,
                 mapping: dict, amp: dict) -> dict:
    row = {
        "source": obs["source"], "observation_id": obs["observation_id"],
        "cve": obs["cve"], "severity": obs["severity"], "package": obs["package"],
        "package_version": obs.get("package_version"), "package_purl": obs.get("package_purl"),
        "image_digest": obs["image_digest"], "repository": obs["repository"],
        "platform": workload["platform"], "cluster": workload["cluster"],
        "namespace": workload.get("namespace"), "workload": workload["workload"],
        "workload_uid": workload.get("workload_uid"),
        "project": workload.get("project"), "prod_critical": workload.get("prod_critical"),
        "exposure_input": workload.get("exposure", "unknown"),
        "publicly_exposed": "N" if workload.get("exposure") == "internal" else "Y",
        "exposure_source": ("WORKLOAD_DECLARATION" if workload.get("exposure") in ("public", "internal")
                            else "UNKNOWN_DEFAULT_PUBLIC"),
        "correlation_status": "CONFIRMED_RUNNING",
        "provider_status": obs["provider_status"], "vex_status": "NOT_EVALUATED",
        "base_outcome": None, "final_outcome": None,
        "decision_rule": None, "decision_status": "REVIEW_REQUIRED", "reasons": [],
    }
    reasons = row["reasons"]
    cve = obs["cve"]
    if not isinstance(cve, str) or not CVE.fullmatch(cve):
        reasons.append("CVE_MAPPING_UNRESOLVED")
        return row
    if obs["provider_status"] not in (("ACTIVE",) if obs["source"] == "AWS_INSPECTOR" else ("Unhealthy",)):
        reasons.append("PROVIDER_STATUS_NOT_ACTIVE")
        return row
    if not isinstance(intel.get("kev"), dict) or intel["kev"].get("complete") is not True:
        reasons.append("AUTHORITATIVE_KEV_UNAVAILABLE")
        return row
    if cve not in intel.get("epss", {}) or cve not in intel.get("cisa", {}):
        reasons.append("INTELLIGENCE_RECORD_MISSING")
        return row
    epss, cisa = intel["epss"][cve], intel["cisa"][cve]
    if epss.get("status") == "FETCH_ERROR" or cisa.get("status") in ("FETCH_ERROR", "INVALID_SSVC"):
        reasons.append("INTELLIGENCE_LOOKUP_FAILED")
        return row
    if epss.get("status") not in ("FOUND", "NOT_FOUND"):
        reasons.append("EPSS_STATUS_UNSUPPORTED")
        return row
    if cisa.get("status") not in ("FOUND", "NO_SSVC", "NO_RECORD"):
        reasons.append("SSVC_STATUS_UNSUPPORTED")
        return row

    kev = "Y" if cve in intel["kev"]["cves"] else "N"
    ti, ti_source = technical_impact({"vulnerability": {"cvss": [
        {"vector": item.get("scoringVector") or item.get("vector") or ""}
        for item in obs.get("cvss", []) if isinstance(item, dict)]}})
    auto, auto_source = "Y", "LOCAL_DEFAULT"
    if cisa["status"] == "FOUND":
        auto, ti = cisa.get("automatable"), cisa.get("technical_impact")
        auto_source = ti_source = "CISA_ADP_SSVC"
    if auto not in ("Y", "N") or ti not in ("P", "T"):
        reasons.append("SSVC_VALUES_INVALID")
        return row
    try:
        pct = float(epss["percentile"]) if epss["status"] == "FOUND" else None
        base = mapping[(kev, row["publicly_exposed"], auto, ti)]
        final, bin_name, rule = apply_amp(base, kev, pct, amp)
    except (KeyError, TypeError, ValueError):
        reasons.append("DECISION_INPUT_INVALID")
        return row

    row.update(kev=kev, automatable=auto, automatable_source=auto_source,
               technical_impact=ti, technical_impact_source=ti_source,
               epss_percentile=pct, epss_probability=epss.get("probability"),
               epss_bin=bin_name, base_outcome=base, final_outcome=final,
               decision_rule=rule, ssvc_status=cisa["status"])
    vs, vr = vex_status(cve, workload, obs, vex_docs)
    row["vex_status"] = vs
    row["vex_reason"] = vr
    if vs == "SUPPRESSED":
        row["decision_status"] = "SUPPRESSED_BY_VEX"
        # Keep the calculated BOD priority as evidence but do not treat as an active deadline.
    elif vs == "REVIEW_REQUIRED":
        reasons.append(vr)
    elif workload.get("prod_critical") is None:
        reasons.append("PROD_CRITICAL_CLASSIFICATION_UNKNOWN")
    else:
        row["decision_status"] = "EVALUATED"
    return row


def assess(inspector: dict | None, defender: list | None, inventories: list[dict],
           intel: dict, vex_docs: dict, policy_dir: Path) -> dict:
    if not inventories:
        raise ValueError("No runtime inventory: cannot claim running workload correlation")
    workloads, unresolved = [], []
    for inventory in inventories:
        if inventory.get("collection_complete") is not True or not isinstance(inventory.get("workloads"), list):
            raise ValueError("Incomplete runtime inventory; do not use partial data")
        workloads.extend(inventory["workloads"])
        unresolved.extend(inventory.get("unresolved") or [])
    if intel.get("complete") is not True:
        raise ValueError("Incomplete intelligence snapshot")
    _, amp, mapping = load_policy(policy_dir)
    results = []
    for observation in observations(inspector, defender):
        running, correlation = join(observation, workloads)
        if not running:
            results.append({
                "source": observation["source"], "observation_id": observation["observation_id"],
                "cve": observation["cve"], "severity": observation["severity"],
                "repository": observation.get("repository"), "image_digest": observation.get("image_digest"),
                "correlation_status": correlation, "decision_status": "NOT_EVALUATED",
                "reasons": [correlation],
            })
            continue
        for workload in running:
            results.append(evaluate_row(observation, workload, intel, vex_docs, mapping, amp))
    return {
        "schema_version": "runtime-assessment/1.0", "policy_model": "cisa:DT_BOD2604:1.0.0",
        "policy_amplifier": amp["id"], "intelligence_fetched_at": intel.get("fetched_at"),
        "inventory_modes": sorted(set(i.get("mode", "UNKNOWN") for i in inventories)),
        "runtime_workloads_observed": len(workloads),
        "runtime_inventory_unresolved": unresolved,
        "observations": results,
        "counts": dict(Counter(r["decision_status"] for r in results)),
        "notes": [
            "A running image is not the same as a confirmed exploitable vulnerability.",
            "Registry/ECR coverage and freshness are NOT established by this join.",
            "A preliminary BOD outcome on REVIEW_REQUIRED does not authorize closing a finding.",
            "3DF requires forensic triage; this workflow never terminates workloads.",
        ],
    }


def markdown_report(report: dict) -> str:
    lines = [
        "# Runtime vulnerability correlation and BOD/EPSS report", "",
        "**No runtime actions taken. Evidence/correlation does not prove complete coverage.**", "",
        "| Provider | Workload | CVE | Severity | Correlation | VEX | KEV | PE | EPSS bin | Base | Final | Status / reason |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for item in report["observations"]:
        def e(x):
            return str(x if x is not None else "—").replace("|", "\\|").replace("\n", " ")
        cells = [item.get(k) for k in ("source", "workload", "cve", "severity", "correlation_status",
                                     "vex_status", "kev", "publicly_exposed", "epss_bin",
                                     "base_outcome", "final_outcome", "decision_status")]
        cells[-1] = e(cells[-1]) + ": " + ",".join(item.get("reasons") or [])
        lines.append("| " + " | ".join(e(c) for c in cells) + " |")
    if not report["observations"]:
        lines.append("| No provider findings | — | — | — | — | — | — | — | — | — | — | INCOMPLETE_COVERAGE |")
    lines += ["", "## Summary", "",
              "Observed workload containers with eligible manifest digest: **" + str(report["runtime_workloads_observed"]) + "**.",
              "Unresolved workload containers: **" + str(len(report["runtime_inventory_unresolved"])) + "**.",
              "Decision statuses: `" + json.dumps(report["counts"], sort_keys=True) + "`.", "",
              "For full source, workload identity and SSVC evidence inspect the JSON artifact.",
              "A missing provider finding is **never** a verified clean workload."]
    return "\n".join(lines) + "\n"


def read_vex_map(path: Path) -> dict:
    mapping = json.loads(path.read_text())
    if not isinstance(mapping, dict):
        raise ValueError("VEX map must be project -> local OpenVEX path")
    docs = {}
    for project, target in mapping.items():
        if not isinstance(project, str) or not isinstance(target, str):
            raise ValueError("VEX map entries must be strings")
        vex_path = (path.parent / target).resolve()
        # Mapping paths are trusted operator configuration; no network fetching.
        validate_vex(vex_path)
        docs[project] = json.loads(vex_path.read_text())
    return docs


def cves_for_intelligence(source_rows: list[dict], inventories: list[dict] | None = None) -> list[str]:
    """Select CVEs on running-image observations; optionally allow all provider CVEs."""
    candidates = source_rows
    if inventories is not None:
        if not inventories or any(i.get("collection_complete") is not True
                                  or not isinstance(i.get("workloads"), list) for i in inventories):
            raise ValueError("Runtime inventory missing/incomplete")
        workloads = [w for inventory in inventories for w in inventory["workloads"]]
        candidates = [row for row in source_rows if join(row, workloads)[0]]
    return sorted({row["cve"] for row in candidates
                   if isinstance(row.get("cve"), str) and CVE.fullmatch(row["cve"])})


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inspector", type=Path, help="Normalized Inspector findings JSON")
    p.add_argument("--defender", type=Path, help="Normalized Defender observations JSON")
    p.add_argument("--inventory", type=Path, nargs="+", help="Runtime inventory JSON(s)")
    p.add_argument("--intel", type=Path, help="CISA KEV + SSVC + FIRST EPSS snapshot")
    p.add_argument("--vex-map", type=Path, help="Map project -> local per-project OpenVEX file")
    p.add_argument("--policy-dir", type=Path, default=Path(__file__).resolve().parents[1] / "policy")
    p.add_argument("--output", type=Path, help="Decision JSON output")
    p.add_argument("--markdown", type=Path, help="Readable report")
    p.add_argument("--cves-only", type=Path, help="Write unique CVEs then exit; for intelligence lookup")
    args = p.parse_args()
    inspector = json.loads(args.inspector.read_text()) if args.inspector else None
    defender = json.loads(args.defender.read_text()) if args.defender else None
    if inspector is None and defender is None:
        p.error("--inspector and/or --defender is required")
    obs = observations(inspector, defender)
    if args.cves_only:
        selected_inventory = ([json.loads(f.read_text()) for f in args.inventory]
                              if args.inventory else None)
        args.cves_only.write_text(
            json.dumps(cves_for_intelligence(obs, selected_inventory), indent=2) + "\n")
        return
    if not (args.inventory and args.intel and args.output and args.markdown):
        p.error("--inventory, --intel, --output and --markdown required for assessment")
    inventories = [json.loads(f.read_text()) for f in args.inventory]
    intel = json.loads(args.intel.read_text())
    vex_docs = read_vex_map(args.vex_map) if args.vex_map else {}
    result = assess(inspector, defender, inventories, intel, vex_docs, args.policy_dir)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    args.markdown.write_text(markdown_report(result))
    print("Runtime policy statuses:", result["counts"])


if __name__ == "__main__":
    main()
