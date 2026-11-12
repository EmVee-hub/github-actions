#!/usr/bin/env python3
"""Small Grype JSON -> BOD 26-04 -> local EPSS amplifier evaluator.

No network calls, no dependencies beyond Python 3.10+. This does not fetch
CISA Vulnrichment or validate that an image is actually deployed.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def load_policy(policy_dir: Path) -> tuple[dict, dict, dict]:
    base = json.loads((policy_dir / "bod-26-04.json").read_text(encoding="utf-8"))
    amp = json.loads((policy_dir / "epss-amplifier.json").read_text(encoding="utf-8"))
    mapping = {}
    for row in base["rows"]:
        key = (row["kev"], row["pe"], row["a"], row["ti"])
        if key in mapping:
            raise ValueError(f"Duplicate BOD combination: {key}")
        mapping[key] = row["outcome"]
    if len(mapping) != 16:
        raise ValueError(f"Expected 16 BOD combinations, got {len(mapping)}")
    if set(amp["table"]) != set(base["outcome_order"]):
        raise ValueError("Amplifier outcomes differ from base outcomes")
    for per_bin in amp["table"].values():
        if set(per_bin) != {"Q1", "Q2", "Q3", "Q4"}:
            raise ValueError("Each amplifier row must cover Q1..Q4")
    return base, amp, mapping


def epss_bin(percentile: float | None) -> str:
    if percentile is None:
        return "Q2"  # explicit local neutral policy, record missing flag separately
    if not 0 <= percentile <= 1:
        raise ValueError(f"Invalid EPSS percentile: {percentile}")
    if percentile < .25:
        return "Q1"
    if percentile < .50:
        return "Q2"
    if percentile < .75:
        return "Q3"
    return "Q4"


def apply_amp(base: str, kev: str, percentile: float | None, amp: dict) -> tuple[str, str, str]:
    bin_name = epss_bin(percentile)
    if kev == "Y":
        return base, bin_name, "KEV_GUARD"
    if base in ("3D", "3DF"):
        return base, bin_name, "URGENT_BASE_GUARD"
    final = amp["table"][base][bin_name]
    if final == "3DF":
        raise ValueError("EPSS must not create 3DF")
    return final, bin_name, "EPSS_UNAVAILABLE_NEUTRAL" if percentile is None else "AMPLIFIED"


def select_cve(match: dict) -> str | None:
    vuln = match.get("vulnerability") or {}
    candidates = [vuln.get("id", "")]
    for item in match.get("relatedVulnerabilities") or []:
        candidates.append(item.get("id", ""))
    for item in (vuln.get("knownExploited") or []):
        candidates.append(item.get("cve", ""))
    for item in (vuln.get("epss") or []):
        candidates.append(item.get("cve", ""))
    return next((v.upper() for v in candidates if isinstance(v, str) and CVE_PATTERN.match(v)), None)


def kev_status(match: dict) -> tuple[str, str]:
    vuln = match.get("vulnerability") or {}
    all_vulns = [vuln] + (match.get("relatedVulnerabilities") or [])
    if any(v.get("knownExploited") for v in all_vulns):
        return "Y", "GRYPE_KEV_ANNOTATION"
    if select_cve(match):
        # A completed Grype scan with updated DB is assumed for negative lookup.
        # Absence from Grype enrichment alone is not a separate fresh CISA check.
        return "N", "GRYPE_DB_ABSENCE_PROVISIONAL"
    return "UNKNOWN", "NO_CVE_MAPPING"


def epss_percentile(match: dict) -> tuple[float | None, str | None, str | None]:
    vuln = match.get("vulnerability") or {}
    all_vulns = [vuln] + (match.get("relatedVulnerabilities") or [])
    candidates = [e for v in all_vulns for e in (v.get("epss") or []) if isinstance(e, dict)]
    if not candidates:
        return None, None, None
    # Prefer most recently dated EPSS row. The percentile is a 0..1 fraction.
    item = sorted(candidates, key=lambda e: str(e.get("date") or ""), reverse=True)[0]
    p = item.get("percentile")
    if p is None:
        return None, None, str(item.get("date") or "")
    return float(p), str(item.get("epss")), str(item.get("date") or "")


def technical_impact(match: dict) -> tuple[str, str]:
    vuln = match.get("vulnerability") or {}
    vectors = [v.get("vector", "") for v in (vuln.get("cvss") or []) if isinstance(v, dict)]
    # The local heuristic is intentionally CVSS v3-only; v4 is not mapped here.
    for vector in vectors:
        if not (vector.startswith("CVSS:3.0/") or vector.startswith("CVSS:3.1/")):
            continue
        metrics = dict(piece.split(":", 1) for piece in vector.split("/")[1:] if ":" in piece)
        if "C" in metrics and "I" in metrics:
            return ("T" if metrics["C"] == "H" and metrics["I"] == "H" else "P"), "LOCAL_CVSS3_HEURISTIC"
    return "T", "LOCAL_CONSERVATIVE_DEFAULT"


def make_decision(match: dict, exposure: str, mapping: dict, amp: dict) -> dict:
    vuln = match.get("vulnerability") or {}
    artifact = match.get("artifact") or {}
    kev, kev_source = kev_status(match)
    percentile, probability, epss_date = epss_percentile(match)
    ti, ti_source = technical_impact(match)
    pe = "N" if exposure == "internal" else "Y"
    row = {
        "vulnerability_id": vuln.get("id"),
        "cve": select_cve(match),
        "package": artifact.get("name"),
        "installed_version": artifact.get("version"),
        "severity": vuln.get("severity"),
        "kev": kev,
        "kev_source": kev_source,
        "publicly_exposed": pe,
        "exposure_source": "PROJECT_DECLARATION" if exposure in ("public", "internal") else "UNKNOWN_DEFAULT_PUBLIC",
        "automatable": "Y",
        "automatable_source": "SSVC_DEFAULT_NOT_VULNRICHMENT",
        "technical_impact": ti,
        "technical_impact_source": ti_source,
        "epss_percentile": percentile,
        "epss_probability": probability,
        "epss_date": epss_date,
        "epss_source": "GRYPE_DATABASE" if percentile is not None else "UNAVAILABLE_NEUTRAL_Q2"
    }
    if kev == "UNKNOWN":
        row.update({"base_outcome": None, "final_outcome": None,
                    "epss_bin": epss_bin(percentile), "rule": "KEV_UNKNOWN", "status": "INCOMPLETE"})
        return row
    base = mapping[(kev, pe, "Y", ti)]
    final, bin_name, rule = apply_amp(base, kev, percentile, amp)
    row.update({"base_outcome": base, "final_outcome": final,
                "epss_bin": bin_name, "rule": rule, "status": "EVALUATED"})
    return row


def evaluate(data: dict, exposure: str, image: str, base: dict, amp: dict, mapping: dict) -> dict:
    if not isinstance(data, dict) or not isinstance(data.get("matches"), list):
        raise ValueError("Invalid Grype report: expected 'matches' array")
    if exposure not in ("public", "internal", "unknown"):
        raise ValueError(f"Invalid exposure: {exposure}")
    findings = [make_decision(m, exposure, mapping, amp) for m in data["matches"]]
    ignored = []
    for match in (data.get("ignoredMatches") or []):
        v = match.get("vulnerability") or {}
        a = match.get("artifact") or {}
        ignored.append({"vulnerability_id": v.get("id"), "package": a.get("name"),
                        "applied_ignore_rules": match.get("appliedIgnoreRules", [])})
    counts = Counter(f.get("final_outcome") or "INCOMPLETE" for f in findings)
    decision = "BLOCK" if counts["3D"] or counts["3DF"] else (
        "REVIEW_REQUIRED" if counts["INCOMPLETE"] else "ALLOW")
    return {
        "image": image,
        "assessed_at": datetime.now(timezone.utc).isoformat(),
        "model": base["id"],
        "amplifier": amp["id"],
        "admission": decision,
        "counts": dict(counts),
        "vex_ignored_count": len(ignored),
        "findings": findings,
        "ignored_matches": ignored,
        "warnings": [
            "Vulnrichment values are not fetched: Automatable uses Y default; TI uses local CVSS3 heuristic/default.",
            "KEV=N is provisional based on absence from completed Grype DB enrichment; direct CISA catalog freshness is not separately verified.",
            "VEX ignore results must be reviewed for precise product/component scope before enforcement."
        ]
    }


def markdown_report(report: dict) -> str:
    esc = lambda x: str(x or "").replace("|", "\\|").replace("\n", " ")
    lines = ["# CI Vulnerability Assessment", "",
             f"- Image: `{esc(report['image'])}`",
             f"- Admission: **{report['admission']}**",
             f"- Base: `{report['model']}`",
             f"- EPSS amplifier: `{report['amplifier']}`",
             f"- VEX-suppressed findings: {report['vex_ignored_count']}", "",
             "| CVE/advisory | Package | KEV | TI | EPSS bin | Base | Final | Source / guard |",
             "|---|---|---|---|---|---|---|---|"]
    for finding in report["findings"]:
        cells = [finding.get("cve") or finding.get("vulnerability_id"), finding.get("package"),
                 finding.get("kev"), finding.get("technical_impact"), finding.get("epss_bin"),
                 finding.get("base_outcome"), finding.get("final_outcome"), finding.get("rule")]
        lines.append("| " + " | ".join(esc(c) for c in cells) + " |")
    lines += ["", "## Known MVP limits", ""] + [f"- {w}" for w in report["warnings"]]
    return "\n".join(lines) + "\n"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--policy-dir", required=True)
    p.add_argument("--image", required=True)
    p.add_argument("--exposure", choices=("public", "internal", "unknown"), default="unknown")
    p.add_argument("--output", required=True)
    p.add_argument("--markdown", required=True)
    a = p.parse_args()
    base, amp, mapping = load_policy(Path(a.policy_dir))
    data = json.loads(Path(a.input).read_text(encoding="utf-8"))
    report = evaluate(data, a.exposure, a.image, base, amp, mapping)
    Path(a.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    Path(a.markdown).write_text(markdown_report(report), encoding="utf-8")
    print(report["admission"])


if __name__ == "__main__":
    main()
