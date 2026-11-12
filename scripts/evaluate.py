#!/usr/bin/env python3
"""Grype JSON + CISA Vulnrichment -> BOD 26-04 -> EPSS evaluator.

The network lookup is kept separate so this evaluator remains deterministic.
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
    policy = amp["probability_policy"]
    if not policy.get("id"):
        raise ValueError("Probability policy needs an id")
    if policy["kev"]["default"] not in ("3D", "3DF") or policy["kev"]["preserve"] != ["3DF"]:
        raise ValueError("KEV policy must remain urgent and preserve 3DF")
    rules = policy["non_kev"]
    allowed = {"FSU", "60D", "30D"}
    if rules["default"] not in allowed or rules["missing"] not in allowed:
        raise ValueError("Invalid non-KEV fallback")
    previous = 2
    for threshold in rules["thresholds"]:
        value = threshold["minimum_probability"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1 or value >= previous:
            raise ValueError("EPSS thresholds must be unique, descending probabilities")
        if threshold["outcome"] not in allowed:
            raise ValueError("Invalid non-KEV outcome")
        previous = value
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
    probability = item.get("epss")
    return (float(p) if p is not None else None,
            str(probability) if probability is not None else None,
            str(item.get("date") or ""))


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


def cisa_values(cve: str | None, enrichment: dict | None) -> dict:
    if not cve:
        return {"status": "NO_CVE"}
    if enrichment is None:
        return {"status": "NOT_QUERIED"}
    return (enrichment.get("cves") or {}).get(cve, {
        "status": "FETCH_ERROR", "reason": "CVE missing from enrichment batch"
    })


def make_decision(match: dict, exposure: str, mapping: dict, amp: dict,
                  enrichment: dict | None = None) -> dict:
    vuln = match.get("vulnerability") or {}
    artifact = match.get("artifact") or {}
    kev, kev_source = kev_status(match)
    percentile, probability, epss_date = epss_percentile(match)
    ti, ti_source = technical_impact(match)
    cve = select_cve(match)
    cisa = cisa_values(cve, enrichment)
    cisa_status = cisa.get("status")
    automatable, automatable_source = "Y", "SSVC_DEFAULT_MISSING_VULNRICHMENT"
    if cisa_status == "FOUND":
        automatable, automatable_source = cisa["automatable"], "CISA_VULNRICHMENT_ADP"
        ti, ti_source = cisa["technical_impact"], "CISA_VULNRICHMENT_ADP"
    pe = "N" if exposure == "internal" else "Y"
    row = {
        "vulnerability_id": vuln.get("id"),
        "cve": cve,
        "package": artifact.get("name"),
        "installed_version": artifact.get("version"),
        "severity": vuln.get("severity"),
        "kev": kev,
        "kev_source": kev_source,
        "publicly_exposed": pe,
        "exposure_source": "PROJECT_DECLARATION" if exposure in ("public", "internal") else "UNKNOWN_DEFAULT_PUBLIC",
        "automatable": automatable,
        "automatable_source": automatable_source,
        "vulnrichment_status": cisa_status,
        "vulnrichment_version": cisa.get("ssvc_version"),
        "vulnrichment_timestamp": cisa.get("ssvc_timestamp"),
        "vulnrichment_source_url": cisa.get("url"),
        "vulnrichment_error": cisa.get("reason") if cisa_status in ("FETCH_ERROR", "INVALID_SSVC") else None,
        "technical_impact": ti,
        "technical_impact_source": ti_source,
        "epss_percentile": percentile,
        "epss_probability": probability,
        "epss_date": epss_date,
        "epss_source": "GRYPE_DATABASE" if percentile is not None else "UNAVAILABLE_NEUTRAL_Q2"
    }
    if kev == "UNKNOWN" or cisa_status in ("FETCH_ERROR", "INVALID_SSVC"):
        reason = "KEV_UNKNOWN" if kev == "UNKNOWN" else "VULNRICHMENT_LOOKUP_FAILED"
        row.update({"base_outcome": None, "final_outcome": None,
                    "epss_bin": epss_bin(percentile), "rule": reason, "status": "INCOMPLETE"})
        return row
    base = mapping[(kev, pe, automatable, ti)]
    final, bin_name, rule = apply_amp(base, kev, percentile, amp)
    row.update({"base_outcome": base, "final_outcome": final,
                "epss_bin": bin_name, "rule": rule, "status": "EVALUATED"})
    return row


def poc_priority(base: str, kev: str, probability: float | str | None,
                 amp: dict) -> tuple[str, str]:
    policy = amp["probability_policy"]
    if kev == "Y":
        target = base if base in policy["kev"]["preserve"] else policy["kev"]["default"]
        return target, "POC_KEV_URGENT"
    rules = policy["non_kev"]
    if probability is None:
        return rules["missing"], "POC_EPSS_PROBABILITY"
    score = float(probability)
    if not 0 <= score <= 1:
        raise ValueError(f"Invalid EPSS probability: {score}")
    for threshold in rules["thresholds"]:
        if score >= threshold["minimum_probability"]:
            return threshold["outcome"], "POC_EPSS_PROBABILITY"
    return rules["default"], "POC_EPSS_PROBABILITY"


def apply_poc_policy(row: dict, amp: dict) -> None:
    """Apply the local KEV/EPSS targets while preserving the BOD result."""
    row["quartile_outcome"] = row["final_outcome"]
    if row["status"] == "INCOMPLETE":
        row.update(admission="REVIEW_REQUIRED", admission_reason=row["rule"])
        return
    target, rule = poc_priority(row["base_outcome"], row["kev"], row["epss_probability"], amp)
    row.update(final_outcome=target, rule=rule,
               admission="BLOCK" if row["kev"] == "Y" else "ALLOW",
               admission_reason=rule if row["kev"] == "Y" else "POC_NON_KEV_SCHEDULED")


def suppression_reason(match: dict, vex: dict | None, image: str) -> str:
    """Annotate Grype-ignored records only; never decide applicability here.

    Require an exact image and component identity before borrowing VEX prose.
    Ambiguous or unavailable explanations are explicit rather than guessed.
    """
    rules = match.get("appliedIgnoreRules") or []
    if not any(r.get("namespace") == "vex" or r.get("vexStatus")
               or "vex" in str(r.get("reason", "")).lower()
               for r in rules if isinstance(r, dict)):
        return "Not provided"
    ids = {v.get("id") for v in [match.get("vulnerability") or {}]
           + (match.get("relatedVulnerabilities") or [])}
    purl = (match.get("artifact") or {}).get("purl")
    reasons = set()
    for statement in (vex or {}).get("statements", []):
        vulnerability = statement.get("vulnerability") or {}
        if not ({vulnerability.get("name"), vulnerability.get("@id")} - {None}) & ids:
            continue
        if statement.get("status") not in ("not_affected", "fixed"):
            continue
        for product in statement.get("products", []):
            if image not in (product.get("@id"), (product.get("identifiers") or {}).get("purl")):
                continue
            if not purl or not any(purl in (c.get("@id"), (c.get("identifiers") or {}).get("purl"))
                                   for c in product.get("subcomponents", [])):
                continue
            reason = statement.get("impact_statement") or statement.get("justification")
            if isinstance(reason, str) and reason.strip():
                reasons.add(reason.strip())
    if len(reasons) == 1:
        return reasons.pop()
    return "Multiple VEX reasons; review source document" if reasons else "Not provided"


def evaluate(data: dict, exposure: str, image: str, base: dict, amp: dict,
             mapping: dict, enrichment: dict | None = None, vex: dict | None = None,
             *, poc_kev_epss: bool = False) -> dict:
    if not isinstance(data, dict) or not isinstance(data.get("matches"), list):
        raise ValueError("Invalid Grype report: expected 'matches' array")
    if exposure not in ("public", "internal", "unknown"):
        raise ValueError(f"Invalid exposure: {exposure}")
    findings = [make_decision(m, exposure, mapping, amp, enrichment) for m in data["matches"]]
    for finding in findings:
        if poc_kev_epss:
            apply_poc_policy(finding, amp)
    ignored = []
    for match in (data.get("ignoredMatches") or []):
        v = match.get("vulnerability") or {}
        a = match.get("artifact") or {}
        ignored.append({"vulnerability_id": v.get("id"), "package": a.get("name"),
                        "applied_ignore_rules": match.get("appliedIgnoreRules", []),
                        "reason": suppression_reason(match, vex, image)})
    counts = Counter(f.get("final_outcome") or "INCOMPLETE" for f in findings)
    admission_counts = Counter(
        f.get("admission") or (
            "REVIEW_REQUIRED" if f["status"] == "INCOMPLETE" else
            "BLOCK" if f["final_outcome"] in ("3D", "3DF") else "ALLOW"
        ) for f in findings)
    decision = "BLOCK" if admission_counts["BLOCK"] else (
        "REVIEW_REQUIRED" if admission_counts["REVIEW_REQUIRED"] else "ALLOW")
    return {
        "image": image,
        "exposure_input": exposure,
        "publicly_exposed": "N" if exposure == "internal" else "Y",
        "exposure_source": ("PROJECT_DECLARATION" if exposure in ("public", "internal")
                            else "UNKNOWN_DEFAULT_PUBLIC"),
        "assessed_at": datetime.now(timezone.utc).isoformat(),
        "model": base["id"],
        "amplifier": amp["probability_policy"]["id"] if poc_kev_epss else amp["id"],
        "admission": decision,
        "probability_policy": amp["probability_policy"] if poc_kev_epss else None,
        "admission_policy": ("LOCAL:POC_KEV_EPSS:1.0.0" if poc_kev_epss
                             else "LOCAL:QUARTILE_CI:1.0.0"),
        "admission_counts": dict(admission_counts),
        "provisional_count": admission_counts["PROVISIONAL"],
        "counts": dict(counts),
        "vex_ignored_count": len(ignored),
        "vulnrichment_counts": dict(Counter(f["vulnrichment_status"] for f in findings)),
        "findings": findings,
        "ignored_matches": ignored,
        "warnings": [
            ("FSU findings are reassessed each scan; missing EPSS uses FSU for non-KEV findings."
             if poc_kev_epss else
             "Urgent quartile-policy findings block CI."),
            "CISA Vulnrichment ADP values are preferred; missing SSVC uses local defaults. Lookup failures require review.",
            "KEV=N is provisional based on absence from completed Grype DB enrichment; direct CISA catalog freshness is not separately verified.",
            "VEX ignore results must be reviewed for precise product/component scope before enforcement."
        ]
    }


def report_legend(report: dict) -> list[str]:
    lines = ["", "## How to read and use this report", "",
             "1. Check Admission. ALLOW permits the image under the selected policy. BLOCK requires remediation or a reviewed, correctly scoped disposition. REVIEW_REQUIRED means assessment data is incomplete.",
             "2. Use Final for the local remediation target and Base for the original BOD result. Group repeated CVEs across packages when reviewing.",
             "3. Review the VEX-suppressed section for applicability evidence. FSU findings stay visible and are reassessed on subsequent scans.",
             "",
             "| Field | Meaning |", "|---|---|",
             "| KEV | Y = listed as known exploited in the available intelligence; N = absent from the scan database enrichment, subject to its freshness. |",
             "| PE | Public exposure. Y = public or conservatively assumed public when unknown; N = declared internal. |",
             "| Automatable | Y/N = exploitation can/cannot be automated according to SSVC or the recorded fallback. |",
             "| TI | P = Partial technical impact; T = Total. |",
             "| SSVC lookup | FOUND = CISA values available; NO_SSVC / NO_RECORD = defaults used; lookup failures require review. |",
             "| Severity | Scanner/vendor severity. The current probability policy does not use it to assign deadlines. |",
             "| EPSS bin | Q1–Q4 are percentile quartiles. The PoC probability policy uses EPSS probability from decision.json. |",
             "| Base / Final | BOD outcome / active policy target. 30D and 60D mean days; 3DF includes forensic follow-up. |",
             "| FSU | Address at a future scheduled upgrade/rebuild; no separate fixed-day deadline. Reevaluate each scan. |",
             "| Defaulted inputs | Assumptions, when reported. Source fields in decision.json provide the full provenance. |",
             "| Decision rule / Admission reason | Explain the target and gate result. POC_KEV_URGENT handles KEV; POC_EPSS_PROBABILITY handles non-KEV. |",
             "",
             "In enforce mode, BLOCK and REVIEW_REQUIRED fail the scan step. Shadow mode reports those decisions while allowing the step to complete.",
             "Download the security-* artifact: report.md is this summary; decision.json includes EPSS probability, input sources and decisions; grype.json and vulnrichment.json contain the scan and enrichment evidence."]
    policy = report.get("probability_policy")
    if policy:
        rules = policy["non_kev"]
        lines += ["", "### Active PoC amplifier", "",
                  "| Condition | Final target | CI |", "|---|---|---|",
                  "| KEV=Y | " + policy["kev"]["default"] + "; preserve " + ", ".join(policy["kev"]["preserve"]) + " | BLOCK |"]
        upper = None
        for threshold in rules["thresholds"]:
            value = threshold["minimum_probability"]
            condition = f"KEV=N, EPSS probability ≥{value:.0%}"
            if upper is not None:
                condition += f" and <{upper:.0%}"
            lines.append(f"| {condition} | {threshold['outcome']} | ALLOW |")
            upper = value
        lines += [f"| KEV=N, below all thresholds | {rules['default']} | ALLOW |",
                  f"| KEV=N, EPSS missing | {rules['missing']} | ALLOW |",
                  "", "These local policy settings come from policy/epss-amplifier.json in the pinned shared action revision. Updating that file requires publishing a revision and updating caller pins."]
    return lines


def markdown_report(report: dict) -> str:
    esc = lambda x: str(x or "").replace("|", "\\|").replace("\n", " ")
    lines = ["# CI Vulnerability Assessment", ""]
    lines += ["## Scan results", "",
              "- Image: `" + esc(report["image"]) + "`",
              "- Exposure: `" + esc(report["exposure_input"]) + "` → PE=`"
                  + esc(report["publicly_exposed"]) + "` (`" + esc(report["exposure_source"]) + "`)",
              "- Admission: **" + esc(report["admission"]) + "**",
              "- Provisional urgent findings (nonblocking): " + str(report["provisional_count"]),
              "- Admission policy: `" + esc(report["admission_policy"]) + "`",
              "- Base model: `" + esc(report["model"]) + "`",
              "- EPSS amplifier: `" + esc(report["amplifier"]) + "`",
              "- VEX-suppressed findings: " + str(report["vex_ignored_count"]), ""]
    lines += ["| CVE/advisory | Package | Severity | KEV | PE | Automatable | TI | SSVC lookup | EPSS bin | Base | Final | Decision rule | Admission | Defaulted inputs | Admission reason |","|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for finding in report["findings"]:
        cells = [finding.get("cve") or finding.get("vulnerability_id"),
                 finding.get("package"), finding.get("severity"), finding.get("kev"),
                 finding.get("publicly_exposed"), finding.get("automatable"),
                 finding.get("technical_impact"), finding.get("vulnrichment_status"),
                 finding.get("epss_bin"), finding.get("base_outcome"),
                 finding.get("final_outcome"), finding.get("rule"),
                 finding.get("admission"), ", ".join(finding.get("defaulted_inputs", [])),
                 finding.get("admission_reason")]
        lines.append("| " + " | ".join(esc(c) for c in cells) + " |")
    if not report["findings"]:
        lines.append("| No active findings | — | — | — | — | — | — | — | — | — | — | — | — | — | — |")
    lines += report_legend(report)
    lines += ["","## VEX-suppressed findings","","VEX can change **applicability**, not the CVE severity. Only findings accepted by Grype's VEX matching are excluded from the active gate; the original records remain below.",""]
    if report["ignored_matches"]:
        lines += ["| Vulnerability | Package | Ignore evidence | Reason |","|---|---|---|---|"]
        for item in report["ignored_matches"]:
            reasons = "; ".join(str(x.get("namespace") or x.get("reason") or x)
                                for x in item.get("applied_ignore_rules", []))
            lines.append("| " + " | ".join(esc(x) for x in
                [item.get("vulnerability_id"), item.get("package"), reasons or "unknown", item.get("reason") or "Not provided"]) + " |")
    else:
        lines.append("_No findings suppressed. Having a VEX document alone does not prove a statement matched._")
    lines += ["", "## Known MVP limits", ""] + ["- " + str(w) for w in report["warnings"]]
    return "\n".join(lines) + "\n"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--policy-dir", required=True)
    p.add_argument("--image", required=True)
    p.add_argument("--vulnrichment", help="CVE Services CISA-ADP lookup JSON from fetch_vulnrichment.py")
    p.add_argument("--exposure", choices=("public", "internal", "unknown"), default="unknown")
    p.add_argument("--vex", help="OpenVEX document for display-only suppression reasons")
    p.add_argument("--output", required=True)
    p.add_argument("--markdown", required=True)
    p.add_argument("--poc-kev-epss", action=argparse.BooleanOptionalAction, default=False,
                   help="Use the PoC KEV gate and EPSS probability targets")
    a = p.parse_args()
    base, amp, mapping = load_policy(Path(a.policy_dir))
    data = json.loads(Path(a.input).read_text(encoding="utf-8"))
    enrichment = json.loads(Path(a.vulnrichment).read_text(encoding="utf-8")) if a.vulnrichment else None
    vex = json.loads(Path(a.vex).read_text(encoding="utf-8")) if a.vex else None
    report = evaluate(data, a.exposure, a.image, base, amp, mapping, enrichment, vex,
                      poc_kev_epss=a.poc_kev_epss)
    Path(a.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    Path(a.markdown).write_text(markdown_report(report), encoding="utf-8")
    print(report["admission"])


if __name__ == "__main__":
    main()


