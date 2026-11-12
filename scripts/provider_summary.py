#!/usr/bin/env python3
"""Render provider normalization evidence; does not evaluate runtime policy."""
import argparse
import html
import json
from pathlib import Path


def cell(value):
    if value is None or value == "":
        return "Unknown"
    return html.escape(str(value)).replace("|", "&#124;").replace("\n", " ").replace("\r", " ")


def render(provider, directory):
    def read(name):
        return json.loads((directory / name).read_text())
    title = "AWS Inspector" if provider == "inspector" else "Azure Defender"
    lines = [f"## {title} normalization (synthetic)", "",
             "Synthetic fixture data only; no cloud credentials or live collection.", "",
             "These are provider observations, before runtime correlation, VEX and BOD/EPSS.", ""]
    if provider == "inspector":
        rows = read("normalized-findings.json")["findings"]
        lines += [f"Normalized package findings: **{len(rows)}**. Distinct vulnerability IDs: **{len({r.get('vulnerability_id') for r in rows})}**.", "",
                  "| Vulnerability | Package | Version | Severity | Provider status | Repository | Provider usage hint |",
                  "|---|---|---|---|---|---|---|"]
        for r in rows:
            p = r.get("package") or {}
            values = [r.get("vulnerability_id"), p.get("name"), p.get("version"), r.get("severity"),
                      r.get("provider_status"), (r.get("asset") or {}).get("repository"),
                      (r.get("runtime") or {}).get("state")]
            lines.append("| " + " | ".join(map(cell, values)) + " |")
        lines += ["", "DEBUG-VULN IDs are invented normalization examples, not real CVEs.",
                  "Provider usage hints do not prove that an image is running in an EKS Pod.",
                  "Full image digests and raw evidence: `poc-inspector-synthetic` artifact."]
    else:
        rows, unresolved, summary = read("observations.json"), read("unresolved.json"), read("summary.json")
        lines += [f"CVE observations: **{len(rows)}**. Unresolved assessments: **{len(unresolved)}**. Excluded non-container assessments: **{summary.get('excluded_noncontainer_count', 0)}**.", "",
                  "| CVE | Severity | Provider status | Detected versions | Image digest | Package PURL | Evaluation |",
                  "|---|---|---|---|---|---|---|"]
        for r in rows:
            values = [r.get("vulnerability_id"), r.get("severity"), r.get("provider_status"),
                      r.get("detected_versions"), r.get("image_digest"), r.get("package_purl"), r.get("decision")]
            lines.append("| " + " | ".join(map(cell, values)) + " |")
        if unresolved:
            lines += ["", "### Unresolved assessments", "", "| Assessment | Reason |", "|---|---|"]
            for r in unresolved:
                lines.append("| " + cell(r.get("assessment_id")) + " | " + cell(r.get("reason")) + " |")
        lines += ["", "Unknown image/package identity prevents runtime matching and scoped VEX evaluation; it does not mean zero vulnerabilities.",
                  "Full observations and collection metadata: `poc-defender-synthetic` artifact."]
    if not rows:
        lines += ["", "**No normalized observations. Coverage remains unverified; this is not a clean security verdict.**"]
    lines += ["", "The combined runtime demo uses separate prepared fixtures in `tests/fixtures/runtime/`; these provider jobs do not feed that demo."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=["inspector", "defender"], required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    print(render(args.provider, args.directory), end="")
