#!/usr/bin/env python3
"""Fetch authoritative CISA KEV, FIRST EPSS percentile and CISA-ADP SSVC.

This is a *point-in-time snapshot*. A failed KEV fetch is fatal; a failed EPSS
or SSVC lookup is marked FETCH_ERROR per CVE, never mistaken for absence.
"""
from __future__ import annotations
import argparse
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from fetch_vulnrichment import fetch_one

CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def get_json(url: str, timeout: int = 30) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   "User-Agent": "runtime-security-poc/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        # Limit untrusted response size.
        raw = response.read(10_000_001)
    if len(raw) > 10_000_000:
        raise ValueError("Unreasonably large intelligence response")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")
    return data


def parse_kev(doc: dict) -> dict:
    vulnerabilities = doc.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities or not doc.get("catalogVersion"):
        raise ValueError("Invalid KEV catalog: missing vulnerabilities/version")
    if doc.get("count") != len(vulnerabilities):
        raise ValueError("CISA KEV count mismatch; refuse incomplete catalog")
    values = [v.get("cveID") for v in vulnerabilities]
    if any(not isinstance(v, str) or not CVE.fullmatch(v) for v in values) or len(set(values)) != len(values):
        raise ValueError("Malformed/duplicate KEV CVEs")
    return {"complete": True, "catalog_version": doc["catalogVersion"],
            "date_released": doc.get("dateReleased"), "cves": sorted(values)}


def parse_epss(doc: dict, requested: list[str]) -> dict:
    if doc.get("status") != "OK" or not isinstance(doc.get("data"), list):
        raise ValueError("FIRST EPSS returned invalid status/data")
    if doc.get("total") != len(doc["data"]):
        raise ValueError("EPSS response incomplete or paginated")
    values = {}
    for item in doc["data"]:
        cve = item.get("cve")
        if cve not in requested or cve in values:
            raise ValueError("Unexpected/duplicate CVE in EPSS")
        prob, pct = float(item["epss"]), float(item["percentile"])
        if not 0 <= prob <= 1 or not 0 <= pct <= 1:
            raise ValueError("EPSS probability/percentile out of range")
        values[cve] = {"status": "FOUND", "probability": prob, "percentile": pct,
                       "date": item.get("date")}
    return values


def fetch_snapshot(cves: list[str], getter=get_json, ssvc_getter=fetch_one) -> dict:
    cves = sorted(set(c.upper() for c in cves))
    if any(not CVE.fullmatch(c) for c in cves):
        raise ValueError("Only CVE identifiers are supported")
    # KEV must be complete to distinguish KEV=N from unverified/unknown.
    kev = parse_kev(getter(KEV_URL))
    epss = {}
    for i in range(0, len(cves), 20):
        batch = cves[i:i+20]
        url = EPSS_URL + "?" + urllib.parse.urlencode({"cve": ",".join(batch)})
        try:
            parsed = parse_epss(getter(url), batch)
            for cve in batch:
                epss[cve] = parsed.get(cve, {"status": "NOT_FOUND"})
        except (OSError, urllib.error.URLError, ValueError, KeyError, TypeError):
            for cve in batch:
                epss[cve] = {"status": "FETCH_ERROR"}
    cisa = {cve: ssvc_getter(cve) for cve in cves}
    return {
        "schema_version": "runtime-intelligence/1.0",
        "complete": True,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "kev": kev,
        "epss": epss,
        "cisa": cisa,
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cves", type=Path, required=True, help="JSON array of CVE strings")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    cves = json.loads(a.cves.read_text())
    if not isinstance(cves, list):
        p.error("Expected JSON CVE string array")
    result = fetch_snapshot(cves)
    a.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Runtime intelligence: snapshot for {len(set(cves))} CVEs")


if __name__ == "__main__":
    main()
