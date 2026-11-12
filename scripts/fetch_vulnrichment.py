#!/usr/bin/env python3
"""Fetch CISA-ADP SSVC Automatable and Technical Impact for Grype CVEs."""
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from evaluate import select_cve

API = "https://cveawg.mitre.org/api/cve/"
CISA_ORG = "134c704f-9b21-4f2e-91b3-4a467353bcc0"


class InvalidSSVC(ValueError):
    """Published CISA SSVC is malformed or unsupported."""


def parse_cisa_ssvc(record: dict, cve: str) -> dict:
    if not isinstance(record, dict):
        raise InvalidSSVC("CVE record must be an object")
    meta = record.get("cveMetadata") or {}
    if str(meta.get("cveId", "")).upper() != cve:
        raise InvalidSSVC("Response CVE ID mismatch")
    if meta.get("state") != "PUBLISHED":
        return {"status": "NO_SSVC", "reason": "CVE is not published"}

    containers = (record.get("containers") or {}).get("adp") or []
    if not isinstance(containers, list):
        raise InvalidSSVC("ADP containers are not an array")
    candidates = []
    for adp in containers:
        if not isinstance(adp, dict):
            continue
        provider = adp.get("providerMetadata") or {}
        if provider.get("shortName") != "CISA-ADP" or provider.get("orgId") != CISA_ORG:
            continue
        for metric in adp.get("metrics") or []:
            other = metric.get("other") if isinstance(metric, dict) else None
            if not isinstance(other, dict) or str(other.get("type", "")).lower() != "ssvc":
                continue
            content = other.get("content")
            if not isinstance(content, dict):
                raise InvalidSSVC("SSVC content is not an object")
            candidates.append(content)
    if not candidates:
        return {"status": "NO_SSVC", "reason": "CISA has no SSVC assessment"}

    content = max(candidates, key=lambda c: str(c.get("timestamp") or ""))
    version = str(content.get("version") or "")
    if not version.startswith("2.0."):
        raise InvalidSSVC(f"Unsupported SSVC version {version!r}")
    if str(content.get("id", "")).upper() != cve:
        raise InvalidSSVC("SSVC CVE ID mismatch")
    if content.get("role") != "CISA Coordinator":
        raise InvalidSSVC("Unexpected SSVC role")
    options = content.get("options")
    if not isinstance(options, list):
        raise InvalidSSVC("SSVC options are not an array")
    values = {}
    for option in options:
        if isinstance(option, dict):
            values.update(option)
    auto = str(values.get("Automatable") or "").lower()
    impact = str(values.get("Technical Impact") or "").lower()
    if auto not in ("yes", "no") or impact not in ("partial", "total"):
        raise InvalidSSVC("Automatable/Technical Impact absent or invalid")
    return {
        "status": "FOUND",
        "automatable": "Y" if auto == "yes" else "N",
        "technical_impact": "T" if impact == "total" else "P",
        "ssvc_version": version,
        "ssvc_timestamp": content.get("timestamp"),
    }


def fetch_one(cve: str, timeout: float = 8.0, retries: int = 2) -> dict:
    url = API + cve
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "grype-policy-ci/1.1"}
    )
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                record = json.load(resp)
            return {"url": url, **parse_cisa_ssvc(record, cve)}
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {"status": "NO_RECORD", "url": url, "reason": "CVE record not found"}
            error = f"CVE Services HTTP {exc.code}"
            retry = exc.code in (429, 500, 502, 503, 504)
        except InvalidSSVC as exc:
            return {"status": "INVALID_SSVC", "url": url, "reason": str(exc)}
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            error = f"CVE Services error: {type(exc).__name__}"
            retry = True
        if retry and attempt < retries:
            time.sleep(min(2 ** attempt, 4))
        else:
            return {"status": "FETCH_ERROR", "url": url, "reason": error}
    raise RuntimeError("Unexpected retry loop exit")


def collect(data: dict, getter=fetch_one) -> dict:
    if not isinstance(data, dict) or not isinstance(data.get("matches"), list):
        raise ValueError("Expected Grype matches array")
    cves = sorted({cve for match in data["matches"] if (cve := select_cve(match))})
    results = {cve: getter(cve) for cve in cves}
    return {
        "source": "CVE_SERVICES_CISA_ADP",
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "cves": results,
        "counts": dict(Counter(item.get("status", "UNKNOWN") for item in results.values())),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--retries", type=int, default=2)
    a = p.parse_args()
    if a.timeout <= 0 or not 0 <= a.retries <= 5:
        p.error("timeout must be positive; retries must be 0..5")
    source = json.loads(Path(a.input).read_text(encoding="utf-8"))
    result = collect(source, getter=lambda cve: fetch_one(cve, a.timeout, a.retries))
    Path(a.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("CISA Vulnrichment:", result["counts"])


if __name__ == "__main__":
    main()
