#!/usr/bin/env python3
"""Minimal fail-closed VEX sanity checks; NOT comprehensive OpenVEX schema validation."""
import json
import sys
from pathlib import Path

VALID_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}


def validate(path: Path) -> None:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("statements"), list):
        raise ValueError("Expected OpenVEX object with 'statements' array")
    if not all(doc.get(k) for k in ("@context", "@id", "author", "version")):
        raise ValueError("Missing basic OpenVEX document metadata")
    for i, stmt in enumerate(doc["statements"]):
        if not isinstance(stmt, dict):
            raise ValueError(f"Statement {i}: expected object")
        if stmt.get("status") not in VALID_STATUSES:
            raise ValueError(f"Statement {i}: invalid status")
        if not (isinstance(stmt.get("vulnerability"), dict) and stmt["vulnerability"].get("name")):
            raise ValueError(f"Statement {i}: vulnerability.name missing")
        products = stmt.get("products")
        if not isinstance(products, list) or not products or not all(isinstance(p, dict) and p.get("@id") for p in products):
            raise ValueError(f"Statement {i}: non-empty products with @id required")
        if stmt["status"] == "not_affected" and not (stmt.get("justification") or stmt.get("impact_statement")):
            raise ValueError(f"Statement {i}: not_affected needs justification or impact_statement")


if __name__ == "__main__":
    try:
        validate(Path(sys.argv[1]))
    except (OSError, ValueError, json.JSONDecodeError, IndexError) as exc:
        print(f"VEX validation failed: {exc}", file=sys.stderr)
        sys.exit(1)
