#!/usr/bin/env python3
"""Collect current Defender assessments. Evidence discovery only; never an admission gate."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
ENDPOINT = 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01'


def subscriptions(value):
    items = json.loads(value)
    if not isinstance(items, list) or not items:
        raise ValueError('AZURE_SUBSCRIPTION_IDS must be a nonempty JSON array of subscription UUIDs')
    return list(dict.fromkeys(str(UUID(item)) for item in items))


def request(body):
    # No shell interpolation, bearer token handling, or resource-graph CLI extension.
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / 'request.json'
        path.write_text(json.dumps(body))
        result = subprocess.run(
            ['az', 'rest', '--method', 'post', '--url', ENDPOINT,
             '--body', '@' + str(path), '--output', 'json', '--only-show-errors'],
            capture_output=True, text=True, timeout=120, check=False)
    if result.returncode:
        # Avoid putting tenant evidence or CLI diagnostics into public logs.
        raise RuntimeError('Azure query failed; check identity, RBAC, API availability and query')
    return json.loads(result.stdout)


def collect(subscription, query, send=request):
    rows, tokens, identities = [], set(), set()
    token = None
    while True:
        options = {'$top': 1000, 'resultFormat': 'objectArray'}
        if token:
            options['$skipToken'] = token
        page = send({'subscriptions': [subscription], 'query': query, 'options': options})
        data = page.get('data')
        if not isinstance(data, list) or page.get('count') != len(data):
            raise ValueError('Invalid ARG response shape/count')
        for row in data:
            if not isinstance(row, dict) or not row.get('id') or not isinstance(row.get('properties'), dict):
                raise ValueError('Invalid assessment row')
            if str(row.get('subscriptionId', '')).lower() != subscription.lower():
                raise ValueError('Assessment outside requested subscription')
            key = row['id'].lower()
            if key in identities:
                raise ValueError('Duplicate assessment across pages; retry collection')
            identities.add(key)
        rows.extend(data)
        token = page.get('$skipToken')
        truncated = str(page.get('resultTruncated', 'false')).lower() == 'true'
        if not token:
            if truncated:
                raise ValueError('Truncated ARG response without continuation token')
            return rows
        if not isinstance(token, str) or token in tokens or not data:
            raise ValueError('Invalid/repeated continuation token')
        tokens.add(token)


def normalize(rows):
    """Provisional CVE observations. Missing product identity explicitly prevents evaluation."""
    observations, unresolved = [], []
    for row in rows:
        p = row['properties']
        additional = p.get('additionalData') or {}
        cves = additional.get('CvesDetails')
        if isinstance(cves, str):
            try:
                cves = json.loads(cves)
            except json.JSONDecodeError:
                cves = None
        if not isinstance(cves, list) or not cves or any(
                not isinstance(cve, dict) or not isinstance(cve.get('CveId'), str)
                or not cve['CveId'].startswith('CVE-') for cve in cves):
            unresolved.append({'assessment_id': row['id'], 'reason': 'missing_or_unrecognized_CvesDetails'})
            continue
        for cve in cves:
            observations.append({
                'schema_version': 'defender-observation/0.1',
                'source': 'azure-defender-for-cloud', 'assessment_id': row['id'],
                'subscription_id': row['subscriptionId'], 'vulnerability_id': cve['CveId'],
                'provider_status': (p.get('status') or {}).get('code'),
                'severity': (p.get('metadata') or {}).get('severity'),
                'resource_details': p.get('resourceDetails'),
                'detected_versions': additional.get('DetectedSoftwareVersions'),
                'fixed_version': additional.get('FixedVersion'),
                'provider_status_details': p.get('status'),
                'image_digest': None, 'package_purl': None, 'runtime_confirmed': None,
                'asset_class': 'unclassified', 'prod_critical': None,
                'vex_status': 'NOT_EVALUATED', 'decision': 'INCOMPLETE',
                'reason': 'Requires validated asset/package mapping, runtime inventory and shared evaluator',
            })
    return observations, unresolved


def write(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    # Refuse to mix previous-run evidence with this run.
    args.out.mkdir(parents=True, exist_ok=False)
    summary = {'collected_at': datetime.now(timezone.utc).isoformat(),
               'collection_status': 'INCOMPLETE', 'runtime_coverage': 'UNKNOWN',
               'policy_evaluation': 'NOT_EVALUATED', 'subscriptions': []}
    try:
        selected = subscriptions(os.environ.get('AZURE_SUBSCRIPTION_IDS', ''))
        query = (ROOT / 'queries/assessments.kql').read_text()
        write(args.out / 'query.json', {'query': query, 'api_version': '2024-04-01'})
        all_rows = []
        # Separate calls prevent an inaccessible subscription being hidden by another scope.
        for subscription in selected:
            rows = collect(subscription, query)
            write(args.out / (subscription + '.raw.json'), rows)
            all_rows.extend(rows)
            summary['subscriptions'].append({'id': subscription, 'assessment_count': len(rows)})
        observations, unresolved = normalize(all_rows)
        write(args.out / 'observations.json', observations)
        write(args.out / 'unresolved.json', unresolved)
        summary.update(collection_status='COMPLETE', assessment_count=len(all_rows),
                       observation_count=len(observations), unresolved_count=len(unresolved),
                       resource_types=dict(Counter(str((r['properties'].get('resourceDetails') or {}).get('ResourceType', 'UNKNOWN')) for r in all_rows)))
        # A completed extraction is never evidence of complete runtime/security coverage.
        return 0
    except Exception as exc:
        summary['error_type'] = type(exc).__name__
        print('Defender collection incomplete. See summary.json; no security verdict produced.', file=sys.stderr)
        return 1
    finally:
        write(args.out / 'summary.json', summary)


if __name__ == '__main__':
    sys.exit(main())
