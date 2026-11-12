#!/usr/bin/env python3
"""Read-only Inspector collection using AWS CLI v2; no Python dependencies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from datetime import datetime, timezone


def aws(region, service, operation, *args):
    result = subprocess.run(
        ['aws', service, operation, '--region', region, '--output', 'json',
         '--no-cli-pager', *args], check=True, text=True, capture_output=True,
        env={**os.environ, 'AWS_RETRY_MODE': 'standard', 'AWS_MAX_ATTEMPTS': '5'},
    )
    return json.loads(result.stdout)


def pages(region, operation, key):
    """Explicit service pagination; never mix CLI max-items with nextToken."""
    rows, seen, token = [], set(), None
    while True:
        args = ['--no-paginate', '--max-results', '100']
        if token:
            args += ['--next-token', token]
        response = aws(region, 'inspector2', operation, *args)
        if not isinstance(response.get(key), list):
            raise ValueError(f'{operation}: missing {key} array')
        rows.extend(response[key])
        token = response.get('nextToken')
        if not token:
            return rows
        if token in seen:
            raise ValueError(f'{operation}: repeated pagination token')
        seen.add(token)


def normalize(findings):
    rows = []
    for finding in findings:
        if finding.get('type') != 'PACKAGE_VULNERABILITY':
            continue  # All other finding types remain in raw-findings.json.
        vuln = finding.get('packageVulnerabilityDetails', {})
        for resource in finding.get('resources', []):
            kind = resource.get('type')
            if kind not in ('AWS_ECR_CONTAINER_IMAGE', 'AWS_EC2_INSTANCE'):
                continue
            details = resource.get('details', {})
            image = details.get('awsEcrContainerImage', {})
            count = image.get('inUseCount')
            runtime = ('UNKNOWN' if count is None else
                       'REPORTED_IN_USE' if count > 0 else 'NOT_REPORTED_IN_USE')
            if kind == 'AWS_EC2_INSTANCE':
                runtime = 'HOST_REQUIRES_INVENTORY'
            for package in vuln.get('vulnerablePackages') or [{}]:
                identity = [finding.get('awsAccountId'), resource.get('region'),
                            kind, resource.get('id'), image.get('imageHash'),
                            image.get('architecture'), vuln.get('vulnerabilityId'),
                            package.get('packageManager'), package.get('name'),
                            package.get('epoch'), package.get('version'),
                            package.get('release'), package.get('arch'),
                            package.get('filePath')]
                rows.append({
                    'schema_version': '0.1',
                    'observation_id': hashlib.sha256(json.dumps(
                        [finding.get('findingArn'), identity], separators=(',', ':')
                    ).encode()).hexdigest(),
                    'source': 'aws-inspector',
                    'finding_arn': finding.get('findingArn'),
                    'account_id': finding.get('awsAccountId'),
                    'region': resource.get('region'),
                    'provider_status': finding.get('status'),
                    'vulnerability_id': vuln.get('vulnerabilityId'),
                    'severity': finding.get('severity'),
                    'first_observed_at': finding.get('firstObservedAt'),
                    'last_observed_at': finding.get('lastObservedAt'),
                    'updated_at': finding.get('updatedAt'),
                    'asset': {'type': kind, 'id': resource.get('id'),
                              'tags': resource.get('tags', {}),
                              'image_digest': image.get('imageHash'),
                              'repository': image.get('repositoryName'),
                              'registry': image.get('registry'),
                              'architecture': image.get('architecture')},
                    'runtime': {'state': runtime, 'in_use_count': count,
                                'last_in_use_at': image.get('lastInUseAt')},
                    'package': package,
                    'cvss': vuln.get('cvss', []),
                    'fix_available': finding.get('fixAvailable'),
                    'exploit_available': finding.get('exploitAvailable'),
                    'epss_probability': finding.get('epss', {}).get('score'),
                    'epss_percentile': None,
                    'kev': None,
                    'prod_critical': None,
                    'vex_status': 'NOT_EVALUATED',
                    'decision_status': 'PENDING_ENRICHMENT_AND_POLICY',
                })
    return rows


def write_json(path, payload):
    path.write_text(json.dumps(payload, indent=2) + '\n')


def collect(region, output):
    output.mkdir(parents=True, exist_ok=False)
    manifest = {'schema_version': '0.1', 'region': region,
                'started_at': datetime.now(timezone.utc).isoformat(),
                'collection_complete': False, 'policy_evaluated': False}
    write_json(output / 'manifest.json', manifest)
    try:
        manifest['caller_account'] = aws(region, 'sts', 'get-caller-identity')['Account']
        # Keep ACTIVE, SUPPRESSED and CLOSED observations. Provider suppression
        # is not project VEX, and provider closure is not verified remediation.
        findings = pages(region, 'list-findings', 'findings')
        write_json(output / 'raw-findings.json', {'findings': findings})
        coverage = pages(region, 'list-coverage', 'coveredResources')
        write_json(output / 'coverage.json', {'coveredResources': coverage})
        rows = normalize(findings)
        write_json(output / 'normalized-findings.json', {'findings': rows})
        manifest.update(collection_complete=True, raw_count=len(findings),
                        normalized_count=len(rows), coverage_count=len(coverage))
    finally:
        manifest['finished_at'] = datetime.now(timezone.utc).isoformat()
        write_json(output / 'manifest.json', manifest)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--region', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    collect(args.region, args.output)
