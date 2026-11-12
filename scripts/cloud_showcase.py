#!/usr/bin/env python3
"""Connected offline demonstration; identity mappings are synthetic, not cloud discovery."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys

from runtime_assess import assess, markdown_report, read_vex_map

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def enrich(inspector, defender, mapping):
    """Explicit fixture-only bridge for identities the provider adapters do not resolve."""
    inspector, defender = copy.deepcopy(inspector), copy.deepcopy(defender)
    if inspector is not None:
        for row in inspector['findings']:
            p = row['package']
            candidates = [m for m in mapping.get('inspector', [])
                          if (m['finding_arn'], m['cve'], m['digest'], m['package'], m['version']) ==
                          (row['finding_arn'], row['vulnerability_id'], row['asset']['image_digest'], p.get('name'), p.get('version'))]
            if len(candidates) > 1:
                raise ValueError('Ambiguous Inspector identity mapping')
            if candidates:
                p['purl'] = candidates[0]['purl']
                row['identity_source'] = 'SYNTHETIC_FIXTURE_MAP'
    if defender is not None:
        for row in defender:
            candidates = [m for m in mapping.get('defender', [])
                          if (m['assessment_id'], m['subscription_id'], m['cve']) ==
                          (row['assessment_id'], row['subscription_id'], row['vulnerability_id'])]
            if len(candidates) > 1:
                raise ValueError('Ambiguous Defender identity mapping')
            if candidates:
                m = candidates[0]
                for key in ('image_digest', 'package_name', 'package_version', 'package_purl'):
                    row[key] = m[key]
                row['resource_details'].update(registry=m['registry'], repository=m['repository'])
                row['identity_source'] = 'SYNTHETIC_FIXTURE_MAP'
    return inspector, defender


def run(output, scenario='all', fixture=None, identity_map=None):
    fixture = fixture or ROOT / 'tests/fixtures/cloud-showcase'
    runtime = ROOT / 'tests/fixtures/runtime'
    output.mkdir(parents=True, exist_ok=False)
    def cli(script, *args):
        subprocess.run([sys.executable, str(ROOT / 'scripts' / script), *map(str, args)], check=True)
    sources = ('inspector', 'defender') if scenario in ('all', 'runtime') else (scenario,)
    inspector = defender = None
    inventories = []
    for source in sources:
        dest = output / source
        if source == 'inspector':
            cli('collect_inspector.py', '--input-file', fixture / 'inspector-raw.json', '--output', dest)
            inspector = read(dest / 'normalized-findings.json')
            platform, name, scope = 'EKS', 'eks', ['--account-id', '123456789012', '--region', 'eu-north-1']
        else:
            cli('read_azure.py', '--input', fixture / 'defender-raw.json', '--out', dest)
            defender = read(dest / 'observations.json')
            platform, name, scope = 'AKS', 'aks', ['--subscription-id', '11111111-1111-1111-1111-111111111111']
        cli('runtime_workloads.py', '--platform', platform, '--cluster', name + '-demo', *scope,
            '--input', runtime / (name + '-pods.json'), '--output', output / (name + '.json'))
        inventories.append(read(output / (name + '.json')))
    mapping = read(identity_map or fixture / 'synthetic-identity-map.json')
    write(output / 'identity-map-used.json', mapping)
    inspector, defender = enrich(inspector, defender, mapping)
    if inspector is not None:
        write(output / 'inspector-enriched.json', inspector)
    if defender is not None:
        write(output / 'defender-enriched.json', defender)
    intel, vex = read(runtime / 'intelligence.json'), read_vex_map(runtime / 'vex-map.json')
    result = assess(inspector, defender, inventories, intel, vex, ROOT / 'policy')
    result['demo_identity_source'] = 'SYNTHETIC_FIXTURE_MAP'
    write(output / 'decisions.json', result)
    lines = ['# Connected cloud security showcase (synthetic)', '',
             '**Raw provider fixtures → actual normalizers → explicit synthetic identity map → Pod matching → project VEX → BOD/EPSS.**', '',
             'No live cloud collection. The map supplies Azure image/package identity and AWS package PURLs; this demonstrates downstream processing, not automatic live identity discovery. Original normalized evidence is retained unchanged.', '',
             'A green job means processing and assertions passed, not that the images are safe.', '']
    for source in sources:
        aws = inspector if source == 'inspector' else None
        azure = defender if source == 'defender' else None
        platform = "EKS" if source == "inspector" else "AKS"
        provider_inventory = [{**i, "workloads": [w for w in i["workloads"] if w["platform"] == platform]} for i in inventories]
        provider_result = assess(aws, azure, provider_inventory, intel, vex, ROOT / 'policy')
        write(output / (source + '-decisions.json'), provider_result)
        lines += ['## ' + ('AWS Inspector' if aws is not None else 'Azure Defender'), '']
        if aws is not None:
            lines += [f"Normalized package observations: **{len(aws['findings'])}**.", '']
        else:
            unresolved = read(output / 'defender/unresolved.json')
            lines += [f'Normalized CVE observations: **{len(azure)}**. Assessments without usable CVE details: **{len(unresolved)}** (see `defender/unresolved.json`).', '']
        lines.append(markdown_report(provider_result).replace('# Running container', '### Running container', 1))
    lines += ['## Combined result', '', markdown_report(result)]
    (output / 'report.md').write_text('\n'.join(lines))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scenario', choices=['all', 'runtime', 'inspector', 'defender'], default='all')
    args = parser.parse_args()
    report = run(args.output, args.scenario)
    active = sum(r['decision_status'] == 'EVALUATED' and r['vex_status'] == 'ACTIVE' for r in report['observations'])
    if active:
        print(f'::warning title=Synthetic security findings::{active} active evaluated findings. See provider-specific outcomes in the summary. Job success does not mean safe images.')
